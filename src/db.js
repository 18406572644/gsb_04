'use strict';

const { DatabaseSync } = require('node:sqlite');
const { now, randomId } = require('./util');

/**
 * 持久层：SQLite（WAL 模式）。
 *
 * 可靠性设计要点：
 * 1. 消息与房间序号 seq 在同一事务中「先落库、后广播」——进程崩溃也不丢已确认消息。
 * 2. messages 上 (room_id, sender_id, client_msg_id) 唯一约束——客户端重试/网络重复
 *    提交同一条消息时不会产生重复记录，实现发送幂等。
 * 3. seq 为每房间单调递增序号，由 rooms.last_seq 计数器在事务内分配——保证房间内
 *    消息全序（时序可控），客户端可凭 seq 检测空洞并触发补发。
 *
 * 富媒体扩展：
 * - messages 多态化：msg_type(text/image/file/voice) + asset_id + quote_seq + recalled；
 * - assets 为内容寻址资源（sha256 全局唯一）→ 重复上传秒传、跨消息共享同一物理对象，
 *   引用计数由「未撤回消息数」实时推导，无计数漂移；
 * - upload_tasks / upload_chunks 记录两阶段发送的阶段一（分块上传进度），支持断点续传；
 * - 资产以 tombstone（status='deleted'）保留行记录用于审计与历史渲染，物理文件单独删除。
 */

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
PRAGMA synchronous = FULL;

CREATE TABLE IF NOT EXISTS users (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  token_random TEXT NOT NULL,
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rooms (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  last_seq   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS members (
  room_id     TEXT NOT NULL REFERENCES rooms(id),
  user_id     TEXT NOT NULL REFERENCES users(id),
  role        TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin','member')),
  muted_until INTEGER NOT NULL DEFAULT 0,
  joined_at   INTEGER NOT NULL,
  PRIMARY KEY (room_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
  room_id       TEXT NOT NULL REFERENCES rooms(id),
  seq           INTEGER NOT NULL,
  client_msg_id TEXT NOT NULL,
  sender_id     TEXT NOT NULL REFERENCES users(id),
  content       TEXT NOT NULL DEFAULT '',
  msg_type      TEXT NOT NULL DEFAULT 'text'
                  CHECK (msg_type IN ('text','image','file','voice')),
  asset_id      TEXT REFERENCES assets(id),
  quote_seq     INTEGER,
  recalled      INTEGER NOT NULL DEFAULT 0,
  recalled_at   INTEGER NOT NULL DEFAULT 0,
  ts            INTEGER NOT NULL,
  PRIMARY KEY (room_id, seq),
  UNIQUE (room_id, sender_id, client_msg_id)  -- 幂等键
);

-- 服务端保存的每用户每房间已确认游标（断线补发的兜底依据）
CREATE TABLE IF NOT EXISTS cursors (
  room_id      TEXT NOT NULL REFERENCES rooms(id),
  user_id      TEXT NOT NULL REFERENCES users(id),
  last_ack_seq INTEGER NOT NULL DEFAULT 0,
  updated_at   INTEGER NOT NULL,
  PRIMARY KEY (room_id, user_id)
);

-- 富媒体资源（内容寻址：sha256 全局唯一 → 天然去重/秒传）
CREATE TABLE IF NOT EXISTS assets (
  id          TEXT PRIMARY KEY,
  sha256      TEXT NOT NULL UNIQUE,
  size        INTEGER NOT NULL,
  mime        TEXT NOT NULL,
  filename    TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('image','file','voice')),
  uploader_id TEXT NOT NULL REFERENCES users(id),
  -- scanning: 扫描中（不可发消息）；ready: 干净可用；infected: 含病毒（hash 拉黑）；
  -- scan_error: 扫描器故障（可重试）；deleted: 物理文件已删（tombstone，保留审计记录）
  status      TEXT NOT NULL DEFAULT 'scanning'
                CHECK (status IN ('scanning','ready','infected','scan_error','deleted')),
  scan_info   TEXT NOT NULL DEFAULT '',
  storage_path TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL,
  ready_at    INTEGER NOT NULL DEFAULT 0
);

-- 上传任务（阶段一）。同一用户对同一内容只允许一个 open 任务 → 中断后凭 hash 找回续传
CREATE TABLE IF NOT EXISTS upload_tasks (
  id           TEXT PRIMARY KEY,
  uploader_id  TEXT NOT NULL REFERENCES users(id),
  asset_id     TEXT REFERENCES assets(id),
  filename     TEXT NOT NULL,
  kind         TEXT NOT NULL CHECK (kind IN ('image','file','voice')),
  mime         TEXT NOT NULL,
  size         INTEGER NOT NULL,
  sha256       TEXT NOT NULL,
  chunk_size   INTEGER NOT NULL,
  total_chunks INTEGER NOT NULL,
  -- open: 上传中(可续传)；completed: 合并完成(含感染/干净)；expired: 超时清理
  status       TEXT NOT NULL DEFAULT 'open'
                 CHECK (status IN ('open','completed','expired')),
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL,
  completed_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS upload_chunks (
  task_id     TEXT NOT NULL REFERENCES upload_tasks(id) ON DELETE CASCADE,
  idx         INTEGER NOT NULL,
  size        INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  PRIMARY KEY (task_id, idx)
);

-- 下载审计
CREATE TABLE IF NOT EXISTS asset_downloads (
  id        TEXT PRIMARY KEY,
  asset_id  TEXT NOT NULL REFERENCES assets(id),
  user_id   TEXT NOT NULL REFERENCES users(id),
  room_id   TEXT NOT NULL REFERENCES rooms(id),
  bytes     INTEGER NOT NULL,
  ts        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_asset ON messages(asset_id);
CREATE INDEX IF NOT EXISTS idx_assets_status_ready ON assets(status, ready_at);
CREATE INDEX IF NOT EXISTS idx_upload_tasks_open ON upload_tasks(status, updated_at);
-- 同用户同内容只允许一个进行中任务（断点后重新 init 直接找回原任务续传）
CREATE UNIQUE INDEX IF NOT EXISTS ux_upload_open_hash
  ON upload_tasks(uploader_id, sha256) WHERE status = 'open';
`;

const MSG_SELECT = `
  SELECT m.room_id AS roomId, m.seq, m.client_msg_id AS clientMsgId,
         m.sender_id AS "from", u.name AS fromName, m.content, m.ts,
         m.msg_type AS msgType, m.asset_id AS assetId, m.quote_seq AS quoteSeq,
         m.recalled, m.recalled_at AS recalledAt,
         a.filename AS assetName, a.size AS assetSize, a.mime AS assetMime,
         a.kind AS assetKind, a.status AS assetStatus
    FROM messages m
    JOIN users u ON u.id = m.sender_id
    LEFT JOIN assets a ON a.id = m.asset_id
`;

const QUOTE_SNIPPET_MAX = 100;

class ChatDB {
  constructor(dbPath) {
    this.db = new DatabaseSync(dbPath);
    this.db.exec(SCHEMA);
    this._migrate();
    this._prepare();
  }

  /** 旧库（只有文本消息版本）平滑升级：补齐新列，新库为 no-op */
  _migrate() {
    const cols = new Set(this.db.prepare('PRAGMA table_info(messages)').all().map((c) => c.name));
    const add = (name, ddl) => {
      if (!cols.has(name)) this.db.exec(`ALTER TABLE messages ADD COLUMN ${name} ${ddl}`);
    };
    // content 在旧库为 NOT NULL：媒体消息无 caption 时写入 ''，兼容旧约束
    add('msg_type', "TEXT NOT NULL DEFAULT 'text'");
    add('asset_id', 'TEXT');
    add('quote_seq', 'INTEGER');
    add('recalled', 'INTEGER NOT NULL DEFAULT 0');
    add('recalled_at', 'INTEGER NOT NULL DEFAULT 0');
  }

  _prepare() {
    const d = this.db;
    this.stmt = {
      insertUser: d.prepare('INSERT INTO users (id, name, token_random, created_at) VALUES (?, ?, ?, ?)'),
      userByName: d.prepare('SELECT * FROM users WHERE name = ?'),
      userById: d.prepare('SELECT * FROM users WHERE id = ?'),

      insertRoom: d.prepare('INSERT INTO rooms (id, name, created_by, created_at) VALUES (?, ?, ?, ?)'),
      roomById: d.prepare('SELECT * FROM rooms WHERE id = ?'),
      roomByName: d.prepare('SELECT * FROM rooms WHERE name = ?'),
      roomsForUser: d.prepare(
        `SELECT r.id, r.name, r.last_seq AS lastSeq, m.role, m.muted_until AS mutedUntil
           FROM rooms r JOIN members m ON m.room_id = r.id
          WHERE m.user_id = ? ORDER BY r.created_at`
      ),

      upsertMember: d.prepare(
        `INSERT INTO members (room_id, user_id, role, muted_until, joined_at)
         VALUES (?, ?, ?, 0, ?)
         ON CONFLICT (room_id, user_id) DO NOTHING`
      ),
      member: d.prepare('SELECT * FROM members WHERE room_id = ? AND user_id = ?'),
      deleteMember: d.prepare('DELETE FROM members WHERE room_id = ? AND user_id = ?'),
      setMuted: d.prepare('UPDATE members SET muted_until = ? WHERE room_id = ? AND user_id = ?'),
      membersOfRoom: d.prepare(
        `SELECT m.user_id AS userId, u.name, m.role, m.muted_until AS mutedUntil
           FROM members m JOIN users u ON u.id = m.user_id WHERE m.room_id = ?`
      ),

      // —— 消息写入（事务内使用）——
      msgByClientId: d.prepare(
        `${MSG_SELECT} WHERE m.room_id = ? AND m.sender_id = ? AND m.client_msg_id = ?`
      ),
      bumpSeq: d.prepare('UPDATE rooms SET last_seq = last_seq + 1 WHERE id = ? RETURNING last_seq'),
      insertMsg: d.prepare(
        `INSERT INTO messages
           (room_id, seq, client_msg_id, sender_id, content, msg_type, asset_id, quote_seq, ts)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ),
      msgBySeq: d.prepare(`${MSG_SELECT} WHERE m.room_id = ? AND m.seq = ?`),
      recallRow: d.prepare('SELECT seq, sender_id, asset_id, recalled FROM messages WHERE room_id = ? AND seq = ?'),
      recallUpdate: d.prepare('UPDATE messages SET recalled = 1, recalled_at = ? WHERE room_id = ? AND seq = ?'),

      // —— 消息读取 ——
      msgsAfter: d.prepare(`${MSG_SELECT} WHERE m.room_id = ? AND m.seq > ? ORDER BY m.seq LIMIT ?`),
      msgsBefore: d.prepare(
        `${MSG_SELECT} WHERE m.room_id = ? AND m.seq < ? ORDER BY m.seq DESC LIMIT ?`
      ),

      // —— 游标 ——
      upsertCursor: d.prepare(
        `INSERT INTO cursors (room_id, user_id, last_ack_seq, updated_at) VALUES (?, ?, ?, ?)
         ON CONFLICT (room_id, user_id)
         DO UPDATE SET last_ack_seq = MAX(last_ack_seq, excluded.last_ack_seq), updated_at = excluded.updated_at`
      ),
      cursor: d.prepare('SELECT last_ack_seq AS lastAckSeq FROM cursors WHERE room_id = ? AND user_id = ?'),

      // —— 资产 ——
      assetBySha: d.prepare('SELECT * FROM assets WHERE sha256 = ?'),
      assetById: d.prepare('SELECT * FROM assets WHERE id = ?'),
      insertAsset: d.prepare(
        `INSERT INTO assets (id, sha256, size, mime, filename, kind, uploader_id,
                             status, storage_path, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ),
      setAssetStatus: d.prepare('UPDATE assets SET status = ?, scan_info = ? WHERE id = ?'),
      resetAssetForReupload: d.prepare(
        `UPDATE assets
            SET status = 'scanning', scan_info = '', storage_path = '', ready_at = 0,
                size = ?, mime = ?, filename = ?, kind = ?, uploader_id = ?, created_at = ?
          WHERE id = ?`
      ),
      setAssetReady: d.prepare(
        "UPDATE assets SET status = 'ready', ready_at = ?, scan_info = '' WHERE id = ?"
      ),
      markAssetDeleted: d.prepare("UPDATE assets SET status = 'deleted' WHERE id = ?"),
      countLiveRefs: d.prepare(
        'SELECT COUNT(*) AS c FROM messages WHERE asset_id = ? AND recalled = 0'
      ),
      // 下载鉴权：当前成员 + 存在一条引用该资产的未撤回消息
      liveRoomForAssetUser: d.prepare(
        `SELECT m.room_id AS roomId FROM messages m
           JOIN members mb ON mb.room_id = m.room_id AND mb.user_id = ?
          WHERE m.asset_id = ? AND m.recalled = 0 LIMIT 1`
      ),
      expiredAssets: d.prepare(
        `SELECT * FROM assets
          WHERE status = 'ready' AND ready_at > 0 AND ready_at < ?
            AND NOT EXISTS (SELECT 1 FROM messages WHERE asset_id = assets.id AND recalled = 0)
          LIMIT ?`
      ),
      insertDownload: d.prepare(
        'INSERT INTO asset_downloads (id, asset_id, user_id, room_id, bytes, ts) VALUES (?, ?, ?, ?, ?, ?)'
      ),
      // 扫描故障对象：超过任务 TTL 仍停在 scan_error（其 open 任务应已过期），物理文件可回收
      staleScanErrorAssets: d.prepare(
        `SELECT * FROM assets WHERE status = 'scan_error' AND created_at < ? LIMIT ?`
      ),

      // —— 上传任务 ——
      openTaskByHash: d.prepare(
        "SELECT * FROM upload_tasks WHERE uploader_id = ? AND sha256 = ? AND status = 'open'"
      ),
      insertTask: d.prepare(
        `INSERT INTO upload_tasks
           (id, uploader_id, asset_id, filename, kind, mime, size, sha256,
            chunk_size, total_chunks, status, created_at, updated_at)
         VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`
      ),
      taskById: d.prepare('SELECT * FROM upload_tasks WHERE id = ?'),
      // 秒传复用：为复用方补一条 completed 任务行（无分片），作为其持有该内容的来源凭证
      insertCompletedTask: d.prepare(
        `INSERT INTO upload_tasks
           (id, uploader_id, asset_id, filename, kind, mime, size, sha256,
            chunk_size, total_chunks, status, created_at, updated_at, completed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'completed', ?, ?, ?)`
      ),
      countOpenTasks: d.prepare(
        "SELECT COUNT(*) AS c FROM upload_tasks WHERE uploader_id = ? AND status = 'open'"
      ),
      upsertChunk: d.prepare(
        `INSERT INTO upload_chunks (task_id, idx, size, received_at) VALUES (?, ?, ?, ?)
         ON CONFLICT (task_id, idx) DO UPDATE SET size = excluded.size, received_at = excluded.received_at`
      ),
      chunkIdxList: d.prepare('SELECT idx FROM upload_chunks WHERE task_id = ? ORDER BY idx'),
      deleteChunk: d.prepare('DELETE FROM upload_chunks WHERE task_id = ? AND idx = ?'),
      deleteChunks: d.prepare('DELETE FROM upload_chunks WHERE task_id = ?'),
      touchTask: d.prepare('UPDATE upload_tasks SET updated_at = ? WHERE id = ?'),
      completeTask: d.prepare(
        `UPDATE upload_tasks SET status = 'completed', asset_id = ?, completed_at = ?, updated_at = ?
          WHERE id = ?`
      ),
      expireTask: d.prepare(
        `UPDATE upload_tasks SET status = 'expired', updated_at = ? WHERE id = ? AND status = 'open'`
      ),
      staleOpenTasks: d.prepare(
        "SELECT * FROM upload_tasks WHERE status = 'open' AND updated_at < ? LIMIT ?"
      ),
      // 用户是否已成功上传过某内容（秒传复用他人资产时，据此判定其有权发送该资产）
      completedTaskByHash: d.prepare(
        `SELECT 1 FROM upload_tasks
          WHERE uploader_id = ? AND sha256 = ? AND status = 'completed' LIMIT 1`
      ),
    };
  }

  /** 在 IMMEDIATE 事务中执行 fn，失败回滚。node:sqlite 为同步驱动，单进程内无并发交错。 */
  _tx(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const r = fn();
      this.db.exec('COMMIT');
      return r;
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch { /* 已回滚 */ }
      throw err;
    }
  }

  // ---------- 用户 ----------

  createUser(id, name, tokenRandom) {
    this.stmt.insertUser.run(id, name, tokenRandom, now());
    return this.stmt.userById.get(id);
  }

  getUserByName(name) { return this.stmt.userByName.get(name); }
  getUserById(id) { return this.stmt.userById.get(id); }

  // ---------- 房间与成员 ----------

  createRoom(id, name, creatorId) {
    return this._tx(() => {
      this.stmt.insertRoom.run(id, name, creatorId, now());
      // 创建者即管理员
      this.stmt.upsertMember.run(id, creatorId, 'admin', now());
      return this.stmt.roomById.get(id);
    });
  }

  getRoom(id) { return this.stmt.roomById.get(id); }
  getRoomByName(name) { return this.stmt.roomByName.get(name); }
  listRoomsForUser(userId) { return this.stmt.roomsForUser.all(userId); }
  listMembers(roomId) { return this.stmt.membersOfRoom.all(roomId); }

  joinRoom(roomId, userId) {
    this.stmt.upsertMember.run(roomId, userId, 'member', now());
    return this.stmt.member.get(roomId, userId);
  }

  /** 退出房间：删除成员关系 —— 退出后立即丧失该房间历史资源的下载权限 */
  removeMember(roomId, userId) {
    return this.stmt.deleteMember.run(roomId, userId).changes > 0;
  }

  getMember(roomId, userId) { return this.stmt.member.get(roomId, userId); }

  /** 设置禁言截止时间（0 表示解除禁言） */
  setMuted(roomId, userId, mutedUntil) {
    this.stmt.setMuted.run(mutedUntil, roomId, userId);
    return this.stmt.member.get(roomId, userId);
  }

  // ---------- 消息 ----------

  /**
   * 幂等写入消息（文本 / 图片 / 文件 / 语音统一入口）。
   * 返回 { message, duplicate }：
   *  - duplicate=false：新消息，已分配 seq 并落库（调用方负责广播）；
   *  - duplicate=true ：同 clientMsgId 的消息已存在，直接返回原消息（调用方只回 ACK，不再广播）。
   * 媒体消息必须传 assetId（且调用方已确认资产 status=ready）。
   */
  insertMessage({
    roomId,
    clientMsgId,
    senderId,
    content = '',
    msgType = 'text',
    assetId = null,
    quoteSeq = null,
  }) {
    return this._tx(() => {
      const existing = this.stmt.msgByClientId.get(roomId, senderId, clientMsgId);
      if (existing) return { message: this._decorateOne(existing), duplicate: true };

      const { last_seq: seq } = this.stmt.bumpSeq.get(roomId);
      const ts = now();
      this.stmt.insertMsg.run(
        roomId, seq, clientMsgId, senderId, content, msgType, assetId, quoteSeq, ts
      );
      const row = this.stmt.msgByClientId.get(roomId, senderId, clientMsgId);
      return { message: this._decorate([row])[0], duplicate: false };
    });
  }

  getMessage(roomId, seq) {
    const row = this.stmt.msgBySeq.get(roomId, seq);
    return row ? this._decorate([row])[0] : null;
  }

  /**
   * 撤回消息。返回：
   *  - { recalled:true, assetId }  本次新撤回（调用方负责广播 + 按规则删文件）
   *  - { already:true }            此前已撤回
   *  - null                        消息不存在
   */
  recallMessage(roomId, seq) {
    return this._tx(() => {
      const row = this.stmt.recallRow.get(roomId, seq);
      if (!row) return null;
      if (row.recalled) return { already: true };
      this.stmt.recallUpdate.run(now(), roomId, seq);
      return { recalled: true, assetId: row.asset_id };
    });
  }

  /** 资产当前被多少条未撤回消息引用（撤回删除规则 / TTL 判定依据） */
  countLiveAssetRefs(assetId) {
    return this.stmt.countLiveRefs.get(assetId).c;
  }

  /** 下载鉴权：用户当前是成员且资产被房间内某条未撤回消息引用时返回 roomId */
  liveRoomForAssetUser(assetId, userId) {
    const row = this.stmt.liveRoomForAssetUser.get(userId, assetId);
    return row ? row.roomId : null;
  }

  /** 断线补发：取 seq > afterSeq 的消息（升序，最多 limit 条） */
  getMessagesAfter(roomId, afterSeq, limit) {
    return this._decorate(this.stmt.msgsAfter.all(roomId, afterSeq, limit));
  }

  /** 历史翻页：取 seq < beforeSeq 的消息，返回时按升序排列 */
  getMessagesBefore(roomId, beforeSeq, limit) {
    return this._decorate(this.stmt.msgsBefore.all(roomId, beforeSeq, limit).reverse());
  }

  /**
   * 组装下发结构：
   *  - 资产元数据挂到 asset（撤回消息不带资产信息）；
   *  - quote 解析为一层摘要（不递归嵌套），被引用消息已撤回时给出 {seq, recalled:true}。
   */
  _decorate(rows) {
    if (!rows.length) return [];
    const quoteSeqs = new Set();
    for (const r of rows) if (r.quoteSeq != null) quoteSeqs.add(r.quoteSeq);
    let quoteMap = new Map();
    if (quoteSeqs.size) {
      const roomId = rows[0].roomId;
      for (const qs of quoteSeqs) {
        const q = this.getMessage(roomId, qs);
        if (q) quoteMap.set(qs, q);
      }
    }
    return rows.map((r) => this._decorateOne(r, quoteMap));
  }

  _decorateOne(r, quoteMap = null) {
    const m = {
      type: 'msg',
      roomId: r.roomId,
      seq: r.seq,
      clientMsgId: r.clientMsgId,
      from: r.from,
      fromName: r.fromName,
      content: r.content || '',
      ts: r.ts,
      msgType: r.msgType || 'text',
      recalled: !!r.recalled,
    };
    if (r.recalledAt) m.recalledAt = r.recalledAt;
    // 撤回墓碑：剥除正文与资产，只保留定位/排序信息（客户端渲染「该消息已撤回」）
    if (r.recalled) return m;
    if (r.assetId && !r.recalled && r.assetStatus === 'ready') {
      m.asset = {
        id: r.assetId,
        name: r.assetName,
        size: r.assetSize,
        mime: r.assetMime,
        kind: r.assetKind,
      };
    } else if (r.assetId) {
      m.asset = { id: r.assetId, gone: r.assetStatus !== 'ready' || !!r.recalled };
    }
    if (r.quoteSeq != null) {
      if (quoteMap) {
        const q = quoteMap.get(r.quoteSeq);
        m.quote = q ? quoteSummary(q) : { seq: r.quoteSeq, gone: true };
      } else {
        const q = this.getMessage(r.roomId, r.quoteSeq);
        m.quote = q ? quoteSummary(q) : { seq: r.quoteSeq, gone: true };
      }
    }
    return m;
  }

  // ---------- 游标 ----------

  saveCursor(roomId, userId, lastAckSeq) {
    this.stmt.upsertCursor.run(roomId, userId, lastAckSeq, now());
  }

  getCursor(roomId, userId) {
    const row = this.stmt.cursor.get(roomId, userId);
    return row ? row.lastAckSeq : 0;
  }

  // ---------- 资产 ----------

  getAssetBySha(sha256) { return this.stmt.assetBySha.get(sha256); }
  getAsset(id) { return this.stmt.assetById.get(id); }

  createAsset({ id, sha256, size, mime, filename, kind, uploaderId, storagePath, status = 'scanning' }) {
    this.stmt.insertAsset.run(
      id, sha256, size, mime, filename, kind, uploaderId, status, storagePath, now()
    );
    return this.stmt.assetById.get(id);
  }

  setAssetStatus(id, status, scanInfo = '') {
    this.stmt.setAssetStatus.run(status, scanInfo, id);
    return this.stmt.assetById.get(id);
  }

  /** 同内容重新上传（deleted/scan_error/残留 scanning）：重置为扫描中，走完整合并+重扫 */
  resetAssetForReupload(id, { size, mime, filename, kind, uploaderId }) {
    this.stmt.resetAssetForReupload.run(
      size, mime, filename, kind, uploaderId, now(), id
    );
    return this.stmt.assetById.get(id);
  }

  setAssetReady(id) {
    this.stmt.setAssetReady.run(now(), id);
    return this.stmt.assetById.get(id);
  }

  markAssetDeleted(id) {
    this.stmt.markAssetDeleted.run(id);
    return this.stmt.assetById.get(id);
  }

  /** TTL 回收：ready 且已无任何未撤回消息引用、ready_at 早于 cutoff 的资产 */
  findExpiredAssets(cutoff, limit = 100) {
    return this.stmt.expiredAssets.all(cutoff, limit);
  }

  /** 长期停留在扫描故障状态的资产（物理文件回收候选，行保留以便同 hash 重传时重扫） */
  findStaleScanErrorAssets(cutoff, limit = 100) {
    return this.stmt.staleScanErrorAssets.all(cutoff, limit);
  }

  recordDownload({ assetId, userId, roomId, bytes }) {
    this.stmt.insertDownload.run(randomId('dl_'), assetId, userId, roomId, bytes, now());
  }

  // ---------- 上传任务 ----------

  findOpenTask(uploaderId, sha256) {
    return this.stmt.openTaskByHash.get(uploaderId, sha256);
  }

  createTask({ id, uploaderId, filename, kind, mime, size, sha256, chunkSize, totalChunks }) {
    const t = now();
    this.stmt.insertTask.run(
      id, uploaderId, filename, kind, mime, size, sha256, chunkSize, totalChunks, t, t
    );
    return this.stmt.taskById.get(id);
  }

  getTask(id) { return this.stmt.taskById.get(id); }

  /** 秒传场景：记录复用方的完成态来源凭证 */
  insertCompletedTask({ id, uploaderId, assetId, filename, kind, mime, size, sha256 }) {
    const t = now();
    this.stmt.insertCompletedTask.run(
      id, uploaderId, assetId, filename, kind, mime, size, sha256, t, t, t
    );
  }
  countOpenTasks(uploaderId) { return this.stmt.countOpenTasks.get(uploaderId).c; }

  putChunk(taskId, idx, size) {
    this.stmt.upsertChunk.run(taskId, idx, size, now());
    this.stmt.touchTask.run(now(), taskId);
  }

  receivedChunkIdx(taskId) {
    return this.stmt.chunkIdxList.all(taskId).map((r) => r.idx);
  }

  /** 删除单条分片登记（磁盘/DB 对齐用） */
  deleteChunk(taskId, idx) {
    this.stmt.deleteChunk.run(taskId, idx);
  }

  deleteChunks(taskId) {
    this.stmt.deleteChunks.run(taskId);
  }

  completeTask(taskId, assetId) {
    const t = now();
    this.stmt.completeTask.run(assetId, t, t, taskId);
    return this.stmt.taskById.get(taskId);
  }

  /** 超时任务标记过期（返回是否本次变更），物理分片由调用方删除 */
  expireTask(taskId) {
    return this.stmt.expireTask.run(now(), taskId).changes > 0;
  }

  findStaleOpenTasks(cutoff, limit = 100) {
    return this.stmt.staleOpenTasks.all(cutoff, limit);
  }

  hasCompletedUpload(uploaderId, sha256) {
    return !!this.stmt.completedTaskByHash.get(uploaderId, sha256);
  }

  close() {
    try { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch { /* 内存库无 WAL */ }
    this.db.close();
  }
}

/** 引用摘要：一层，截断长文本；被撤回的消息只给 seq + recalled 标记 */
function quoteSummary(q) {
  if (q.recalled) return { seq: q.seq, recalled: true };
  const s = {
    seq: q.seq,
    from: q.from,
    fromName: q.fromName,
    msgType: q.msgType,
  };
  if (q.content) s.content = q.content.length > QUOTE_SNIPPET_MAX
    ? `${q.content.slice(0, QUOTE_SNIPPET_MAX)}…` : q.content;
  if (q.asset) s.asset = { id: q.asset.id, name: q.asset.name, kind: q.asset.kind, gone: !!q.asset.gone };
  return s;
}

module.exports = { ChatDB };
