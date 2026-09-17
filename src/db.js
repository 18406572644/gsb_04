'use strict';

const { DatabaseSync } = require('node:sqlite');
const { now } = require('./util');

/**
 * 持久层：SQLite（WAL 模式）。
 *
 * 可靠性设计要点：
 * 1. 消息与房间序号 seq 在同一事务中「先落库、后广播」——进程崩溃也不丢已确认消息。
 * 2. messages 上 (room_id, sender_id, client_msg_id) 唯一约束——客户端重试/网络重复
 *    提交同一条消息时不会产生重复记录，实现发送幂等。
 * 3. seq 为每房间单调递增序号，由 rooms.last_seq 计数器在事务内分配——保证房间内
 *    消息全序（时序可控），客户端可凭 seq 检测空洞并触发补发。
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
  active      INTEGER NOT NULL DEFAULT 1,  -- 0 = 已持久退群（区别于仅断线的运行时离房）
  left_at     INTEGER,                    -- 退群时间；NULL = 在群
  PRIMARY KEY (room_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
  room_id       TEXT NOT NULL REFERENCES rooms(id),
  seq           INTEGER NOT NULL,
  client_msg_id TEXT NOT NULL,
  sender_id     TEXT NOT NULL REFERENCES users(id),
  content       TEXT NOT NULL,           -- 非文本消息时为 caption（可为 ''）
  ts            INTEGER NOT NULL,
  kind          TEXT NOT NULL DEFAULT 'text' CHECK (kind IN ('text','image','file','voice')),
  asset_id      TEXT,                    -- 富媒体消息关联的 asset（text 为 NULL）
  reply_to_seq  INTEGER,                 -- 引用的同房间消息 seq
  recalled_at   INTEGER,                 -- 撤回墓碑时间；NULL = 有效
  meta          TEXT,                    -- 发送时冗余展示元数据 JSON（兜底）
  PRIMARY KEY (room_id, seq),
  UNIQUE (room_id, sender_id, client_msg_id)  -- 幂等键
);
CREATE INDEX IF NOT EXISTS idx_messages_asset ON messages(asset_id);
CREATE INDEX IF NOT EXISTS idx_messages_reply ON messages(room_id, reply_to_seq);

-- 富媒体资源（逻辑资产）。物理 blob 按 sha256 内容寻址、可被多个 asset 行共享
CREATE TABLE IF NOT EXISTS assets (
  id          TEXT PRIMARY KEY,
  sha256      TEXT NOT NULL,
  size        INTEGER NOT NULL,
  mime        TEXT NOT NULL,             -- 服务端 magic 探测结果，不信任客户端
  kind        TEXT NOT NULL CHECK (kind IN ('image','file','voice')),
  width       INTEGER,
  height      INTEGER,
  duration_ms INTEGER,
  file_name   TEXT NOT NULL,
  blob_status TEXT NOT NULL DEFAULT 'ready'
                CHECK (blob_status IN ('ready','deleted','quarantined')),
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_sha ON assets(sha256);

-- 两阶段上传的任务状态机
CREATE TABLE IF NOT EXISTS upload_tasks (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL REFERENCES users(id),
  file_name       TEXT NOT NULL,
  kind            TEXT NOT NULL CHECK (kind IN ('image','file','voice')),
  declared_size   INTEGER NOT NULL,
  declared_sha256 TEXT,
  chunk_size      INTEGER NOT NULL,
  total_chunks    INTEGER NOT NULL,
  status          TEXT NOT NULL
                    CHECK (status IN ('open','ready','quarantined','failed','aborted','expired')),
  asset_id        TEXT REFERENCES assets(id),
  error_code      TEXT,
  duration_ms     INTEGER,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_user   ON upload_tasks(user_id, status);
CREATE INDEX IF NOT EXISTS idx_tasks_sha    ON upload_tasks(declared_sha256, user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_expire ON upload_tasks(status, expires_at);

-- 已收且单片 hash 校验通过的分片凭证（字节在文件系统，此表为事实源）
CREATE TABLE IF NOT EXISTS upload_chunks (
  task_id     TEXT NOT NULL REFERENCES upload_tasks(id) ON DELETE CASCADE,
  idx         INTEGER NOT NULL,
  size        INTEGER NOT NULL,
  sha256      TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  PRIMARY KEY (task_id, idx)
);

-- 服务端保存的每用户每房间已确认游标（断线补发的兜底依据）
CREATE TABLE IF NOT EXISTS cursors (
  room_id      TEXT NOT NULL REFERENCES rooms(id),
  user_id      TEXT NOT NULL REFERENCES users(id),
  last_ack_seq INTEGER NOT NULL DEFAULT 0,
  updated_at   INTEGER NOT NULL,
  PRIMARY KEY (room_id, user_id)
);
`;

const MSG_SELECT = `
  SELECT m.room_id AS roomId, m.seq, m.client_msg_id AS clientMsgId,
         m.sender_id AS "from", u.name AS fromName, m.content, m.ts,
         m.kind, m.asset_id AS assetId, m.reply_to_seq AS replyToSeq,
         m.recalled_at AS recalledAt, m.meta,
         a.sha256 AS assetSha, a.size AS assetSize, a.mime AS assetMime,
         a.file_name AS assetName, a.width AS assetWidth, a.height AS assetHeight,
         a.duration_ms AS assetDurationMs, a.blob_status AS assetStatus,
         rk.sender_id AS replyFrom, ru.name AS replyFromName,
         rk.kind AS replyKind, substr(rk.content, 1, 60) AS replySnippet,
         rk.recalled_at AS replyRecalledAt, ra.blob_status AS replyAssetStatus
    FROM messages m
    JOIN users u  ON u.id = m.sender_id
    LEFT JOIN assets a   ON a.id = m.asset_id
    LEFT JOIN messages rk ON rk.room_id = m.room_id AND rk.seq = m.reply_to_seq
    LEFT JOIN users ru   ON ru.id = rk.sender_id
    LEFT JOIN assets ra  ON ra.id = rk.asset_id
`;

class ChatDB {
  constructor(dbPath) {
    this.db = new DatabaseSync(dbPath);
    this.db.exec(SCHEMA);
    this._migrate();
    this._prepare();
  }

  /** 老库平滑加列：SQLite ADD COLUMN 带常量 DEFAULT 为元数据级操作，不重写表 */
  _migrate() {
    const cols = (t) => this.db.prepare(`PRAGMA table_info(${t})`).all().map((c) => c.name);
    const add = (table, col, ddl) => {
      if (!cols(table).includes(col)) this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
    };
    add('members', 'active', 'active INTEGER NOT NULL DEFAULT 1');
    add('members', 'left_at', 'left_at INTEGER');
    add('messages', 'kind', "kind TEXT NOT NULL DEFAULT 'text'");
    add('messages', 'asset_id', 'asset_id TEXT');
    add('messages', 'reply_to_seq', 'reply_to_seq INTEGER');
    add('messages', 'recalled_at', 'recalled_at INTEGER');
    add('messages', 'meta', 'meta TEXT');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_messages_asset ON messages(asset_id)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_messages_reply ON messages(room_id, reply_to_seq)');
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
          WHERE m.user_id = ? AND m.active = 1 ORDER BY r.created_at`
      ),

      // 重新加入即恢复 active；角色与禁言状态保留（禁言不能靠退群/重进解除）
      upsertMember: d.prepare(
        `INSERT INTO members (room_id, user_id, role, muted_until, joined_at, active, left_at)
         VALUES (?, ?, ?, 0, ?, 1, NULL)
         ON CONFLICT (room_id, user_id) DO UPDATE SET active = 1, left_at = NULL`
      ),
      member: d.prepare('SELECT * FROM members WHERE room_id = ? AND user_id = ?'),
      activeMember: d.prepare(
        'SELECT * FROM members WHERE room_id = ? AND user_id = ? AND active = 1'
      ),
      deactivateMember: d.prepare(
        'UPDATE members SET active = 0, left_at = ? WHERE room_id = ? AND user_id = ?'
      ),
      setMuted: d.prepare('UPDATE members SET muted_until = ? WHERE room_id = ? AND user_id = ?'),
      membersOfRoom: d.prepare(
        `SELECT m.user_id AS userId, u.name, m.role, m.muted_until AS mutedUntil
           FROM members m JOIN users u ON u.id = m.user_id
          WHERE m.room_id = ? AND m.active = 1`
      ),

      // —— 消息写入（事务内使用）——
      msgByClientId: d.prepare(
        `${MSG_SELECT} WHERE m.room_id = ? AND m.sender_id = ? AND m.client_msg_id = ?`
      ),
      msgBySeq: d.prepare(`${MSG_SELECT} WHERE m.room_id = ? AND m.seq = ?`),
      bumpSeq: d.prepare('UPDATE rooms SET last_seq = last_seq + 1 WHERE id = ? RETURNING last_seq'),
      insertMsg: d.prepare(
        `INSERT INTO messages
           (room_id, seq, client_msg_id, sender_id, content, ts, kind, asset_id, reply_to_seq)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ),
      recallMsg: d.prepare(
        'UPDATE messages SET recalled_at = ? WHERE room_id = ? AND seq = ? AND recalled_at IS NULL'
      ),

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
      insertAsset: d.prepare(
        `INSERT INTO assets (id, sha256, size, mime, kind, width, height, duration_ms, file_name, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ),
      assetById: d.prepare('SELECT * FROM assets WHERE id = ?'),
      readyAssetsBySha: d.prepare("SELECT id FROM assets WHERE sha256 = ? AND blob_status = 'ready'"),
      setAssetStatusBySha: d.prepare('UPDATE assets SET blob_status = ? WHERE sha256 = ?'),
      // 秒传：仅查本人历史 ready 任务对应的 ready asset
      userReadyAssetBySha: d.prepare(
        `SELECT a.id FROM upload_tasks t JOIN assets a ON a.id = t.asset_id
          WHERE t.user_id = ? AND t.declared_sha256 = ?
            AND t.status = 'ready' AND a.blob_status = 'ready' LIMIT 1`
      ),
      countLiveMsgRefsBySha: d.prepare(
        `SELECT COUNT(*) AS n FROM assets a
           JOIN messages m ON m.asset_id = a.id AND m.recalled_at IS NULL
          WHERE a.sha256 = ? AND a.blob_status = 'ready'`
      ),
      countTaskRefsBySha: d.prepare(
        `SELECT COUNT(*) AS n FROM upload_tasks
          WHERE declared_sha256 = ?
            AND (status = 'open' OR (status = 'ready' AND updated_at > ?))`
      ),
      // 下载鉴权：该 asset 被「请求者为 active 成员」的房间内一条未撤回消息引用
      liveAssetRefForUser: d.prepare(
        `SELECT 1 FROM messages m
           JOIN members mb ON mb.room_id = m.room_id AND mb.user_id = ? AND mb.active = 1
          WHERE m.asset_id = ? AND m.recalled_at IS NULL LIMIT 1`
      ),
      orphanAssets: d.prepare(
        `SELECT id, sha256 FROM assets
          WHERE blob_status = 'ready' AND created_at < ? LIMIT ?`
      ),
      assetReadyTaskOwners: d.prepare(
        `SELECT user_id AS userId FROM upload_tasks WHERE asset_id = ? AND status = 'ready' LIMIT 1`
      ),
      assetReferencedLiveInRoom: d.prepare(
        `SELECT 1 FROM messages
          WHERE room_id = ? AND asset_id = ? AND recalled_at IS NULL LIMIT 1`
      ),

      // —— 上传任务 ——
      insertTask: d.prepare(
        `INSERT INTO upload_tasks
           (id, user_id, file_name, kind, declared_size, declared_sha256, chunk_size,
            total_chunks, status, duration_ms, created_at, updated_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)`
      ),
      taskById: d.prepare('SELECT * FROM upload_tasks WHERE id = ?'),
      updateTaskAsset: d.prepare(
        'UPDATE upload_tasks SET status = ?, asset_id = ?, error_code = ?, updated_at = ? WHERE id = ?'
      ),
      updateTaskStatus: d.prepare(
        'UPDATE upload_tasks SET status = ?, error_code = ?, updated_at = ? WHERE id = ?'
      ),
      countOpenTasks: d.prepare("SELECT COUNT(*) AS n FROM upload_tasks WHERE user_id = ? AND status = 'open'"),
      expiredOpenTasks: d.prepare(
        "SELECT id FROM upload_tasks WHERE status = 'open' AND expires_at < ? LIMIT ?"
      ),
      oldQuarantinedTasks: d.prepare(
        `SELECT id, file_name FROM upload_tasks
          WHERE status = 'quarantined' AND updated_at < ? LIMIT ?`
      ),

      // —— 分片凭证 ——
      upsertChunk: d.prepare(
        `INSERT INTO upload_chunks (task_id, idx, size, sha256, received_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (task_id, idx) DO UPDATE SET size = excluded.size, sha256 = excluded.sha256,
                                                   received_at = excluded.received_at`
      ),
      chunkByIdx: d.prepare('SELECT * FROM upload_chunks WHERE task_id = ? AND idx = ?'),
      chunksOfTask: d.prepare('SELECT idx, size, sha256 FROM upload_chunks WHERE task_id = ? ORDER BY idx'),
      countChunks: d.prepare('SELECT COUNT(*) AS n FROM upload_chunks WHERE task_id = ?'),
      deleteChunks: d.prepare('DELETE FROM upload_chunks WHERE task_id = ?'),
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

  getMember(roomId, userId) { return this.stmt.member.get(roomId, userId); }

  /** 仅返回 active=1 的成员行（富媒体/消息/下载鉴权使用） */
  getActiveMember(roomId, userId) { return this.stmt.activeMember.get(roomId, userId); }

  /** 持久退群：置 active=0。返回是否命中行。 */
  deactivateMember(roomId, userId) {
    return this.stmt.deactivateMember.run(now(), roomId, userId).changes > 0;
  }

  /** 设置禁言截止时间（0 表示解除禁言） */
  setMuted(roomId, userId, mutedUntil) {
    this.stmt.setMuted.run(mutedUntil, roomId, userId);
    return this.stmt.member.get(roomId, userId);
  }

  // ---------- 消息 ----------

  /**
   * 幂等写入消息。
   * 返回 { message, duplicate }：
   *  - duplicate=false：新消息，已分配 seq 并落库（调用方负责广播）；
   *  - duplicate=true ：同 clientMsgId 的消息已存在，直接返回原消息（调用方只回 ACK，不再广播）。
   */
  insertMessage({ roomId, clientMsgId, senderId, content, kind = 'text', assetId = null, replyToSeq = null }) {
    return this._tx(() => {
      const existing = this.stmt.msgByClientId.get(roomId, senderId, clientMsgId);
      if (existing) return { message: existing, duplicate: true };

      const { last_seq: seq } = this.stmt.bumpSeq.get(roomId);
      const ts = now();
      this.stmt.insertMsg.run(
        roomId, seq, clientMsgId, senderId, content, ts, kind, assetId, replyToSeq
      );
      const message = this.stmt.msgByClientId.get(roomId, senderId, clientMsgId);
      return { message, duplicate: false };
    });
  }

  getMessage(roomId, seq) { return this.stmt.msgBySeq.get(roomId, seq); }

  /**
   * 撤回（墓碑）：仅置 recalled_at，不删行（支撑引用墓碑与审计）。
   * 幂等：已撤回返回 { recalled:false, message }，调用方不再重复广播。
   */
  recallMessage(roomId, seq, atMs = now()) {
    return this._tx(() => {
      const before = this.stmt.msgBySeq.get(roomId, seq);
      const info = this.stmt.recallMsg.run(atMs, roomId, seq);
      return { recalled: info.changes > 0, message: this.stmt.msgBySeq.get(roomId, seq), before };
    });
  }

  /** 断线补发：取 seq > afterSeq 的消息（升序，最多 limit 条） */
  getMessagesAfter(roomId, afterSeq, limit) {
    return this.stmt.msgsAfter.all(roomId, afterSeq, limit);
  }

  /** 历史翻页：取 seq < beforeSeq 的消息，返回时按升序排列 */
  getMessagesBefore(roomId, beforeSeq, limit) {
    return this.stmt.msgsBefore.all(roomId, beforeSeq, limit).reverse();
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

  insertAsset(a) {
    this.stmt.insertAsset.run(
      a.id, a.sha256, a.size, a.mime, a.kind,
      a.width ?? null, a.height ?? null, a.durationMs ?? null, a.fileName, now()
    );
    return this.stmt.assetById.get(a.id);
  }

  getAsset(id) { return this.stmt.assetById.get(id); }

  /** 某 sha 下是否已有 ready 物理 blob（二级存储去重判定） */
  hasReadyBlob(sha256) { return this.stmt.readyAssetsBySha.get(sha256) !== undefined; }

  /** 秒传：仅当本人历史 ready 任务已产生 ready asset 时命中，返回 assetId */
  findUserReadyAssetBySha(userId, sha256) {
    const row = this.stmt.userReadyAssetBySha.get(userId, sha256);
    return row ? row.id : null;
  }

  assetHasLiveRefForUser(assetId, userId) {
    return this.stmt.liveAssetRefForUser.get(userId, assetId) !== undefined;
  }

  /** asset 是否由该用户的任务上传（msg 发送 scope 判定） */
  isAssetOwner(assetId, userId) {
    return this.db.prepare(
      'SELECT 1 FROM upload_tasks WHERE asset_id = ? AND user_id = ? LIMIT 1'
    ).get(assetId, userId) !== undefined;
  }

  /** asset 是否已被某房间一条未撤回消息引用（msg 发送 scope 判定） */
  assetReferencedLiveInRoom(roomId, assetId) {
    return this.stmt.assetReferencedLiveInRoom.get(roomId, assetId) !== undefined;
  }

  /** blob 存活计数：未撤回消息引用数 与 open/宽限期任务占用数 */
  blobRefCounts(sha256, graceCutoff) {
    return {
      liveMessages: this.stmt.countLiveMsgRefsBySha.get(sha256).n,
      tasks: this.stmt.countTaskRefsBySha.get(sha256, graceCutoff).n,
    };
  }

  markBlobAssetsStatus(sha256, status) {
    this.stmt.setAssetStatusBySha.run(status, sha256);
  }

  listOrphanAssetCandidates(cutoff, limit = 200) {
    return this.stmt.orphanAssets.all(cutoff, limit);
  }

  // ---------- 上传任务 / 分片 ----------

  insertUploadTask(t) {
    this.stmt.insertTask.run(
      t.id, t.userId, t.fileName, t.kind, t.size, t.sha256 ?? null,
      t.chunkSize, t.totalChunks, t.durationMs ?? null, t.createdAt, t.updatedAt, t.expiresAt
    );
    return this.stmt.taskById.get(t.id);
  }

  getUploadTask(id) { return this.stmt.taskById.get(id); }

  finishUploadTask(id, status, assetId, errorCode, atMs = now()) {
    this.stmt.updateTaskAsset.run(status, assetId, errorCode, atMs, id);
    return this.stmt.taskById.get(id);
  }

  setUploadTaskStatus(id, status, errorCode, atMs = now()) {
    this.stmt.updateTaskStatus.run(status, errorCode, atMs, id);
    return this.stmt.taskById.get(id);
  }

  countOpenTasksForUser(userId) { return this.stmt.countOpenTasks.get(userId).n; }

  listExpiredOpenTasks(nowMs, limit = 200) {
    return this.stmt.expiredOpenTasks.all(nowMs, limit).map((r) => r.id);
  }

  listOldQuarantinedTasks(cutoff, limit = 200) {
    return this.stmt.oldQuarantinedTasks.all(cutoff, limit);
  }

  upsertChunkReceipt(taskId, idx, size, sha256, atMs = now()) {
    this.stmt.upsertChunk.run(taskId, idx, size, sha256, atMs);
  }

  getChunk(taskId, idx) { return this.stmt.chunkByIdx.get(taskId, idx); }

  listChunks(taskId) { return this.stmt.chunksOfTask.all(taskId); }

  countChunks(taskId) { return this.stmt.countChunks.get(taskId).n; }

  deleteTaskAndChunks(taskId) {
    return this._tx(() => {
      this.stmt.deleteChunks.run(taskId);
      this.db.prepare('DELETE FROM upload_tasks WHERE id = ?').run(taskId);
    });
  }

  close() {
    try { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch { /* 内存库无 WAL */ }
    this.db.close();
  }
}

module.exports = { ChatDB };
