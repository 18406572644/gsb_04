'use strict';

const http = require('node:http');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { WebSocketServer } = require('ws');

const { ChatDB } = require('./db');
const { Hub, Connection } = require('./hub');
const { LocalStorage } = require('./storage');
const { VirusScanner } = require('./scanner');
const { UploadService, HttpError } = require('./uploads');
const defaultConfig = require('./config');
const {
  randomId,
  randomSecret,
  signToken,
  verifyToken,
  isNonEmptyString,
  parseFrame,
  now,
} = require('./util');

/** 业务错误：handler 抛出，统一转成 error 帧回给客户端 */
class ChatError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}
const fail = (code, message) => {
  throw new ChatError(code, message);
};

/** 令牌桶限流（按用户），防刷屏 */
class TokenBucket {
  constructor(ratePerSec, burst) {
    this.rate = ratePerSec;
    this.burst = burst;
    this.buckets = new Map();
  }
  take(key) {
    const t = now();
    let b = this.buckets.get(key);
    if (!b) {
      b = { tokens: this.burst, updated: t };
      this.buckets.set(key, b);
    }
    b.tokens = Math.min(this.burst, b.tokens + ((t - b.updated) / 1000) * this.rate);
    b.updated = t;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }
}

const MEDIA_KINDS = new Set(['image', 'file', 'voice']);

function createChatServer(overrides = {}) {
  const config = { ...defaultConfig, ...overrides };
  const db = new ChatDB(config.dbPath);
  const hub = new Hub(config);
  const limiter = new TokenBucket(config.rateLimitPerSec, config.rateLimitBurst);
  const publicDir = path.join(__dirname, '..', 'public');
  // 内存库（测试）默认配临时存储目录，stop 时自动清掉；生产按 config 路径落盘
  const autoTempStorage = overrides.storageDir == null && config.dbPath === ':memory:';
  const storageRoot = autoTempStorage
    ? fs.mkdtempSync(path.join(os.tmpdir(), 'chat-storage-'))
    : path.resolve(config.storageDir);
  const storage = new LocalStorage({
    storageDir: path.join(storageRoot, 'objects'),
    chunkDir: path.join(storageRoot, 'chunks'),
  });
  const scanner = new VirusScanner(config, overrides.virusJudge ? { judge: overrides.virusJudge } : {});
  const uploads = new UploadService({ db, storage, scanner, config });

  // ---------------------------------------------------------------- 消息处理

  /** 断线补发：把 roomId 中 seq > fromSeq 的消息按序推给连接，分批，客户端按 sync_done 续拉 */
  function replayRoom(conn, roomId, fromSeq) {
    const batch = db.getMessagesAfter(roomId, fromSeq, config.syncBatchSize + 1);
    const hasMore = batch.length > config.syncBatchSize;
    const slice = hasMore ? batch.slice(0, config.syncBatchSize) : batch;
    for (const m of slice) hub.send(conn, m, { track: true, roomId, seq: m.seq });
    const lastSeq = slice.length ? slice[slice.length - 1].seq : fromSeq;
    hub.send(conn, { type: 'sync_done', roomId, lastSeq, hasMore });
  }

  function requireMember(conn, roomId) {
    const member = db.getMember(roomId, conn.userId);
    if (!member) fail('NOT_MEMBER', 'not a member of this room');
    return member;
  }

  function requireAdmin(conn, roomId) {
    const member = requireMember(conn, roomId);
    if (member.role !== 'admin') fail('FORBIDDEN', 'admin role required');
    return member;
  }

  /** 发送前的统一闸机：成员、禁言、限流（文本/媒体共用配额） */
  function preSend(conn, roomId) {
    const member = requireMember(conn, roomId);
    if (member.muted_until > now()) {
      fail('MUTED', `you are muted until ${new Date(member.muted_until).toISOString()}`);
    }
    if (!limiter.take(conn.userId)) fail('RATE_LIMITED', 'sending too fast, slow down');
    return member;
  }

  /** 校验并解析引用：目标必须存在且在允许的 seq 窗口内（只挂一层摘要，不递归） */
  function resolveQuote(roomId, quoteSeq) {
    if (quoteSeq == null) return null;
    if (!Number.isInteger(quoteSeq) || quoteSeq <= 0) fail('BAD_REQUEST', 'invalid quoteSeq');
    const room = db.getRoom(roomId);
    if (!room) fail('NO_SUCH_ROOM', 'room not found');
    if (room.last_seq - quoteSeq > config.quoteWindowSeq) fail('QUOTE_TOO_OLD', 'quoted message is too old');
    const target = db.getMessage(roomId, quoteSeq);
    if (!target) fail('QUOTE_NOT_FOUND', 'quoted message not found');
    return quoteSeq;
  }

  const handlers = {
    ping(conn, msg) {
      hub.send(conn, { type: 'pong', t: msg.t });
    },

    create_room(conn, msg) {
      if (!isNonEmptyString(msg.name, 64)) fail('BAD_REQUEST', 'invalid room name');
      if (db.getRoomByName(msg.name)) fail('ROOM_EXISTS', 'room name already taken');
      const room = db.createRoom(randomId('r_'), msg.name, conn.userId);
      hub.joinRoom(conn, room.id);
      hub.send(conn, {
        type: 'joined',
        roomId: room.id,
        name: room.name,
        role: 'admin',
        mutedUntil: 0,
        lastSeq: 0,
      });
    },

    join(conn, msg) {
      if (!isNonEmptyString(msg.room, 128)) fail('BAD_REQUEST', 'invalid room');
      const room = db.getRoom(msg.room) || db.getRoomByName(msg.room);
      if (!room) fail('NO_SUCH_ROOM', 'room not found');
      db.joinRoom(room.id, conn.userId);
      hub.joinRoom(conn, room.id);
      const member = db.getMember(room.id, conn.userId);
      hub.send(conn, {
        type: 'joined',
        roomId: room.id,
        name: room.name,
        role: member.role,
        mutedUntil: member.muted_until,
        lastSeq: room.last_seq,
      });
      // 补发：优先用客户端上报的进度，否则用服务端游标（新设备场景）
      const fromSeq = Number.isInteger(msg.lastSeq) ? msg.lastSeq : db.getCursor(room.id, conn.userId);
      if (fromSeq < room.last_seq) replayRoom(conn, room.id, fromSeq);
    },

    // 主动离开房间 = 退出成员关系：立即丧失该房间历史资源的下载权限（重连不会自动恢复，需重新 join）
    leave(conn, msg) {
      if (!isNonEmptyString(msg.roomId, 128)) fail('BAD_REQUEST', 'invalid roomId');
      db.removeMember(msg.roomId, conn.userId);
      hub.leaveRoom(conn, msg.roomId);
      hub.send(conn, { type: 'left', roomId: msg.roomId });
    },

    msg(conn, msg) {
      if (!isNonEmptyString(msg.roomId, 128)) fail('BAD_REQUEST', 'invalid roomId');
      if (!isNonEmptyString(msg.clientMsgId, 64)) fail('BAD_REQUEST', 'invalid clientMsgId');
      if (!isNonEmptyString(msg.content, config.maxContentLength)) {
        fail('BAD_REQUEST', `content must be 1..${config.maxContentLength} chars`);
      }
      preSend(conn, msg.roomId);
      const quoteSeq = resolveQuote(msg.roomId, msg.quoteSeq);

      // 先落库（同事务分配 seq），再 ACK，再广播 —— 崩溃也不丢已确认消息
      const { message, duplicate } = db.insertMessage({
        roomId: msg.roomId,
        clientMsgId: msg.clientMsgId,
        senderId: conn.userId,
        content: msg.content,
        msgType: 'text',
        quoteSeq,
      });
      hub.send(conn, {
        type: 'ack',
        roomId: msg.roomId,
        clientMsgId: msg.clientMsgId,
        seq: message.seq,
        ts: message.ts,
      });
      if (!duplicate) {
        // 重复提交（客户端重试）只回 ACK，不再广播 —— 发送幂等
        hub.broadcast(msg.roomId, message, { track: true, seq: message.seq });
      }
    },

    /**
     * 富媒体消息（两阶段发送的「阶段二：消息状态确认」）。
     * 帧里只带 assetId（不带任何文件字节）：大文件绝不经过 WebSocket。
     * 只有资产 status=ready（合并校验通过 + 病毒扫描干净）才允许消息落库。
     */
    media(conn, msg) {
      if (!isNonEmptyString(msg.roomId, 128)) fail('BAD_REQUEST', 'invalid roomId');
      if (!isNonEmptyString(msg.clientMsgId, 64)) fail('BAD_REQUEST', 'invalid clientMsgId');
      if (!isNonEmptyString(msg.assetId, 64)) fail('BAD_REQUEST', 'invalid assetId');
      if (msg.content != null && !isNonEmptyString(msg.content, config.maxContentLength)) {
        fail('BAD_REQUEST', `caption must be 1..${config.maxContentLength} chars`);
      }
      preSend(conn, msg.roomId);
      const quoteSeq = resolveQuote(msg.roomId, msg.quoteSeq);

      const asset = db.getAsset(msg.assetId);
      if (!asset) fail('ASSET_NOT_FOUND', 'asset not found; upload it first');
      // 下载/发送鉴权：本人上传，或本人曾完成过同内容（sha256）的上传（跨用户秒传场景）
      if (asset.uploader_id !== conn.userId && !db.hasCompletedUpload(conn.userId, asset.sha256)) {
        fail('FORBIDDEN', 'not your asset');
      }
      switch (asset.status) {
        case 'ready': break;
        case 'infected': fail('VIRUS_DETECTED', `asset blocked: ${asset.scan_info}`);
        case 'scan_error': fail('SCAN_UNAVAILABLE', 'virus scan pending; retry later');
        case 'scanning': fail('ASSET_NOT_READY', 'upload not finalized yet');
        default: fail('ASSET_GONE', 'asset no longer available');
      }

      const { message, duplicate } = db.insertMessage({
        roomId: msg.roomId,
        clientMsgId: msg.clientMsgId,
        senderId: conn.userId,
        content: msg.content || '',
        msgType: asset.kind,
        assetId: asset.id,
        quoteSeq,
      });
      hub.send(conn, {
        type: 'ack',
        roomId: msg.roomId,
        clientMsgId: msg.clientMsgId,
        seq: message.seq,
        ts: message.ts,
      });
      if (!duplicate) hub.broadcast(msg.roomId, message, { track: true, seq: message.seq });
    },

    /**
     * 撤回（仅发送者本人，默认 2 分钟窗口，可配置）。
     * 文件删除规则：撤回后若该资产没有其他未撤回消息引用，则物理删除文件并置 tombstone；
     * 仍被其他消息引用（同文件发过多条/多个房间）时保留。
     */
    recall(conn, msg) {
      if (!isNonEmptyString(msg.roomId, 128) || !Number.isInteger(msg.seq)) {
        fail('BAD_REQUEST', 'invalid roomId/seq');
      }
      requireMember(conn, msg.roomId);
      const target = db.getMessage(msg.roomId, msg.seq);
      if (!target) fail('NOT_FOUND', 'message not found');
      if (target.from !== conn.userId) fail('FORBIDDEN', 'only the sender can recall');
      if (config.recallWindowMs >= 0 && now() - target.ts > config.recallWindowMs) {
        fail('RECALL_WINDOW_EXPIRED', 'recall window has expired');
      }

      const res = db.recallMessage(msg.roomId, msg.seq);
      if (!res) fail('NOT_FOUND', 'message not found');
      if (res.recalled && res.assetId && config.deleteAssetOnRecall) {
        if (db.countLiveAssetRefs(res.assetId) === 0) {
          const asset = db.getAsset(res.assetId);
          if (asset && asset.status === 'ready') {
            // 先删文件、成功后再置 tombstone：删除失败则保持 ready（仍可下载），
            // 之后由 TTL 清理（无引用 ready 资产）兜底回收。
            storage.deleteObject(asset.sha256)
              .then(() => db.markAssetDeleted(asset.id))
              .catch((err) => console.error('[recall] asset delete failed, left for GC', asset.id, err));
          }
        }
      }
      // 幂等：重复撤回也广播（track 走 ACK 重发，客户端按墓碑状态自行去重；
      // 漏收的端在重连补发时也会从 DB 拿到 recalled 消息）
      hub.broadcast(msg.roomId, {
        type: 'recalled',
        roomId: msg.roomId,
        seq: msg.seq,
        ts: now(),
      }, { track: true, seq: msg.seq });
    },

    // 客户端累积 ACK：清除未确认队列 + 持久化游标（断线补发的兜底依据）
    ack(conn, msg) {
      if (!isNonEmptyString(msg.roomId, 128) || !Number.isInteger(msg.seq)) return;
      if (!conn.rooms.has(msg.roomId)) return; // 只处理本连接已加入的房间
      conn.ack(msg.roomId, msg.seq);
      db.saveCursor(msg.roomId, conn.userId, msg.seq);
    },

    sync(conn, msg) {
      if (!isNonEmptyString(msg.roomId, 128)) fail('BAD_REQUEST', 'invalid roomId');
      requireMember(conn, msg.roomId);
      const fromSeq = Number.isInteger(msg.lastSeq) ? msg.lastSeq : db.getCursor(msg.roomId, conn.userId);
      replayRoom(conn, msg.roomId, fromSeq);
    },

    history(conn, msg) {
      if (!isNonEmptyString(msg.roomId, 128)) fail('BAD_REQUEST', 'invalid roomId');
      requireMember(conn, msg.roomId);
      const limit = Math.min(Math.max(1, msg.limit || 50), config.historyMaxLimit);
      const before = Number.isInteger(msg.beforeSeq) ? msg.beforeSeq : Number.MAX_SAFE_INTEGER;
      const messages = db.getMessagesBefore(msg.roomId, before, limit);
      hub.send(conn, { type: 'history', roomId: msg.roomId, messages, hasMore: messages.length === limit });
    },

    rooms(conn) {
      hub.send(conn, { type: 'rooms', rooms: db.listRoomsForUser(conn.userId) });
    },

    members(conn, msg) {
      if (!isNonEmptyString(msg.roomId, 128)) fail('BAD_REQUEST', 'invalid roomId');
      requireMember(conn, msg.roomId);
      const online = new Set(hub.onlineUserIds(msg.roomId));
      const members = db.listMembers(msg.roomId).map((m) => ({ ...m, online: online.has(m.userId) }));
      hub.send(conn, { type: 'members', roomId: msg.roomId, members });
    },

    mute(conn, msg) {
      requireAdmin(conn, msg.roomId);
      const target = db.getMember(msg.roomId, msg.userId);
      if (!target) fail('NOT_MEMBER', 'target is not a member');
      if (target.role === 'admin') fail('FORBIDDEN', 'cannot mute an admin');
      const minutes = Number(msg.minutes);
      if (!Number.isFinite(minutes) || minutes < 1 || minutes > 1440) {
        fail('BAD_REQUEST', 'minutes must be 1..1440');
      }
      const until = now() + Math.round(minutes * 60_000);
      db.setMuted(msg.roomId, msg.userId, until);
      hub.broadcast(msg.roomId, {
        type: 'notice',
        roomId: msg.roomId,
        event: 'muted',
        userId: msg.userId,
        until,
        by: conn.userId,
      });
    },

    unmute(conn, msg) {
      requireAdmin(conn, msg.roomId);
      const target = db.getMember(msg.roomId, msg.userId);
      if (!target) fail('NOT_MEMBER', 'target is not a member');
      db.setMuted(msg.roomId, msg.userId, 0);
      hub.broadcast(msg.roomId, {
        type: 'notice',
        roomId: msg.roomId,
        event: 'unmuted',
        userId: msg.userId,
        by: conn.userId,
      });
    },
  };

  function onFrame(conn, raw, isBinary = false) {
    // 硬性边界：二进制帧一律拒绝。大文件只允许走 HTTP 分块上传，
    // 避免单个巨型帧被整帧缓冲进内存、阻塞该连接的文本收发（背压）。
    if (isBinary) {
      if (config.rejectBinaryWs) {
        try { conn.ws.close(1009, 'binary frames forbidden; use HTTP upload'); } catch { /* 已关闭 */ }
        return;
      }
      hub.send(conn, { type: 'error', code: 'BAD_FRAME', message: 'binary frames are not supported' });
      return;
    }
    const msg = parseFrame(raw);
    if (!msg) {
      hub.send(conn, { type: 'error', code: 'BAD_FRAME', message: 'invalid JSON frame' });
      return;
    }
    const handler = handlers[msg.type];
    if (!handler) {
      hub.send(conn, { type: 'error', code: 'UNKNOWN_TYPE', message: `unknown type: ${msg.type}` });
      return;
    }
    try {
      handler(conn, msg);
    } catch (err) {
      if (err instanceof ChatError) {
        hub.send(conn, {
          type: 'error',
          code: err.code,
          message: err.message,
          ref: msg.clientMsgId || msg.roomId || undefined,
        });
      } else {
        console.error('[handler error]', msg.type, err);
        hub.send(conn, { type: 'error', code: 'INTERNAL', message: 'internal error' });
      }
    }
  }

  // ---------------------------------------------------------------- HTTP 层

  const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' };

  function readBody(req, limit = 64 * 1024) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > limit) {
          reject(new HttpError(413, 'BODY_TOO_LARGE', 'request body too large'));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString()));
      req.on('error', reject);
    });
  }

  /** HTTP 鉴权：Authorization: Bearer <token> 或 ?token=（与 WS 同一套演示 token） */
  function authenticate(req, url) {
    const header = req.headers.authorization;
    let token = null;
    if (header && header.startsWith('Bearer ')) token = header.slice(7).trim();
    if (!token) token = url.searchParams.get('token');
    const userId = token && verifyToken(token, config.authSecret);
    return userId ? db.getUserById(userId) : null;
  }

  function contentDisposition(asset) {
    const name = `filename*=UTF-8''${encodeURIComponent(asset.filename)}`;
    // image/voice 允许内联渲染（类型白名单已限定），file 一律附件下载（防同源 HTML XSS）
    const kind = asset.kind === 'file' ? 'attachment' : 'inline';
    return `${kind}; ${name}`;
  }

  /** GET /api/assets/:id/download —— 按权限流式下载（含 Range 续传） */
  async function handleDownload(req, res, url, user) {
    const id = url.pathname.split('/')[3];
    const asset = db.getAsset(id);
    if (!asset) {
      res.writeHead(404).end(JSON.stringify({ error: 'asset not found' }));
      return;
    }
    if (asset.status !== 'ready') {
      // 撤回删除 / TTL 清理 / 病毒拉黑都在此收口
      const code = asset.status === 'infected' ? 422 : 410;
      res.writeHead(code, { 'content-type': 'application/json' })
        .end(JSON.stringify({ error: `asset ${asset.status}` }));
      return;
    }
    // 下载权限：当前成员关系 ∩ 房间内存在引用该资产的未撤回消息。
    // 退出房间（成员行已删）、消息全部撤回（无存活引用）都会被拒绝。
    const roomId = db.liveRoomForAssetUser(asset.id, user.id);
    if (!roomId) {
      res.writeHead(403, { 'content-type': 'application/json' })
        .end(JSON.stringify({ error: 'no download permission (not a member or message recalled)' }));
      return;
    }

    const objectPath = storage.objectPath(asset.sha256);
    let stat;
    try {
      stat = await fsp.stat(objectPath);
    } catch {
      res.writeHead(410, { 'content-type': 'application/json' })
        .end(JSON.stringify({ error: 'object missing on storage' }));
      return;
    }

    const headers = {
      'content-type': asset.mime,
      'content-disposition': contentDisposition(asset),
      'accept-ranges': 'bytes',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'none'",
      'cache-control': 'private, max-age=3600',
    };

    let start = 0;
    let end = stat.size - 1;
    const range = req.headers.range;
    if (range) {
      const m = /^bytes=(\d*)-(\d*)$/.exec(range);
      if (m && (m[1] || m[2])) {
        if (m[1]) start = parseInt(m[1], 10);
        if (m[2]) end = parseInt(m[2], 10);
        if (m[1] && !m[2]) end = stat.size - 1;
        if (!m[1] && m[2]) { start = Math.max(0, stat.size - parseInt(m[2], 10)); end = stat.size - 1; }
      }
      if (start > end || start >= stat.size) {
        res.writeHead(416, { 'content-range': `bytes */${stat.size}` }).end();
        return;
      }
      res.writeHead(206, { ...headers, 'content-range': `bytes ${start}-${end}/${stat.size}`, 'content-length': end - start + 1 });
    } else {
      res.writeHead(200, { ...headers, 'content-length': stat.size });
    }

    let bytesSent = 0;
    const stream = fs.createReadStream(objectPath, { start, end });
    stream.on('data', (c) => { bytesSent += c.length; });
    stream.on('error', () => { try { res.destroy(); } catch { /* 客户端已断开 */ } });
    res.on('close', () => stream.destroy());
    stream.pipe(res);
    res.on('finish', () => {
      try { db.recordDownload({ assetId: asset.id, userId: user.id, roomId, bytes: bytesSent }); } catch { /* 审计失败不影响下载 */ }
    });
  }

  async function readJson(req) {
    try {
      return JSON.parse(await readBody(req));
    } catch {
      throw new HttpError(400, 'BAD_REQUEST', 'invalid JSON body');
    }
  }

  const httpServer = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const sendJson = (code, obj, headers = {}) => {
      res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', ...headers });
      res.end(JSON.stringify(obj));
    };

    try {
      if (req.method === 'POST' && url.pathname === '/api/login') {
        // 演示级登录：按用户名创建/复用账号，返回签名 token
        const body = await readJson(req);
        if (!isNonEmptyString(body.name, 32)) return sendJson(400, { error: 'invalid name' });
        let user = db.getUserByName(body.name);
        if (!user) user = db.createUser(randomId('u_'), body.name, randomSecret());
        const token = signToken(user.id, user.token_random, config.authSecret);
        return sendJson(200, { userId: user.id, name: user.name, token });
      }

      if (req.method === 'GET' && url.pathname === '/healthz') {
        return sendJson(200, { ok: true, ...hub.stats() });
      }

      // —— 上传 / 下载 API（需鉴权）——
      if (url.pathname.startsWith('/api/')) {
        const user = authenticate(req, url);
        if (!user) return sendJson(401, { error: 'unauthorized' });

        const parts = url.pathname.split('/'); // ['', 'api', 'uploads'|'assets', ...]
        if (req.method === 'POST' && url.pathname === '/api/uploads') {
          const body = await readJson(req);
          const result = await uploads.init({ id: user.id }, body);
          return sendJson(result.resumed ? 200 : 201, result);
        }
        if (parts[2] === 'uploads' && parts[3]) {
          const taskId = parts[3];
          if (req.method === 'GET' && parts.length === 4) {
            return sendJson(200, uploads.getStatus({ id: user.id }, taskId));
          }
          if (req.method === 'POST' && parts[4] === 'complete') {
            return sendJson(200, await uploads.complete({ id: user.id }, taskId));
          }
          if (req.method === 'POST' && parts[4] === 'abort') {
            return sendJson(200, await uploads.abort({ id: user.id }, taskId));
          }
          if (req.method === 'PUT' && parts[4] === 'chunks' && parts[5] != null) {
            const idx = Number(parts[5]);
            if (!Number.isInteger(idx)) throw new HttpError(400, 'BAD_REQUEST', 'bad chunk idx');
            const len = req.headers['content-length'] ? Number(req.headers['content-length']) : null;
            const result = await uploads.putChunk({ id: user.id }, taskId, idx, req, len);
            return sendJson(200, result);
          }
        }
        if (req.method === 'GET' && parts[2] === 'assets' && parts[4] === 'download') {
          return handleDownload(req, res, url, user);
        }
        return sendJson(404, { error: 'not found' });
      }

      if (req.method === 'GET') {
        const rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
        const file = path.resolve(publicDir, rel);
        if (!file.startsWith(publicDir) || !MIME[path.extname(file)]) {
          res.writeHead(404).end('not found');
          return;
        }
        fs.readFile(file, (err, data) => {
          if (err) {
            res.writeHead(404).end('not found');
            return;
          }
          res.writeHead(200, { 'content-type': MIME[path.extname(file)] });
          res.end(data);
        });
        return;
      }

      res.writeHead(404).end('not found');
    } catch (err) {
      if (err instanceof HttpError) {
        return sendJson(err.status, { error: err.code, message: err.message, details: err.details || undefined });
      }
      console.error('[http error]', req.method, req.url, err);
      if (!res.headersSent) sendJson(500, { error: 'internal error' });
      else try { res.destroy(); } catch { /* 已结束 */ }
    }
  });

  // ---------------------------------------------------------------- WS 层

  // maxPayload：WebSocket 帧内存硬上限（默认 64KB）。超限的帧在解析期直接 1009 断开，
  // 大文件无法通过 WS 占用整帧内存 / 制造背压 —— 文件通道只有 HTTP。
  const wss = new WebSocketServer({ noServer: true, maxPayload: config.wsMaxPayload || 64 * 1024 });

  httpServer.on('upgrade', (req, socket, head) => {
    const reject = (code, text) => {
      socket.write(`HTTP/1.1 ${code} ${text}\r\nConnection: close\r\n\r\n`);
      socket.destroy();
    };
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname !== '/ws') return reject(404, 'Not Found');

    const userId = verifyToken(url.searchParams.get('token'), config.authSecret);
    const user = userId && db.getUserById(userId);
    if (!user) return reject(401, 'Unauthorized');

    const denied = hub.checkAdmission(user.id);
    if (denied) return reject(503, denied);

    wss.handleUpgrade(req, socket, head, (ws) => {
      const conn = new Connection(ws, user);
      hub.add(conn);

      ws.on('pong', () => {
        conn.lastPong = now();
      });
      ws.on('message', (raw, isBinary) => onFrame(conn, raw, isBinary));
      ws.on('close', () => hub.remove(conn));
      ws.on('error', () => {}); // 错误后必随 close，统一在 close 清理

      hub.send(conn, {
        type: 'welcome',
        userId: user.id,
        name: user.name,
        serverTime: now(),
        upload: {
          maxFileSize: config.maxFileSize,
          chunkSize: config.chunkSize,
          kinds: [...MEDIA_KINDS],
        },
      });
    });
  });

  // ---------------------------------------------------------------- 定时任务

  /**
   * 过期清理：
   * 1. open 上传任务超过 uploadTtlMs → 置 expired + 删临时分片（中断续传的有界回收）；
   * 2. ready 资产超过 assetTtlMs 且无任何未撤回消息引用 → 物理删除 + tombstone；
   * 3. scan_error 资产超过 uploadTtlMs（重试窗口已过）→ 回收物理文件，行保留以便同 hash 重传重扫；
   * 4. 崩溃残留的 *.tmp-* 临时文件。
   */
  async function cleanupSweep() {
    let tasks = 0;
    let assets = 0;
    try {
      tasks = await uploads.sweepStaleTasks();

      if (config.assetTtlMs > 0) {
        const cutoff = now() - config.assetTtlMs;
        for (const a of db.findExpiredAssets(cutoff, 200)) {
          await storage.deleteObject(a.sha256).catch(() => {});
          db.markAssetDeleted(a.id);
          assets++;
        }
      }

      const errCutoff = now() - config.uploadTtlMs;
      for (const a of db.findStaleScanErrorAssets(errCutoff, 200)) {
        await storage.deleteObject(a.sha256).catch(() => {});
      }

      await storage.pruneTempFiles().catch(() => {});
    } catch (err) {
      console.error('[cleanup] sweep failed', err);
    }
    return { tasks, assets };
  }

  const timers = [
    setInterval(() => hub.heartbeatSweep(), config.heartbeatIntervalMs),
    setInterval(() => hub.resendSweep(), config.ackResendIntervalMs),
  ];
  let cleanupTimer = null;
  if (config.cleanupIntervalMs > 0) {
    cleanupTimer = setInterval(() => { cleanupSweep(); }, config.cleanupIntervalMs);
    timers.push(cleanupTimer);
  }
  for (const t of timers) t.unref();

  // ---------------------------------------------------------------- 生命周期

  async function start() {
    const addr = await new Promise((resolve, reject) => {
      httpServer.listen(config.port, config.host, () => resolve(httpServer.address()));
      httpServer.once('error', reject);
    });
    await storage.pruneTempFiles().catch(() => {});
    console.log(
      `[chat] listening on http://${addr.address}:${addr.port}  (db: ${config.dbPath}, storage: ${config.storageDir})`
    );
    return addr;
  }

  function stop() {
    for (const t of timers) clearInterval(t);
    for (const conn of [...hub.all]) {
      hub.send(conn, { type: 'server_shutdown' });
      conn.ws.terminate();
    }
    wss.close();
    httpServer.close();
    db.close();
    if (autoTempStorage) {
      try { fs.rmSync(storageRoot, { recursive: true, force: true }); } catch { /* 退出时尽力清理 */ }
    }
  }

  return { config, db, hub, httpServer, wss, storage, storageRoot, scanner, uploads, cleanupSweep, start, stop };
}

// 直接运行：node src/server.js
if (require.main === module) {
  const server = createChatServer();
  server.start();
  const shutdown = () => {
    console.log('\n[chat] shutting down...');
    server.stop();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

module.exports = { createChatServer };
