'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { WebSocketServer } = require('ws');

const { ChatDB } = require('./db');
const { Hub, Connection } = require('./hub');
const { LocalStorage } = require('./storage');
const { Scanner } = require('./scanner');
const { UploadManager, UploadError } = require('./uploads');
const defaultConfig = require('./config');
const {
  randomId,
  randomSecret,
  signToken,
  verifyToken,
  isNonEmptyString,
  signAssetTicket,
  verifyAssetTicket,
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

/** 数据库消息行 -> 下发帧（实时广播 / sync / history 共用，形状一致） */
function toMsgFrame(m) {
  const frame = {
    type: 'msg',
    roomId: m.roomId,
    seq: m.seq,
    clientMsgId: m.clientMsgId,
    from: m.from,
    fromName: m.fromName,
    content: m.content,
    ts: m.ts,
    kind: m.kind || 'text',
    recalledAt: m.recalledAt || 0,
  };
  if (m.assetId) {
    frame.asset = {
      id: m.assetId,
      name: m.assetName,
      size: m.assetSize,
      mime: m.assetMime,
      status: m.assetStatus,
      meta: {
        width: m.assetWidth ?? null,
        height: m.assetHeight ?? null,
        durationMs: m.assetDurationMs ?? null,
      },
    };
  }
  if (m.replyToSeq != null) {
    frame.replyTo = {
      seq: m.replyToSeq,
      fromName: m.replyFromName || null,
      kind: m.replyKind || 'text',
      snippet: m.replyRecalledAt ? '' : (m.replySnippet || ''),
      recalled: !!m.replyRecalledAt,
    };
  }
  return frame;
}

function createChatServer(overrides = {}) {
  const config = { ...defaultConfig, ...overrides };
  const db = new ChatDB(config.dbPath);
  const hub = new Hub(config);
  const limiter = new TokenBucket(config.rateLimitPerSec, config.rateLimitBurst);
  const storage = new LocalStorage({ root: config.storageRoot });
  const scanner = new Scanner(config);
  const uploads = new UploadManager({ db, storage, scanner, config });
  const publicDir = path.join(__dirname, '..', 'public');

  // ---------------------------------------------------------------- 消息处理

  /** 断线补发：把 roomId 中 seq > fromSeq 的消息按序推给连接，分批，客户端按 sync_done 续拉 */
  function replayRoom(conn, roomId, fromSeq) {
    const batch = db.getMessagesAfter(roomId, fromSeq, config.syncBatchSize + 1);
    const hasMore = batch.length > config.syncBatchSize;
    const slice = hasMore ? batch.slice(0, config.syncBatchSize) : batch;
    for (const m of slice) hub.send(conn, toMsgFrame(m), { track: true, roomId, seq: m.seq });
    const lastSeq = slice.length ? slice[slice.length - 1].seq : fromSeq;
    hub.send(conn, { type: 'sync_done', roomId, lastSeq, hasMore });
  }

  /** 要求当前为在群（active）成员；已持久退群（active=0）一律拒绝 */
  function requireMember(conn, roomId) {
    const member = db.getMember(roomId, conn.userId);
    if (!member) fail('NOT_MEMBER', 'not a member of this room');
    if (!member.active) fail('MEMBERSHIP_INACTIVE', 'you have left this room');
    return member;
  }

  function requireAdmin(conn, roomId) {
    const member = requireMember(conn, roomId);
    if (member.role !== 'admin') fail('FORBIDDEN', 'admin role required');
    return member;
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
      // 补发：优先用客户端上报的进度，否则用服务端游标（新设备则从游标开始）
      const fromSeq = Number.isInteger(msg.lastSeq) ? msg.lastSeq : db.getCursor(room.id, conn.userId);
      if (fromSeq < room.last_seq) replayRoom(conn, room.id, fromSeq);
    },

    leave(conn, msg) {
      if (!isNonEmptyString(msg.roomId, 128)) fail('BAD_REQUEST', 'invalid roomId');
      // mode='detach'（默认）：仅本连接退出广播集（旧客户端行为，members 行保留）
      // mode='leave'：持久退群（active=0），该用户所有连接同时移出广播集
      const persisted = msg.mode === 'leave';
      if (persisted) {
        const member = db.getMember(msg.roomId, conn.userId);
        if (!member) fail('NOT_MEMBER', 'not a member of this room');
        if (member.active) db.deactivateMember(msg.roomId, conn.userId);
        hub.leaveRoomForUser(conn.userId, msg.roomId);
      } else {
        hub.leaveRoom(conn, msg.roomId);
      }
      hub.send(conn, { type: 'left', roomId: msg.roomId, persisted });
    },

    msg(conn, msg) {
      if (!isNonEmptyString(msg.roomId, 128)) fail('BAD_REQUEST', 'invalid roomId');
      if (!isNonEmptyString(msg.clientMsgId, 64)) fail('BAD_REQUEST', 'invalid clientMsgId');
      const kind = msg.kind === undefined ? 'text' : msg.kind;
      if (!['text', 'image', 'file', 'voice'].includes(kind)) fail('BAD_REQUEST', 'invalid kind');
      // text: 正文非空；富媒体: caption 可省略（按 '' 计）但有长度上限
      let content = msg.content;
      if (content === undefined || content === null) content = '';
      if (typeof content !== 'string'
          || (kind === 'text'
            ? !(content.length > 0 && content.length <= config.maxContentLength)
            : content.length > config.captionMaxLength)) {
        fail('BAD_REQUEST',
          kind === 'text'
            ? `content must be 1..${config.maxContentLength} chars`
            : `caption must be <= ${config.captionMaxLength} chars`);
      }
      let replyToSeq = null;
      if (msg.replyToSeq !== undefined && msg.replyToSeq !== null) {
        if (!Number.isInteger(msg.replyToSeq) || msg.replyToSeq < 1) fail('BAD_REQUEST', 'invalid replyToSeq');
        replyToSeq = msg.replyToSeq;
      }

      const member = requireMember(conn, msg.roomId);
      if (member.muted_until > now()) {
        fail('MUTED', `you are muted until ${new Date(member.muted_until).toISOString()}`);
      }
      if (!limiter.take(conn.userId)) fail('RATE_LIMITED', 'sending too fast, slow down');

      let assetId = null;
      if (kind !== 'text') {
        if (!isNonEmptyString(msg.assetId, 128)) fail('BAD_REQUEST', 'assetId required for rich messages');
        const asset = db.getAsset(msg.assetId);
        if (!asset) fail('NO_SUCH_ASSET', 'asset not found');
        if (asset.kind !== kind) fail('BAD_REQUEST', 'asset kind mismatch');
        if (asset.blob_status === 'quarantined') fail('ASSET_INFECTED', 'asset was quarantined');
        if (asset.blob_status !== 'ready') fail('ASSET_DELETED', 'asset is not available');
        // scope：只能发送自己上传的 asset，或该 asset 已在本房间作为未撤回消息存在
        // （防止拿别人的 assetId 跨房间拖取文件）
        if (!db.isAssetOwner(asset.id, conn.userId)
            && !db.assetReferencedLiveInRoom(msg.roomId, asset.id)) {
          fail('ASSET_SCOPE', 'asset is not usable in this room');
        }
        assetId = asset.id;
      }

      if (replyToSeq != null) {
        const target = db.getMessage(msg.roomId, replyToSeq);
        if (!target) fail('BAD_REPLY', 'referenced message does not exist');
      }

      // 先落库（同事务分配 seq），再 ACK，再广播 —— 富媒体字节绝不出现在帧中
      const { message, duplicate } = db.insertMessage({
        roomId: msg.roomId,
        clientMsgId: msg.clientMsgId,
        senderId: conn.userId,
        content,
        kind,
        assetId,
        replyToSeq,
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
        hub.broadcast(msg.roomId, toMsgFrame(message), { track: true, seq: message.seq });
      }
    },

    // 富媒体下载票：校验「active 成员 + 房间内有未撤回引用」后发短时 HMAC 票
    asset_ticket(conn, msg) {
      if (!isNonEmptyString(msg.roomId, 128) || !isNonEmptyString(msg.assetId, 128)) {
        fail('BAD_REQUEST', 'invalid roomId/assetId');
      }
      requireMember(conn, msg.roomId);
      const asset = db.getAsset(msg.assetId);
      if (!asset) fail('NO_SUCH_ASSET', 'asset not found');
      if (asset.blob_status !== 'ready') fail('ASSET_DELETED', 'asset is not available');
      if (!db.assetHasLiveRefForUser(asset.id, conn.userId)) {
        fail('ASSET_FORBIDDEN', 'no permission to access this asset');
      }
      const exp = now() + config.assetTicketTtlMs;
      hub.send(conn, {
        type: 'asset_ticket',
        assetId: asset.id,
        ticket: signAssetTicket(conn.userId, asset.id, exp, config.authSecret),
        expiresAt: exp,
      });
    },

    // 撤回：发送者在时间窗内，或本房 admin（不限时、可撤回他人）。墓碑保留行。
    recall(conn, msg) {
      if (!isNonEmptyString(msg.roomId, 128) || !Number.isInteger(msg.seq)) {
        fail('BAD_REQUEST', 'invalid roomId/seq');
      }
      const member = requireMember(conn, msg.roomId);
      const target = db.getMessage(msg.roomId, msg.seq);
      if (!target) fail('NOT_FOUND', 'message not found');
      if (target.recalledAt) {
        hub.send(conn, {
          type: 'recalled', roomId: msg.roomId, seq: msg.seq,
          by: target.from, recalledAt: target.recalledAt,
        });
        return;
      }
      const isAdmin = member.role === 'admin';
      if (target.from !== conn.userId && !isAdmin) fail('RECALL_FORBIDDEN', 'can only recall your own message');
      if (!isAdmin && now() - target.ts > config.recallWindowMs) {
        fail('RECALL_TOO_LATE', `recall window is ${config.recallWindowMs / 1000}s`);
      }
      const { recalled, message } = db.recallMessage(msg.roomId, msg.seq);
      if (recalled) {
        hub.broadcast(msg.roomId, {
          type: 'recalled', roomId: msg.roomId, seq: msg.seq,
          by: conn.userId, recalledAt: message.recalledAt,
        });
        // 撤回后若该 blob 已无任何活引用/任务占用，物理删除（隔离副本不删）
        if (message.assetId) {
          const asset = db.getAsset(message.assetId);
          if (asset && asset.blob_status === 'ready') {
            uploads.gcBlobIfUnreferenced(asset.sha256).catch((e) => console.error('[gc]', e));
          }
        }
      }
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
      const messages = db.getMessagesBefore(msg.roomId, before, limit).map(toMsgFrame);
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

  function onFrame(conn, raw) {
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

  function readBody(req, limit = 8192) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > limit) {
          reject(new Error('body too large'));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString()));
      req.on('error', reject);
    });
  }

  /** HTTP Bearer 鉴权（复用 WS 同一套登录 token），返回 user 或 null */
  function authenticate(req) {
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer ')) return null;
    const userId = verifyToken(h.slice(7), config.authSecret);
    return userId ? db.getUserById(userId) : null;
  }

  function requireHttpUser(req, res) {
    const user = authenticate(req);
    if (!user) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'UNAUTHORIZED', message: 'login required' }));
      return null;
    }
    return user;
  }

  /** 把 UploadError 转成 HTTP 错误响应 */
  function sendUploadError(res, err) {
    if (err instanceof UploadError) {
      res.writeHead(err.status, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: err.code, message: err.message, ...err.extra }));
      return;
    }
    console.error('[upload error]', err);
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'INTERNAL', message: 'internal error' }));
  }

  /** GET /api/assets/:id?ticket= —— 凭短时 HMAC 票 Range 流式下载/播放 */
  function serveAsset(req, res, url) {
    const assetId = decodeURIComponent(url.pathname.split('/').pop());
    const claims = verifyAssetTicket(url.searchParams.get('ticket'), config.authSecret);
    const failAsset = (code, message, status = 403) => {
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: code, message }));
    };
    if (!claims || claims.assetId !== assetId) return failAsset('ASSET_FORBIDDEN', 'invalid ticket');
    const asset = db.getAsset(assetId);
    if (!asset) return failAsset('NO_SUCH_ASSET', 'asset not found', 404);
    if (asset.blob_status !== 'ready') return failAsset('ASSET_DELETED', 'asset unavailable', 410);
    // 鉴权：请求者当前为某房间 active 成员，且该房有一条引用此 asset 的未撤回消息
    if (!db.assetHasLiveRefForUser(assetId, claims.userId)) {
      return failAsset('ASSET_FORBIDDEN', 'no permission to access this asset');
    }
    const st = storage.statBlob(asset.sha256);
    if (!st || st.size !== asset.size) {
      return failAsset('ASSET_DELETED', 'blob missing', 410);
    }

    const inline = asset.kind === 'image' || asset.kind === 'voice';
    const dispositionType = inline ? 'inline' : 'attachment';
    const fname = encodeURIComponent(asset.file_name);
    const headers = {
      'Accept-Ranges': 'bytes',
      'Content-Type': inline ? asset.mime : 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'private, no-store',
      'Content-Disposition': `${dispositionType}; filename*=UTF-8''${fname}`,
    };

    const range = req.headers.range;
    const size = asset.size;
    if (range) {
      const m = /^bytes=(\d*)-(\d*)$/.exec(range);
      if (m) {
        let start = m[1] === '' ? undefined : Number(m[1]);
        let end = m[2] === '' ? undefined : Number(m[2]);
        // 后缀形式 bytes=-N
        if (m[1] === '' && m[2] !== '') {
          start = Math.max(0, size - Number(m[2]));
          end = size - 1;
        } else if (m[2] === '') {
          end = size - 1;
        }
        if (!Number.isInteger(start) || !Number.isInteger(end) || start > end || start >= size) {
          res.writeHead(416, { 'Content-Range': `bytes */${size}` });
          return res.end();
        }
        end = Math.min(end, size - 1);
        res.writeHead(206, {
          ...headers,
          'Content-Range': `bytes ${start}-${end}/${size}`,
          'Content-Length': end - start + 1,
        });
        const stream = storage.openBlob(asset.sha256, { start, end });
        stream.on('error', () => res.destroy());
        return stream.pipe(res);
      }
    }
    res.writeHead(200, { ...headers, 'Content-Length': size });
    const stream = storage.openBlob(asset.sha256);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
  }

  const httpServer = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const json = (code, obj) => {
      res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(obj));
    };

    if (req.method === 'POST' && url.pathname === '/api/login') {
      // 演示级登录：按用户名创建/复用账号，返回签名 token
      try {
        const body = JSON.parse(await readBody(req));
        if (!isNonEmptyString(body.name, 32)) return json(400, { error: 'invalid name' });
        let user = db.getUserByName(body.name);
        if (!user) user = db.createUser(randomId('u_'), body.name, randomSecret());
        const token = signToken(user.id, user.token_random, config.authSecret);
        return json(200, { userId: user.id, name: user.name, token });
      } catch {
        return json(400, { error: 'bad request' });
      }
    }

    if (req.method === 'GET' && url.pathname === '/healthz') {
      return json(200, { ok: true, ...hub.stats() });
    }

    // ---------------------------------------------------- 富媒体上传 / 下载

    const upMatch = url.pathname.match(
      /^\/api\/uploads\/([^/]+)(?:\/(chunks|complete|abort)(?:\/(\d+))?)?\/?$/
    );
    if (upMatch) {
      const user = requireHttpUser(req, res);
      if (!user) return;
      const taskId = decodeURIComponent(upMatch[1]);
      const sub = upMatch[2] || '';
      try {
        // PUT /api/uploads/:id/chunks/:idx —— raw 字节流式落盘
        if (req.method === 'PUT' && sub === 'chunks') {
          const idx = Number(upMatch[3]);
          const result = await uploads.putChunk(user, taskId, idx, req, {
            declaredSha: req.headers['x-chunk-sha256'],
            contentLength: req.headers['content-length']
              ? Number(req.headers['content-length']) : null,
          });
          return json(200, result);
        }
        // GET /api/uploads/:id —— 任务状态 / 续传差集
        if (req.method === 'GET' && sub === '') {
          return json(200, await uploads.getTask(user, taskId));
        }
        // POST /api/uploads/:id/complete
        if (req.method === 'POST' && sub === 'complete') {
          const body = JSON.parse(await readBody(req));
          return json(200, await uploads.complete(user, taskId, body.sha256));
        }
        // POST /api/uploads/:id/abort
        if (req.method === 'POST' && sub === 'abort') {
          return json(200, await uploads.abort(user, taskId));
        }
      } catch (err) {
        return sendUploadError(res, err);
      }
    }

    if (req.method === 'POST' && url.pathname === '/api/uploads') {
      const user = requireHttpUser(req, res);
      if (!user) return;
      try {
        const body = JSON.parse(await readBody(req));
        return json(200, await uploads.createTask(user, body));
      } catch (err) {
        return sendUploadError(res, err);
      }
    }

    if (req.method === 'GET' && /^\/api\/assets\/[^/]+\/?$/.test(url.pathname)) {
      return serveAsset(req, res, url);
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
  });

  // ---------------------------------------------------------------- WS 层

  // maxPayload：富媒体字节一律走 HTTP，WS 只承载小的 JSON 控制/消息帧（超限自动 1009）
  const wss = new WebSocketServer({ noServer: true, maxPayload: config.wsMaxPayload });

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
      ws.on('message', (raw) => onFrame(conn, raw));
      ws.on('close', () => hub.remove(conn));
      ws.on('error', () => {}); // 错误后必随 close，统一在 close 清理

      hub.send(conn, { type: 'welcome', userId: user.id, name: user.name, serverTime: now() });
    });
  });

  // ---------------------------------------------------------------- 定时任务

  const timers = [
    setInterval(() => hub.heartbeatSweep(), config.heartbeatIntervalMs),
    setInterval(() => hub.resendSweep(), config.ackResendIntervalMs),
  ];
  if (config.reapIntervalMs > 0) {
    timers.push(setInterval(() => { uploads.runReap().catch((e) => console.error('[reap]', e)); },
      config.reapIntervalMs));
  }
  for (const t of timers) t.unref();

  // ---------------------------------------------------------------- 生命周期

  async function start() {
    await uploads.init();
    return new Promise((resolve) => {
      httpServer.listen(config.port, config.host, () => {
        const addr = httpServer.address();
        console.log(`[chat] listening on http://${addr.address}:${addr.port}  (db: ${config.dbPath})`);
        resolve(addr);
      });
    });
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
  }

  return { config, db, hub, storage, scanner, uploads, httpServer, wss, start, stop };
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
