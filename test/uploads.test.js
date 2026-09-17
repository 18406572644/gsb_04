'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const WebSocket = require('ws');

const { createChatServer } = require('../src/server');
const { signAssetTicket } = require('../src/util');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

async function startServer(overrides = {}) {
  const storageRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'chat-up-'));
  const server = createChatServer({
    port: 0,
    host: '127.0.0.1',
    dbPath: ':memory:',
    heartbeatIntervalMs: 60_000,
    ackResendAfterMs: 60_000,
    reapIntervalMs: 0, // 测试内手动 runReap
    storageRoot,
    ...overrides,
  });
  const addr = await server.start();
  return { server, port: addr.port, storageRoot };
}

async function login(port, name) {
  const res = await fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name }),
  });
  assert.equal(res.status, 200);
  return res.json();
}

class Client {
  static async connect(port, token) {
    const c = new Client();
    c.log = []; c.pending = []; c.waiters = [];
    c.closed = new Promise((res) => (c._onClosed = res));
    c.ws = new WebSocket(`ws://127.0.0.1:${port}/ws?token=${encodeURIComponent(token)}`);
    c.ws.on('message', (raw) => {
      const m = JSON.parse(raw.toString());
      c.log.push(m);
      for (const w of [...c.waiters]) {
        if (w.pred(m)) {
          c.waiters.splice(c.waiters.indexOf(w), 1);
          clearTimeout(w.timer);
          w.resolve(m);
          return;
        }
      }
      c.pending.push(m);
    });
    c.ws.on('close', (code) => { c.closeCode = code; c._onClosed(); });
    await new Promise((res, rej) => { c.ws.once('open', res); c.ws.once('error', rej); });
    await c.waitFor((m) => m.type === 'welcome');
    return c;
  }
  send(obj) { this.ws.send(JSON.stringify(obj)); }
  waitFor(pred, timeout = 3000) {
    const idx = this.pending.findIndex(pred);
    if (idx >= 0) return Promise.resolve(this.pending.splice(idx, 1)[0]);
    return new Promise((resolve, reject) => {
      const w = { pred, resolve };
      w.timer = setTimeout(() => reject(new Error('waitFor timeout')), timeout);
      this.waiters.push(w);
    });
  }
  close() { this.ws.close(); return this.closed; }
}

async function createRoom(client, name) {
  client.send({ type: 'create_room', name });
  const joined = await client.waitFor((m) => m.type === 'joined' && m.name === name);
  return joined.roomId;
}
async function joinRoom(client, room) {
  client.send({ type: 'join', room, lastSeq: 0 });
  return client.waitFor((m) => m.type === 'joined' && m.roomId === room);
}

// --------------------------------------------------------------- HTTP 辅助

async function http(port, p, { method = 'GET', token, body, raw, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.authorization = `Bearer ${token}`;
  const res = await fetch(`http://127.0.0.1:${port}${p}`, {
    method, headers: h,
    body: raw !== undefined ? raw : (body !== undefined ? JSON.stringify(body) : undefined),
  });
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json().catch(() => null) : Buffer.from(await res.arrayBuffer());
  return { status: res.status, data, headers: res.headers };
}

const PNG = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
  0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x06, 0x00, 0x00, 0x00, 0x1c, 0x4c, 0x79, 0xd4,
]);

/** 完整上传：建任务→逐片 PUT→complete；返回 complete 响应 */
async function uploadAll(port, token, { fileName, kind, data, chunkSize, sha = sha256(data), extra = {} }) {
  const cs = chunkSize || 65536;
  const created = await http(port, '/api/uploads', {
    method: 'POST', token,
    body: { filename: fileName, size: data.length, sha256: sha, kind, chunkSize: cs, ...extra },
  });
  assert.equal(created.status, 200, JSON.stringify(created.data));
  if (created.data.instant) return created.data;
  const taskId = created.data.taskId;
  const n = Math.ceil(data.length / cs);
  for (let i = 0; i < n; i++) {
    const slice = data.subarray(i * cs, Math.min((i + 1) * cs, data.length));
    const r = await http(port, `/api/uploads/${taskId}/chunks/${i}`, {
      method: 'PUT', token, raw: slice,
      headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Sha256': sha256(slice) },
    });
    assert.equal(r.status, 200, `chunk ${i}: ${JSON.stringify(r.data)}`);
  }
  const done = await http(port, `/api/uploads/${taskId}/complete`, {
    method: 'POST', token, body: { sha256: sha },
  });
  assert.equal(done.status, 200, JSON.stringify(done.data));
  return done.data;
}

async function ticketFor(client, roomId, assetId) {
  client.send({ type: 'asset_ticket', roomId, assetId });
  const m = await client.waitFor((x) => x.type === 'asset_ticket' && x.assetId === assetId);
  return m.ticket;
}

async function setupTwoUsers(overrides) {
  const env = await startServer(overrides);
  const a = await login(env.port, 'alice');
  const b = await login(env.port, 'bob');
  const ca = await Client.connect(env.port, a.token);
  const cb = await Client.connect(env.port, b.token);
  const roomId = await createRoom(ca, 'general');
  await joinRoom(cb, roomId);
  return { ...env, a, b, ca, cb, roomId };
}

// --------------------------------------------------------------- 用例

test('富媒体全链路：分片上传→两阶段图片消息（帧内仅元数据）→ticket→下载字节一致', async () => {
  const t = await setupTwoUsers();
  try {
    const up = await uploadAll(t.port, t.a.token, { fileName: 'a.png', kind: 'image', data: PNG });
    assert.equal(up.mime, 'image/png');
    assert.deepEqual(up.meta, { width: 1, height: 1, durationMs: null });

    const cid = crypto.randomUUID();
    t.ca.send({ type: 'msg', roomId: t.roomId, clientMsgId: cid,
      kind: 'image', assetId: up.assetId, content: '看图' });
    const ack = await t.ca.waitFor((m) => m.type === 'ack' && m.clientMsgId === cid);
    assert.ok(ack.seq > 0);

    // 广播到 bob：只有元数据，没有任何文件字节
    const msg = await t.cb.waitFor((m) => m.type === 'msg' && m.clientMsgId === cid);
    assert.equal(msg.kind, 'image');
    assert.equal(msg.asset.id, up.assetId);
    assert.equal(msg.asset.size, PNG.length);
    assert.equal(JSON.stringify(msg).length < 65536, true);
    assert.equal(msg.content, '看图');

    // bob 凭权限取票并下载
    const ticket = await ticketFor(t.cb, t.roomId, up.assetId);
    const dl = await http(t.port, `/api/assets/${up.assetId}?ticket=${encodeURIComponent(ticket)}`);
    assert.equal(dl.status, 200);
    assert.equal(dl.headers.get('x-content-type-options'), 'nosniff');
    assert.deepEqual(dl.data, PNG);
  } finally { await t.ca.close(); await t.cb.close(); await t.server.stop(); }
});

test('Range 下载：206 + Content-Range，多段拼接等于原文件', async () => {
  const t = await setupTwoUsers();
  try {
    const data = Buffer.alloc(150_000, 0x5a); // file 类型任意字节
    const up = await uploadAll(t.port, t.a.token, { fileName: 'big.bin', kind: 'file', data });
    const cid = crypto.randomUUID();
    t.ca.send({ type: 'msg', roomId: t.roomId, clientMsgId: cid, kind: 'file', assetId: up.assetId });
    await t.cb.waitFor((m) => m.type === 'msg' && m.clientMsgId === cid);
    const ticket = await ticketFor(t.cb, t.roomId, up.assetId);

    const r1 = await fetch(`http://127.0.0.1:${t.port}/api/assets/${up.assetId}?ticket=${ticket}`,
      { headers: { Range: 'bytes=0-99' } });
    assert.equal(r1.status, 206);
    assert.equal(r1.headers.get('content-range'), `bytes 0-99/${data.length}`);
    const p1 = Buffer.from(await r1.arrayBuffer());
    assert.equal(p1.length, 100);

    const r2 = await fetch(`http://127.0.0.1:${t.port}/api/assets/${up.assetId}?ticket=${ticket}`,
      { headers: { Range: 'bytes=100-' } });
    assert.equal(r2.status, 206);
    const p2 = Buffer.from(await r2.arrayBuffer());
    assert.equal(Buffer.concat([p1, p2]).length, data.length);
    assert.deepEqual(Buffer.concat([p1, p2]), data);

    // 非法 Range → 416
    const r3 = await fetch(`http://127.0.0.1:${t.port}/api/assets/${up.assetId}?ticket=${ticket}`,
      { headers: { Range: 'bytes=999999-' } });
    assert.equal(r3.status, 416);
  } finally { await t.ca.close(); await t.cb.close(); await t.server.stop(); }
});

test('断点续传：中断后 GET 任务状态，仅补缺失片即可 complete', async () => {
  const env = await startServer();
  try {
    const u = await login(env.port, 'u');
    const data = Buffer.alloc(150_000, 7);
    const cs = 65536;
    const created = await http(env.port, '/api/uploads', {
      method: 'POST', token: u.token,
      body: { filename: 'x.bin', kind: 'file', size: data.length, sha256: sha256(data), chunkSize: cs },
    });
    const taskId = created.data.taskId;
    // 只传第 0、2 片（跳过第 1 片）
    for (const i of [0, 2]) {
      const slice = data.subarray(i * cs, Math.min((i + 1) * cs, data.length));
      const r = await http(env.port, `/api/uploads/${taskId}/chunks/${i}`, {
        method: 'PUT', token: u.token, raw: slice,
        headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Sha256': sha256(slice) },
      });
      assert.equal(r.status, 200);
    }
    // complete 报缺片
    const inc = await http(env.port, `/api/uploads/${taskId}/complete`, {
      method: 'POST', token: u.token, body: { sha256: sha256(data) },
    });
    assert.equal(inc.status, 409);
    assert.equal(inc.data.error, 'NOT_ALL_CHUNKS');
    assert.deepEqual(inc.data.missing, [1]);
    // 查询状态，只补第 1 片
    const st = await http(env.port, `/api/uploads/${taskId}`, { token: u.token });
    assert.deepEqual(st.data.receivedChunks.map((c) => c.idx).sort(), [0, 2]);
    const slice = data.subarray(cs, 2 * cs);
    await http(env.port, `/api/uploads/${taskId}/chunks/1`, {
      method: 'PUT', token: u.token, raw: slice,
      headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Sha256': sha256(slice) },
    });
    const done = await http(env.port, `/api/uploads/${taskId}/complete`, {
      method: 'POST', token: u.token, body: { sha256: sha256(data) },
    });
    assert.equal(done.status, 200);
    assert.equal(done.data.size, data.length);
  } finally { await env.server.stop(); }
});

test('分片 hash 不符 → 422 且可重传纠正；同片幂等重传 200', async () => {
  const env = await startServer();
  try {
    const u = await login(env.port, 'u');
    const data = Buffer.alloc(100, 1);
    const created = await http(env.port, '/api/uploads', {
      method: 'POST', token: u.token,
      body: { filename: 'x.bin', kind: 'file', size: data.length, sha256: sha256(data), chunkSize: 65536 },
    });
    const taskId = created.data.taskId;
    const bad = await http(env.port, `/api/uploads/${taskId}/chunks/0`, {
      method: 'PUT', token: u.token, raw: data,
      headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Sha256': 'a'.repeat(64) },
    });
    assert.equal(bad.status, 422);
    assert.equal(bad.data.error, 'CHUNK_HASH_MISMATCH');
    // 正确 hash 重传
    const ok = await http(env.port, `/api/uploads/${taskId}/chunks/0`, {
      method: 'PUT', token: u.token, raw: data,
      headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Sha256': sha256(data) },
    });
    assert.equal(ok.status, 200);
    // 再传一次同样片 → 幂等
    const again = await http(env.port, `/api/uploads/${taskId}/chunks/0`, {
      method: 'PUT', token: u.token, raw: data,
      headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Sha256': sha256(data) },
    });
    assert.equal(again.status, 200);
    assert.equal(again.data.reused, true);
  } finally { await env.server.stop(); }
});

test('秒传：同用户同 sha 命中；他人 sha 不命中；两用户同内容物理 blob 仅一份', async () => {
  const env = await startServer();
  try {
    const a = await login(env.port, 'alice2');
    const b = await login(env.port, 'bob2');
    const data = Buffer.alloc(1200, 0x42);
    const up1 = await uploadAll(env.port, a.token, { fileName: 'same.bin', kind: 'file', data });

    const second = await http(env.port, '/api/uploads', {
      method: 'POST', token: a.token,
      body: { filename: 'copy.bin', kind: 'file', size: data.length, sha256: sha256(data), chunkSize: 65536 },
    });
    assert.equal(second.data.instant, true);
    assert.equal(second.data.assetId, up1.assetId);

    // bob 同样的 sha 不能秒传
    const other = await http(env.port, '/api/uploads', {
      method: 'POST', token: b.token,
      body: { filename: 'same.bin', kind: 'file', size: data.length, sha256: sha256(data), chunkSize: 65536 },
    });
    assert.equal(other.data.instant, false);
    const up2 = await uploadAll(env.port, b.token, { fileName: 'same.bin', kind: 'file', data });
    assert.notEqual(up1.assetId, up2.assetId);

    // blob 目录下同 sha 物理文件只有一份
    const blobPath = env.server.storage.blobPath(sha256(data));
    assert.ok(fs.existsSync(blobPath));
  } finally { await env.server.stop(); }
});

test('病毒/违规：EICAR 隔离 422、伪装图片 MAGIC_MISMATCH、危险扩展名', async () => {
  const env = await startServer();
  try {
    const u = await login(env.port, 'sec');

    const eicar = Buffer.concat([Buffer.alloc(10, 0x61),
      Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}'), Buffer.from('STANDARD')]);
    const r1 = await uploadAll0(env.port, u.token, 'v.txt', 'file', eicar);
    assert.equal(r1.done.status, 422);
    assert.equal(r1.done.data.error, 'INFECTED');
    // 隔离区有文件
    const q = await fsp.readdir(path.join(env.storageRoot, 'quarantine'));
    assert.equal(q.length, 1);
    // 任务状态 quarantined
    const st = await http(env.port, `/api/uploads/${r1.taskId}`, { token: u.token });
    assert.equal(st.data.status, 'quarantined');

    const r2 = await uploadAll0(env.port, u.token, 'fake.png', 'image', Buffer.from('not image'));
    assert.equal(r2.done.status, 422);
    assert.equal(r2.done.data.error, 'MAGIC_MISMATCH');

    const r3 = await uploadAll0(env.port, u.token, 'evil.exe', 'file', Buffer.from('MZxxxx'));
    assert.equal(r3.done.status, 422);
    assert.equal(r3.done.data.error, 'DANGEROUS_EXTENSION');
  } finally { await env.server.stop(); }
});

// 上传到 complete 为止（不断言成功），返回 {taskId, done}
async function uploadAll0(port, token, fileName, kind, data) {
  const cs = 65536;
  const created = await http(port, '/api/uploads', {
    method: 'POST', token,
    body: { filename: fileName, size: data.length, sha256: sha256(data), kind, chunkSize: cs },
  });
  const taskId = created.data.taskId;
  for (let i = 0; i < Math.ceil(data.length / cs); i++) {
    const slice = data.subarray(i * cs, Math.min((i + 1) * cs, data.length));
    await http(port, `/api/uploads/${taskId}/chunks/${i}`, {
      method: 'PUT', token, raw: slice,
      headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Sha256': sha256(slice) },
    });
  }
  const done = await http(port, `/api/uploads/${taskId}/complete`, {
    method: 'POST', token, body: { sha256: sha256(data) },
  });
  return { taskId, done };
}

test('clamd 不可用 fail-closed：complete 503 且任务保持 open 可重试', async () => {
  const env = await startServer({
    scannerMode: 'clamd', scannerFailPolicy: 'closed',
    clamdHost: '127.0.0.1', clamdPort: 1, clamdTimeoutMs: 500,
  });
  try {
    const u = await login(env.port, 'c');
    const r = await uploadAll0(env.port, u.token, 'a.png', 'image', PNG);
    assert.equal(r.done.status, 503);
    assert.equal(r.done.data.error, 'SCAN_UNAVAILABLE');
    const st = await http(env.port, `/api/uploads/${r.taskId}`, { token: u.token });
    assert.equal(st.data.status, 'open'); // 可再点 complete
  } finally { await env.server.stop(); }
});

test('引用 reply：正常引用带摘要；引用不存在 seq → BAD_REPLY；被引撤回后 replyTo.recalled', async () => {
  const t = await setupTwoUsers();
  try {
    const cid1 = crypto.randomUUID();
    t.ca.send({ type: 'msg', roomId: t.roomId, clientMsgId: cid1, content: '第一条' });
    const m1 = await t.cb.waitFor((m) => m.type === 'msg' && m.clientMsgId === cid1);

    const cid2 = crypto.randomUUID();
    t.ca.send({ type: 'msg', roomId: t.roomId, clientMsgId: cid2,
      content: '第二条', replyToSeq: m1.seq });
    const m2 = await t.cb.waitFor((m) => m.type === 'msg' && m.clientMsgId === cid2);
    assert.equal(m2.replyTo.seq, m1.seq);
    assert.equal(m2.replyTo.snippet, '第一条');
    assert.equal(m2.replyTo.recalled, false);

    const bad = crypto.randomUUID();
    t.ca.send({ type: 'msg', roomId: t.roomId, clientMsgId: bad,
      content: 'x', replyToSeq: 9999 });
    const err = await t.ca.waitFor((m) => m.type === 'error' && m.code === 'BAD_REPLY');
    assert.ok(err);

    // 撤回第一条 → 引用它的消息在历史中 replyTo.recalled=true
    t.ca.send({ type: 'recall', roomId: t.roomId, seq: m1.seq });
    await t.cb.waitFor((m) => m.type === 'recalled' && m.seq === m1.seq);
    t.cb.send({ type: 'history', roomId: t.roomId, beforeSeq: m2.seq + 1, limit: 10 });
    const hist = await t.cb.waitFor((m) => m.type === 'history');
    const reply = hist.messages.find((m) => m.seq === m2.seq);
    assert.equal(reply.replyTo.recalled, true);
    const recalled = hist.messages.find((m) => m.seq === m1.seq);
    assert.ok(recalled.recalledAt > 0);
  } finally { await t.ca.close(); await t.cb.close(); await t.server.stop(); }
});

test('撤回：普通成员超时拒绝；admin 可撤回他人；最后引用撤回后 blob 删除 410', async () => {
  const t = await setupTwoUsers({ recallWindowMs: 50, completedBlobGraceMs: 0 });
  try {
    // bob（普通成员）发消息，超过撤回窗后自己撤回 → RECALL_TOO_LATE
    const data = Buffer.alloc(500, 9);
    const up = await uploadAll(t.port, t.b.token, { fileName: 'f.bin', kind: 'file', data });
    const cid = crypto.randomUUID();
    t.cb.send({ type: 'msg', roomId: t.roomId, clientMsgId: cid, kind: 'file', assetId: up.assetId });
    const m = await t.ca.waitFor((x) => x.type === 'msg' && x.clientMsgId === cid);
    await sleep(80);
    t.cb.send({ type: 'recall', roomId: t.roomId, seq: m.seq });
    const late = await t.cb.waitFor((x) => x.type === 'error' && x.code === 'RECALL_TOO_LATE');
    assert.ok(late);

    // bob 再发一条，alice（admin）可不受时间窗限制撤回他人消息
    const upB = await uploadAll(t.port, t.b.token, { fileName: 'g.bin', kind: 'file', data: Buffer.alloc(300, 3) });
    const cidB = crypto.randomUUID();
    t.cb.send({ type: 'msg', roomId: t.roomId, clientMsgId: cidB, kind: 'file', assetId: upB.assetId });
    const mb = await t.ca.waitFor((x) => x.type === 'msg' && x.clientMsgId === cidB);
    t.ca.send({ type: 'recall', roomId: t.roomId, seq: mb.seq });
    await t.cb.waitFor((x) => x.type === 'recalled' && x.seq === mb.seq);
    // blob 被 GC，asset 置 deleted，再取票被拒
    const shaB = t.server.db.getAsset(upB.assetId).sha256;
    for (let i = 0; i < 25; i++) {
      if (!t.server.storage.hasBlob(shaB)) break;
      await sleep(20);
    }
    assert.equal(t.server.storage.hasBlob(shaB), false);
    t.cb.send({ type: 'asset_ticket', roomId: t.roomId, assetId: upB.assetId });
    const deny = await t.cb.waitFor((x) => x.type === 'error' && x.code === 'ASSET_DELETED');
    assert.ok(deny);
    // 第一条未撤回消息的 blob 仍在
    assert.equal(t.server.storage.hasBlob(t.server.db.getAsset(up.assetId).sha256), true);
  } finally { await t.ca.close(); await t.cb.close(); await t.server.stop(); }
});

test('ASSET_SCOPE：跨房间引用他人上传的 assetId 被拒；同房已有未撤回引用可复用', async () => {
  const t = await setupTwoUsers();
  try {
    const up = await uploadAll(t.port, t.a.token, { fileName: 'a.png', kind: 'image', data: PNG });
    // room1：alice 正常发送，同房 bob 随后引用同一 asset 应允许（附件在本房已可见）
    const cidA = crypto.randomUUID();
    t.ca.send({ type: 'msg', roomId: t.roomId, clientMsgId: cidA, kind: 'image', assetId: up.assetId });
    await t.cb.waitFor((m) => m.type === 'msg' && m.clientMsgId === cidA);
    const cidReuse = crypto.randomUUID();
    t.cb.send({ type: 'msg', roomId: t.roomId, clientMsgId: cidReuse, kind: 'image', assetId: up.assetId });
    assert.ok(await t.ca.waitFor((m) => m.type === 'msg' && m.clientMsgId === cidReuse));

    // room2：bob 加入另一个房间，引用 alice 仅在 room1 出现过的 asset → ASSET_SCOPE
    t.ca.send({ type: 'create_room', name: 'secret' });
    const j2 = await t.ca.waitFor((m) => m.type === 'joined' && m.name === 'secret');
    await joinRoom(t.cb, j2.roomId);
    const cidBad = crypto.randomUUID();
    t.cb.send({ type: 'msg', roomId: j2.roomId, clientMsgId: cidBad, kind: 'image', assetId: up.assetId });
    const err = await t.cb.waitFor((m) => m.type === 'error' && m.code === 'ASSET_SCOPE');
    assert.ok(err);
  } finally { await t.ca.close(); await t.cb.close(); await t.server.stop(); }
});

test('持久退群：sync/history/ticket/下载全拒；rejoin 恢复；detach 不退群', async () => {
  const t = await setupTwoUsers();
  try {
    const up = await uploadAll(t.port, t.a.token, { fileName: 'a.png', kind: 'image', data: PNG });
    const cid = crypto.randomUUID();
    t.ca.send({ type: 'msg', roomId: t.roomId, clientMsgId: cid, kind: 'image', assetId: up.assetId });
    await t.cb.waitFor((m) => m.type === 'msg' && m.clientMsgId === cid);
    const ticket = await ticketFor(t.cb, t.roomId, up.assetId);

    // bob 持久退群
    t.cb.send({ type: 'leave', roomId: t.roomId, mode: 'leave' });
    const left = await t.cb.waitFor((m) => m.type === 'left' && m.persisted === true);
    assert.ok(left);

    t.cb.send({ type: 'sync', roomId: t.roomId, lastSeq: 0 });
    assert.ok(await t.cb.waitFor((m) => m.type === 'error' && m.code === 'MEMBERSHIP_INACTIVE'));
    t.cb.send({ type: 'history', roomId: t.roomId, limit: 5 });
    assert.ok(await t.cb.waitFor((m) => m.type === 'error' && m.code === 'MEMBERSHIP_INACTIVE'));
    t.cb.send({ type: 'asset_ticket', roomId: t.roomId, assetId: up.assetId });
    assert.ok(await t.cb.waitFor((m) => m.type === 'error' && m.code === 'MEMBERSHIP_INACTIVE'));

    // 旧票也因 active=0 被下载端拒绝
    const dl = await http(t.port, `/api/assets/${up.assetId}?ticket=${encodeURIComponent(ticket)}`);
    assert.equal(dl.status, 403);

    // 重新加入恢复，全部历史可见
    await joinRoom(t.cb, t.roomId);
    const ticket2 = await ticketFor(t.cb, t.roomId, up.assetId);
    const dl2 = await http(t.port, `/api/assets/${up.assetId}?ticket=${encodeURIComponent(ticket2)}`);
    assert.equal(dl2.status, 200);
  } finally { await t.ca.close(); await t.cb.close(); await t.server.stop(); }
});

test('票安全：过期票/伪造签名 403；无鉴权头 401；超限 413；并发任务 429', async () => {
  const t = await setupTwoUsers();
  try {
    const up = await uploadAll(t.port, t.a.token, { fileName: 'a.png', kind: 'image', data: PNG });
    const cid = crypto.randomUUID();
    t.ca.send({ type: 'msg', roomId: t.roomId, clientMsgId: cid, kind: 'image', assetId: up.assetId });
    await t.cb.waitFor((m) => m.type === 'msg' && m.clientMsgId === cid);

    const expired = signAssetTicket(t.b.userId, up.assetId, Date.now() - 1000, t.server.config.authSecret);
    assert.equal((await http(t.port, `/api/assets/${up.assetId}?ticket=${expired}`)).status, 403);
    const forged = (await ticketFor(t.cb, t.roomId, up.assetId)).slice(0, -2) + 'aa';
    assert.equal((await http(t.port, `/api/assets/${up.assetId}?ticket=${encodeURIComponent(forged)}`)).status, 403);
    assert.equal((await http(t.port, '/api/uploads', { method: 'POST', body: {} })).status, 401);

    // 超限：图片声明 >10MiB
    const tooBig = await http(t.port, '/api/uploads', {
      method: 'POST', token: t.a.token,
      body: { filename: 'x.png', kind: 'image', size: 20_000_000 },
    });
    assert.equal(tooBig.status, 413);

    // 并发任务上限（maxConcurrentUploads 默认 4）
    const env2 = await startServer({ maxConcurrentUploads: 1 });
    try {
      const u = await login(env2.port, 'lonely');
      const mk = () => http(env2.port, '/api/uploads', {
        method: 'POST', token: u.token,
        body: { filename: 'x', kind: 'file', size: 10 },
      });
      assert.equal((await mk()).status, 200);
      assert.equal((await mk()).status, 429);
    } finally { await env2.server.stop(); }
  } finally { await t.ca.close(); await t.cb.close(); await t.server.stop(); }
});

test('reaper：过期 open 任务、孤儿 asset、隔离文件被清；有消息引用的 asset 保留', async () => {
  const env = await startServer({
    uploadTaskTtlMs: 30, orphanAssetTtlMs: 30, quarantineTtlMs: 30, completedBlobGraceMs: 0,
  });
  try {
    const u = await login(env.port, 'reaper');
    // 1) 未完成任务
    const open = await http(env.port, '/api/uploads', {
      method: 'POST', token: u.token,
      body: { filename: 'o', kind: 'file', size: 10, chunkSize: 65536 },
    });
    assert.equal(open.status, 200);
    // 2) 孤儿 asset（complete 但不发消息）
    const orphanData = Buffer.alloc(50, 4);
    const orphan = await uploadAll(env.port, u.token, { fileName: 'o.bin', kind: 'file', data: orphanData });
    // 3) 隔离文件（回拨 mtime 模拟已过隔离 TTL）
    const eicar = Buffer.from('xxX5O!P%@AP[4\\PZX54(P^)7CC)7}yy');
    await uploadAll0(env.port, u.token, 'v.txt', 'file', eicar);
    const qdir = path.join(env.storageRoot, 'quarantine');
    for (const f of await fsp.readdir(qdir)) {
      fs.utimesSync(path.join(qdir, f), 0, 0);
    }

    await sleep(80);
    const r = await env.server.uploads.runReap();
    assert.ok(r.expiredTasks >= 1);
    assert.ok(r.orphanBlobs >= 1);
    assert.ok(r.quarantine >= 1);
    assert.equal(env.server.storage.hasBlob(sha256(orphanData)), false);
    // 过期任务 tmp 目录已删
    const tmp = await fsp.readdir(path.join(env.storageRoot, 'tmp'));
    assert.equal(tmp.includes(open.data.taskId), false);
  } finally { await env.server.stop(); }
});

test('WS 大帧 1009：富媒体字节进不了 WebSocket，同房其他连接不受影响', async () => {
  const t = await setupTwoUsers({ wsMaxPayload: 65536 });
  try {
    const big = 'x'.repeat(200_000);
    const code = await new Promise((resolve) => {
      t.ca.ws.once('close', (c) => resolve(c));
      t.ca.ws.send(big);
    });
    assert.equal(code, 1009);
    // bob 的连接仍能正常收发
    const cid = crypto.randomUUID();
    t.cb.send({ type: 'ping', t: 1 });
    assert.ok(await t.cb.waitFor((m) => m.type === 'pong'));
  } finally { await t.cb.close(); await t.server.stop(); }
});
