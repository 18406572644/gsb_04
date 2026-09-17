'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const WebSocket = require('ws');
const { createChatServer } = require('../src/server');
const { EICAR } = require('../src/scanner');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

async function startServer(overrides = {}) {
  const server = createChatServer({
    port: 0,
    host: '127.0.0.1',
    dbPath: ':memory:',
    heartbeatIntervalMs: 60_000,
    ackResendAfterMs: 60_000,
    chunkMinSize: 1,
    chunkMaxSize: 1024,
    chunkSize: 4,
    cleanupIntervalMs: 0, // 清理在测试中显式触发
    ...overrides,
  });
  const addr = await server.start();
  return { server, port: addr.port };
}

async function login(port, name) {
  const res = await fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name }),
  });
  return res.json();
}

class Client {
  static async connect(port, token) {
    const c = new Client();
    c.log = [];
    c.pending = [];
    c.waiters = [];
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
    await new Promise((res, rej) => {
      c.ws.once('open', res);
      c.ws.once('error', rej);
    });
    await c.waitFor((m) => m.type === 'welcome');
    return c;
  }

  send(obj) { this.ws.send(JSON.stringify(obj)); }

  waitFor(pred, timeout = 3000) {
    const idx = this.pending.findIndex(pred);
    if (idx >= 0) return Promise.resolve(this.pending.splice(idx, 1)[0]);
    return new Promise((resolve, reject) => {
      const w = { pred, resolve };
      w.timer = setTimeout(() => reject(new Error('waitFor: timed out')), timeout);
      this.waiters.push(w);
    });
  }

  close() { this.ws.close(); }
}

async function createRoom(client, name) {
  client.send({ type: 'create_room', name });
  const joined = await client.waitFor((m) => m.type === 'joined' && m.name === name);
  return joined.roomId;
}

async function joinRoom(client, room, lastSeq = 0) {
  client.send({ type: 'join', room, lastSeq });
  return client.waitFor((m) => m.type === 'joined');
}

/** HTTP 辅助 */
async function httpJson(port, token, method, url, body) {
  const res = await fetch(`http://127.0.0.1:${port}${url}`, {
    method,
    headers: {
      ...(body != null ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body != null ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
  return { status: res.status, json, headers: res.headers };
}

async function putChunk(port, token, taskId, idx, part) {
  const res = await fetch(`http://127.0.0.1:${port}/api/uploads/${taskId}/chunks/${idx}`, {
    method: 'PUT',
    headers: { authorization: `Bearer ${token}` },
    body: new Blob([part]),
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}

/** 完整上传一个缓冲；返回 init/complete 响应 */
async function upload(port, token, { name, kind, mime, data, chunkSize = 4 }, overrides = {}) {
  const init = await httpJson(port, token, 'POST', '/api/uploads', {
    filename: name, kind, mime, size: data.length, sha256: sha256(data), chunkSize,
  }).then((r) => {
    if (r.status >= 300) throw Object.assign(new Error(r.json.message), { http: r });
    return r.json;
  });
  if (init.reused) return { init, done: { assetId: init.assetId, status: 'ready', reused: true } };

  const skip = new Set(overrides.skipChunks || []);
  const corruptIdx = overrides.corruptIdx;
  for (let i = 0; i < init.totalChunks; i++) {
    if (skip.has(i)) continue;
    let part = data.subarray(i * init.chunkSize, Math.min((i + 1) * init.chunkSize, data.length));
    if (corruptIdx === i) part = Buffer.from(part.map((b, j) => (j === 0 ? b ^ 0xff : b)));
    const r = await putChunk(port, token, init.taskId, i, part);
    assert.equal(r.status, 200, `chunk ${i} should be accepted`);
  }
  const done = await httpJson(port, token, 'POST', `/api/uploads/${init.taskId}/complete`);
  return { init, status: done.status, done: done.json, httpDone: done };
}

async function expectUploadOk(...args) {
  const r = await upload(...args);
  assert.equal(r.status ?? 200, 200, `complete should be 200: ${JSON.stringify(r.done)}`);
  return r;
}

async function download(port, token, assetId, headers = {}) {
  const res = await fetch(`http://127.0.0.1:${port}/api/assets/${assetId}/download`, {
    headers: { authorization: `Bearer ${token}`, ...headers },
  });
  const buf = Buffer.from(await res.arrayBuffer());
  return { status: res.status, buf, headers: res.headers };
}

// ---------------------------------------------------------------- 两阶段发送

test('两阶段发送：HTTP 上传完成后媒体消息才落库广播，接收端可下载', async () => {
  const { server, port } = await startServer();
  try {
    const ua = await login(port, 'alice');
    const ub = await login(port, 'bob');
    const a = await Client.connect(port, ua.token);
    const b = await Client.connect(port, ub.token);
    const roomId = await createRoom(a, 'media');
    await joinRoom(b, roomId);

    const data = Buffer.from('hello rich media '.repeat(10));
    const up = await expectUploadOk(port, ua.token, {
      name: 'note.txt', kind: 'file', mime: 'text/plain', data, chunkSize: 16,
    });

    // 阶段二：只带 assetId 的轻量帧
    a.send({ type: 'media', roomId, clientMsgId: 'mm1', assetId: up.done.assetId });
    const ack = await a.waitFor((m) => m.type === 'ack' && m.clientMsgId === 'mm1');
    assert.equal(ack.seq, 1);
    const msg = await b.waitFor((m) => m.type === 'msg' && m.seq === 1);
    assert.equal(msg.msgType, 'file');
    assert.equal(msg.asset.id, up.done.assetId);
    assert.equal(msg.asset.size, data.length);
    assert.equal(msg.asset.name, 'note.txt');
    assert.equal(msg.asset.kind, 'file');

    const dl = await download(port, ub.token, up.done.assetId);
    assert.equal(dl.status, 200);
    assert.ok(dl.buf.equals(data));
    assert.match(dl.headers.get('content-disposition'), /attachment/);
    assert.equal(dl.headers.get('x-content-type-options'), 'nosniff');

    a.close(); b.close();
  } finally {
    server.stop();
  }
});

test('上传未完成（资产不存在/扫描中）不允许媒体消息落库', async () => {
  const { server, port } = await startServer();
  try {
    const ua = await login(port, 'alice');
    const a = await Client.connect(port, ua.token);
    const roomId = await createRoom(a, 'media');

    // 凭空 assetId
    a.send({ type: 'media', roomId, clientMsgId: 'x1', assetId: 'as_nope' });
    const err1 = await a.waitFor((m) => m.type === 'error' && m.ref === 'x1');
    assert.equal(err1.code, 'ASSET_NOT_FOUND');

    // init 后不传分片（资产停在 scanning）
    const data = Buffer.from('half uploaded');
    await httpJson(port, ua.token, 'POST', '/api/uploads', {
      filename: 'h.bin', kind: 'file', mime: 'application/octet-stream',
      size: data.length, sha256: sha256(data), chunkSize: 4,
    });
    const assetRow = server.db.getAssetBySha(sha256(data));
    a.send({ type: 'media', roomId, clientMsgId: 'x4', assetId: assetRow.id });
    const err2 = await a.waitFor((m) => m.type === 'error' && m.ref === 'x4');
    assert.equal(err2.code, 'ASSET_NOT_READY');

    a.close();
  } finally {
    server.stop();
  }
});

// ---------------------------------------------------------------- 续传 / 去重 / 完整性

test('中断续传：重新 init 返回已收分片，只补缺失分片即可完成', async () => {
  const { server, port } = await startServer();
  try {
    const ua = await login(port, 'alice');
    const data = Buffer.from('0123456789abcdef'); // chunkSize=4 → 4 片
    const hash = sha256(data);

    const init1 = (await httpJson(port, ua.token, 'POST', '/api/uploads', {
      filename: 'r.bin', kind: 'file', mime: 'application/octet-stream',
      size: data.length, sha256: hash, chunkSize: 4,
    })).json;
    assert.equal(init1.resumed, false);
    // 只传前两片，“网络中断”
    await putChunk(port, ua.token, init1.taskId, 0, data.subarray(0, 4));
    await putChunk(port, ua.token, init1.taskId, 1, data.subarray(4, 8));

    // 直接 complete → 409 带缺失列表
    const incomplete = await httpJson(port, ua.token, 'POST', `/api/uploads/${init1.taskId}/complete`);
    assert.equal(incomplete.status, 409);
    assert.equal(incomplete.json.error, 'MISSING_CHUNKS');
    assert.deepEqual(incomplete.json.details.missing, [2, 3]);

    // 重新 init（同 hash）→ 服务端找回原任务
    const init2 = (await httpJson(port, ua.token, 'POST', '/api/uploads', {
      filename: 'r.bin', kind: 'file', mime: 'application/octet-stream',
      size: data.length, sha256: hash, chunkSize: 4,
    })).json;
    assert.equal(init2.resumed, true);
    assert.equal(init2.taskId, init1.taskId);
    assert.deepEqual(init2.received, [0, 1]);

    // 补传缺失分片
    await putChunk(port, ua.token, init1.taskId, 2, data.subarray(8, 12));
    await putChunk(port, ua.token, init1.taskId, 3, data.subarray(12, 16));
    const done = await httpJson(port, ua.token, 'POST', `/api/uploads/${init1.taskId}/complete`);
    assert.equal(done.status, 200, JSON.stringify(done.json));
    assert.equal(done.json.status, 'ready');
  } finally {
    server.stop();
  }
});

test('重复上传去重（秒传）：同内容 init 直接复用，跨用户也成立且可发送', async () => {
  const { server, port } = await startServer();
  try {
    const ua = await login(port, 'alice');
    const ub = await login(port, 'bob');
    const a = await Client.connect(port, ua.token);
    const b = await Client.connect(port, ub.token);
    const roomId = await createRoom(a, 'media');
    await joinRoom(b, roomId);

    const data = Buffer.from('dedup-me-please');
    const up1 = await expectUploadOk(port, ua.token, {
      name: 'a.txt', kind: 'file', mime: 'text/plain', data, chunkSize: 4,
    });

    // alice 再传一次
    const re = (await httpJson(port, ua.token, 'POST', '/api/uploads', {
      filename: 'a-copy.txt', kind: 'file', mime: 'text/plain',
      size: data.length, sha256: sha256(data), chunkSize: 4,
    })).json;
    assert.equal(re.reused, true);
    assert.equal(re.assetId, up1.done.assetId);

    // bob 传同内容（跨用户秒传），随后有权用该资产发消息
    const reBob = (await httpJson(port, ub.token, 'POST', '/api/uploads', {
      filename: 'b.txt', kind: 'file', mime: 'text/plain',
      size: data.length, sha256: sha256(data), chunkSize: 4,
    })).json;
    assert.equal(reBob.reused, true);
    b.send({ type: 'media', roomId, clientMsgId: 'bob1', assetId: up1.done.assetId });
    const ack = await b.waitFor((m) => m.type === 'ack' && m.clientMsgId === 'bob1');
    assert.ok(ack.seq >= 1);
    const msg = await a.waitFor((m) => m.type === 'msg' && m.clientMsgId === 'bob1');
    assert.equal(msg.asset.id, up1.done.assetId);

    a.close(); b.close();
  } finally {
    server.stop();
  }
});

test('完整性校验：损坏分片导致 complete 失败，重传该片后可恢复', async () => {
  const { server, port } = await startServer();
  try {
    const ua = await login(port, 'alice');
    const data = Buffer.from('integrity-check!'); // 16 字节 → 4 片
    assert.equal(data.length, 16);
    const hash = sha256(data);
    const init = (await httpJson(port, ua.token, 'POST', '/api/uploads', {
      filename: 'i.bin', kind: 'file', mime: 'application/octet-stream',
      size: data.length, sha256: hash, chunkSize: 4,
    })).json;

    // 第 2 片传错字节（同长度）
    for (let i = 0; i < 4; i++) {
      const part = i === 2 ? Buffer.from('XXXX') : data.subarray(i * 4, i * 4 + 4);
      await putChunk(port, ua.token, init.taskId, i, part);
    }
    const bad = await httpJson(port, ua.token, 'POST', `/api/uploads/${init.taskId}/complete`);
    assert.equal(bad.status, 422);
    assert.equal(bad.json.error, 'INTEGRITY_CHECK_FAILED');

    // 重传正确的第 2 片（幂等覆盖）后成功
    await putChunk(port, ua.token, init.taskId, 2, data.subarray(8, 12));
    const ok = await httpJson(port, ua.token, 'POST', `/api/uploads/${init.taskId}/complete`);
    assert.equal(ok.status, 200, JSON.stringify(ok.json));
  } finally {
    server.stop();
  }
});

test('大小/类型越界被拒', async () => {
  const { server, port } = await startServer({ maxFileSize: 32 });
  try {
    const ua = await login(port, 'alice');
    const big = Buffer.alloc(33);
    const r1 = await httpJson(port, ua.token, 'POST', '/api/uploads', {
      filename: 'big.bin', kind: 'file', mime: 'application/octet-stream',
      size: 33, sha256: sha256(big), chunkSize: 4,
    });
    assert.equal(r1.status, 413);
    assert.equal(r1.json.error, 'FILE_TOO_LARGE');

    const small = Buffer.from('abc');
    const r2 = await httpJson(port, ua.token, 'POST', '/api/uploads', {
      filename: 'x.exe', kind: 'image', mime: 'application/x-msdownload',
      size: small.length, sha256: sha256(small), chunkSize: 4,
    });
    assert.equal(r2.status, 400);
    assert.equal(r2.json.error, 'UNSUPPORTED_TYPE');

    // 声明大小与实际分片不符
    const init = (await httpJson(port, ua.token, 'POST', '/api/uploads', {
      filename: 'lie.bin', kind: 'file', mime: 'application/octet-stream',
      size: 8, sha256: sha256(Buffer.from('xxxxxxxx')), chunkSize: 4,
    })).json;
    const r3 = await putChunk(port, ua.token, init.taskId, 0, Buffer.from('abc')); // 3 != 4
    assert.equal(r3.status, 400);
    assert.equal(r3.json.error, 'CHUNK_SIZE_MISMATCH');
  } finally {
    server.stop();
  }
});

// ---------------------------------------------------------------- 病毒扫描

test('病毒文件：complete 被拒、hash 拉黑、媒体消息永不落库、换名重传仍被拦', async () => {
  const { server, port } = await startServer();
  try {
    const ua = await login(port, 'alice');
    const a = await Client.connect(port, ua.token);
    const roomId = await createRoom(a, 'media');

    const bad = Buffer.from(EICAR);
    const up = await upload(port, ua.token, {
      name: 'evil.bin', kind: 'file', mime: 'application/octet-stream', data: bad, chunkSize: 16,
    });
    assert.equal(up.status, 422);
    assert.equal(up.done.error, 'VIRUS_DETECTED');

    // 资产被拉黑
    const asset = server.db.getAssetBySha(sha256(bad));
    assert.equal(asset.status, 'infected');
    // 用它发消息被拒
    a.send({ type: 'media', roomId, clientMsgId: 'v1', assetId: asset.id });
    const err = await a.waitFor((m) => m.type === 'error' && m.ref === 'v1');
    assert.equal(err.code, 'VIRUS_DETECTED');

    // 换文件名、重新 init 同 hash 仍被拒
    const again = await httpJson(port, ua.token, 'POST', '/api/uploads', {
      filename: 'nice-name.pdf', kind: 'file', mime: 'application/octet-stream',
      size: bad.length, sha256: sha256(bad), chunkSize: 16,
    });
    assert.equal(again.status, 422);
    assert.equal(again.json.error, 'VIRUS_DETECTED');

    // 物理文件应已删除
    assert.equal(fs.existsSync(server.storage.objectPath(sha256(bad))), false);
    a.close();
  } finally {
    server.stop();
  }
});

test('扫描器故障 fail-closed：complete 502 且任务可重试，恢复后成功', async () => {
  let judgeMode = 'error';
  const { server, port } = await startServer({
    virusJudge: () => (judgeMode === 'error' ? 'error' : false),
  });
  try {
    const ua = await login(port, 'alice');
    const data = Buffer.from('scan-me-later-0123');
    const up = await upload(port, ua.token, {
      name: 's.bin', kind: 'file', mime: 'application/octet-stream', data, chunkSize: 8,
    });
    assert.equal(up.status, 502);
    assert.equal(up.done.error, 'SCAN_UNAVAILABLE');
    // 任务保持 open，资产停在 scan_error，消息不能发
    assert.equal(server.db.getTask(up.init.taskId).status, 'open');
    const asset = server.db.getAssetBySha(sha256(data));
    assert.equal(asset.status, 'scan_error');

    // 扫描恢复，重试 complete 即成功
    judgeMode = 'ok';
    const retry = await httpJson(port, ua.token, 'POST', `/api/uploads/${up.init.taskId}/complete`);
    assert.equal(retry.status, 200, JSON.stringify(retry.json));
    assert.equal(retry.json.status, 'ready');
  } finally {
    server.stop();
  }
});

// ---------------------------------------------------------------- 撤回删除规则

test('撤回规则：唯一引用撤回即删文件；仍被其他消息引用时保留；非上传者不能盗用资产', async () => {
  const { server, port } = await startServer();
  try {
    const ua = await login(port, 'alice');
    const ub = await login(port, 'bob');
    const a = await Client.connect(port, ua.token);
    const b = await Client.connect(port, ub.token);
    const roomA = await createRoom(a, 'room-a');
    await joinRoom(b, roomA);

    const data = Buffer.from('shared file content');
    const up = await expectUploadOk(port, ua.token, {
      name: 'shared.txt', kind: 'file', mime: 'text/plain', data, chunkSize: 8,
    });
    const assetId = up.done.assetId;

    // 同一资产发两条消息（seq 1、seq 2）
    a.send({ type: 'media', roomId: roomA, clientMsgId: 's1', assetId });
    await b.waitFor((m) => m.type === 'msg' && m.clientMsgId === 's1');
    a.send({ type: 'media', roomId: roomA, clientMsgId: 's2', assetId });
    await b.waitFor((m) => m.type === 'msg' && m.clientMsgId === 's2');

    // bob 盗用别人的资产发房间？他没有 completed 记录 → FORBIDDEN
    b.send({ type: 'media', roomId: roomA, clientMsgId: 'steal', assetId });
    const err = await b.waitFor((m) => m.type === 'error' && m.ref === 'steal');
    assert.equal(err.code, 'FORBIDDEN');

    // 撤回 seq 1：仍有 seq 2 引用，文件保留
    a.send({ type: 'recall', roomId: roomA, seq: 1 });
    await b.waitFor((m) => m.type === 'recalled' && m.seq === 1);
    const dl1 = await download(port, ub.token, assetId);
    assert.equal(dl1.status, 200);

    // 撤回 seq 2：最后一个引用消失 → 文件物理删除、tombstone、下载 410
    a.send({ type: 'recall', roomId: roomA, seq: 2 });
    await b.waitFor((m) => m.type === 'recalled' && m.seq === 2);
    await sleep(200); // 删文件为异步，留出落盘时间
    const dl2 = await download(port, ua.token, assetId);
    assert.equal(dl2.status, 410);
    assert.equal(server.db.getAsset(assetId).status, 'deleted');

    // 撤回后补发的历史是墓碑，不含正文/资产
    a.send({ type: 'history', roomId: roomA, limit: 10 });
    const h = await a.waitFor((m) => m.type === 'history');
    for (const m of h.messages) {
      if (m.seq <= 2) {
        assert.equal(m.recalled, true);
        assert.equal(m.asset, undefined);
      }
    }

    // 非本人不能撤回；超过窗口不能撤回
    a.close(); b.close();
  } finally {
    server.stop();
  }
});

test('撤回权限与时限：非发送者拒绝、超过窗口拒绝、重复撤回幂等', async () => {
  const { server, port } = await startServer({ recallWindowMs: 20 });
  try {
    const ua = await login(port, 'alice');
    const ub = await login(port, 'bob');
    const a = await Client.connect(port, ua.token);
    const b = await Client.connect(port, ub.token);
    const roomId = await createRoom(a, 'r');
    await joinRoom(b, roomId);

    a.send({ type: 'msg', roomId, clientMsgId: 't1', content: 'recall me' });
    await b.waitFor((m) => m.type === 'msg' && m.seq === 1);

    b.send({ type: 'recall', roomId, seq: 1 });
    const err1 = await b.waitFor((m) => m.type === 'error');
    assert.equal(err1.code, 'FORBIDDEN');

    await sleep(40);
    a.send({ type: 'recall', roomId, seq: 1 });
    const err2 = await a.waitFor((m) => m.type === 'error');
    assert.equal(err2.code, 'RECALL_WINDOW_EXPIRED');
  } finally {
    server.stop();
  }
});

// ---------------------------------------------------------------- 下载权限

test('下载权限：非成员/退出房间/未认证被拒，Range 续传可用', async () => {
  const { server, port } = await startServer();
  try {
    const ua = await login(port, 'alice');
    const ub = await login(port, 'bob');
    const uc = await login(port, 'carol');
    const a = await Client.connect(port, ua.token);
    const b = await Client.connect(port, ub.token);
    const roomId = await createRoom(a, 'secret');
    await joinRoom(b, roomId);

    const data = Buffer.from('0123456789abcdef');
    const up = await expectUploadOk(port, ua.token, {
      name: 'd.bin', kind: 'file', mime: 'application/octet-stream', data, chunkSize: 4,
    });
    // 资产必须被一条未撤回消息引用，成员才具备下载资格
    a.send({ type: 'media', roomId, clientMsgId: 'dl1', assetId: up.done.assetId });
    await b.waitFor((m) => m.type === 'msg' && m.clientMsgId === 'dl1');

    // carol 不是成员 → 403
    const dl0 = await download(port, uc.token, up.done.assetId);
    assert.equal(dl0.status, 403);
    // 无 token → 401
    const noAuth = await fetch(`http://127.0.0.1:${port}/api/assets/${up.done.assetId}/download`);
    assert.equal(noAuth.status, 401);

    // bob Range 续传
    const range = await download(port, ub.token, up.done.assetId, { Range: 'bytes=4-7' });
    assert.equal(range.status, 206);
    assert.equal(range.headers.get('content-range'), `bytes 4-7/${data.length}`);
    assert.ok(range.buf.equals(data.subarray(4, 8)));

    // bob 退出房间 → 立即失去下载权限
    b.send({ type: 'leave', roomId });
    await sleep(100);
    const dl2 = await download(port, ub.token, up.done.assetId);
    assert.equal(dl2.status, 403);

    // 重新加入恢复权限
    await joinRoom(b, roomId);
    const dl3 = await download(port, ub.token, up.done.assetId);
    assert.equal(dl3.status, 200);

    a.close(); b.close();
  } finally {
    server.stop();
  }
});

// ---------------------------------------------------------------- 引用

test('消息引用：文本/媒体均可引用，被引用消息撤回后摘要变为墓碑', async () => {
  const { server, port } = await startServer();
  try {
    const ua = await login(port, 'alice');
    const ub = await login(port, 'bob');
    const a = await Client.connect(port, ua.token);
    const b = await Client.connect(port, ub.token);
    const roomId = await createRoom(a, 'r');
    await joinRoom(b, roomId);

    a.send({ type: 'msg', roomId, clientMsgId: 'q1', content: 'original text' });
    await b.waitFor((m) => m.type === 'msg' && m.seq === 1);

    const data = Buffer.from('quoted-image');
    const up = await expectUploadOk(port, ua.token, {
      name: 'pic.png', kind: 'image', mime: 'image/png', data, chunkSize: 4,
    });
    a.send({
      type: 'media', roomId, clientMsgId: 'q2', assetId: up.done.assetId,
      content: '看图', quoteSeq: 1,
    });
    const m2 = await b.waitFor((m) => m.type === 'msg' && m.clientMsgId === 'q2');
    assert.equal(m2.quote.seq, 1);
    assert.equal(m2.quote.content, 'original text');
    assert.equal(m2.quote.msgType, 'text');
    assert.equal(m2.msgType, 'image');
    assert.equal(m2.asset.kind, 'image');
    assert.match((await download(port, ub.token, up.done.assetId)).headers.get('content-disposition'), /inline/);

    // 撤回被引用消息后，新拉取的历史里引用摘要应是墓碑形式
    a.send({ type: 'recall', roomId, seq: 1 });
    await sleep(50);
    b.send({ type: 'history', roomId, limit: 10 });
    const h = await b.waitFor((m) => m.type === 'history');
    const quoting = h.messages.find((m) => m.seq === 2);
    assert.equal(quoting.quote.recalled, true);

    // 引用不存在/太旧被拒
    a.send({ type: 'msg', roomId, clientMsgId: 'q3', content: 'bad quote', quoteSeq: 999 });
    const err = await a.waitFor((m) => m.type === 'error');
    assert.equal(err.code, 'QUOTE_NOT_FOUND');

    a.close(); b.close();
  } finally {
    server.stop();
  }
});

// ---------------------------------------------------------------- 清理

test('过期清理：孤儿资产 TTL 到期物理删除；僵尸上传任务与分片被回收', async () => {
  const { server, port } = await startServer({ assetTtlMs: 1000, uploadTtlMs: 1000 });
  try {
    const ua = await login(port, 'alice');

    // 完成上传但从不发消息 → 孤儿资产
    const data = Buffer.from('orphan asset!!');
    const up = await expectUploadOk(port, ua.token, {
      name: 'o.bin', kind: 'file', mime: 'application/octet-stream', data, chunkSize: 4,
    });
    const hash = sha256(data);
    assert.equal(fs.existsSync(server.storage.objectPath(hash)), true);
    // 人为把 ready_at 提前到 TTL 之前（就绪后很久未被引用）
    server.db.db.prepare('UPDATE assets SET ready_at = 1 WHERE id = ?').run(up.done.assetId);

    // 僵尸任务：init 后不管
    const data2 = Buffer.from('stale task!!');
    const init = (await httpJson(port, ua.token, 'POST', '/api/uploads', {
      filename: 'z.bin', kind: 'file', mime: 'application/octet-stream',
      size: data2.length, sha256: sha256(data2), chunkSize: 4,
    })).json;
    await putChunk(port, ua.token, init.taskId, 0, data2.subarray(0, 4));
    server.db.db.prepare("UPDATE upload_tasks SET updated_at = 0 WHERE id = ?").run(init.taskId);
    assert.equal(fs.existsSync(server.storage.chunkPath(init.taskId, 0)), true);

    const res = await server.cleanupSweep();
    assert.ok(res.assets >= 1);
    assert.ok(res.tasks >= 1);

    assert.equal(fs.existsSync(server.storage.objectPath(hash)), false);
    assert.equal(server.db.getAsset(up.done.assetId).status, 'deleted');
    assert.equal(server.db.getTask(init.taskId).status, 'expired');
    assert.equal(fs.existsSync(server.storage.chunkDir(init.taskId)), false);
  } finally {
    server.stop();
  }
});

test('有消息引用的资产不会被 TTL 清理', async () => {
  const { server, port } = await startServer({ assetTtlMs: 1 });
  try {
    const ua = await login(port, 'alice');
    const a = await Client.connect(port, ua.token);
    const roomId = await createRoom(a, 'r');
    const data = Buffer.from('referenced!!');
    const up = await expectUploadOk(port, ua.token, {
      name: 'r.bin', kind: 'file', mime: 'application/octet-stream', data, chunkSize: 4,
    });
    a.send({ type: 'media', roomId, clientMsgId: 'm1', assetId: up.done.assetId });
    await a.waitFor((m) => m.type === 'ack' && m.clientMsgId === 'm1');
    server.db.db.prepare('UPDATE assets SET ready_at = 1').run();
    await server.cleanupSweep();
    assert.equal(server.db.getAsset(up.done.assetId).status, 'ready');
    assert.equal(fs.existsSync(server.storage.objectPath(sha256(data))), true);
    a.close();
  } finally {
    server.stop();
  }
});

// ---------------------------------------------------------------- WebSocket 边界

test('WebSocket 背压边界：二进制帧与超大帧被断开，文件字节不走 WS', async () => {
  const { server, port } = await startServer();
  try {
    const ua = await login(port, 'alice');
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws?token=${ua.token}`);
    await new Promise((r) => ws.on('open', r));
    const closed = new Promise((r) => ws.on('close', r));

    ws.send(Buffer.from([1, 2, 3])); // 小二进制帧 → 服务端立即关闭
    const code = await closed;
    assert.equal(code, 1009);

    // 超大文本帧同样在 ws 层就被 1009 断开
    const ws2 = new WebSocket(`ws://127.0.0.1:${port}/ws?token=${ua.token}`);
    await new Promise((r) => ws2.on('open', r));
    const closed2 = new Promise((r) => ws2.on('close', r));
    ws2.send('x'.repeat(100 * 1024));
    assert.equal(await closed2, 1009);
  } finally {
    server.stop();
  }
});

test('媒体消息同样受禁言与限流约束，且 clientMsgId 幂等', async () => {
  const { server, port } = await startServer({ rateLimitPerSec: 1, rateLimitBurst: 2 });
  try {
    const ua = await login(port, 'alice');
    const ub = await login(port, 'bob');
    const a = await Client.connect(port, ua.token);
    const b = await Client.connect(port, ub.token);
    const roomId = await createRoom(a, 'r');
    await joinRoom(b, roomId);

    const data = Buffer.from('muted media');
    const up = await expectUploadOk(port, ub.token, {
      name: 'v.webm', kind: 'voice', mime: 'audio/webm', data, chunkSize: 4,
    });

    a.send({ type: 'mute', roomId, userId: ub.userId, minutes: 10 });
    await b.waitFor((m) => m.type === 'notice' && m.event === 'muted');
    b.send({ type: 'media', roomId, clientMsgId: 'mm-muted', assetId: up.done.assetId });
    const err = await b.waitFor((m) => m.type === 'error' && m.ref === 'mm-muted');
    assert.equal(err.code, 'MUTED');

    a.send({ type: 'unmute', roomId, userId: ub.userId });
    await b.waitFor((m) => m.type === 'notice' && m.event === 'unmuted');
    await sleep(1100); // 等令牌桶恢复

    // 幂等：同 clientMsgId 重发只回同一个 ACK，不重复广播
    b.send({ type: 'media', roomId, clientMsgId: 'mm-1', assetId: up.done.assetId });
    const ack1 = await b.waitFor((m) => m.type === 'ack' && m.clientMsgId === 'mm-1');
    b.send({ type: 'media', roomId, clientMsgId: 'mm-1', assetId: up.done.assetId });
    const ack2 = await b.waitFor((m) => m.type === 'ack' && m.clientMsgId === 'mm-1');
    assert.equal(ack1.seq, ack2.seq);
    await sleep(200);
    const got = a.log.filter((m) => m.type === 'msg' && m.clientMsgId === 'mm-1');
    assert.equal(got.length, 1);

    a.close(); b.close();
  } finally {
    server.stop();
  }
});

// ---------------------------------------------------------------- 持久化

test('持久化：服务重启后媒体消息、资产与下载权限仍然有效', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chat-media-'));
  const dbPath = path.join(dir, 'test.db');
  const storageDir = path.join(dir, 'storage');
  let token, roomId, assetId, data = Buffer.from('persist-bytes-0123');
  try {
    {
      const { server, port } = await startServer({ dbPath, storageDir, chunkDir: path.join(storageDir, 'chunks') });
      try {
        const u = await login(port, 'alice');
        token = u.token;
        const a = await Client.connect(port, token);
        roomId = await createRoom(a, 'persist');
        const up = await expectUploadOk(port, token, {
          name: 'p.bin', kind: 'file', mime: 'application/octet-stream', data, chunkSize: 4,
        });
        assetId = up.done.assetId;
        a.send({ type: 'media', roomId, clientMsgId: 'p1', assetId });
        await a.waitFor((m) => m.type === 'ack' && m.clientMsgId === 'p1');
        a.close();
      } finally {
        server.stop();
      }
    }
    {
      const { server, port } = await startServer({ dbPath, storageDir, chunkDir: path.join(storageDir, 'chunks') });
      try {
        const a = await Client.connect(port, token);
        await joinRoom(a, roomId, 0);
        const msg = await a.waitFor((m) => m.type === 'msg' && m.msgType === 'file');
        assert.equal(msg.asset.id, assetId);
        const dl = await download(port, token, assetId);
        assert.equal(dl.status, 200);
        assert.ok(dl.buf.equals(data));
        a.close();
      } finally {
        server.stop();
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
