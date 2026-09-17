'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const { LocalStorage } = require('../src/storage');
const { Scanner, sniff, EICAR_SIGNATURE } = require('../src/scanner');
const defaultConfig = require('../src/config');

async function mkRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'chat-store-'));
}

/** 最小合法 PNG（1×1），sniff 不校验 CRC */
function png1x1() {
  return Buffer.from([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, // width
    0x00, 0x00, 0x00, 0x01, // height
    0x08, 0x06, 0x00, 0x00, 0x00,
    0x1c, 0x4c, 0x79, 0xd4,
  ]);
}

function gif(w = 3, h = 2) {
  const b = Buffer.alloc(13);
  b.write('GIF89a', 0, 'ascii');
  b.writeUInt16LE(w, 6);
  b.writeUInt16LE(h, 8);
  return b;
}

/** 最小 JPEG 风格 SOF0：FFD8 FFC0 len p height width... */
function jpeg(w = 0x0020, h = 0x0010) {
  const b = Buffer.alloc(17, 0);
  b[0] = 0xff; b[1] = 0xd8; b[2] = 0xff; b[3] = 0xc0;
  b.writeUInt16BE(0x0011, 4); // 段长
  b[6] = 0x08;               // 精度
  b.writeUInt16BE(h, 7);
  b.writeUInt16BE(w, 9);
  return b;
}

function webpLossy(w = 100, h = 50) {
  const b = Buffer.alloc(30);
  b.write('RIFF', 0, 'ascii');
  b.writeUInt32LE(22, 4);
  b.write('WEBP', 8, 'ascii');
  b.write('VP8 ', 12, 'ascii');
  b.writeUInt32LE(10, 16);
  b[23] = 0x9d; b[24] = 0x01; b[25] = 0x2a;
  b.writeUInt16LE(w, 26);
  b.writeUInt16LE(h, 28);
  return b;
}

test('magic sniff: PNG/JPEG/GIF/WebP 类型与宽高', () => {
  assert.deepEqual(sniff(png1x1()), { mime: 'image/png', meta: { width: 1, height: 1 } });
  assert.deepEqual(sniff(jpeg()).meta, { width: 0x0020, height: 0x0010 });
  assert.equal(sniff(jpeg()).mime, 'image/jpeg');
  assert.deepEqual(sniff(gif()).meta, { width: 3, height: 2 });
  assert.equal(sniff(webpLossy()).mime, 'image/webp');
  assert.deepEqual(sniff(webpLossy()).meta, { width: 100, height: 50 });
});

test('magic sniff: WebM/Ogg/MP4 容器与未知类型', () => {
  assert.equal(sniff(Buffer.from([0x1a, 0x45, 0xdf, 0xa3, 0, 0, 0, 0])).mime, 'audio/webm');
  assert.equal(sniff(Buffer.from('OggSxxxx')).mime, 'audio/ogg');
  const mp4 = Buffer.alloc(12); mp4.write('ftyp', 4, 'ascii');
  assert.equal(sniff(mp4).mime, 'audio/mp4');
  assert.equal(sniff(Buffer.from('plain text content')), null);
});

test('storage: 分片流式组装 hash 正确、物理去重、Range 读', async () => {
  const root = await mkRoot();
  const storage = new LocalStorage({ root });
  await storage.init();
  const taskId = 't_test';
  await storage.ensureTaskDir(taskId);

  const parts = [Buffer.alloc(70000, 1), Buffer.alloc(30000, 2), Buffer.from([3, 4, 5])];
  for (let i = 0; i < parts.length; i++) {
    const { stream } = storage.openChunkTmp(taskId, i);
    await new Promise((resolve, reject) => {
      stream.on('finish', resolve);
      stream.on('error', reject);
      stream.end(parts[i]);
    });
    await storage.commitChunk(taskId, i);
  }

  const { sha256, size } = await storage.assemble(taskId, parts.length);
  const expectSha = crypto.createHash('sha256').update(Buffer.concat(parts)).digest('hex');
  assert.equal(sha256, expectSha);
  assert.equal(size, 100003);

  const c1 = await storage.commitBlob(storage.assembledPath(taskId), sha256);
  assert.equal(c1.reused, false);
  assert.ok(fs.existsSync(storage.blobPath(sha256)));
  // 再来一次同 sha（模拟二级去重）：独立任务目录组装同内容，reused=true
  const task2 = 't_dup';
  await storage.ensureTaskDir(task2);
  const { stream: ws2 } = storage.openChunkTmp(task2, 0);
  await new Promise((res, rej) => { ws2.on('finish', res); ws2.on('error', rej); ws2.end(Buffer.concat(parts)); });
  await storage.commitChunk(task2, 0);
  const a2 = await storage.assemble(task2, 1);
  assert.equal(a2.sha256, expectSha);
  const c2 = await storage.commitBlob(a2.assembledPath, sha256);
  assert.equal(c2.reused, true);
  assert.equal(storage.statBlob(sha256).size, 100003);

  // Range 读
  const range = await new Promise((resolve, reject) => {
    const chunks = [];
    const s = storage.openBlob(sha256, { start: 100, end: 102 });
    s.on('data', (c) => chunks.push(c));
    s.on('end', () => resolve(Buffer.concat(chunks)));
    s.on('error', reject);
  });
  assert.equal(range.length, 3);
  assert.deepEqual(range, Buffer.from([1, 1, 1]));

  await storage.removeTaskDir(taskId);
  await storage.removeTaskDir(task2);
  await storage.deleteBlob(sha256);
  assert.equal(storage.hasBlob(sha256), false);
  await fsp.rm(root, { recursive: true, force: true });
});

test('scanner: EICAR 跨块命中、扩展名拦截、magic 不符、干净文件放行', async () => {
  const root = await mkRoot();
  const cfg = { ...defaultConfig, scannerMode: 'builtin', storageRoot: root };
  const scanner = new Scanner(cfg);
  const good = path.join(root, 'a.png');
  await fsp.writeFile(good, png1x1());
  const r1 = await scanner.scan(good, { kind: 'image', fileName: 'a.png' });
  assert.equal(r1.status, 'clean');
  assert.equal(r1.mime, 'image/png');
  assert.deepEqual(r1.meta, { width: 1, height: 1 });

  // 文本内容伪装成图片 → MAGIC_MISMATCH
  const fake = path.join(root, 'fake.png');
  await fsp.writeFile(fake, Buffer.from('not an image at all'));
  const r2 = await scanner.scan(fake, { kind: 'image', fileName: 'fake.png' });
  assert.equal(r2.code, 'MAGIC_MISMATCH');

  // 危险扩展名
  const exe = path.join(root, 'x.exe');
  await fsp.writeFile(exe, Buffer.from('MZ binary'));
  const r3 = await scanner.scan(exe, { kind: 'file', fileName: 'x.exe' });
  assert.equal(r3.code, 'DANGEROUS_EXTENSION');

  // EICAR 跨 64KiB 块边界
  const vir = path.join(root, 'v.txt');
  const prefix = Buffer.alloc(64 * 1024 + 5, 0x61);
  await fsp.writeFile(vir, Buffer.concat([prefix, EICAR_SIGNATURE, Buffer.from(' tail')]));
  const r4 = await scanner.scan(vir, { kind: 'file', fileName: 'v.txt' });
  assert.equal(r4.code, 'INFECTED');
  assert.deepEqual(r4.threats, ['eicar-test-signature']);

  await fsp.rm(root, { recursive: true, force: true });
});

test('scanner: clamd 不可用 fail-closed → error / fail-open → clean', async () => {
  const root = await mkRoot();
  const good = path.join(root, 'a.png');
  await fsp.writeFile(good, png1x1());

  const closed = new Scanner({
    ...defaultConfig, scannerMode: 'clamd', scannerFailPolicy: 'closed',
    clamdHost: '127.0.0.1', clamdPort: 1, clamdTimeoutMs: 500,
  });
  const rc = await closed.scan(good, { kind: 'image', fileName: 'a.png' });
  assert.equal(rc.status, 'error');
  assert.equal(rc.code, 'SCAN_UNAVAILABLE');

  const open = new Scanner({
    ...defaultConfig, scannerMode: 'clamd', scannerFailPolicy: 'open',
    clamdHost: '127.0.0.1', clamdPort: 1, clamdTimeoutMs: 500,
  });
  const ro = await open.scan(good, { kind: 'image', fileName: 'a.png' });
  assert.equal(ro.status, 'clean');

  await fsp.rm(root, { recursive: true, force: true });
});
