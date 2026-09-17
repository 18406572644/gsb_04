'use strict';

/**
 * 可插拔病毒/内容扫描。
 *
 * - ExtensionGuard：危险扩展名黑名单（确定性）
 * - MagicSniff：magic byte 判定真实类型（不信任客户端 MIME），并解析图片宽高
 * - scanEicar：流式跨块匹配 EICAR 标准测试签名（确定性）
 * - ClamdScanner：用 node:net 手写 clamd INSTREAM 协议（零第三方依赖）
 *
 * 扫描结果：{ status:'clean'|'infected'|'error', code, threats[], mime, meta }
 * 外部扫描器（clamd）不可用时按 failPolicy 决定 open(放行)/closed(拒绝完成)；
 * 本地确定性检查始终生效，不受策略影响。
 */

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const net = require('node:net');
const path = require('node:path');

const EICAR_SIGNATURE = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}');
const PREFIX_LIMIT = 1 << 20; // 仅读文件前 1MiB 做类型解析（有界内存）

// ---------------------------------------------------------------- magic / 尺寸

function u16be(b, o) { return (b[o] << 8) | b[o + 1]; }
function u24le(b, o) { return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16); }

/** 解析 JPEG 首个 SOF 帧取宽高；遍历到则返回，超出前缀返回 null */
function jpegSize(buf) {
  if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8) return null;
  let i = 2;
  while (i + 4 < buf.length) {
    if (buf[i] !== 0xff) { i++; continue; }
    while (buf[i] === 0xff && i < buf.length) i++; // 跳过填充
    const marker = buf[i++];
    // 无长度段的 marker（SOI/EOI/TEM/RSTn）
    if (marker === 0xd8 || marker === 0xd9 || marker === 0x01
        || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (i + 2 > buf.length) return null;
    const len = u16be(buf, i);
    // SOF0/1/2/3/5/6/7/9/10/11/13/14/15（排除 DHT=C4、DAC=CC、JPG=C8）
    const isSof = (marker >= 0xc0 && marker <= 0xcf)
      && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc;
    if (isSof && i + 8 <= buf.length) {
      return { width: u16be(buf, i + 5), height: u16be(buf, i + 3) };
    }
    i += len;
  }
  return null;
}

function webpSize(buf) {
  if (buf.length < 30 || buf.toString('ascii', 0, 4) !== 'RIFF'
      || buf.toString('ascii', 8, 12) !== 'WEBP') return null;
  const fourcc = buf.toString('ascii', 12, 16);
  if (fourcc === 'VP8 ') {
    // 有损：frame tag(3) + start code 9d 01 2a，其后 width/height 各 16bit LE
    if (buf.length < 30 || buf[23] !== 0x9d || buf[24] !== 0x01 || buf[25] !== 0x2a) return null;
    return { width: buf.readUInt16LE(26), height: buf.readUInt16LE(28) };
  }
  if (fourcc === 'VP8L') {
    if (buf.length < 26 || buf[20] !== 0x2f) return null;
    const v = buf.readUInt32LE(21);
    return { width: (v & 0x3fff) + 1, height: ((v >> 14) & 0x3fff) + 1 };
  }
  if (fourcc === 'VP8X') {
    if (buf.length < 30) return null;
    return { width: u24le(buf, 24) + 1, height: u24le(buf, 27) + 1 };
  }
  return null;
}

/** 基于前导字节判定真实类型，返回 { mime, meta:{width,height}|null } */
function sniff(buf) {
  if (buf.length >= 8 && buf[0] === 0x89 && buf.toString('ascii', 1, 4) === 'PNG'
      && buf[4] === 0x0d && buf[5] === 0x0a && buf[6] === 0x1a && buf[7] === 0x0a) {
    const size = buf.length >= 24 ? { width: u16be(buf, 18), height: u16be(buf, 22) } : null;
    return { mime: 'image/png', meta: size };
  }
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return { mime: 'image/jpeg', meta: jpegSize(buf) };
  }
  if (buf.length >= 10 && (buf.toString('ascii', 0, 6) === 'GIF87a'
      || buf.toString('ascii', 0, 6) === 'GIF89a')) {
    return { mime: 'image/gif', meta: { width: buf.readUInt16LE(6), height: buf.readUInt16LE(8) } };
  }
  if (buf.length >= 12 && buf.toString('ascii', 0, 4) === 'RIFF'
      && buf.toString('ascii', 8, 12) === 'WEBP') {
    return { mime: 'image/webp', meta: webpSize(buf) };
  }
  if (buf.length >= 4 && buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3) {
    return { mime: 'audio/webm', meta: null }; // EBML（MediaRecorder 产出 audio/webm）
  }
  if (buf.length >= 4 && buf.toString('ascii', 0, 4) === 'OggS') {
    return { mime: 'audio/ogg', meta: null };
  }
  if (buf.length >= 12 && buf.toString('ascii', 4, 8) === 'ftyp') {
    return { mime: 'audio/mp4', meta: null }; // ISO BMFF（mp42/isom/M4A 等品牌）
  }
  return null;
}

async function sniffFile(filePath) {
  let fh;
  try {
    fh = await fsp.open(filePath, 'r');
    const st = await fh.stat();
    const len = Math.min(st.size, PREFIX_LIMIT);
    const buf = Buffer.allocUnsafe(len);
    if (len > 0) await fh.read(buf, 0, len, 0);
    return sniff(buf);
  } finally {
    await fh?.close();
  }
}

// ---------------------------------------------------------------- EICAR

/** 流式扫描整个文件匹配 EICAR 签名（carry 处理跨块） */
function scanEicar(filePath) {
  return new Promise((resolve, reject) => {
    const input = fs.createReadStream(filePath);
    let carry = Buffer.alloc(0);
    let found = false;
    input.on('data', (chunk) => {
      const joined = Buffer.concat([carry, chunk]);
      if (joined.indexOf(EICAR_SIGNATURE) !== -1) {
        found = true;
        input.destroy();
        resolve(true);
        return;
      }
      carry = joined.subarray(Math.max(0, joined.length - (EICAR_SIGNATURE.length - 1)));
    });
    input.on('end', () => resolve(found));
    input.on('error', (err) => {
      if (err.code === 'ERR_STREAM_PREMATURE_CLOSE') return; // 主动 destroy
      reject(err);
    });
  });
}

// ---------------------------------------------------------------- ClamAV

/**
 * clamd INSTREAM 客户端。每块先发 4 字节大端长度（≤64KiB）再发数据，
 * 结束发 4 字节零包；读取 'stream: OK | FOUND <name> | ERROR...' 应答。
 */
class ClamdScanner {
  constructor({ host, port, socketPath, timeoutMs }) {
    this.host = host;
    this.port = port;
    this.socketPath = socketPath || '';
    this.timeoutMs = timeoutMs;
  }

  _connect() {
    return new Promise((resolve, reject) => {
      const sock = this.socketPath
        ? net.connect(this.socketPath)
        : net.connect({ host: this.host, port: this.port });
      const timer = setTimeout(() => {
        sock.destroy(new Error('clamd connect timeout'));
      }, this.timeoutMs);
      sock.once('connect', () => { clearTimeout(timer); resolve(sock); });
      sock.once('error', (err) => { clearTimeout(timer); reject(err); });
    });
  }

  async scan(filePath) {
    let sock;
    try {
      sock = await this._connect();
    } catch (err) {
      return { status: 'error', code: 'SCAN_UNAVAILABLE', threats: [], detail: err.message };
    }

    return new Promise((resolve) => {
      let reply = Buffer.alloc(0);
      const done = (r) => {
        try { sock.destroy(); } catch { /* 已关闭 */ }
        resolve(r);
      };
      const timer = setTimeout(() => done({
        status: 'error', code: 'SCAN_UNAVAILABLE', threats: [], detail: 'clamd timeout',
      }), this.timeoutMs);

      sock.on('data', (d) => {
        reply = Buffer.concat([reply, d]);
        if (!reply.includes(0x0a) && reply.length < 4096) return; // 等应答行结束
        clearTimeout(timer);
        const text = reply.toString().trim();
        if (/\sFOUND(\r?\n|$)/.test(text)) {
          const name = text.replace(/^stream:\s*/i, '').replace(/\s+FOUND[\s\S]*$/i, '').trim();
          done({ status: 'infected', code: 'INFECTED', threats: [name || 'unknown'] });
        } else if (/^stream:\s*OK/i.test(text)) {
          done({ status: 'clean', code: null, threats: [] });
        } else {
          done({ status: 'error', code: 'SCAN_UNAVAILABLE', threats: [], detail: text });
        }
      });
      sock.on('error', () => {
        clearTimeout(timer);
        done({ status: 'error', code: 'SCAN_UNAVAILABLE', threats: [] });
      });

      // 分块发送（背压）
      const CHUNK = 64 * 1024;
      const input = fs.createReadStream(filePath, { highWaterMark: CHUNK });
      input.on('data', (chunk) => {
        input.pause();
        const header = Buffer.alloc(4);
        header.writeUInt32BE(chunk.length, 0);
        sock.write(header);
        sock.write(chunk, () => input.resume());
      });
      input.on('end', () => {
        sock.write(Buffer.alloc(4)); // 零长度包结束会话
      });
      input.on('error', () => {
        clearTimeout(timer);
        done({ status: 'error', code: 'SCAN_UNAVAILABLE', threats: [] });
      });
    });
  }
}

// ---------------------------------------------------------------- 组合扫描器

class Scanner {
  constructor(config) {
    this.config = config;
    this.clamd = config.scannerMode === 'clamd'
      ? new ClamdScanner({
        host: config.clamdHost, port: config.clamdPort,
        socketPath: config.clamdSocket, timeoutMs: config.clamdTimeoutMs,
      })
      : null;
  }

  /**
   * @param {string} filePath complete 组装出的整文件路径
   * @param {{kind:string, fileName:string}} ctx
   * @returns {Promise<{status:string,code:?string,threats:string[],mime:?string,meta:?object}>}
   */
  async scan(filePath, { kind, fileName } = {}) {
    // 1) 危险扩展名（仅普通文件）
    if (kind === 'file' && this.config.blockedExtensions.length) {
      const ext = path.extname(fileName || '').slice(1).toLowerCase();
      if (this.config.blockedExtensions.includes(ext)) {
        return { status: 'infected', code: 'DANGEROUS_EXTENSION', threats: [`*.${ext}`], mime: null, meta: null };
      }
    }

    // 2) magic 类型校验（image/voice 必须匹配白名单；file 任意，仅记录）
    const found = await sniffFile(filePath);
    let mime = found?.mime || null;
    const meta = found?.meta || null;
    if (kind === 'image') {
      if (!mime || !mime.startsWith('image/') || !this.config.allowedImageMime.includes(mime)) {
        return { status: 'infected', code: 'MAGIC_MISMATCH', threats: [], mime, meta };
      }
    } else if (kind === 'voice') {
      if (!mime || !mime.startsWith('audio/') || !this.config.allowedVoiceMime.includes(mime)) {
        return { status: 'infected', code: 'MAGIC_MISMATCH', threats: [], mime, meta };
      }
    } else {
      // 普通文件不限制类型；下载按 octet-stream，MIME 仅记录
      mime = mime || 'application/octet-stream';
    }

    // 3) EICAR（off 模式跳过特征查杀）
    if (this.config.scannerMode !== 'off' && await scanEicar(filePath)) {
      return { status: 'infected', code: 'INFECTED', threats: ['eicar-test-signature'], mime, meta };
    }

    // 4) 可选 ClamAV
    if (this.clamd) {
      const r = await this.clamd.scan(filePath);
      if (r.status === 'infected') return { ...r, mime, meta };
      if (r.status === 'error') {
        if (this.config.scannerFailPolicy === 'closed') return { ...r, mime, meta };
        // fail-open：外部扫描不可用仅放行（确定性检查已全部通过）
      }
    }

    return { status: 'clean', code: null, threats: [], mime, meta };
  }
}

module.exports = { Scanner, ClamdScanner, sniff, jpegSize, webpSize, EICAR_SIGNATURE };
