'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { pipeline } = require('node:stream/promises');
const { Transform } = require('node:stream');

/**
 * 本地对象存储（演示级；接口形状与 S3/OSS 等对象存储一致，可平滑替换）。
 *
 * 布局：
 *   <storageDir>/ab/<sha256>        完成态对象，内容寻址（同哈希即同一物理文件，天然去重）
 *   <chunkDir>/<taskId>/<idx>       上传任务的临时分片，原子 tmp+rename 落盘
 *
 * 关键取舍：
 * - 全程流式读写 + 落盘，内存占用与文件大小无关（只持有小块缓冲），大文件不压垮服务器；
 * - 分块先各自落盘，complete 时按序流式合并并校验 sha256/总大小，任何不符直接失败；
 * - 合并目标先写 .tmp 再 rename，崩溃只可能留下 tmp 垃圾（清理任务兜底），不会出现半截对象。
 */
class LocalStorage {
  constructor({ storageDir, chunkDir }) {
    this.storageDir = path.resolve(storageDir);
    this.chunkRoot = path.resolve(chunkDir);
    fs.mkdirSync(this.storageDir, { recursive: true });
    fs.mkdirSync(this.chunkRoot, { recursive: true });
  }

  objectPath(sha256) {
    return path.join(this.storageDir, sha256.slice(0, 2), sha256.slice(2, 4), sha256);
  }

  chunkDir(taskId) {
    return path.join(this.chunkRoot, taskId);
  }

  chunkPath(taskId, idx) {
    return path.join(this.chunkDir(taskId), String(idx));
  }

  async objectExists(sha256) {
    try {
      await fsp.access(this.objectPath(sha256));
      return true;
    } catch {
      return false;
    }
  }

  chunkSize(taskId, idx) {
    try {
      return fs.statSync(this.chunkPath(taskId, idx)).size;
    } catch {
      return -1;
    }
  }

  /**
   * 流式写入一个分片：边收边算 sha256、边累计字节，超过 maxSize 立即中断。
   * 成功后原子改名到正式分片路径。返回 { size, sha256 }。
   */
  async putChunk(taskId, idx, readable, { maxSize }) {
    const dir = this.chunkDir(taskId);
    await fsp.mkdir(dir, { recursive: true });
    const finalPath = this.chunkPath(taskId, idx);
    const tmpPath = `${finalPath}.tmp-${process.pid}`;
    const hash = crypto.createHash('sha256');
    let size = 0;
    let tooLarge = false;
    const out = fs.createWriteStream(tmpPath);
    const monitor = new Transform({
      transform(chunk, _enc, cb) {
        size += chunk.length;
        if (size > maxSize) {
          tooLarge = true;
          cb(new Error('chunk exceeds declared size'));
          return;
        }
        hash.update(chunk);
        cb(null, chunk);
      },
    });
    try {
      await pipeline(readable, monitor, out);
      await fsp.rename(tmpPath, finalPath);
      return { size, sha256: hash.digest('hex') };
    } catch (err) {
      await fsp.rm(tmpPath, { force: true });
      throw err;
    }
  }

  /** 已落盘分片的下标列表 */
  async listChunks(taskId) {
    try {
      const entries = await fsp.readdir(this.chunkDir(taskId));
      return entries.filter((n) => /^\d+$/.test(n)).map(Number).sort((a, b) => a - b);
    } catch {
      return [];
    }
  }

  /**
   * 按序单遍流式合并全部分片为对象文件，边合并边累计大小与 sha256。
   * 任一分片缺失、总大小不符、哈希不符都删除 tmp 并抛错，绝不留下半截正式对象。
   * 背压交给 pipeline（异步生成器 → WriteStream），内存只持有单个流缓冲块。
   */
  async mergeChunks(task, expected) {
    const dest = this.objectPath(expected.sha256);
    await fsp.mkdir(path.dirname(dest), { recursive: true });
    if (await this.objectExists(expected.sha256)) return dest; // 同内容已存在（秒传落盘）

    const tmp = `${dest}.tmp-${process.pid}`;
    const hash = crypto.createHash('sha256');
    let size = 0;
    let aborted = null;
    const self = this;

    async function* merged() {
      for (let idx = 0; idx < task.total_chunks; idx++) {
        const p = self.chunkPath(task.id, idx);
        const exists = await fsp.stat(p).catch(() => null);
        if (!exists) { aborted = new Error(`missing chunk ${idx}`); return; }
        // 用 pipeline 把单分片抽干为块序列，天然处理背压
        for await (const c of fs.createReadStream(p)) {
          size += c.length;
          if (size > task.size) { aborted = new Error('merged size exceeds declared size'); return; }
          hash.update(c);
          yield c;
        }
      }
    }

    try {
      await pipeline(merged(), fs.createWriteStream(tmp));
      if (aborted) throw aborted;
      if (size !== task.size) throw new Error(`size mismatch: got ${size}, want ${task.size}`);
      if (hash.digest('hex') !== expected.sha256) throw new Error('sha256 mismatch');
      await fsp.rename(tmp, dest);
      return dest;
    } catch (err) {
      await fsp.rm(tmp, { force: true });
      throw err;
    }
  }

  /** 流式读取对象（下载用，支持 Range 由调用方处理） */
  openObject(sha256) {
    return fs.createReadStream(this.objectPath(sha256));
  }

  statObject(sha256) {
    return fs.statSync(this.objectPath(sha256));
  }

  async deleteObject(sha256) {
    await fsp.rm(this.objectPath(sha256), { force: true });
  }

  async deleteChunks(taskId) {
    await fsp.rm(this.chunkDir(taskId), { recursive: true, force: true });
  }

  /** 清理崩溃残留的 *.tmp-* 文件（分片与对象合并的中间产物），启动时与定时任务调用 */
  async pruneTempFiles() {
    const isTmp = (n) => n.includes('.tmp-');
    const walk = async (dir, depth) => {
      let entries;
      try {
        entries = await fsp.readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
          if (depth > 0 && !isTmp(e.name)) await walk(full, depth - 1);
        } else if (isTmp(e.name)) {
          await fsp.rm(full, { force: true });
        }
      }
    };
    await Promise.all([walk(this.storageDir, 3), walk(this.chunkRoot, 2)]);
  }
}

module.exports = { LocalStorage };
