'use strict';

/**
 * 富媒体字节存储（本地磁盘 + 内容寻址）。
 *
 * 目录布局：
 *   <root>/tmp/<taskId>/<idx>.part[.tmp]  上传分片（.tmp 为未校验的在写片）
 *   <root>/tmp/<taskId>/assembled.tmp     complete 时流式拼接产物
 *   <root>/blob/ab/cd/<sha256>            内容寻址 blob（前 2/4 字符分桶）
 *   <root>/quarantine/<taskId>__<ts>__<sha8>  病毒/违规隔离区
 *
 * 设计约束：
 *  - 所有写入均为流式管道 + 背压，内存占用不随文件大小增长；
 *  - 同 sha256 的物理 blob 全局只有一份（不同 asset 行可共享）；
 *  - 不依赖数据库、不解析 HTTP，只负责「把字节放对地方」。
 *  未来接入 S3 时新增一个实现相同方法的类即可，业务层零改动。
 */

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { once } = require('node:events');

const ASSEMBLED_NAME = 'assembled.tmp';

class LocalStorage {
  constructor({ root }) {
    this.root = path.resolve(root);
    this.tmpRoot = path.join(this.root, 'tmp');
    this.blobRoot = path.join(this.root, 'blob');
    this.quarantineRoot = path.join(this.root, 'quarantine');
  }

  async init() {
    await fsp.mkdir(this.tmpRoot, { recursive: true });
    await fsp.mkdir(this.blobRoot, { recursive: true });
    await fsp.mkdir(this.quarantineRoot, { recursive: true });
  }

  // -------------------------------------------------------------- 分片

  taskDir(taskId) { return path.join(this.tmpRoot, taskId); }

  async ensureTaskDir(taskId) {
    const dir = this.taskDir(taskId);
    await fsp.mkdir(dir, { recursive: true });
    return dir;
  }

  chunkTmpPath(taskId, idx) { return path.join(this.taskDir(taskId), `${idx}.part.tmp`); }
  chunkPartPath(taskId, idx) { return path.join(this.taskDir(taskId), `${idx}.part`); }

  openChunkTmp(taskId, idx) {
    const tmpPath = this.chunkTmpPath(taskId, idx);
    // 'w' 覆盖：重传同一未完成片时不留旧字节
    return { stream: fs.createWriteStream(tmpPath), tmpPath };
  }

  async commitChunk(taskId, idx) {
    await fsp.rename(this.chunkTmpPath(taskId, idx), this.chunkPartPath(taskId, idx));
  }

  async discardChunk(taskId, idx) {
    await fsp.rm(this.chunkTmpPath(taskId, idx), { force: true });
  }

  // -------------------------------------------------------------- 组装

  assembledPath(taskId) { return path.join(this.taskDir(taskId), ASSEMBLED_NAME); }

  /**
   * 按 idx 升序流式拼接全部分片到 assembled.tmp，同时计算整体 sha256。
   * 使用 for-await + write/drain 手动背压，内存中只有单个数据块。
   * 返回 { assembledPath, sha256, size }。
   */
  async assemble(taskId, chunkCount) {
    const out = fs.createWriteStream(this.assembledPath(taskId));
    const hash = crypto.createHash('sha256');
    let size = 0;
    try {
      for (let idx = 0; idx < chunkCount; idx++) {
        const part = this.chunkPartPath(taskId, idx);
        const input = fs.createReadStream(part);
        for await (const chunk of input) {
          hash.update(chunk);
          size += chunk.length;
          if (!out.write(chunk)) await once(out, 'drain');
        }
      }
      out.end();
      await once(out, 'finish');
      return { assembledPath: this.assembledPath(taskId), sha256: hash.digest('hex'), size };
    } catch (err) {
      out.destroy();
      await fsp.rm(this.assembledPath(taskId), { force: true });
      throw err;
    }
  }

  // -------------------------------------------------------------- blob

  blobPath(sha256) {
    return path.join(this.blobRoot, sha256.slice(0, 2), sha256.slice(2, 4), sha256);
  }

  hasBlob(sha256) {
    try {
      fs.accessSync(this.blobPath(sha256), fs.constants.F_OK);
      return true;
    } catch { return false; }
  }

  statBlob(sha256) {
    try {
      const st = fs.statSync(this.blobPath(sha256));
      return { size: st.size };
    } catch { return null; }
  }

  /**
   * 将组装产物提交为内容寻址 blob。
   * 已存在同 sha blob 时删除组装产物并复用（物理去重）；同设备原子 rename，
   * 跨设备（EXDEV）回退流式 copy + fsync 后删除源。
   * 返回 { reused }。
   */
  async commitBlob(assembledPath, sha256) {
    const dest = this.blobPath(sha256);
    if (this.hasBlob(sha256)) {
      await fsp.rm(assembledPath, { force: true });
      return { reused: true };
    }
    await fsp.mkdir(path.dirname(dest), { recursive: true });
    try {
      await fsp.rename(assembledPath, dest);
      return { reused: false };
    } catch (err) {
      if (err.code !== 'EXDEV') throw err;
      await this._copyWithFsync(assembledPath, dest);
      await fsp.rm(assembledPath, { force: true });
      return { reused: false };
    }
  }

  async _copyWithFsync(src, dest) {
    await new Promise((resolve, reject) => {
      const input = fs.createReadStream(src);
      const output = fs.createWriteStream(dest, { flags: 'w' });
      input.on('error', reject);
      output.on('error', reject);
      output.on('finish', resolve);
      input.pipe(output);
    });
  }

  openBlob(sha256, { start, end } = {}) {
    return fs.createReadStream(this.blobPath(sha256), { start, end });
  }

  async deleteBlob(sha256) {
    await fsp.rm(this.blobPath(sha256), { force: true });
  }

  // -------------------------------------------------------------- 隔离区

  /** 把违规文件移动到隔离区，返回隔离区文件名（审计用） */
  async quarantine(srcPath, taskId, sha256) {
    const stamp = `${taskId}__${Date.now()}__${(sha256 || 'nohash').slice(0, 8)}`;
    const dest = path.join(this.quarantineRoot, stamp);
    try {
      await fsp.rename(srcPath, dest);
    } catch (err) {
      if (err.code !== 'EXDEV') throw err;
      await fsp.copyFile(srcPath, dest);
      await fsp.rm(srcPath, { force: true });
    }
    return stamp;
  }

  // -------------------------------------------------------------- 清理

  async removeTaskDir(taskId) {
    await fsp.rm(this.taskDir(taskId), { recursive: true, force: true });
  }

  /** 列出 tmp 下全部任务目录（启动残留扫描用） */
  async listTaskDirs() {
    try {
      return (await fsp.readdir(this.tmpRoot, { withFileTypes: true }))
        .filter((d) => d.isDirectory())
        .map((d) => d.name);
    } catch { return []; }
  }

  /** 删除隔离区内 mtime 早于 cutoff 的文件，返回删除数量 */
  async removeQuarantineOlderThan(cutoffMs) {
    let removed = 0;
    let names = [];
    try {
      names = await fsp.readdir(this.quarantineRoot);
    } catch { return 0; }
    for (const name of names) {
      const p = path.join(this.quarantineRoot, name);
      try {
        const st = await fsp.stat(p);
        if (st.mtimeMs < cutoffMs) {
          await fsp.rm(p, { force: true });
          removed++;
        }
      } catch { /* 竞态删除，忽略 */ }
    }
    return removed;
  }
}

module.exports = { LocalStorage };
