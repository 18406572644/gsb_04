'use strict';

/**
 * 两阶段上传的编排层：任务状态机 + 分片接收 + 组装/扫描/去重 + 过期清理。
 *
 * 不直接解析 HTTP：putChunk 接收原始 IncomingMessage 流，由路由层鉴权后调用。
 * 所有文件字节全程流式处理；DB 事务只包裹同步短操作，文件 IO 在事务外。
 */

const crypto = require('node:crypto');
const fsp = require('node:fs/promises');
const { once } = require('node:events');

const { randomId, isInt, isSha256, safeFileName, now } = require('./util');

/** 携带 HTTP 状态码的业务错误 */
class UploadError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

const KINDS = new Set(['image', 'file', 'voice']);

class UploadManager {
  constructor({ db, storage, scanner, config }) {
    this.db = db;
    this.storage = storage;
    this.scanner = scanner;
    this.config = config;
  }

  async init() {
    await this.storage.init();
    await this.sweepStaleTmp();
  }

  sizeLimit(kind) {
    if (kind === 'image') return this.config.maxImageSize;
    if (kind === 'voice') return this.config.maxVoiceSize;
    return this.config.maxFileSize;
  }

  // -------------------------------------------------------------- 查询 DTO

  _taskDto(task, receivedChunks = undefined) {
    return {
      taskId: task.id,
      status: task.status,
      filename: task.file_name,
      kind: task.kind,
      size: task.declared_size,
      chunkSize: task.chunk_size,
      chunkCount: task.total_chunks,
      receivedChunks: receivedChunks === undefined
        ? this.db.listChunks(task.id) : receivedChunks,
      assetId: task.asset_id,
      expiresAt: task.expires_at,
      errorCode: task.error_code,
    };
  }

  /** 取属于本人的任务；非本人 403，不存在 404，终态按规则抛 410 */
  async _ownedTask(user, taskId) {
    const task = this.db.getUploadTask(taskId);
    if (!task) throw new UploadError(404, 'NO_SUCH_TASK', 'upload task not found');
    if (task.user_id !== user.id) throw new UploadError(403, 'FORBIDDEN', 'not your upload task');
    if (task.status === 'expired' || task.status === 'aborted') {
      throw new UploadError(410, 'TASK_EXPIRED', 'upload task expired or aborted');
    }
    return task;
  }

  async _ownedOpenTask(user, taskId) {
    const task = await this._ownedTask(user, taskId);
    if (task.status !== 'open') {
      throw new UploadError(409, 'TASK_NOT_OPEN', `task is ${task.status}`);
    }
    return task;
  }

  // -------------------------------------------------------------- 创建（含秒传）

  async createTask(user, body) {
    const kind = body.kind;
    if (!KINDS.has(kind)) throw new UploadError(415, 'UNSUPPORTED_KIND', 'unsupported kind');
    const fileName = safeFileName(body.filename);
    const size = body.size;
    if (!isInt(size, 1, this.sizeLimit(kind))) {
      throw new UploadError(413, 'FILE_TOO_LARGE', `size must be 1..${this.sizeLimit(kind)}`);
    }
    let chunkSize = this.config.uploadChunkSize;
    if (body.chunkSize !== undefined && body.chunkSize !== null) {
      if (!isInt(body.chunkSize, this.config.uploadChunkMin, this.config.uploadChunkMax)) {
        throw new UploadError(400, 'BAD_REQUEST', 'invalid chunkSize');
      }
      chunkSize = body.chunkSize;
    }
    const sha = isSha256(body.sha256) ? body.sha256 : null;
    const durationMs = kind === 'voice' && isInt(body.durationMs, 0, 24 * 3600_000)
      ? body.durationMs : null;

    // 秒传：仅限本人历史 ready 任务对应的、物理仍存在的 blob —— 防止猜 sha 拖走他人文件
    if (sha) {
      const assetId = this.db.findUserReadyAssetBySha(user.id, sha);
      if (assetId && this.storage.hasBlob(sha)) {
        return { taskId: null, status: 'ready', instant: true, assetId, expiresAt: 0 };
      }
    }

    // 每用户活跃任务并发闸
    if (this.db.countOpenTasksForUser(user.id) >= this.config.maxConcurrentUploads) {
      throw new UploadError(429, 'TOO_MANY_UPLOADS', 'too many concurrent uploads');
    }

    const totalChunks = Math.ceil(size / chunkSize);
    const ts = now();
    const task = {
      id: randomId('t_'),
      userId: user.id,
      fileName,
      kind,
      size,
      sha256: sha,
      chunkSize,
      totalChunks,
      durationMs,
      createdAt: ts,
      updatedAt: ts,
      expiresAt: ts + this.config.uploadTaskTtlMs,
    };
    this.db.insertUploadTask(task);
    await this.storage.ensureTaskDir(task.id);
    return { ...this._taskDto(this.db.getUploadTask(task.id), []), instant: false };
  }

  async getTask(user, taskId) {
    const t = await this._ownedTask(user, taskId);
    return this._taskDto(t);
  }

  // -------------------------------------------------------------- 分片上传

  /**
   * 流式接收单个分片。req 为原始请求流；contentLength 取 Content-Length。
   * 内存恒定：数据块边收边 hash、边写盘，超期望长度立即中止。
   */
  async putChunk(user, taskId, idx, req, { declaredSha, contentLength }) {
    if (!isInt(idx)) throw new UploadError(416, 'BAD_CHUNK_INDEX', 'invalid chunk index');
    if (!isSha256(declaredSha)) {
      throw new UploadError(400, 'BAD_REQUEST', 'X-Chunk-Sha256 header required (hex64)');
    }
    const task = await this._ownedOpenTask(user, taskId);
    if (idx < 0 || idx >= task.total_chunks) {
      throw new UploadError(416, 'BAD_CHUNK_INDEX', 'chunk index out of range');
    }
    const expectedSize = idx === task.total_chunks - 1
      ? task.declared_size - (task.total_chunks - 1) * task.chunk_size
      : task.chunk_size;
    if (Number.isInteger(contentLength) && contentLength !== expectedSize) {
      throw new UploadError(413, 'CHUNK_SIZE_MISMATCH',
        `chunk must be exactly ${expectedSize} bytes`);
    }

    // 幂等：同片重传且 hash 一致直接成功（排空请求体保活连接）
    const existing = this.db.getChunk(taskId, idx);
    if (existing) {
      if (existing.sha256 === declaredSha) {
        req.resume();
        return { ok: true, idx, size: existing.size, sha256: existing.sha256, reused: true };
      }
      throw new UploadError(409, 'CHUNK_CONFLICT', 'chunk already uploaded with different hash');
    }

    await this.storage.ensureTaskDir(taskId);
    const { stream, tmpPath } = this.storage.openChunkTmp(taskId, idx);
    const hash = crypto.createHash('sha256');
    let received = 0;
    let aborted = false;

    let idle = null;
    const resetIdle = () => {
      clearTimeout(idle);
      idle = setTimeout(() => req.destroy(new Error('chunk idle timeout')),
        this.config.chunkIdleTimeoutMs);
    };

    try {
      const result = await new Promise((resolve, reject) => {
        const fail = (err) => { if (!aborted) { aborted = true; reject(err); } };
        resetIdle();
        req.on('data', (chunk) => {
          if (aborted) return;
          resetIdle();
          received += chunk.length;
          if (received > expectedSize) {
            fail(new UploadError(413, 'CHUNK_TOO_LARGE', `chunk exceeds ${expectedSize} bytes`));
            req.destroy();
            return;
          }
          hash.update(chunk);
          if (!stream.write(chunk)) req.pause(), stream.once('drain', () => req.resume());
        });
        req.on('end', () => {
          clearTimeout(idle);
          stream.end();
        });
        req.on('aborted', () => fail(new UploadError(499, 'UPLOAD_ABORTED', 'client aborted')));
        req.on('error', (err) => fail(err.status === 413 ? err
          : new UploadError(400, 'CHUNK_IO_ERROR', err.message)));
        stream.on('error', (err) => fail(new UploadError(500, 'STORAGE_ERROR', err.message)));
        stream.on('finish', () => {
          clearTimeout(idle);
          if (aborted) return;
          if (received !== expectedSize) {
            reject(new UploadError(422, 'CHUNK_SIZE_MISMATCH',
              `got ${received} bytes, expected ${expectedSize}`));
            return;
          }
          const digest = hash.digest('hex');
          if (digest !== declaredSha) {
            reject(new UploadError(422, 'CHUNK_HASH_MISMATCH', 'chunk checksum mismatch'));
            return;
          }
          resolve(digest);
        });
      });

      await this.storage.commitChunk(taskId, idx);
      this.db.upsertChunkReceipt(taskId, idx, received, result);
      return { ok: true, idx, size: received, sha256: result, reused: false };
    } catch (err) {
      clearTimeout(idle);
      stream.destroy();
      await this.storage.discardChunk(taskId, idx);
      throw err;
    }
  }

  // -------------------------------------------------------------- 完成

  async complete(user, taskId, declaredSha) {
    if (!isSha256(declaredSha)) {
      throw new UploadError(400, 'BAD_REQUEST', 'sha256 (hex64) required to complete');
    }
    const task = await this._ownedOpenTask(user, taskId);

    const receipts = this.db.listChunks(taskId);
    if (receipts.length !== task.total_chunks) {
      const got = new Set(receipts.map((c) => c.idx));
      const missing = [];
      for (let i = 0; i < task.total_chunks; i++) if (!got.has(i)) missing.push(i);
      throw new UploadError(409, 'NOT_ALL_CHUNKS', 'missing chunks', { missing });
    }

    let assembled;
    try {
      assembled = await this.storage.assemble(taskId, task.total_chunks);
    } catch (err) {
      throw new UploadError(500, 'STORAGE_ERROR', err.message);
    }

    // 整体大小 / sha 校验
    if (assembled.size !== task.declared_size || assembled.sha256 !== declaredSha) {
      await fsp.rm(assembled.assembledPath, { force: true });
      this.db.setUploadTaskStatus(taskId, 'failed', 'HASH_MISMATCH');
      await this.storage.removeTaskDir(taskId);
      throw new UploadError(422, 'HASH_MISMATCH',
        'assembled file size/sha256 mismatch; please re-upload');
    }

    // 病毒 / magic / 扩展名扫描
    const verdict = await this.scanner.scan(assembled.assembledPath, {
      kind: task.kind, fileName: task.file_name,
    });

    if (verdict.status === 'infected') {
      await this.storage.quarantine(assembled.assembledPath, taskId, assembled.sha256);
      this.db.finishUploadTask(taskId, 'quarantined', null, verdict.code);
      await this.storage.removeTaskDir(taskId);
      throw new UploadError(422, verdict.code,
        verdict.code === 'INFECTED' ? 'malicious content detected and quarantined'
          : verdict.code === 'MAGIC_MISMATCH' ? 'file content does not match declared type'
            : 'blocked file type',
        { threats: verdict.threats });
    }

    if (verdict.status === 'error') {
      // fail-closed：组装产物保留，任务仍 open，客户端可稍后重试 complete
      throw new UploadError(503, verdict.code || 'SCAN_UNAVAILABLE',
        'scanner unavailable, please retry later');
    }

    // clean：提交内容寻址 blob（同 sha 物理复用），并新建独立 asset 行
    await this.storage.commitBlob(assembled.assembledPath, assembled.sha256);
    const assetId = randomId('a_');
    this.db.insertAsset({
      id: assetId,
      sha256: assembled.sha256,
      size: assembled.size,
      mime: verdict.mime,
      kind: task.kind,
      width: verdict.meta?.width ?? null,
      height: verdict.meta?.height ?? null,
      durationMs: task.duration_ms,
      fileName: task.file_name,
    });
    this.db.finishUploadTask(taskId, 'ready', assetId, null);
    await this.storage.removeTaskDir(taskId);

    return {
      assetId,
      status: 'ready',
      sha256: assembled.sha256,
      size: assembled.size,
      mime: verdict.mime,
      kind: task.kind,
      meta: {
        width: verdict.meta?.width ?? null,
        height: verdict.meta?.height ?? null,
        durationMs: task.duration_ms,
      },
    };
  }

  async abort(user, taskId) {
    const task = await this._ownedTask(user, taskId);
    if (task.status === 'open') {
      this.db.setUploadTaskStatus(taskId, 'aborted', null);
    }
    await this.storage.removeTaskDir(taskId);
    return { ok: true };
  }

  // -------------------------------------------------------------- blob GC

  /**
   * 当且仅当「未撤回消息活引用」与「open/宽限期 ready 任务占用」都为 0 时，
   * 物理删除 blob 并把同 sha 的 asset 行置 deleted。隔离副本不在此处理。
   */
  async gcBlobIfUnreferenced(sha256, atMs = now()) {
    const { liveMessages, tasks } = this.db.blobRefCounts(
      sha256, atMs - this.config.completedBlobGraceMs
    );
    if (liveMessages > 0 || tasks > 0) return { deleted: false, liveMessages, tasks };
    await this.storage.deleteBlob(sha256);
    this.db.markBlobAssetsStatus(sha256, 'deleted');
    return { deleted: true, liveMessages: 0, tasks: 0 };
  }

  // -------------------------------------------------------------- reaper

  /**
   * 一轮清理：过期 open 任务、隔离区 TTL、孤儿 asset、tmp 残留。
   * 返回各项计数（测试断言 / /healthz 观测用）。
   */
  async runReap(atMs = now()) {
    const result = { expiredTasks: 0, quarantine: 0, orphanBlobs: 0, staleTmp: 0 };

    for (const id of this.db.listExpiredOpenTasks(atMs)) {
      await this.storage.removeTaskDir(id);
      this.db.setUploadTaskStatus(id, 'expired', null);
      result.expiredTasks++;
    }

    result.quarantine = await this.storage.removeQuarantineOlderThan(
      atMs - this.config.quarantineTtlMs
    );

    const graceCutoff = atMs - this.config.completedBlobGraceMs;
    for (const a of this.db.listOrphanAssetCandidates(atMs - this.config.orphanAssetTtlMs)) {
      const { liveMessages, tasks } = this.db.blobRefCounts(a.sha256, graceCutoff);
      if (liveMessages === 0 && tasks === 0 && this.storage.hasBlob(a.sha256)) {
        const r = await this.gcBlobIfUnreferenced(a.sha256, atMs);
        if (r.deleted) result.orphanBlobs++;
      }
    }

    return result;
  }

  /** 启动时清理：tmp 下存在但 DB 无对应 open 任务、且超过 TTL 的残留目录 */
  async sweepStaleTmp() {
    const dirs = await this.storage.listTaskDirs();
    for (const id of dirs) {
      const task = this.db.getUploadTask(id);
      if (task && task.status === 'open' && task.expires_at > now()) continue;
      try {
        const st = await fsp.stat(this.storage.taskDir(id));
        if (now() - st.mtimeMs > this.config.uploadTaskTtlMs) {
          await this.storage.removeTaskDir(id);
        }
      } catch { /* 已消失，忽略 */ }
    }
  }
}

module.exports = { UploadManager, UploadError };
