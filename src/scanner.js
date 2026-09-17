'use strict';

const fs = require('node:fs');
const net = require('node:net');

/** EICAR 测试签名：mocked 模式下用它验证全链路（生产上任何杀软都能识别） */
const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

/**
 * 病毒扫描器。
 *
 * 判定结果三态（必须区分「有毒」和「扫不了」）：
 *   { verdict:'clean' }                 干净
 *   { verdict:'infected', signature }   检出病毒 —— 对象删除、hash 拉黑、消息永不落库
 *   { verdict:'error', error }          扫描器自身故障 —— 由 failClosed 配置决定阻断或放行
 *
 * 模式：
 *   off     直通（仅限开发/测试显式关闭）
 *   mocked  可注入判定函数，默认命中 EICAR 即感染（测试用）
 *   clamav  ClamAV clamd INSTREAM 协议（TCP）
 */
class VirusScanner {
  constructor(config, { judge = null } = {}) {
    this.mode = config.virusScanMode;
    this.host = config.virusScanHost;
    this.port = numberOr(config.virusScanPort, 3310);
    this.failClosed = config.virusFailClosed;
    // 测试/定制注入：(filePath, asset) => boolean（true=感染）| 'error'
    this.judge = judge;
  }

  /** 扫描磁盘上的对象文件，返回三态判定 */
  async scanFile(filePath, asset = null) {
    if (this.mode === 'off') return { verdict: 'clean' };

    if (this.mode === 'mocked') {
      try {
        if (this.judge) {
          const r = await this.judge(filePath, asset);
          if (r === 'error') return { verdict: 'error', error: 'mocked scanner error' };
          return r ? { verdict: 'infected', signature: 'mocked.TEST' } : { verdict: 'clean' };
        }
        const buf = fs.readFileSync(filePath);
        if (buf.includes(Buffer.from(EICAR))) {
          return { verdict: 'infected', signature: 'EICAR.TEST' };
        }
        return { verdict: 'clean' };
      } catch (err) {
        return { verdict: 'error', error: err.message };
      }
    }

    if (this.mode === 'clamav') return this._scanClamav(filePath);

    return { verdict: 'error', error: `unknown scan mode: ${this.mode}` };
  }

  /** ClamAV INSTREAM：4 字节大端长度前缀 + 数据块（≤64KB），零长度块结束 */
  _scanClamav(filePath) {
    return new Promise((resolve) => {
      const socket = net.connect({ host: this.host, port: this.port });
      let reply = '';
      let settled = false;
      const done = (r) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(r);
      };

      socket.setTimeout(15_000);
      socket.on('timeout', () => done({ verdict: 'error', error: 'clamav timeout' }));
      socket.on('error', (err) => done({ verdict: 'error', error: err.message }));
      socket.on('data', (d) => {
        reply += d.toString();
        if (/:\s*(OK|FOUND|ERROR)[\s\S]*$/m.test(reply) || reply.includes('\0')) {
          if (/FOUND/.test(reply)) {
            const m = reply.match(/stream:\s*(.+?)\s*FOUND/);
            done({ verdict: 'infected', signature: (m && m[1]) || 'unknown' });
          } else if (/:\s*OK/.test(reply)) {
            done({ verdict: 'clean' });
          } else {
            done({ verdict: 'error', error: reply.trim() || 'clamav error' });
          }
        }
      });

      socket.on('connect', () => {
        socket.write('zINSTREAM\0');
        const rs = fs.createReadStream(filePath, { highWaterMark: 64 * 1024 });
        rs.on('data', (chunk) => {
          // ClamAV 要求每块 ≤ 64KB；highWaterMark 不保证上限，这里再切一刀
          for (let off = 0; off < chunk.length; off += 64 * 1024) {
            const part = chunk.subarray(off, off + 64 * 1024);
            const len = Buffer.alloc(4);
            len.writeUInt32BE(part.length, 0);
            socket.write(len);
            socket.write(part);
          }
        });
        rs.on('end', () => socket.write(Buffer.alloc(4))); // 零长度块 = 结束
        rs.on('error', (err) => done({ verdict: 'error', error: err.message }));
      });
    });
  }

  /** 按 failClosed 策略把扫描器故障归一化为最终判定 */
  applyFailurePolicy(result) {
    if (result.verdict !== 'error') return result;
    return this.failClosed
      ? { verdict: 'error', error: result.error } // 阻断：资产停在 scan_error，消息不能发
      : { verdict: 'clean', warned: true, error: result.error }; // 放行但留痕
  }
}

function numberOr(v, dflt) {
  const n = Number(v);
  return Number.isFinite(n) ? n : dflt;
}

module.exports = { VirusScanner, EICAR };
