// tests/_tls_stub.mjs
import EventEmitter from 'node:events';

class FakeTLSSocket extends EventEmitter {
  constructor(opts, ok) {
    super();
    this._opts = opts;
    this._ok = ok;
  }
  setTimeout(_ms) {}
  getProtocol() { return this._ok ? this._opts.minVersion : null; }
  getCipher() { return this._ok ? { name: 'TLS_FAKE_CIPHER' } : null; }
  end() { this.emit('end'); }
  destroy() { this.emit('close'); }
}

export function connect(options, onSecure) {
  const v = String(options?.minVersion || '');
  const ok = v === 'TLSv1.2' || v === 'TLSv1.3';
  const sock = new FakeTLSSocket(options, ok);
  queueMicrotask(() => {
    if (ok) {
      if (typeof onSecure === 'function') onSecure();
      sock.emit('secureConnect');
    } else {
      sock.emit('error', new Error('unsupported protocol version'));
    }
  });
  return sock;
}

export default { connect };
