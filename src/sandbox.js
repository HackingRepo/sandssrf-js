"use strict";

const { spawn, execFileSync } = require("node:child_process");
const { EventEmitter } = require("node:events");
const dns = require("node:dns");
const net = require("node:net");
const http = require("node:http");
const https = require("node:https");
const tls = require("node:tls");
const path = require("node:path");

const ranges = require("./ranges");
const { SandboxUnavailableError, SandboxError } = require("./errors");

const HELPER = path.join(__dirname, "helper.js");

function haveBinary(name) {
  try {
    execFileSync("sh", ["-c", `command -v ${name}`], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

// check is the allow-list is matched against the *resolved numeric address*, so a
// hostname entry like "db.internal" must never match and would be silently
// mocked without any notice, the operator believing they had carved it out. Reject non-numeric
// allow list entries
function validateAllow(list) {
  if (!Array.isArray(list)) {
    throw new SandboxError(
      'the "allow" option must be an array of "addr" or "addr:port" strings',
      "SANDSSRF_CONFIG",
    );
  }
  for (const entry of list) {
    if (typeof entry !== "string" || allowHost(entry) === null) {
      throw new SandboxError(
        `allow entry ${
          JSON.stringify(entry)
        } is not a numeric address or "addr:port". ` +
          "Hostnames are not supported here (they are matched against the resolved " +
          "address); resolve it yourself or use a literal IP.",
        "SANDSSRF_CONFIG",
      );
    }
  }
  return list;
}

// The IP part of an "addr" or "addr:port" entry, or null if it is not numeric.
// Handles bare IPv4/IPv6, "v4:port", and square bracketed "[v6]:port" formats.
function allowHost(entry) {
  if (net.isIP(entry)) return entry; // bare IPv4 or IPv6
  if (entry.startsWith("[")) { // [v6] or [v6]:port
    const end = entry.indexOf("]");
    if (end > 0 && net.isIP(entry.slice(1, end))) {
      const rest = entry.slice(end + 1);
      if (rest === "" || /^:\d+$/.test(rest)) return entry.slice(1, end);
    }
    return null;
  }
  const i = entry.lastIndexOf(":"); // v4:port just one single colon
  if (
    i > 0 && /^\d+$/.test(entry.slice(i + 1)) && net.isIP(entry.slice(0, i))
  ) {
    return entry.slice(0, i);
  }
  return null;
}

class Sandbox extends EventEmitter {
  constructor(options = {}) {
    super();
    this._opts = {
      mock: options.mock || ranges.defaultMock(),
      mock6: options.mock6 || ranges.defaultMock6(),
      ports: options.ports || ranges.DEFAULT_PORTS,
      allow: new Set(validateAllow(options.allow || [])),
      connectTimeout: options.connectTimeout ?? 10000,
      startTimeout: options.startTimeout ?? 10000,
    };
    this._pending = new Map();
    this._nextId = 1;
    this._state = "starting";
    this._error = null;
    this._child = null;
    this._readyPromise = this._start();
    this._readyPromise.catch(() => {});
  }

  get state() {
    return this._state;
  }

  _start() {
    return new Promise((resolve, reject) => {
      for (const bin of ["unshare", "ip"]) {
        if (!haveBinary(bin)) {
          // If the required binaries, not installed tell the operator, that they need install them
          return reject(this._fail(
            `the "${bin}" binary is required but was not found. ` +
              "On Alpine: apk add util-linux iproute2. On Debian/Ubuntu: apt install util-linux iproute2.",
          ));
        }
      }

      const config = JSON.stringify({
        mock: this._opts.mock,
        mock6: this._opts.mock6,
        ports: this._opts.ports,
      });

      let child;
      try {
        // Create the namespace
        child = spawn("unshare", ["-Ur", "-n", process.execPath, HELPER], {
          stdio: ["ignore", "ignore", "pipe", "ipc"],
          env: { ...process.env, SANDSSRF_CONFIG: config }, // Pass the SANDSSRF config
        });
      } catch (err) {
        // If the namespace cannot be created, tell the operator why, instead of failing open
        return reject(
          this._fail(`could not spawn the sandbox helper: ${err.message}`),
        );
      }
      this._child = child;

      let stderr = "";
      child.stderr?.on("data", (d) => {
        stderr += d.toString().slice(0, 4096);
      });

      const timer = setTimeout(() => {
        // If the sandbox hangs exceeds the start timeout, fail close, not hanging forever
        reject(
          this._fail(
            `the sandbox helper did not become ready within ${this._opts.startTimeout}ms`,
          ),
        );
        child.kill("SIGKILL");
      }, this._opts.startTimeout);
      timer.unref?.();

      child.on(
        "message",
        (m, handle) =>
          this._onMessage(m, handle, {
            resolve,
            reject,
            timer,
            stderr: () => stderr,
          }),
      );

      child.on("error", (err) => {
        clearTimeout(timer);
        reject(this._fail(`sandbox helper failed to start: ${err.message}`));
      });

      child.on("exit", (code, signal) => {
        clearTimeout(timer);
        const wasReady = this._state === "ready";
        if (this._state !== "closed") {
          const detail = stderr.trim()
            ? `: ${stderr.trim().split("\n").pop()}`
            : "";
          // If the namespace failed to be created due to issues, report to the user, what is the reason and the status code and also it is likely related to restrictions of creation
          // Of a user namespace
          const err = this._fail(
            `sandbox helper exited (code=${code} signal=${signal})${detail}. ` +
              "This usually means the container forbids creating a user namespace " +
              "(Docker's default seccomp profile). Try --cap-add SYS_ADMIN or " +
              "--security-opt seccomp=unconfined, or run the probe in the README.",
          );
          if (!wasReady) reject(err);
        }
        // fail every in-flight request rather than leaving them hanging
        for (const [, p] of this._pending) {
          p.reject(
            this._error || new SandboxError("helper exited", "SANDSSRF_CLOSED"),
          );
        }
        this._pending.clear();
      });

      child.unref?.();
    });
  }

  _onMessage(m, handle, boot) {
    if (!m || typeof m !== "object") return;

    if (m.type === "ready") {
      clearTimeout(boot.timer);
      this._state = "ready";
      this.emit("ready", {
        routes: m.routes,
        requested: m.requested,
        listening: m.listening,
      });
      return boot.resolve(this);
    }
    if (m.type === "fatal") {
      clearTimeout(boot.timer);
      return boot.reject(this._fail(m.message));
    }
    if (m.type === "blocked") {
      // The mock answered. No legitimate user fetches an internal by accident, so this
      // is a high-confidence SSRF signal, not false positive noise.
      this.emit("blocked", { host: m.host, method: m.method, path: m.path });
      return;
    }

    const p = this._pending.get(m.id);
    if (!p) {
      handle?.destroy?.();
      return;
    }
    this._pending.delete(m.id);

    if (m.type === "socket") return p.resolve(handle);
    if (m.type === "fallthrough") return p.fallthrough();
    return p.reject(
      // If the connection, failed in the sandbox, report that
      new SandboxError(
        `connection to ${p.address}:${p.port} failed inside the sandbox (${m.code})`,
        m.code,
      ),
    );
  }

  _fail(message) {
    const err = new SandboxUnavailableError(message);
    this._state = "failed";
    this._error = err;
    // EventEmitter throws when 'error' is emitted with no listener, which would
    // turn a handled startup failure into an uncatchable crash.
    if (this.listenerCount("error") > 0) this.emit("error", err);
    return err;
  }

  /** Resolves when the sandbox is usable; rejects if it can never be. */
  ready() {
    return this._readyPromise;
  }

  /**
   * Resolve once in the host namespace, then connect inside the sandbox.
   * Because the address is not the hostname, that is what crosses into the helper,
   * there is no second resolution for a rebinding attack to poison.
   */
  async connect(host, port) {
    if (this._state === "failed") throw this._error;
    if (this._state === "closed") {
      throw new SandboxError("sandbox is closed", "SANDSSRF_CLOSED");
    }
    await this._readyPromise;

    const address = net.isIP(host) ? host : await this._resolve(host);

    if (
      this._opts.allow.has(`${address}:${port}`) ||
      this._opts.allow.has(address)
    ) {
      return this._directConnect(address, port);
    }
    return this._sandboxConnect(address, port);
  }

  async _resolve(host) {
    let list;
    try {
      list = await dns.promises.lookup(host, { all: true });
    } catch (err) {
      // If the dns cannot rsolve the host
      throw new SandboxError(
        `could not resolve "${host}" (${err.code})`,
        "SANDSSRF_DNS",
      );
    }
    if (!list.length) {
      // If the dns does not resolve the host to anything, error out
      throw new SandboxError(
        `"${host}" resolved to no addresses`,
        "SANDSSRF_DNS",
      );
    }
    return list[0].address;
  }

  _sandboxConnect(address, port) {
    return new Promise((resolve, reject) => {
      const id = this._nextId++;
      const timer = setTimeout(() => {
        this._pending.delete(id);
        // If the connection stalls, reject that as a timeout, to protect the rest of the web app, and avoiding DoS
        reject(
          new SandboxError(
            `connection to ${address}:${port} timed out`,
            "SANDSSRF_TIMEOUT",
          ),
        );
      }, this._opts.connectTimeout);
      timer.unref?.();

      const done = (fn) => (...args) => {
        clearTimeout(timer);
        fn(...args);
      };

      this._pending.set(id, {
        address,
        port,
        resolve: done(resolve),
        reject: done(reject),
        // No route inside the sandbox: the kernel says this destination is not
        // in any mocked range, so it is safe to reach for real host network.
        fallthrough: done(() =>
          this._directConnect(address, port).then(resolve, reject)
        ),
      });

      try {
        this._child.send({ type: "connect", id, address, port });
      } catch (err) {
        clearTimeout(timer);
        this._pending.delete(id);
        reject(this._error || err);
      }
    });
  }

  _directConnect(address, port) {
    return new Promise((resolve, reject) => {
      const sock = net.connect({ host: address, port });
      // If the whitelisted target, hang, abort the connection with a timeout
      const timer = setTimeout(() => {
        sock.destroy();
        reject(
          new SandboxError(
            `connection to ${address}:${port} timed out`,
            "SANDSSRF_TIMEOUT",
          ),
        );
      }, this._opts.connectTimeout);
      timer.unref?.();
      sock.once("connect", () => {
        clearTimeout(timer);
        resolve(sock);
      });
      sock.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  /** An http.Agent whose sockets come from the sandbox. */
  Agent(options = {}) {
    // keepAlive defaults off; a caller may enable it. This is safe: http.Agent
    // pools sockets per origin (host:port), and every new origin still goes
    // through createConnection below, so a pooled socket is only ever reused for
    // the same contained destination -- it cannot leak across a redirect.
    const agent = new http.Agent({ keepAlive: false, ...options });

    // createConnection is a METHOD on http.Agent, it is not a constructor option.
    // Passing it to the constructor is silently ignored without any errors and every request would
    // go direct, which will fail-open with no error. Assign it here instead.
    agent.createConnection = (opts, cb) => {
      this.connect(opts.host || opts.hostname, Number(opts.port) || 80)
        .then((sock) => cb(null, sock), cb);
    };
    return agent;
  }

  /** An https.Agent whose sockets come from the sandbox. TLS is unchanged: we
   *  connect by address and still verify the certificate against the hostname 
   * to restore legitimate TLS access, without introducing a security risk. */
  httpsAgent(options = {}) {
    const agent = new https.Agent({ keepAlive: false, ...options });
    agent.createConnection = (opts, cb) => {
      const hostname = opts.host || opts.hostname;
      this.connect(hostname, Number(opts.port) || 443)
        .then((sock) => {
          const tlsSock = tls.connect({
            ...opts,
            socket: sock,
            servername: opts.servername ||
              (net.isIP(hostname) ? undefined : hostname),
          });
          tlsSock.once("secureConnect", () => cb(null, tlsSock));
          tlsSock.once("error", cb);
        }, cb);
    };
    return agent;
  }

  async close() {
    if (this._state === "closed") return;
    this._state = "closed";
    for (const [, p] of this._pending) {
      p.reject(new SandboxError("sandbox closed", "SANDSSRF_CLOSED"));
    }
    this._pending.clear();
    if (this._child && this._child.connected) this._child.disconnect();
    this._child?.kill("SIGTERM");
  }
}

// Export the Sandbox class
module.exports = { Sandbox };
