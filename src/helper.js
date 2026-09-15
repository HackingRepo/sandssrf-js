"use strict";
// That module responsible for running and managing the SSRF sandbox.
//
// Responsibilities:
//   1. install AnyIP routes so every mocked range is delivered locally
//   2. serve the mock internal network
//   3. connect on request, and hand the CONNECTED socket back to the parent
//      over SCM_RIGHTS socket type process.send with that captured handle. The socket namespace is
//      fixed at socket() creation and travels with the FD, so the parent that in
//      the host namespace, ends up holding a socket that can only ever reach by
//      the sandbox.

const { execFileSync } = require("node:child_process");
const net = require("node:net");
const http = require("node:http");

// Parse the SANDSSRF config
const cfg = JSON.parse(process.env.SANDSSRF_CONFIG || "{}");
const mock4 = cfg.mock || [];
const mock6 = cfg.mock6 || [];
const ports = cfg.ports || [80];

// A simple wrapper that runs ip with the args, without getting any output
function ip(args) {
  try {
    execFileSync("ip", args, { stdio: ["ignore", "ignore", "pipe"] });
    return true;
  } catch {
    return false;
  }
}

// Same as ip sligtly, but that one returns the output, as a String
function ipOut(args) {
  try {
    return execFileSync("ip", args, { stdio: ["ignore", "pipe", "ignore"] })
      .toString();
  } catch {
    return null;
  }
}

// Converts an ipv6 address, to a raw 32 bit integer
function v4ToInt(a) {
  const o = a.split(".");
  if (o.length !== 4) throw new Error("bad v4");
  return o.reduce((n, p) => {
    const v = Number(p);
    if (!/^\d+$/.test(p) || v < 0 || v > 255) throw new Error("bad v4");
    return ((n << 8) >>> 0) + v;
  }, 0) >>> 0;
}

// Converts a raw 32 bit integer, into back an ip address
function intToV4(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(
    ".",
  );
}
function expandV6(a) {
  if (a.indexOf("::") !== a.lastIndexOf("::")) throw new Error("bad v6"); // Handles special edge case, when at most one '::'
  let head, tail;
  if (a.includes("::")) [head, tail] = a.split("::");
  else {
    head = a;
    tail = null;
  }
  const h = head ? head.split(":") : [];
  const t = tail === null ? null : (tail ? tail.split(":") : []);
  let groups;
  if (t === null) {
    if (h.length !== 8) throw new Error("bad v6");
    groups = h;
  } else {
    const miss = 8 - (h.length + t.length);
    if (miss < 1) throw new Error("bad v6");
    groups = [...h, ...Array(miss).fill("0"), ...t];
  }
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g || "0")) throw new Error("bad v6");
    n = (n << 16n) + BigInt(parseInt(g || "0", 16));
  }
  return n;
}

// Convert a raw ipv6 address into a string
function v6ToStr(n) {
  const p = [];
  for (let i = 0; i < 8; i++) {
    p.unshift((n & 0xffffn).toString(16));
    n >>= 16n;
  }
  return p.join(":");
}
function probeAddr(cidr) {
  const slash = cidr.indexOf("/");
  const addr = slash === -1 ? cidr : cidr.slice(0, slash);
  const len = slash === -1 ? null : Number(cidr.slice(slash + 1));
  if (addr.includes(":")) {
    if (len !== null && (!Number.isInteger(len) || len < 0 || len > 128)) {
      throw new Error("bad prefix");
    }
    const full = expandV6(addr);
    return (len === null || len >= 128) ? v6ToStr(full) : v6ToStr(full | 1n);
  }
  if (len !== null && (!Number.isInteger(len) || len < 0 || len > 32)) {
    throw new Error("bad prefix");
  }
  const n = v4ToInt(addr);
  return (len === null || len >= 32) ? intToV4(n) : intToV4((n | 1) >>> 0);
}

// Is a probe address inside `cidr` actually delivered to our mock like dev, lo?
// A malformed CIDR, which never installed, throws in probeAddr and is reported
// uncovered, by example we fail on anything we cannot positively confirm.
function covered(cidr, v6) {
  let addr;
  try {
    addr = probeAddr(cidr);
  } catch {
    return false;
  }
  const out = ipOut([...(v6 ? ["-6"] : []), "route", "get", addr]);
  return out !== null && /\bdev lo\b/.test(out);
}

// Bring loopback to the sandbox namespace
function setup() {
  if (!ip(["link", "set", "lo", "up"])) {
    throw new Error("could not bring up loopback in the sandbox namespace");
  }
  for (const cidr of mock4) ip(["route", "add", "local", cidr, "dev", "lo"]);
  for (const cidr of mock6) {
    ip(["-6", "route", "add", "local", cidr, "dev", "lo"]);
  }

  const requested = mock4.length + mock6.length;
  if (requested === 0) {
    throw new Error("no ranges to mock; the sandbox would contain nothing");
  }

  const uncovered = [];
  for (const cidr of mock4) if (!covered(cidr, false)) uncovered.push(cidr);
  for (const cidr of mock6) if (!covered(cidr, true)) uncovered.push(cidr);
  if (uncovered.length) {
    // Refuse if the mocked range are not routed inside the sandbox
    throw new Error(
      `${uncovered.length} of ${requested} mocked range(s) are not routed inside ` +
        `the sandbox and would reach the real network: ${
          uncovered.join(", ")
        }. ` +
        "Refusing to start rather than provide partial containment.",
    );
  }
  return requested;
}

// Serve a mock
function serveMock() {
  const handler = (req, res) => {
    send({
      type: "blocked",
      host: req.headers.host || null,
      method: req.method,
      path: req.url,
    });
    res.writeHead(200, { "content-type": "text/plain", "x-sandssrf": "mock" });
    res.end("sandssrf: simulated internal service\n");
  };
  let listening = 0;
  for (const port of ports) {
    const srv = http.createServer(handler);
    srv.on("error", () => {}); // a port we cannot bind is simply not mocked
    try {
      srv.listen(port, "0.0.0.0");
      listening++;
    } catch { /* ignore */ }
    srv.unref();
  }
  return listening;
}

function send(msg, handle, cb) {
  if (!process.send) return;
  try {
    process.send(msg, handle, cb);
  } catch { /* parent went away */ }
}

process.on("message", (m) => {
  if (!m || m.type !== "connect") return;

  // The parent has already resolved the hostname in the host namespace and
  // sends a literal address, so no DNS happens in here, basically the sandbox has no
  // route to a resolver and the address is pinned across the whole exchange.
  const sock = net.connect({ host: m.address, port: m.port });

  sock.once("connect", () => {
    // Wait for the send callback before releasing the fd: destroying it
    // immediately leads to a race condition between the SCM_RIGHTS transfer.
    send({ type: "socket", id: m.id }, sock, () => sock.destroy());
  });

  sock.once("error", (err) => {
    // No route inside the sandbox means the destination is not in any mocked
    // range by example in case, the kernel has classified it as external. The parent it may
    // then connect to it for real. Every other error stays an error.
    const code = err.code === "ENETUNREACH" || err.code === "EHOSTUNREACH"
      ? "fallthrough"
      : "error";
    send({ type: code, id: m.id, code: err.code });
    sock.destroy();
  });
});

try {
  const routes = setup();
  const listening = serveMock();
  // Report when the sandbox is ready
  send({
    type: "ready",
    routes,
    requested: mock4.length + mock6.length,
    listening,
  });
} catch (err) {
  // Report when the sandbox is failing fatal
  send({ type: "fatal", message: err.message });
  process.exit(1);
}

// Keep the process alive on the IPC channel alone.
process.on("disconnect", () => process.exit(0));
