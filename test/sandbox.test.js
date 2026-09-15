'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const { createSSRFSandbox } = require('../src/index.js');

const get = (url, opts) => new Promise((resolve) => {
  const req = http.get(url, opts, (res) => {
    let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ ok: true, status: res.statusCode, headers: res.headers, body: b }));
  });
  req.on('error', (e) => resolve({ ok: false, code: e.code, message: e.message }));
  req.setTimeout(8000, () => req.destroy(new Error('timeout')));
});

describe('sandssrf', { concurrency: false }, () => {
  let sb, agent, realService, blocked;

  before(async () => {
    // A real service on the host, standing in for something internal the app
    // must never expose to a user-supplied URL.
    realService = http.createServer((q, r) => r.end('REAL-HOST-SERVICE'));
    await new Promise((r) => realService.listen(48080, '127.0.0.1', r));

    sb = createSSRFSandbox();
    blocked = [];
    sb.on('blocked', (e) => blocked.push(e));
    await sb.ready();
    agent = sb.Agent();
  });

  after(async () => { await sb?.close(); realService?.close(); });

  test('the sandbox starts', () => {
    assert.equal(sb.state, 'ready');
  });

  describe('internal destinations on a mocked port are simulated', () => {
    for (const target of [
      'http://169.254.169.254/latest/meta-data/',
      'http://10.1.2.3/admin',
      'http://192.168.0.1/',
      'http://172.16.5.5/',
      'http://100.64.0.1/',
      'http://168.63.129.16/',
      'http://127.0.0.1/',
      'http://0.0.0.0/',
      'http://10.0.0.5:6379/',
      'http://192.168.1.1:8080/',
    ]) {
      test(target, async () => {
        const res = await get(target, { agent });
        assert.equal(res.ok, true, `expected the mock to answer, got ${res.code}`);
        assert.equal(res.headers['x-sandssrf'], 'mock',
          'the response must come from the simulated network, not a real service');
      });
    }
  });

  describe('internal destinations on an unmocked port are refused, never reached', () => {
    // Containment does not require simulation. A port the mock does not listen
    // on is refused inside the sandbox, which is equally safe, the matter is
    // that the real service on the host is never reached.
    for (const target of ['http://127.0.0.1:48080/', 'http://10.1.2.3:49999/']) {
      test(target, async () => {
        const res = await get(target, { agent });
        assert.equal(res.ok, false, 'must not succeed');
        assert.doesNotMatch(String(res.body ?? ''), /REAL-HOST-SERVICE/);
        assert.match(String(res.code), /ECONNREFUSED|SANDSSRF_/);
      });
    }
  });

  test('the same process reaches the real service without the sandssrf agent', async () => {
    const res = await get('http://127.0.0.1:48080/');
    assert.equal(res.body, 'REAL-HOST-SERVICE',
      'the rest of the application must be unaffected by the sandssrf sandbox');
  });

  test('containment is reported as an event', () => {
    assert.ok(blocked.length > 0, 'every mock hit is a high-confidence SSRF signal');
    assert.ok(blocked.some((e) => e.host && e.host.includes('169.254.169.254')));
  });

  test('an allowlisted destination is reached for real', async () => {
    const allowed = createSSRFSandbox({ allow: ['127.0.0.1:48080'] });
    await allowed.ready();
    const res = await get('http://127.0.0.1:48080/', { agent: allowed.Agent() });
    assert.equal(res.body, 'REAL-HOST-SERVICE');
    await allowed.close();
  });

  test('concurrent connections all transit the sandbox', async () => {
    const N = 40;
    const results = await Promise.all(
      Array.from({ length: N }, (_, i) => get(`http://10.${(i % 250) + 1}.0.9/x${i}`, { agent })));
    const mocked = results.filter((r) => r.ok && r.headers['x-sandssrf'] === 'mock').length;
    assert.equal(mocked, N, `${mocked}/${N} transited the sandbox`);
  });

  test('connect() pins the resolved address', async () => {
    // Resolution happens once, in the host namespace, and only address
    // crosses into the helper to make sure there is no second lookup to poison.
    let lookups = 0;
    const dns = require('node:dns');
    const real = dns.promises.lookup;
    dns.promises.lookup = async (h, o) => {
      if (h !== 'pinned.test') return real(h, o);
      lookups++;
      return o?.all ? [{ address: '10.9.9.9', family: 4 }] : { address: '10.9.9.9', family: 4 };
    };
    try {
      const res = await get('http://pinned.test/', { agent });
      assert.equal(res.headers['x-sandssrf'], 'mock');
      assert.equal(lookups, 1, `resolved ${lookups} times; must be exactly 1`);
    } finally { dns.promises.lookup = real; }
  });

  test('a destination with no route in the sandbox falls through to a real connect', async () => {
    // in case an address not in the mocked range and has no route inside the
    // namespace, so the helper reports ENETUNREACH and the parent connects
    const narrow = createSSRFSandbox({ mock: ['10.0.0.0/8'], mock6: [] });
    await narrow.ready();
    const calls = [];
    narrow._directConnect = (address, port) => {
      calls.push({ address, port });
      return Promise.resolve(new net.Socket());
    };

    await narrow.connect('203.0.113.5', 80);   // not mocked by this sandbox
    assert.deepEqual(calls, [{ address: '203.0.113.5', port: 80 }],
      'must fall through to a real connect, using the address already resolved');

    calls.length = 0;
    const inSandbox = await narrow.connect('10.1.2.3', 80);   // mocked
    assert.equal(calls.length, 0, 'a mocked destination must never fall through');
    inSandbox.destroy();
    await narrow.close();
  });

  test('close() makes further connections fail closed', async () => {
    const tmp = createSSRFSandbox();
    await tmp.ready();
    await tmp.close();
    await assert.rejects(() => tmp.connect('10.0.0.1', 80), /closed/);
  });
});

describe('failure is loud, never silent', () => {
  test('an unusable sandbox rejects instead of degrading', async () => {
    // No AnyIP routes can be installed, so the sandbox would mock nothing.
    // It must refuse rather than quietly pass traffic through the internet.
    const sb = createSSRFSandbox({ mock: [], mock6: [], startTimeout: 6000 });
    await assert.rejects(() => sb.ready(), (e) => e.code === 'SANDSSRF_UNAVAILABLE');
    await assert.rejects(() => sb.connect('93.184.216.34', 80), (e) => e.code === 'SANDSSRF_UNAVAILABLE');
    await sb.close();
  });
});

describe('partial route coverage fails closed, never open', () => {

  test('a range that cannot be installed makes the sandbox refuse to start', async () => {
    // 169.254.0.0/33 is not a valid prefix, so `ip route add` skips it. The old
    // behaviour installed 203.0.113.0/24, reported ready, and silently let the
    // 169.254 range (cloud metadata lives here) reach the real network. The sandbox must not start
    const sb = createSSRFSandbox({
      mock: ['203.0.113.0/24', '169.254.0.0/33'],
      mock6: [],
      startTimeout: 8000,
    });
    await assert.rejects(
      () => sb.ready(),
      (e) => e.code === 'SANDSSRF_UNAVAILABLE' && /169\.254\.0\.0\/33/.test(e.message),
      'must fail closed and name the range that would have escaped');
    // and a connection must not silently succeed either
    await assert.rejects(() => sb.connect('169.254.169.254', 80),
      (e) => e.code === 'SANDSSRF_UNAVAILABLE');
    await sb.close();
  });

  test('a fully-covered custom range list still starts (no false failure)', async () => {
    // The coverage check must not reject a legitimate config by example including
    // 127.0.0.0/8, whose `ip route add` always fails with EEXIST yet is in fact
    // routed locally by a pre-existing kernel route.
    const sb = createSSRFSandbox({ mock: ['10.0.0.0/8', '127.0.0.0/8', '192.168.0.0/16'], mock6: [] });
    await sb.ready();
    assert.equal(sb.state, 'ready');
    // the covered ranges are actually contained
    const res = await get('http://192.168.7.7/', { agent: sb.Agent() });
    assert.equal(res.headers?.['x-sandssrf'], 'mock');
    await sb.close();
  });
});

describe('readiness telemetry is correct', () => {
  test('the ready event reports covered == requested', async () => {
    const sb = createSSRFSandbox({ mock: ['10.0.0.0/8', '192.168.0.0/16'], mock6: ['fc00::/7'] });
    const ev = await new Promise((res, rej) => { sb.on('ready', res); sb.ready().catch(rej); });
    assert.equal(ev.requested, 3, 'must report how many ranges were requested');
    assert.equal(ev.routes, ev.requested, 'every requested range must be verified as contained');
    assert.ok(ev.listening > 0);
    await sb.close();
  });
});

describe('allow entries must be numeric, never a hostname', () => {
  test('a hostname allow entry is rejected at construction', () => {
    for (const bad of ['db.internal', 'db.internal:5432', 'not an ip', '']) {
      assert.throws(() => createSSRFSandbox({ allow: [bad] }),
        (e) => e.code === 'SANDSSRF_CONFIG',
        `allow:[${JSON.stringify(bad)}] must throw SANDSSRF_CONFIG`);
    }
  });

  test('numeric addr and addr:port entries must be still accepted', async () => {
    const sb = createSSRFSandbox({ allow: ['127.0.0.1', '10.0.0.1:6379', '::1', '[::1]:80'] });
    await sb.ready();
    assert.equal(sb.state, 'ready');
    await sb.close();
  });
});

describe('direct/allowlisted connects are time-bounded', { concurrency: false }, () => {
  test('a direct connect that never completes rejects with a timeout', async () => {
    const sb = createSSRFSandbox({ allow: ['203.0.113.9:80'], connectTimeout: 200 });
    await sb.ready();                                  // finish startup
    const realConnect = net.connect;
    net.connect = () => new net.Socket();             // never emits 'connect' or 'error'
    try {
      await assert.rejects(() => sb.connect('203.0.113.9', 80),
        (e) => e.code === 'SANDSSRF_TIMEOUT',
        'a hung direct connection must time out, not hang forever');
    } finally { net.connect = realConnect; }
    await sb.close();
  });
});

// Supply chain security tests
describe('packaging', () => {
  const pkg = require('../package.json');
  test('zero runtime dependencies', () => {
    assert.deepEqual(pkg.dependencies, {});
    assert.deepEqual(pkg.devDependencies, {});
  });
  test('no lifecycle scripts', () => {
    for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
      assert.equal(pkg.scripts[hook], undefined);
    }
  });
  test('declared entry points exist', () => {
    const fs = require('node:fs'), path = require('node:path');
    for (const rel of [pkg.main, pkg.types, pkg.exports['.'].require, pkg.exports['.'].types]) {
      assert.ok(fs.existsSync(path.join(__dirname, '..', rel)), `${rel} is declared but missing`);
    }
  });
  test('engines and os must be declared', () => {
    assert.ok(pkg.engines.node);
    assert.deepEqual(pkg.os, ['linux']);
  });
  test('files allow-list is set', () => {
    assert.ok(Array.isArray(pkg.files) && pkg.files.length > 0);
  });
});
