# sandssrf

The new ERA of SSRF defense, the new title, prehaps you hear `The new ERA of SSRF` and so famous, that is `The new ERA of SSRF defense` not the attack itself, it is the new era of ssrf defense meaning that makes ssrf obselete vuln

That is our engineering decision of us, we thinked about how to mitigate truly SSRF, and that is the project that implements our decision

SSRF containment for Node.js. User-supplied URLs run against a **simulated internal network** inside a Linux
namespace; public traffic is unaffected, and the rest of your application is untouched.

- **Zero dependencies.** Pure Node — no native addon, no build step, no prebuilt binaries.
- **The kernel does the classifying.** Internal ranges are installed as routes, so longest-prefix match decides
  what is internal. There is no userspace range check to get wrong and no "unrecognised, therefore allowed" path.
- **DNS rebinding is not a category here.** Whatever address DNS returns, if it falls in a mocked range it goes to
  the mock. There is no check to win a race against.
- **Scoped per Agent.** Your database, cache and internal APIs keep working normally.
- **parser differential** That thing is finally fixed, the problem with dssrf and microsoft AntiSSRF and many ssrf libraries that is the big threat, to bypass them, that introduced in `Black USA` conference
   with the title `The new ERA of SSRF`, That is the most way you can bypass these anti ssrf libs, sandssrf solves it, the kernel manages the parsing and it is secure against that entire bypass modern class

## Difference with other libaries

it so important to ask `Why i create sandssrf?`, dssrf already the exist, the honest answer is `parser differential`, here sandssrf is secure against that class of bypass, dssrf is received a lot of advisories old versions
and our security community finds parser vulns, so that is the ultimate solution

## Usage

```js
const { createSSRFSandbox } = require('sandssrf');

const sandbox = createSSRFSandbox();
const agent = sandbox.Agent();

sandbox.on('blocked', (e) => log.warn('SSRF attempt', e));

// user-supplied URL
await fetchWith(agent, userUrl);

// All rest of normal usage, is unaffected
await pgcon.query('select 1');
```

## Install

```bash
npm install @insitetechjp/sandssrf
```

Linux only. Requires the `unshare` (util-linux) and `ip` (iproute2) binaries they must be present on Debian, Ubuntu, RHEL and
most base images. On Alpine: Run `apk add util-linux iproute2` to install them.

## How it works

`createSSRFSandbox()` spawns a helper process into a new user + network namespace:

```
unshare -Ur -n node helper.js
```

Inside that namespace, every internal range is installed with Linux **AnyIP**:

```
ip route add local 10.0.0.0/8     dev lo
ip route add local 169.254.0.0/16 dev lo
...
```

One listener then answers for every address in those ranges — 16.7 million addresses for `10/8` alone, with no TUN
device and no packet parsing.

When you request a connection:

1. The **parent** resolves the hostname once, in the host namespace.
2. Only the resulting **address** crosses into the helper, so no second lookup exists to poison, and the
   destination is pinned for the whole exchange.
3. The helper connects *inside* the sandbox and hands the connected socket back over `SCM_RIGHTS`
   which do (`process.send(msg, socket)`). A socket's namespace is fixed at creation and travels with the fd, so the parent
   ends up holding a socket that can only be ever reach the sandbox.
4. If the address has **no route** in the sandbox, the kernel says it is not internal, and the parent connects to
   that same pinned address for real.

HTTP Redirects need no special handling: each hop is a new connection, so each hop is contained.

## API

### `createSSRFSandbox(options?)` -> `Sandbox`

Returns immediately; the namespace starts in the background and connections queue until it is ready.

| Option | Default | Meaning |
| --- | --- | --- |
| `mock` | IANA special-purpose IPv4 + cloud metadata | IPv4 CIDRs answered by the simulated network |
| `mock6` | IANA special-purpose IPv6 | IPv6 CIDRs answered by the simulated network |
| `ports` | 80, 443, 8080, 6379, 5432, ... | ports the mock listens on |
| `allow` | `[]` | `"addr"` or `"addr:port"` reached for real despite matching a mocked range |
| `connectTimeout` | `10000` | the connect Timeout in ms |
| `startTimeout` | `10000` | The sandbox start timeout in ms |

### `sandbox.Agent(options?)` / `sandbox.httpsAgent(options?)`

`http.Agent` / `https.Agent` whose sockets come from the sandbox. TLS is unchanged because the socket connects by
address while the certificate is still verified against the hostname.

### `sandbox.connect(host, port)` -> `Promise<net.Socket>`

The primitive, for non-HTTP protocols. that is good news, many SSRF libaries, not have that feature just HTTP http agent, meaning you can use it safely for raw stuff, not just HTTP because SSRF begins to be outside of just HTTP

### `sandbox.ready()` / `sandbox.close()` / `sandbox.state`

`ready()` resolves when usable and **rejects if the sandbox cannot start** and it never fails silently.

### Events

- `ready` - `{ routes, requested, listening }` (`routes` === `requested`; the sandbox refuses to start if that requested range could not be contained)
- `blocked` - `{ host, method, path }`. An event that SSRF blocked with full details, not just a block, normally in ssrf libs, it just blocks or drops silently, it gives you nothing, sandssrf gives you what the attacker tried probing especially in your internal network
- `error` - An event indicating the sandbox became unusable.

## Containers

This is the one thing to check before deploying. Creating a user namespace needs unprivileged user namespaces to be permitted by the target containerzation technology:

| Runtime | Usually works? |
| --- | --- |
| Kubernetes (default) | **yes** - pods run seccomp `Unconfined` unless `SeccompDefault` is enabled |
| CRI-O / Podman | **yes** - their default profiles do not deny `clone(CLONE_NEWUSER)` |
| `docker run` (default) | **verify** — Docker's default seccomp profile is the restrictive one |

If the helper cannot start, `ready()` rejects with `SANDSSRF_UNAVAILABLE` and a message naming the likely cause.
For Docker, either `--security-opt seccomp=unconfined`, or run the fetching workload where user namespaces are
permitted.

## Limitations

Stated plainly, because a security library that hides these is worse than none.

- **Linux only.** `package.json` declares `"os": ["linux"]`, Expanding to more platforms is not possible, because Windows and MacOS do not have a good way to do so, windows does have HNS, but requires windows containres and Hyper-V which go against the complexity and unwanted stuff spawned, and heavy disk space, an SSRF defense libary must not bloat the disk.
- **Sockets it creates, not every socket in the process.** Traffic that does not go through a sandbox `Agent` by example
  a direct `fetch()` elsewhere, a subprocess like `curl` or `git`, a native addon by the way is not contained, That is expected behavior running commands is a bad praticse, and also it may lead bigger than SSRF many times, Command Injection.
- **Unmocked ports are refused, not simulated.** A destination inside a mocked range on a port the mock does not
  listen on gets `ECONNREFUSED`. Still contained, just not simulated. Extend `ports` if you need more mocked ports.
- **Public destinations are not restricted.** An attacker can still point you at any *public* host. That is a
  different control (a destination allowlist), that is Reverse SSRF whiches a different completly problem, That will be for it a seperate dressrf or similar, anyway that is another problem.
- **The mocked range list still matters.** The kernel classifies without error, but only over the ranges you give
  it. The defaults follow the IANA special-purpose registries; keep them current.
- **The mock is an oracle.** Whatever it returns is processed by your application as if real. It returns an inert,
  clearly-marked body and sets `x-sandssrf: mock` http header.
- **`fetch()`/undici** takes a `dispatcher`, not an `http.Agent`. Use `sandbox.Agent()` with `http`/`https`, or
  `sandbox.connect()` to build your own dispatcher.
- **Proxy** if you do use a proxy, it is not encought sandssrf to mitigate SSRF because the proxy rewrites and control the traffic whiches another layer, you need either avoid proxy, or use a safe proxy which will be soon available as a project
