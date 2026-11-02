# TLS plaintext visibility by library uprobes: viability

Status: **viability assessment (go / no-go), not a build design.** Written 2026-11-02 against
`docs/design/network-detection.md` (section 6.3 already scopes "plaintext at the TLS library
boundary" as a LATER mimi capability, after the connect, DNS and SNI probes; this doc builds on
that and does not reopen it), mimi as it is today (one tracepoint, `sched_process_exec`; the
probe copies, the loader parses; CO-RE off the kernel's BTF; a DynamicUser unit with
`CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_ADMIN`/`CAP_DAC_READ_SEARCH`), and banken's `Event`
(`internal/event/event.go`: typed Sysmon-named fields plus `Raw`, matchable by Sigma name).
Nothing here is built; no code is changed by this doc.

The question: can banken, through mimi, see the exact URL, method and headers of HTTPS traffic on
the host - without a MITM proxy, without a CA, without touching the traffic - by putting eBPF
uprobes on the TLS library's plaintext boundary (`SSL_write`/`SSL_read` and equivalents)? And is
it worth doing?

## 0. Verdict first

**viable-with-conditions.**

- It works, it is proven prior art (bcc `sslsniff`, ecapture, Pixie/Stirling, DeepFlow, Beyla),
  and it stays listener-only: a uprobe reads a buffer the process already holds in plaintext and
  cannot slow, alter or block the connection beyond its own trap cost.
- It is viable for ONE population: processes that call a **dynamically linked** OpenSSL, GnuTLS
  or NSS (plus Node, which exports its bundled OpenSSL symbols). For that population the
  attach is by exported symbol, the public function signatures have been stable for twenty years,
  and the correlation to the connection can be done with no library struct offsets at all.
- It is **permanently dark**, without per-binary work, for Go's `crypto/tls`, rustls, statically
  linked and stripped OpenSSL (static curl, python-build-standalone, Bun/Electron/Chrome
  BoringSSL), Java's JSSE, and every HTTP/3 stack. That is the population an attacker's tooling
  and most cloud-native infrastructure come from. The doc says so and the ledger must too.
- The Go path is "done" by three projects and is NOT recommended for mimi: a per-Go-release
  offsets treadmill with unsafe uretprobes, against simple-is-good.
- SNI + DNS names (sections 3.5 and 6.1 of the network design, already MITM-free, far cheaper,
  and covering EVERY stack because they are on the wire) get most of the hostname-keyed detection
  value. URL capture adds a different class (URI patterns, user agents, exfil method detail: the
  SigmaHQ `proxy` rules) that names cannot give. Sequence it AFTER connect, DNS and SNI, and only
  after a census of the TLS stacks on the hosts that matter.

Top three conditions, in order: (1) OpenSSL/GnuTLS/NSS-dynamic only, declared as such in the
scope ledger, no Go in the first cut; (2) opt-in, headers-only, bounded bytes, `Authorization`/
`Cookie` redacted by default, bodies never; (3) a census first (which libraries the live processes
on hokkaido actually map) so the decision to build rests on a measured share, not an estimate.

## 1. Does it work, and how

### 1.1 The mechanism

A TLS library has exactly one place where the application hands it plaintext to encrypt
(`SSL_write(ssl, buf, num)`) and one where it hands decrypted plaintext back
(`SSL_read(ssl, buf, num)` returning the count). A uprobe on the entry of `SSL_write` sees
`buf` and `num` in the first three argument registers; a uprobe on the entry of `SSL_read` saves
`buf` per thread and a uretprobe reads the return value and copies that many bytes. The probe
copies a bounded prefix of the buffer into the ring buffer with the pid/tid, uid, comm and a
direction flag; the loader does everything else (exactly mimi's rule today: the probe copies, the
loader parses). Nothing is parsed in BPF.

The equivalents: OpenSSL and BoringSSL `SSL_write`/`SSL_read` and the `_ex` variants
(`SSL_write_ex`/`SSL_read_ex`, which CPython's `_ssl` module uses, with the byte count in an
out-parameter read on return); GnuTLS `gnutls_record_send`/`gnutls_record_recv`; NSS
`PR_Write`/`PR_Read`/`PR_Send`/`PR_Recv` (Firefox, Thunderbird); mbedTLS/wolfSSL
`mbedtls_ssl_write`/`wolfSSL_write` (embedded, rare on a server; same shape).

### 1.2 Correlating plaintext to the connection

`SSL_write` takes an `SSL*`, not an fd. Two ways to get from the call to a socket:

- **Struct offsets** (the ecapture way): read `ssl->rbio->num` (the fd) through a per-OpenSSL-
  version table of `ssl_st`/`bio_st` offsets. Works, but the layouts change across 1.0.2 /
  1.1.0 / 1.1.1 / 3.x and there is no BTF for user libraries, so it is a hand-maintained table.
  That is the "CO-RE-shaped work with no BTF to lean on" that section 6.3 warned about.
- **Nesting** (the Pixie/Stirling way): `SSL_write` calls `write`/`send`/`sendmsg` on the socket
  before it returns. A uprobe sets a per-thread "inside SSL_write, buf, len" record; a kprobe on
  `tcp_sendmsg` (or the `sys_enter_sendto`/`write` tracepoints) fired by the SAME thread while
  that record is live supplies the socket. With `tcp_sendmsg` the `struct sock` is the first
  argument and `bpf_get_socket_cookie` gives the same cookie the connect probe (3.4) can stamp on
  its `connect` event, so the loader joins plaintext to the 4-tuple on (pid, cookie) with zero
  user-library offsets. Edge: a write that buffers (non-blocking EAGAIN, a BIO buffer) will not
  nest a send that time; the ssl pointer to cookie mapping, once seen, is cached per process.

The nesting approach is the one that fits mimi: offset-free, library-version-free, and it reuses
the socket cookie the network design already keeps in `Raw`.

### 1.3 Reassembly

One HTTP request is not one `SSL_write`. curl sends the request line and headers in one call and a
body in another; CPython's `http.client` does the same; nginx streams responses in many. The
loader keeps a small per-(pid, cookie, direction) buffer with a byte cap and emits an event when it
has a complete header block (`\r\n\r\n`) that starts with a method token and a path, then
resyncs on the next message boundary. Keep-alive connections carry many requests; pipelining is
rare enough to treat as "first request of the buffer, rest dropped and counted". HTTP/2 is a
different problem (section 3.3).

### 1.4 Prior art and what each proves

- **bcc `sslsniff`** (iovisor): the canonical demonstration. uprobes on `SSL_write`/`SSL_read`,
  `gnutls_record_send`/`recv`, NSS `PR_Write`/`PR_Read`; prints the plaintext with pid and comm.
  Proves: the mechanism is a few hundred lines and the symbols are stable.
- **ecapture** (gojue): Go + eBPF, no CA. Captures plaintext from OpenSSL/BoringSSL/GnuTLS/NSS by
  uprobe, with the fd read through per-version `ssl_st` offset tables (it ships a table per
  OpenSSL release); also captures TLS master secrets to write a decryptable pcapng; has a
  `gotls` mode that hooks Go's `crypto/tls` by symbol. Proves: dynamic libs are easy; the per-
  version offset table is the maintenance cost; Go is possible but per-Go-version.
- **Pixie / Stirling** (px.dev, CNCF): production eBPF tracer. OpenSSL by uprobe with the nested-
  syscall correlation; Go TLS by uprobes on `crypto/tls.(*Conn).Write`/`Read` with the Go
  register ABI, Go version read from `.go.buildinfo`, struct offsets from DWARF when present and
  from a generated per-version table otherwise; avoids uretprobes on Go (they crash Go programs
  when the stack is moved) by probing every `RET` found by disassembly; parses HTTP/1, HTTP/2
  (HPACK), gRPC and others in userspace. Proves: Go is viable at the cost of a dedicated team.
- **DeepFlow** (Yunshan, CNCF sandbox): OpenSSL and Go TLS uprobes, HTTP/1 and HTTP/2 including
  Go's `http2` package, per-Go-version handling. Proves the same as Pixie: feasible, heavy.
- **Beyla / OpenTelemetry eBPF Instrumentation** (Grafana, donated 2025): for Go it does NOT hook
  TLS at all, it hooks `net/http` directly (`ServeHTTP`, `(*Client).do`, the http2 transport) and
  reads method/URL/status from Go structs through a per-Go-version offsets table it generates in
  CI; for everything else, OpenSSL uprobes plus kprobes. Proves: the Go answer is "hook above
  TLS", and it needs a generated offsets table maintained per Go release.

Nothing in this list has a Rust/rustls, Java or Chromium/BoringSSL-static answer by symbol.
That absence is itself data.

## 2. Coverage, per TLS stack, honestly

This is the crux. A uprobe needs an address. A dynamically linked library gives one by exported
symbol with no work; anything else needs per-binary work or is out of reach.

### 2.1 Dynamically linked OpenSSL / GnuTLS / NSS: feasible

Attach by exported symbol (`SSL_write` in `libssl.so.3`, `gnutls_record_send` in
`libgnutls.so.30`, `PR_Write` in `libnspr4.so`). aya resolves the symbol from the ELF and
attaches; the public C signatures are stable across every release in use. Version drift on this
path is near zero if the fd comes from nesting (1.2) and not from `ssl_st` offsets.

Who is here, on a Linux host: nginx, Apache, HAProxy, Postfix, Dovecot, curl and libcurl (git
over https, nix, apt/dnf via libcurl or GnuTLS), wget, OpenSSL `s_client`, CPython's `ssl`
module as distros and nixpkgs build it, PHP, Ruby, Perl, systemd-resolved's DoT, OpenVPN,
Firefox (NSS), Node's official binary (it bundles OpenSSL statically but EXPORTS the symbols for
native addons, so it attaches like a library; confirm with `nm -D` on the deployed binary).

Operational cost that is real on NixOS: there is no one `libssl.so.3`. Every closure that carries
its own OpenSSL is a different store path, and each is a separate inode to attach to. The loader
must discover libraries from the live processes (`/proc/PID/maps`, triggered by the exec events
mimi already has) rather than from a fixed path, continuously, and must attach to new paths
after a rebuild. Pixie does exactly this; it is loader work, not probe work, but it is the
largest new piece of the loader and it needs `/proc` visibility the unit does not have today
(section 4).

### 2.2 Go `crypto/tls` (static, no libssl): viable in principle, not recommended for mimi

Go never calls libssl. The plaintext boundary is `crypto/tls.(*Conn).Write` and `Read`, linked
into every Go binary. What it takes, all of it per binary and per Go release:

- Symbol resolution: Go keeps function names in `.gopclntab` even after `-s -w`, so a stripped Go
  binary is still resolvable (unlike stripped C). Obfuscated builds (garble) remove them: dark.
- Calling convention: register ABI since Go 1.17 (arguments in AX, BX, CX, DI, SI, R8...),
  different before; the Go version is in `.go.buildinfo`.
- Return values: uretprobes are unsafe on Go (goroutine stacks are moved and the uretprobe's
  patched return address breaks it). Pixie disassembles the function and places a uprobe on each
  `RET`. That is a disassembler in the loader.
- The connection: `(*Conn).conn` is an interface holding a `*net.TCPConn` whose fd is several
  struct hops down, every hop an offset that changes with Go releases. Pixie reads DWARF when it
  is there (it usually is not in shipped binaries) and ships a generated offsets table otherwise;
  Beyla generates one per Go version in CI. Nesting (1.2) also works for Go and avoids the fd
  hops; it does not avoid the ABI and RET work.
- HTTP/2: Go clients and servers speak h2 by default on TLS, so the plaintext at the TLS
  boundary is HPACK-compressed frames (3.3). Beyla and DeepFlow hook the `http2` package instead.

So: feasible, demonstrated by three projects, and each of them staffs it as a product line. It is
a per-Go-release treadmill (two releases a year, plus the `net/http` internals moving) with a
disassembler and an offsets generator in the loader. For mimi this fails simple-is-good and
"no rough edges" (a crucial offsets table is exactly an unexplained constant). The one honest
alternative with a fixed cost is to reuse Beyla/OBI's generated offsets table as data; that is a
dependency decision for later, if the census (2.5) says Go matters enough.

What a Go process still gives with no per-binary work: its DNS query (3.5 of the network design,
Go's resolver speaks UDP to the stub), its SNI (6.1), its 4-tuple (3.4). Names, not URLs.

### 2.3 What breaks, and what is out of reach

- **rustls** (uv, deno, rustup, many Rust CLIs and a growing share of Rust services): no C
  symbols; the internal functions are monomorphised and mangled per crate version, inlined at
  will. No stable address to probe. Dark.
- **Statically linked OpenSSL, stripped**: a static curl, python-build-standalone (what uv
  installs: `_ssl` carries its own OpenSSL with the symbols local), most container-shipped
  single-file binaries. No exported symbol. Signature scanning for `SSL_write`'s code pattern is
  possible and is per-build fragile; out of scope. Dark.
- **musl / Alpine**: Alpine's packaged `libssl3.so` is dynamic and probeable like glibc's; the
  issue is static builds, not musl itself.
- **BoringSSL inside Chrome, Electron (VS Code, Slack, Discord), Bun** (the native `claude`
  binary is a Bun-compiled executable): BoringSSL statically linked, symbols not exported or
  stripped. Dark by symbol. Measure the actual `claude` binary with `nm -D` before assuming
  either way; ecapture's BoringSSL support is for Android's exported `libssl.so`, not for these.
- **Java (JSSE)**: TLS in Java bytecode, no native boundary. Dark to uprobes; a JVMTI agent is
  the only route, which is not mimi.
- **HTTP/3 / QUIC**: encryption inside the application's QUIC stack (quiche, ngtcp2, msquic,
  quic-go, Chrome). OpenSSL 3.2+ QUIC clients do go through `SSL_write` on a stream object, which
  is probeable; everything else is dark. Browsers to CDNs are increasingly h3.
- **kTLS**: nginx/OpenSSL with kernel TLS offload hands plaintext to `sendmsg` on a kTLS socket,
  encrypted in the kernel. A kprobe on `tls_sw_sendmsg` sees it; a different hook, minor.
- **Detectability**: a uprobe is an `int3` in the process's text; a process that compares its own
  `SSL_write` bytes to the file sees it. Rare, cheap for malware, worth a line in the security
  model, not a blocker.

### 2.4 Net: what share does the dynamic path give

No honest universal percentage exists; it depends entirely on which hosts. By population class:

- **A classic distro server** (web/mail/proxy daemons, package manager, scripting runtimes,
  curl/git/wget): the dynamic path sees the clear majority of HTTPS by request volume. This is
  the fleet the prior art was built for and where it earns its keep.
- **A cloud-native / Go-heavy host** (docker, containerd, kubelet, etcd, Prometheus, Grafana,
  Terraform, Vault, Caddy, Traefik, gh, kubectl, helm, tailscale, restic, rclone, gitea): the
  dynamic path sees a minority; most HTTPS is Go, dark.
- **Attacker tooling and droppers**: static Go, static Rust, static C. Dark, first. Section 6.3
  of the network design already says "the population an attacker brings is the population this
  misses first"; nothing here changes that.
- **An agent host like hokkaido** (the `claude` user): git/curl/nix/python/node are covered;
  `gh` (Go), `uv` (rustls) and the Bun-built `claude` itself are dark by symbol. Note that on
  this host the per-agent proxy in nixos-agent-containment already sees destination host:port
  for the agent's traffic (CONNECT, not MITM), so names are already in hand there; URLs would be
  the new datum, and the agent binary that issues most of them is the one most likely dark.

### 2.5 The census that should precede any build

Before deciding, measure on the hosts that matter, with no code written: for every live process,
which TLS library (if any) its `/proc/PID/maps` shows mapped, and for each static binary that
talks TLS whether `nm -D` exports `SSL_write`. One evening, a table of (process, stack,
probeable yes/no), and the decision rests on the host's actual population. If the probeable
column is a minority of the processes you care about, stop here and keep names.

## 3. The hard parts and costs

### 3.1 Symbol and offset resolution, version drift

Dynamic C libraries: attach by symbol, stable signatures, no drift worth naming. The drift is
elsewhere: the per-host library discovery (2.1), and the `_ex` variants and NSS/GnuTLS names,
each a short fixed list. Avoid `ssl_st` offsets entirely by nesting (1.2); the day something needs
the TLS version or the SNI from the SSL object, SNI already comes from the ClientHello probe.

Go: everything drifts (2.2). Not in the first cut.

### 3.2 Reassembly and partial reads

Loader-side, per (pid, cookie, direction), byte-capped (a few KB), time-capped, emits on a
complete HTTP/1.x header block, drops and counts anything else (binary protocols, a request that
started before attach, an over-cap header block). Testable on the Mac with fixtures the way
`mimi-types` tests the exec parsing today. Bodies are never buffered; the cap is the design.

### 3.3 HTTP/2 and HPACK

On TLS, curl with `--http2`, every browser, every Go client and most gRPC speak h2. The headers
are HPACK-compressed against a dynamic table built up over the connection. Decoding needs the
connection's state from its first frame; a connection that began before mimi attached (every
long-lived one at startup) is undecodable except for literal-encoded headers. The loader needs an
HPACK decoder (a bounded, well-specified thing; the Go `x/net/http2/hpack` has a Rust equivalent)
and must mark "h2, headers undecodable" honestly for mid-stream connections. HTTP/1.1-only in
the first cut, with h2 counted and reported, is the simple version.

### 3.4 Throughput and overhead

A uprobe costs an `int3` trap plus the BPF program, on the order of a few microseconds per hit,
noticeably more than a kprobe. A busy TLS server doing tens of thousands of requests a second
with two to four `SSL_write`/`SSL_read` calls each spends a measurable fraction of a core in
the probes; Pixie reports low single-digit percent CPU at typical loads. On an agent host or a
dev box it is noise. The copy is bounded (first N bytes per call, N in the low KB) so the ring
buffer traffic is proportional to request count, not bytes. The loader must never back-pressure
the application: a full ring drops and counts (the `DROPS` map mimi already has), it does not
stall. That bound is also the listener-only guarantee under load.

The existing benchmark harness (`docs/design/benchmarking.md`) should carry a line for this probe
on and off against a local nginx or a curl loop before it ships to any host.

### 3.5 PII and privacy: the real policy cost

This is the one cost that is not engineering. Today banken holds execs, files and connections.
With this probe it holds, for every probeable process of every user including root, the full
request line and headers of every HTTPS exchange: `Authorization: Bearer ...`, session cookies,
API keys in query strings, the URLs of everything anyone on the host visits. An EDR that writes
that to `/var/log/mimi/events.jsonl` is holding every credential on the host in one file.

Minimum conditions, non-negotiable in the design that follows this doc:

- Off by default; one option turns it on (`services.mimi.tls.enable`), per the containment
  tenet "every permission one option".
- Headers only, never bodies. A byte cap in the probe, not just the loader.
- `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie` redacted in the loader by
  default (value replaced by a marker and a length), with an explicit option to keep them, and
  query strings truncated after a bound.
- Optional scoping to a uid or a set of uids (the agent user), so an operator can watch the agent
  and not the humans. On hokkaido that is the whole point.
- A paragraph in banken's security model stating what the sink then contains and who can read it
  (the sink is `UMask 0077` under the DynamicUser today; banken reads it; keep it that way).

### 3.6 BPF-side size and the "no parsing in BPF" rule

The probe does one thing per hit: bounded copy of (pid, tid, uid, comm, direction, cookie, len,
first N bytes) into the ring buffer, through the per-CPU scratch slot as the exec probe does
(the payload is over the 512-byte stack). No HTTP in BPF, no HPACK in BPF, no string search in
BPF. mimi already does everything that way; this does not change the rule, it depends on it.

## 4. mimi fit

### 4.1 Listener-only: yes, with one rule written down

A uprobe program observes. It cannot change a return value (`bpf_override_return` only works on
error-injectable kernel functions, never on user code), it cannot delay the call beyond its own
trap cost, and if the loader dies or the ring is full the application does not notice. That is
listener-only by construction, and it is the property the MITM alternative lacks (a dead proxy
takes the network down; a dead mimi takes nothing down).

The one escape hatch is `bpf_probe_write_user`, the helper that writes user memory from a probe
(it warns in dmesg on use). Together with `bpf_send_signal`, it must be forbidden in mimi's
probe by review and by a grep in the gate, as the written form of the charter. With that line,
the capability stays within "pure telemetry, never enforces" and within what
`mimi-listener-only` reserves for a separate sibling (in-kernel enforcement, which this is not).

### 4.2 Capability and hardening implications

New needs against the current unit (`module.nix`):

- Attaching a uprobe is `perf_event_open` on the uprobe PMU: `CAP_PERFMON` (held) and read
  access to the target file. `/nix/store` is readable; a binary under a home directory is not
  (`ProtectHome=true`). The native `claude` installer puts the binary in `~/.local`; on hokkaido
  the agent's own tools live in home. Either `ProtectHome=read-only` or an honest "not probed
  under home" line.
- Library discovery reads `/proc/PID/maps` of other users' processes: `CAP_SYS_PTRACE`
  (`PTRACE_MODE_READ`) and `ProtectProc` from `invisible` to `default`. That is a real loosening
  of a tight unit; it should apply only when the option is on (`lib.mkIf`), so a host without
  TLS capture keeps today's unit byte for byte.
- `SystemCallFilter` is already open for `perf_event_open` and `bpf`; nothing else new.
- nixos-hardening's sysctls are already bypassed by the `CAP_SYS_ADMIN` the unit holds for the
  same reason; no change.

### 4.3 A mimi capability, not a sibling

It is the same shape as every mimi probe: a BPF program in the same object, the same ring buffer,
the same `process`/ancestry attribution, the same versioned wire schema (`kind: "http"`), the same
loader and sink. A separate sibling would duplicate all of that for one probe and give banken a
second stream to join on pid. The things that argue for separation (the hardening loosening and
the data class) are handled by the option: the program attaches, and the unit loosens, only when
`services.mimi.tls.enable` is set. Section 6.3 already calls it a mimi capability; this doc
agrees.

### 4.4 What the event looks like in banken

Wire: `kind: "http"`, the OCSF HTTP Activity (4002) shape beside `process`: `http_request
{http_method, url {hostname, path, query_string, scheme}, user_agent, version}`, `dst_endpoint`,
`connection_info`, plus `Raw["TlsLibrary"]`, `Raw["SocketCookie"]`, a `truncated` flag and a
`decode` field (`"h1"`, `"h2-undecodable"`).

banken side, nothing new in the typed struct: `Category = "proxy"` (the Sigma logsource
category whose rules key on URLs), the typed network fields from the join (`DestinationIp`,
`DestinationPort`, `DestinationHostname`), process fields as for every mimi event, and the HTTP
detail in `Raw` under the Sigma `proxy` names the rules actually use, which are hyphenated and so
cannot be Go fields anyway: `Raw["cs-method"]`, `Raw["c-uri"]`, `Raw["cs-host"]`,
`Raw["c-useragent"]`, `Raw["cs-version"]`, `Raw["cs-referer"]`. `Raw` is already matched by
name, so the pinned `rules/web/proxy_generic/` set (on the order of a hundred rules: suspicious
user agents, C2 URI patterns, paste-site uploads; count the pinned tree before quoting a number)
becomes reachable with a `pipeline.yml` entry for `category: proxy` and no rename map. That is the
detection value names cannot give: not WHERE a process connected, but WHAT it asked for and AS
WHOM (user agent), attributed to pid and ancestry, which no proxy log has.

## 5. Verdict, conditions, and what it will never see

**viable-with-conditions.** Build it only under these:

1. **Names first.** Connect (3.4), DNS (3.5) and SNI (6.1) ship before this. They are on the wire,
   so they cover every stack in the dark list above, Go and Rust and Bun included, for the cost
   of one bounded copy per connection and no library discovery, no privacy switch, no HPACK. For
   the five pinned Linux network rules and for every domain-keyed IOC, that IS the detection
   value, and it is cheap; URL capture is the next class of value, not a better version of this
   one. If a rough number is wanted: names are most of the value for a fraction of the effort,
   and this doc recommends sequencing URL capture after them without reservation.
2. **Census before build** (2.5). A table of live processes by TLS stack on hokkaido and on any
   other host it would deploy to. If the probeable share of the processes that matter is small,
   stop and keep names.
3. **Scope: dynamically linked OpenSSL (and BoringSSL exported), GnuTLS, NSS, and Node, by
   exported symbol; fd by nesting, no `ssl_st` offsets; HTTP/1.1 headers only; h2 counted and
   marked undecodable in the first cut.** No Go, no Rust, no static, no Java, no h3. Declared
   in the scope ledger as exactly that, with the dark list verbatim, so no line ever says
   "supported" for a stack that cannot deliver it.
4. **Opt-in, bounded, redacted, scopable by uid** (3.5), and the unit's loosening applied only
   when the option is on (4.2). A security-model paragraph lands with the option.
5. **The listener rule in writing**: no `bpf_probe_write_user`, no `bpf_send_signal`, gated.
6. **A benchmark line** on and off before any host runs it.

Go later, if ever, as its own decision: either reuse an upstream generated offsets table
(Beyla/OBI) as data with its maintenance accepted, or hook `net/http` above TLS the same way.
Both are a per-Go-release commitment; neither belongs in the first cut.

What it will NEVER see without deeper per-binary work, stated for the ledger: rustls; statically
linked and stripped OpenSSL (static curl, python-build-standalone, most single-file container
binaries); BoringSSL inside Chrome, Electron and Bun (the native `claude` binary, pending
measurement); Java; HTTP/3 outside OpenSSL's own QUIC; any Go binary; obfuscated Go even with
per-binary work. For all of those, mimi's answer stays the DNS name, the SNI and the 4-tuple,
and that answer is honest and still useful.
