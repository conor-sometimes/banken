# Network detection - connection tuples, DNS names, and TLS without decryption

Status: **implementation design, not implemented.** Written 2026-11-02 against the tree on
`distro-matrix-mimi`. It refers to four things in that tree:

- the Event schema at `internal/event/event.go`
- the parsers under `internal/parser/`
- the routing table at `internal/sigma/pipeline.yml`
- the SigmaHQ ledger at `tests/emulations/SIGMAHQ.md`

Nothing here is built. No code is changed by this doc.

banken carries NO network telemetry, and this doc fixes that. The normalised `Event` has process
and file fields plus `Raw`. Nothing on it says where a process connected. Because of that, all
five SigmaHQ Linux `network_connection/` rules are deferred in `SIGMAHQ.md` (the
"auditd-network-fields engine gap"):

- `net_connection_lnx_back_connect_shell_dev` (Image endswith `/bin/bash`, DestinationIp not loopback)
- `net_connection_lnx_crypto_mining_indicators` (DestinationHostname in a Monero pool list)
- `net_connection_lnx_domain_localtonet_tunnel` (DestinationHostname endswith localto.net, Initiated true)
- `net_connection_lnx_ngrok_tunnel` (DestinationHostname contains tunnel.*.ngrok.com)
- `net_connection_lnx_susp_malware_callback_port` (Initiated true, DestinationPort in a list, DestinationIp not private, by `|cidr`)

Two of the five rules key on an IP and a port. Three key on a HOSTNAME. That split is the spine
of this doc. A connection tuple is cheap: auditd already has it today, undecoded, in `saddr`. A
hostname is a different datum. No syscall carries it. Only a DNS observation can supply it
honestly.

Read these first, in this order:

- `docs/design/sigma-pipelines.md` - the routing mechanism this doc extends.
- `docs/design/sysmon-linux.md` sections 1, 5 and 6 - which Sysmon event IDs exist on Linux
  (EID 3 yes, EID 22 no).
- the five rule files above, in the pinned SigmaHQ tree
  (`output/sigma-r2026-07-01/rules/linux/network_connection/`).
- the header of `tests/sigmahq-emul.nix` - why network rules are "ambient noise" today.

In one picture, the design does four things:

- The Event grows the Sysmon network field names and a category.
- The raw-auditd parser decodes the `saddr` of an audited `connect`/`sendto` into those fields.
  That closes the two IP rules on the default floor.
- A DNS observation from mimi or Sysmon fills `QueryName` and feeds a small answer cache. The
  cache gives connections their `DestinationHostname`, closing the three hostname rules.
- TLS detail comes later, from the host side, by eBPF (in-kernel probes). Never from a proxy.

---

## 1. The gap in one picture

```
today
  auditd  execve -----> Event{Image, CommandLine, User, ...}           --> process_creation rules   OK
  auditd  connect ----> (not audited; no rule installs it)               --> nothing
  sysmon  EID 1 ------> Event{Image, CommandLine, ParentImage, ...}     --> process_creation rules   OK
  sysmon  EID 3 ------> Event{Image, Raw{DestinationIp, ...}}            --> network rules: by accident only
  mimi    exec -------> Event{Image, CommandLine, Ancestry, ...}         --> process_creation rules   OK

after this design
  auditd  connect/sendto (SOCKADDR saddr decoded) ---> Event{Category: network_connection,
                                                              DestinationIp, DestinationPort, Initiated}
  sysmon  EID 3 --------------------------------------> Event{Category: network_connection, Destination*, Source*, Protocol, Initiated}
  sysmon  EID 22 (Windows only) ----------------------> Event{Category: dns_query, QueryName, QueryResults}
  mimi    connect (inet_sock_set_state) --------------> Event{Category: network_connection, full tuple, Protocol}
  mimi    dns (UDP/53 payload, parsed in userspace) --> Event{Category: dns_query, QueryName, QueryResults}
  engine  answer cache: dns_query -> (ip -> name) ----> network_connection.DestinationHostname filled when observed
  sigma   category: network_connection | dns_query ---> routed AND gated by Event.Category
```

### 1.1 Why the five rules "fire" today, and why that is a bug to fix first

`tests/sigmahq-emul.nix` records that network_connection rules trip "even on the benign baseline".
It subtracts them as ambient noise. Here is the mechanism, read from the code at this tree:

- `Rule.Match` (`internal/sigma/rule.go`) gates a rule on `event.Source` only (`AppliesTo`). A
  `category: network_connection` rule routed to `auditd` is evaluated against every auditd event,
  execs included.
- `net_connection_lnx_back_connect_shell_dev` is `selection and not filter`, where `selection` is
  `Image|endswith: '/bin/bash'` and `filter` is `DestinationIp` in a list. On an exec event
  `DestinationIp` is absent, so `filter` is false, `not filter` is true, and the rule fires on
  every bash exec.

So the first thing network detection needs is not a field but a gate. A rule that declares a
logsource category must only be evaluated against events of that category. The same gate makes
adding a `connect` audit rule safe. An audited `connect` group carries `SYSCALL.exe` and a
`PROCTITLE`, which `foldAuditGroup` turns into `Image` + `CommandLine` today. Without the gate,
every process_creation rule would fire a second time on every connect the process makes. Section
4.2 specifies the gate. Section 8.3 removes the "ambient network noise" carve-out from the harness
once it exists.

---

## 2. Event schema extension

### 2.1 The fields

The field names are the Windows Sysmon / SigmaHQ names, verbatim. This is for the same reason the
process fields are (see the `event.go` header comment). The matcher looks a field up by its rule
name, with no translation table. So every Windows AND Linux network rule applies with no per-rule
change.

A survey of the pinned tree's `windows/network_connection/` (51 rules) and `windows/dns_query/`
confirms the names rules actually use:

- `Image` 214
- `Initiated` 41
- `DestinationIp` 27
- `DestinationHostname` 26
- `DestinationPort` 24
- `Protocol` 7
- `SourcePort` 3
- `SourceIp` 2
- `QueryName` 21

Plus a few `SourceHostname` / `SourceIsIpv6`.

```go
// Category is the Sigma logsource category this event is an instance of
// ("process_creation", "network_connection", "file_event", "dns_query"), set by
// the parser from what the source record IS. Empty when the parser cannot say
// (an ad-hoc check, a standalone auditd record). Used by the routing gate
// (section 4.2); never matched on by a rule.
Category string `json:"category,omitempty"`

// Network connection (Sigma category network_connection; Sysmon EID 3 names).
// A source that does not carry a datum leaves it zero, as with every field.
DestinationIp       string `json:"destinationIp,omitempty"`       // literal address text, v4 or v6
DestinationPort     int    `json:"destinationPort,omitempty"`     // 0 = absent
DestinationHostname string `json:"destinationHostname,omitempty"` // only when OBSERVED (section 5.4)
SourceIp            string `json:"sourceIp,omitempty"`
SourcePort          int    `json:"sourcePort,omitempty"`
Protocol            string `json:"protocol,omitempty"`            // "tcp" | "udp" | "" (unknown)
// Initiated is Sysmon's outbound flag as the rules spell it: "true" for a
// connection this host opened, "false" for one it accepted, "" when the source
// cannot say. A string, not a bool, because the rules compare it to the string
// 'true' and the third state (unknown) must stay distinguishable from false.
Initiated string `json:"initiated,omitempty"`

// DNS query (Sigma category dns_query; Sysmon EID 22 names).
QueryName    string `json:"queryName,omitempty"`    // the question name, as asked
QueryResults string `json:"queryResults,omitempty"` // answers in Sysmon's rendering (section 5.3)
```

`Event.Field` gains the nine names. Ports are rendered with `strconv.Itoa`, like `ProcessId`. An
int 0 means "absent", so a port can never match `0` by accident. `AllText` gains the string
fields, so a keyword rule and the IOC (indicator-of-compromise) lookup see an address or a
hostname the way they see a path. The JSON tags are what `tests/fixtures/*.json` and `banken
check` carry, so a network fixture is just an Event with these keys.

### 2.2 What stays Raw

`Raw` keeps anything a source carries that no rule in the pinned tree keys on in a way that needs
typing:

- Sysmon's `SourceHostname`, `SourcePortName`, `DestinationPortName`, `SourceIsIpv6`,
  `DestinationIsIpv6`, `ProcessGuid`, `RuleName`.
- auditd's `saddr` hex. It is kept verbatim beside the decoded fields, so a service:auditd rule or
  an operator reading an alert still sees the original bytes.
- mimi's `Ancestry` and the socket cookie.

`Raw` is matchable by name already, so nothing is lost. It just is not promised.

No `CommunityId`. It is a hash over the 5-tuple for cross-tool correlation. Nothing in banken or in
the pinned rules consumes it, and auditd cannot produce one (it has no source tuple). It is a
two-line addition in the OCSF (open cybersecurity schema) sink the day a SIEM (a central security
analytics platform) asks for it. Adding it now is cramming.

### 2.3 Why a Category and not "the field is absent"

The process/file split works by absence today: `TargetFilename` is empty on an exec. It works
because no process_creation rule is written `and not filter_on_TargetFilename`. The network rules
are written that way (section 1.1). And `|cidr` filters on an absent field are common in the
Windows set too. Absence is not a category. One string on the Event, set by the parser from the
record type it just folded, is the simplest thing that is correct.

---

## 3. Sources: what each can populate, and what it cannot

### 3.1 Raw auditd: `connect` and `sendto` (the default floor)

This is the source every banken host has, so it is the one that closes rules first.

**The audit rules to add** go in `module.nix`, beside the `banken-exec` rules. `docs/deployment.md`
has them for the vendor distros. `distrocheck` A1 checks they are loaded:

```
-a always,exit -F arch=b64 -S connect -F a2=16 -k banken-net
-a always,exit -F arch=b64 -S connect -F a2=28 -k banken-net
-a always,exit -F arch=b64 -S sendto  -F a4=16 -k banken-net
-a always,exit -F arch=b64 -S sendto  -F a4=28 -k banken-net
-a always,exit -F arch=b32 -S connect -F a2=16 -k banken-net
-a always,exit -F arch=b32 -S connect -F a2=28 -k banken-net
```

Why each part, so nothing here is a magic number:

- `a2` of `connect(fd, addr, addrlen)` and `a4` of `sendto(fd, buf, len, flags, addr, addrlen)` is
  the `addrlen`. `16` is `sizeof(struct sockaddr_in)` (2 family + 2 port + 4 addr + 8 pad). `28`
  is `sizeof(struct sockaddr_in6)` (2 + 2 + 4 flowinfo + 16 addr + 4 scope). An AF_UNIX address is
  `2 + strlen(path) + 1`. So this filter drops the overwhelming majority of `connect` calls on a
  host (dbus, journald, nscd, systemd sockets) in the kernel, before auditd ever sees them. It
  filters on length, not family. So a UNIX path of exactly 13 or 25 characters slips through: the
  decoder sees family 1 and the group becomes no network event. The cost of that is one log line,
  not a false alert. The widely used Neo23x0 auditd ruleset documents the same trick for its
  `network_connect_4`/`_6` keys.
- **No `-F success=1`.** A `connect` on a non-blocking socket returns `-EINPROGRESS`, and the audit
  record says `success=no exit=-115`. That IS the connection. curl, every browser, every Go
  program and systemd-resolved all connect non-blocking. A `success=1` filter would audit only
  blocking connects (bash's `/dev/tcp`, python's default socket) and silently miss the rest. A
  refused or timed-out connect to a C2 (command-and-control) server is also a detection, not noise.
- `sendto` with an address covers unconnected UDP, such as a resolver's query or a syslog shipper.
  A `send`/`write`/`sendmsg` on a CONNECTED socket passes no address and emits no `SOCKADDR`
  record. The `connect` that made the socket connected was audited, so the tuple was seen once.
  `sendmsg` with an explicit `msg_name` (some resolvers, some Go paths) is not covered by these six
  rules. That is a known, recorded gap, closed by mimi (section 3.4). It is not closed by auditing
  `sendmsg`: its address length is inside `struct msghdr`, not an argument, so it cannot be
  length-filtered and would admit every AF_UNIX `sendmsg` on the host.
- `b32`: the 32-bit ABI has had a direct `connect` since kernel 4.3. The older multiplexed
  `socketcall` is not covered. This is recorded, the same way the existing `b32 execve` rule covers
  only the direct call.
- The key `banken-net` is the proof hook (`auditctl -l | grep -q banken-net` in the harness, the
  same as `banken-exec`). It lands in `Raw["key"]` for provenance.

**The `SOCKADDR` record and the `saddr` decode.** An audited `connect` writes one group:

```
type=SYSCALL  msg=audit(1762000000.123:4567): arch=c000003e syscall=42 success=no exit=-115 a0=3 a1=7ffd... a2=10 ... pid=4242 ppid=4100 auid=1000 uid=1000 ... comm="curl" exe="/usr/bin/curl" key="banken-net"
type=SOCKADDR msg=audit(1762000000.123:4567): saddr=0200115CC000020A0000000000000000
type=PROCTITLE msg=audit(1762000000.123:4567): proctitle=6375726C002D7300687474703A2F2F3139322E302E322E31302F78
```

`saddr` is the raw `struct sockaddr` bytes the caller passed, hex-encoded, `addrlen` bytes long.
It is decoded as a C struct, not as a string. So `normaliseAuditValue` leaves it alone: it is not
in the hex-decoded key list, and must not be, because decoding it to "text" would produce binary.
The decode is one function, `decodeSockaddr(hex string) (family int, ip netip.Addr, port int, ok bool)`,
in a new `internal/parser/sockaddr.go`. It is shared by every parser that ever sees the raw hex:

```
bytes 0..1   sa_family, u16 in HOST byte order. x86_64 and aarch64 are little-endian, so
             AF_INET  (2)  is "0200", AF_INET6 (10) is "0A00", AF_UNIX (1) is "0100".
             banken reads the audit log of the host it runs on, so host order is the parser's
             own; a big-endian host is not a banken target today and would be caught by the
             fixture, not guessed at.
AF_INET  (need >= 16 bytes):
  bytes 2..3   sin_port, u16 in NETWORK order (big-endian): "115C" = 0x115C = 4444
  bytes 4..7   sin_addr, 4 bytes in network order: "C000020A" = 192.0.2.10
  bytes 8..15  zero padding, ignored
AF_INET6 (need >= 28 bytes):
  bytes 2..3   sin6_port, network order
  bytes 4..7   sin6_flowinfo, ignored
  bytes 8..23  sin6_addr, 16 bytes in network order
  bytes 24..27 sin6_scope_id, ignored (a link-local scope is not a destination a rule names)
any other family, or too few bytes, or non-hex: ok=false, and the group is NOT a network event.
```

The worked example above decodes to `DestinationIp=192.0.2.10 DestinationPort=4444`. Now consider
an IPv4-mapped IPv6 destination (`::ffff:192.0.2.10`), which a dual-stack socket produces. It is
rendered exactly as `netip.Addr.String()` renders it. The `|cidr` matcher parses it back with
`netip.ParseAddr`. But `netip`'s `Contains` on a v4 prefix does not match a v4-mapped v6 address.
So the private-range filter of the callback-port rule would NOT exclude `::ffff:10.0.0.1`. The
decoder therefore unmaps (`Addr.Unmap()`) before rendering. The destination is the v4 host either
way, and a rule written with v4 ranges should see v4. That one call is the only normalisation. It
is named here so it is not a surprise in review.

**Folding into the Event** (`foldAuditGroup`). A group is a network event when its records include
a `SOCKADDR` that decodes to AF_INET/AF_INET6, and no `EXECVE`:

- `Category = "network_connection"`, `DestinationIp`, `DestinationPort` from the decode.
- `Initiated = "true"`. This is not an inference from the bytes but a consequence of the rule set.
  The only syscalls banken audits with an address are `connect` and `sendto`, both outbound by
  definition. The day an `accept`/`recvfrom` rule is added, the fold must read `SYSCALL.syscall`
  per arch to tell the direction. Until then there is nothing to decide. The `b64`/`b32` syscall
  numbers are deliberately not tabled now.
- `Image`, `User`, `PID`, `PPID`, `CurrentDirectory` from `SYSCALL`/`CWD` as today, so the
  process_creation-style selections inside the network rules (`Image|endswith: '/bin/bash'`) work.
- `CommandLine` from `PROCTITLE` as today (the kernel caps proctitle at 128 bytes; a connect has
  no `EXECVE` record, so the full argv is never available on a network event).
- `Raw["saddr"]` keeps the hex. `Raw["syscall"]`, `Raw["key"]`, `Raw["exit"]` and `Raw["success"]`
  are already there. So an operator can tell a refused connect from an established one in the
  alert, and a `service: auditd` rule can match them.
- `Protocol`, `SourceIp`, `SourcePort`, `DestinationHostname`: empty. See the ledger.

**What raw auditd cannot give**, said once:

- No hostname. A syscall carries an address, never a name.
- No source tuple. The kernel picks the source port after `connect` returns, and it is not in any
  record.
- No protocol. A `connect` on a UDP socket looks identical to TCP; the `socket()` call that set
  the type is a different event and is not audited.
- No inbound. `accept` is not audited, by choice.
- No `sendmsg`-with-address and no `socketcall` (above).
- argv only as a 128-byte proctitle.
- No `ParentImage` (same as execs).

Event-to-process correlation is intrinsic: one audit id per syscall, `SYSCALL.pid/exe/comm` in the
same group. So there is no cross-event join to get wrong. What is lost is only what the syscall
does not carry.

**Volume.** Every outbound TCP connect and every unconnected UDP send on the host becomes a group.
The `addrlen` filter removes the AF_UNIX bulk in the kernel. On a busy server this is tens to
hundreds of groups per second, each a few hundred bytes. The parser cost is one hex decode per
group. Item 2 of the build sequence measures it with `bench/` before the rule ships on by default.
`services.banken.audit.network` (default on) is the one option that turns it off.

### 3.2 Laurel

Laurel reassembles the same group into one JSON line and has its own sockaddr parser. So a Laurel
`SOCKADDR` record arrives already structured (family, address, port) rather than as hex. The
Laurel parser maps that object onto the same fields, with the same `Category`/`Initiated` rule as
3.1. The exact key names are pinned from a captured line into `testdata/laurel_sample.jsonl` when
the item lands; they are not assumed here. Laurel adds `ParentImage` (`SYSCALL.PPID.exe`) to the
network event, which raw auditd cannot. Everything else in 3.1's "cannot give" list holds for
Laurel too, because it is the same audit stream.

### 3.3 Sysmon EID 3 (and EID 22)

This is the cheapest cross-source win, because the parser exists and the names already match. Today
`sysmonToEvent` maps EID 1's names to the typed fields and drops every other `Data Name` into
`Raw`. So an EID 3 line already carries `Raw["DestinationIp"]` and friends. They are matchable by
name, but ungated and untyped. `DestinationPort` arrives as text, which `|cidr` does not care about
but the Category gate does. The change is a `switch` on `EventID`:

- EID 1: `Category = "process_creation"` (what is mapped today).
- EID 3: `Category = "network_connection"`. Sets `DestinationIp`, `DestinationPort` (atoi),
  `DestinationHostname`, `SourceIp`, `SourcePort`, `Protocol` (Sysmon emits `tcp`/`udp`
  lower-case already), and `Initiated` (Sysmon emits the literal `true`/`false`). `Image`, `User`,
  `ProcessId` as for EID 1. `SourceHostname`, `*PortName`, `*IsIpv6` stay in `Raw`.
- EID 11 / 23: `Category = "file_event"` (`TargetFilename` is mapped today; the category is new).
- EID 22: `Category = "dns_query"`. Sets `QueryName`, `QueryResults` (verbatim), `Image`, `User`.
  **This event does not exist on Linux** (`sysmon-linux.md` section 1: DnsQuery is Windows-only,
  and the Linux build emits nothing for it). The mapping is written once because the parser is
  shared with the future Windows Sysmon source, where EID 22 is the richest DNS source there is. On
  a Linux host it is inert, and the ledger says so.
- Everything else: `Category = ""` (unknown, matches any rule's category, as today).

**Honest limit on `DestinationHostname` from Sysmon-for-Linux.** On Windows, Sysmon fills EID 3's
`DestinationHostname` from its own DNS cache (it observes queries) and from reverse lookups.
Whether the Linux build populates it, and from what, is undocumented. That is the same
documentation gap `sysmon-linux.md` records for the event list. The parser maps the field if
present. The distro matrix's S stage captures a real EID 3 line and records whether the name was
there (item 5). The ledger marks the three hostname rules "supported (sysmon)" only after that line
shows a name. banken does no reverse lookup to paper over an empty field: a PTR record is
attacker-controlled, and a lookup from the detector is a network call that leaks what banken is
looking at.

### 3.4 mimi: the connection probe

mimi is listener-only telemetry (its README: "process execs today, file and network next"). A
network probe fits its charter exactly, and it never enforces. The design keeps mimi's two rules:
the probe copies, the loader parses, over one versioned wire schema.

**The hook is the `sock:inet_sock_set_state` tracepoint**, filtered to `newstate == TCP_SYN_SENT`
(outbound) and, later, `TCP_SYN_RECV`/`TCP_ESTABLISHED` from a listener (inbound). Why this one,
and not a kprobe on `tcp_connect` or the `sys_enter_connect` syscall tracepoint:

- It is a tracepoint with a stable, self-describing record format: `family`, `protocol`, `sport`,
  `dport`, `saddr`/`daddr`, `saddr_v6`/`daddr_v6`, `oldstate`/`newstate`, in-tree since 4.16. It
  needs no `struct sock` offsets, so no CO-RE (compile-once-run-everywhere) entry in `OFFSET_TABLE`
  for the tuple. The only field mimi still needs from `task_struct` is what it already resolves for
  execs.
- The transition to `SYN_SENT` fires inside `tcp_connect`, in the context of the task that called
  `connect`. So `bpf_get_current_pid_tgid`/`comm`/the ancestry walk attribute it correctly. It
  fires only when a SYN actually goes out: a `connect` on a closed fd or an `EINVAL` never gets
  here. The source port is assigned by then (`inet_hash_connect` runs before `tcp_connect`). So
  mimi carries the full 4-tuple and `Protocol = "tcp"`, which auditd cannot.
- `sys_enter_connect` reads the sockaddr from USER memory at syscall entry. Those are the same
  bytes auditd logs, with the same "no protocol, no source" limits. Worse, it leaves a window where
  the caller can rewrite the buffer after the probe read it. The kernel's own state transition is
  the truth, so read that.
- UDP has no state machine. The design closes UDP in two steps. The DNS probe (3.5) covers the UDP
  flow that matters for detection. A later `udp_sendmsg` kprobe (with one CO-RE offset for the
  destination) covers the rest if a rule ever needs it. Neither is in the first mimi item.

**The wire format** is `mimi/3`, `kind: "connect"`, in the OCSF shape mimi already uses. It adds
`dst_endpoint` and `src_endpoint` objects and `connection_info {protocol_name, direction}`. These
are the OCSF Network Activity (4001) objects, so the banken sink and a future lake agree with the
sensor. The `process` object is the same as for `exec` (pid, name, file.path, user, parent,
ancestry). banken's `Mimi` parser switches on `kind` and sets `Category` accordingly. The schema
bump uses the contract mechanism that already exists: `mimiSchema` in `mimi.go`, the shared golden
fixture, `just contract`. banken keeps reading `mimi/2` exec lines during the overlap.

**One limit.** `file.path` on a connect event is the task's `exe`, read the same way as for execs.
A connect by a process whose exec predates mimi's start is still attributed, because it is read
from the live task, not from a cache. There is no hostname: the socket has an address. The join in
5.4 adds it.

### 3.5 mimi: the DNS probe (names without MITM)

The DNS question name is plaintext on the wire, even when the connection that follows is TLS. For
a host EDR (endpoint detection and response) that is the cheapest, most honest "which domain"
signal there is. It needs no CA, no proxy and no decryption. It is first-class scope, not a
follow-on.

**The hook** is the UDP send and receive paths, filtered to destination or source port 53. It
copies the datagram payload into the ring buffer with the process identity. The payload is at most
512 bytes, the classic DNS-over-UDP limit; EDNS can allow larger answers, and those are truncated
at 512 and marked. The probe does NOT parse DNS. Parsing a compressed-label wire format inside the
BPF verifier's bounds is exactly the kind of cleverness that becomes a rough edge. The loader
(Rust, std, testable on the Mac) does the parsing. It reads the question section into `QueryName`
and the answer section's A/AAAA/CNAME records into `QueryResults`, and emits `kind: "dns"`.

Which attachment delivers the bytes is settled by a spike inside the item. These requirements are
fixed:

- destination port 53
- attributed to the calling task
- both directions
- bytes plus length

There are two candidates. The syscall tracepoints are `sys_enter_sendto`/`sys_exit_recvfrom` and
the `sendmsg`/`recvmsg` pair, reading the user buffer. The socket-layer kprobe pair is
`udp_sendmsg`/`udp_recvmsg`, reading the skb. The syscall pair is simpler and offset-free. The
socket pair catches a resolver that uses a connected socket and plain `write`. The spike picks
whichever one captures glibc, musl, Go's resolver and systemd-resolved's stub in one go.

Why not a uprobe on `getaddrinfo`? It misses every static binary, every Go program (its own
resolver speaks UDP directly) and every program that builds its own packets. That is exactly the
population an attacker's tooling comes from. The wire is the only place every resolver meets.

**systemd-resolved** runs on every matrix distro except where disabled. The application sends to
`127.0.0.53:53`. The probe captures that and attributes it to the application, which is the
attribution that matters. resolved then forwards upstream; that is captured again and attributed to
resolved. The join (5.4) is keyed on the answer, which the application receives from the stub, so
it works unchanged.

**Honest limits.** DNS over TCP (truncated answers, large zones) is not read in the first cut; that
needs stream reassembly, and it is recorded. DNS over TLS (853) and DNS over HTTPS (443) hide the
question from this probe by design. A browser or a resolver configured for DoH leaves only the
connection tuple to its DoH server. That tuple is itself a `network_connection` event, and a rule
can key on it. An `/etc/hosts` entry or a hardcoded IP never produces a query, so there is no name,
which is the correct answer. mimi reads the datagram. It does not block, rewrite or answer it
(listener-only).

### 3.6 Recommended order

1. **Raw auditd** first. It is the floor every host has, needs zero new privilege, and closes two
   of the five rules on the harness that already exists. It also forces the schema and the category
   gate to exist, which everything else builds on.
2. **Sysmon EID 3.** A parser switch and a captured golden line. Parity on the S stage of the
   matrix. It may or may not bring a hostname, which is measured, not assumed.
3. **mimi connect.** The richest tuple: protocol, source, kernel truth. Parity on the M stage.
4. **mimi DNS plus the answer join.** This closes the remaining three rules from the richest
   source. It also gives every other source (auditd included, on the same host) a
   `DestinationHostname` it could never carry alone.
5. TLS SNI, then SSL-library uprobes (section 6). These come later, as separate mimi capabilities.

Laurel's sockaddr mapping is a small parity item slotted after 1.

---

## 4. Sigma routing

### 4.1 Pipeline entries

`pipeline.yml` gains two entries after `process-creation-any`. Same shape, identity renames:

```yaml
  - name: network-connection-any
    when: { category: network_connection }
    sources: [auditd, laurel, mimi, sysmon, generic]
    rename: {}

  - name: dns-query-any
    when: { category: dns_query }
    sources: [mimi, sysmon, generic]   # auditd/laurel never carry a query name
    rename: {}
```

The five Linux rules declare `product: linux` and are caught by the `linux` entry first, which
already lists every source. The two new entries are for category-only rules, and for documenting
which sources can satisfy the category. Renames stay empty because the Event uses the rules'
names; that is the point of section 2.1. The `sigma-pipelines.md` table gains the two rows.

### 4.2 The category gate

`pipeline.route` returns the matched entry's category condition. `Rule` gains `Category string`:
the rule's declared logsource category, lower-cased, "" when none. `Rule.AppliesTo(source)` becomes
`AppliesTo(source, category)`, with one more test:

```
rule.Category == "" || event.Category == "" || rule.Category == event.Category
```

Empty on either side matches, exactly as `Source` does today. So:

- A rule with no category runs everywhere (the `service: auditd` rules, keyword rules).
- An event a parser could not classify still matches every rule, so a source-agnostic verdict never
  changes. Such an event is an ad-hoc `banken check` input without a category, or a standalone
  auditd record.
- The prefilter `Matcher` applies the same test where it applies `AppliesTo` today.

The conformance differential (pySigma, source-less and category-less events) is unaffected.

The effect:

- `back_connect_shell_dev` stops matching bash execs.
- process_creation rules stop matching connect groups.
- a `file_event` rule stops being evaluated against an exec at all. Today it is evaluated and fails
  on absence, which is correct but wasted.

The harness carve-out in `sigmahq-emul.nix` for "ambient network rules" goes away (8.3).

### 4.3 Values the rules use, checked against the matcher

- `DestinationPort: [888, 999, ...]` are YAML ints. `yamlValues` renders scalars as text, and
  `Field("DestinationPort")` renders the int the same way, so `888 == "888"`. Pinned by a test.
- `Initiated: 'true'` is a string compare against the literal; section 2.1 stores the literal.
- `DestinationIp|cidr` with v4 and v6 prefixes: `opCIDR` already parses the event value with
  `netip.ParseAddr`; the `Unmap()` in 3.1 keeps v4 destinations v4.
- `DestinationHostname|endswith`/`|contains`: plain folded string ops on the observed name.
- `Image|endswith: '/bin/bash'`: the network event carries `Image` from `SYSCALL.exe`. NixOS
  `/nix/store/...-bash-5.x/bin/bash` ends with it, and a vendor distro's `/usr/bin/bash` does too.

All five rules already compile today: `sigmacov` loads them, and `|cidr` is implemented. What was
missing was events with the fields, and a gate that stops the wrong events.

---

## 5. DNS: names are first-class

### 5.1 What a name buys

Three of the five Linux rules key on `DestinationHostname`, as do 26 of 51 Windows network rules.
21 Windows `dns_query` rules key on `QueryName`. A domain is the one network indicator that
survives CDN IP churn, is readable without decryption, and is what threat-intel feeds publish.
`rules/ioc/` lists can hold domains today, and the IOC lookup scans `AllText`. So `QueryName` on
the Event makes every domain IOC live with no further code.

### 5.2 Sources, honestly

| source | query name | answers | notes |
| --- | --- | --- | --- |
| raw auditd / Laurel | no | no | a `sendto` to port 53 is seen as a tuple (`DestinationPort=53`) and nothing else; the payload is never audited |
| Sysmon-for-Linux | no | no | EID 22 is Windows-only; nothing is emitted on Linux |
| Sysmon on Windows (future) | yes (EID 22 `QueryName`) | yes (`QueryResults`) | the parser mapping is shared and written once (3.3) |
| mimi | yes | yes | UDP/53 payload, parsed in the loader (3.5); DoT/DoH/TCP-DNS limits recorded |

So on Linux the DNS source is mimi, full stop. The design does not pretend otherwise, and it does
not add a resolver-log scraper (systemd-resolved's debug log, dnsmasq's query log) as a stand-in.
Those logs exist on some hosts only, attribute to the resolver rather than the process, and would
be a third parser for a datum mimi gives per-process.

### 5.3 The `dns_query` event

The event sets `Category = "dns_query"`. `QueryName` is the question name without the trailing
dot, and nobody lower-cases it: rules fold case themselves. `QueryResults` is in the rendering
Sysmon uses, which the Windows rules were written against: `type: <rrtype> <value>;` per record,
e.g. `type: 5 cdn.example.net;::ffff:93.184.216.34;`. Sysmon writes v4 answers as v4-mapped v6;
the mimi loader writes the same, so one parser serves both, and the join below unmaps. `Image`,
`User`, `PID` come from the process. There is one event per question. A response with several
answers is one event with several records in `QueryResults`. The query and its response are one
event when the loader can pair them (same socket, same transaction id, within a short window), and
two when it cannot. A query that got no answer is itself a signal: `QueryResults` empty.

### 5.4 The answer join: `DestinationHostname` from observed DNS

Sysmon on Windows fills EID 3's hostname from its own DNS cache. banken does the same, in the
engine, source-agnostic:

- A small in-memory map `ip -> (name, expires)`, fed by every `dns_query` event that carries
  answers. The source can be mimi today or Sysmon EID 22 on Windows later. A CNAME chain resolves
  to the QUESTION name, because that is what the process asked for and what the rules list
  (`pool.minexmr.com`, not the CDN host it points at). The map is bounded (a few thousand entries,
  LRU) and TTL-honoured, with a floor of 60 seconds so a 0-TTL answer still covers the connect that
  follows it milliseconds later.
- A `network_connection` event with `DestinationHostname == ""` and a `DestinationIp` in the map
  gets the name. `Raw["HostnameSource"] = "dns-cache"` so an alert says where it came from. A
  source that carried its own name (Sysmon) is not overwritten.
- Only observed answers, ever. No reverse lookup, no `/etc/hosts` reading, no guess. A connect to
  an IP the host never resolved has no hostname, and the hostname rules correctly stay silent. The
  IP rules still see it.

The join is what lets a host close all five rules while running auditd for execs and mimi only for
DNS. The network event can come from the floor source, and the name from the sensor. It lives in
`internal/engine` because that is where every source's events meet. It is one type with two
methods (`observe(dnsEvent)`, `name(ip)`), no goroutine, called on the event path.

### 5.5 Deferred, with reasons

- DNS over TCP. Stream reassembly in the loader; needed for large answers only.
- DoT/DoH content. Encrypted by design; the tuple to the resolver remains visible.
- Response-code and NXDOMAIN-rate rules. These need `QueryStatus`. mimi can carry the RCODE cheaply
  once the loader parses headers, and it will, but no pinned rule needs it yet.
- Query-name entropy / DGA (domain-generation-algorithm) scoring. A different feature, not a field.

---

## 6. TLS without decryption, and why there is no MITM in this design

### 6.1 SNI: the TLS destination name from the first packet

A TLS ClientHello carries the Server Name Indication (SNI) in plaintext, before any key exchange.
It is the destination hostname the client intends, straight from the client, with no CA and no
interception. For a process that was given a hardcoded IP, or that resolved over DoH, SNI is the
name DNS did not show.

This is scoped as a mimi capability. The `inet_sock_set_state` transition to `ESTABLISHED` marks a
freshly connected TCP socket. On the first `sendmsg`/`write` on it, the probe copies the first
outbound payload up to a bound, a few hundred bytes. The loader checks for a TLS handshake record
with a ClientHello and parses the `server_name` extension. The result lands on the same
`network_connection` event as a second name source:

- `DestinationHostname` if it is empty
- `Raw["HostnameSource"] = "sni"`
- `Raw["TlsSni"]` always, since a mismatch between the DNS name and the SNI is itself interesting

It needs a bound copy of one buffer per new connection, and no reassembly. The ClientHello is in
the first segment in practice; a split one is recorded as unparsed, not guessed.

One caveat, stated now. Encrypted ClientHello (ECH) encrypts the SNI under a key published in DNS.
Where ECH is deployed (some browsers to some CDNs, and growing), the probe sees only the outer
`public_name` (the CDN's). That is still a hostname, just a less specific one. ECH does not hide
the DNS query for the ECH config itself: that is an HTTPS record query, which the DNS probe sees.
So the DNS probe stays the primary name source, and SNI is the second. ECH degrades the second.

### 6.2 Why not MITM

A MITM (man-in-the-middle) proxy is a local TLS-terminating proxy with a trusted CA installed on
the host. It is how network appliances get HTTP detail. The question "do we need one for good
detail" is fair. The answer for a host EDR is no, and this design does not propose one:

- A proxy only wins when you do NOT control the endpoint. It exists to see inside TLS from the
  middle, because the middle is all an appliance has. banken and mimi run ON the host, in the
  kernel the process runs in, with the same privilege the process's TLS library runs under. The
  plaintext exists in that process's memory before encryption and after decryption. The host can
  read it at the library boundary (6.3). That is the same plaintext a proxy sees, without the
  proxy.
- A proxy costs what a host EDR must not afford:
  - a trusted CA on the host, a key that, if taken, lets an attacker impersonate every site to
    every process
  - every TLS connection re-terminated: latency, a second TCP connection, certificate pinning
    broken, mTLS broken, QUIC not covered
  - a routing change that is itself a tamper target

  It is also enforcement-adjacent: a proxy that is down takes the network down, which violates
  mimi's listener-only charter by construction.
- A proxy sees the socket, not the process. Attribution back to pid/user/ancestry is a second
  join. The eBPF hooks have the task in hand.

So SNI (6.1) and the DNS name (3.5) are the no-cost names. The library hook (6.3) is the "good
detail" path. Both are host-side, both are listener-only, and neither needs a CA.

### 6.3 Later: plaintext at the TLS library boundary (SSL uprobes)

This is the ecapture / Pixie approach. It uses uprobes on `SSL_write`/`SSL_read` (OpenSSL,
BoringSSL) and `gnutls_record_send`/`_recv` (GnuTLS), reading the buffer argument before
encryption or after decryption. That yields URLs, headers and bodies: the detail a proxy would
give, attributed to the process, with no proxy. It is scoped as a LATER mimi capability, after the
connection and DNS probes, because its costs are real and specific:

- Per-library, per-version symbol and offset resolution. A shared library's exported symbol is
  easy (`SSL_write` in `libssl.so.3`). But a struct field needed for the fd or the version is not
  stable across OpenSSL releases. That is CO-RE-shaped work with no BTF (BPF type info) to lean on.
- Statically linked and stripped TLS has no exported symbol to probe. That covers Go's
  `crypto/tls`, Rust's rustls, a static curl, and every malware dropper. Go needs its own
  per-binary function discovery (`crypto/tls.(*Conn).Write`), with Go's register ABI, per Go
  version. The population an attacker brings is the population this misses first, and the design
  says so rather than overselling it.
- Volume and privacy. Plaintext bodies are the highest-volume, most sensitive bytes on the host.
  The capability needs three things: a bound (first N bytes, headers only by default), an explicit
  operator switch, and a statement in the security model about what banken then holds.
- Where it lands on the Event: an `http_activity`-shaped event (OCSF 4002) with `Url`, `Method`,
  `UserAgent`. No pinned Linux Sigma rule keys on those today. The `proxy` category rules in
  SigmaHQ do (`c-uri`, `cs-user-agent`, `cs-host`). That is the day the `rename` map in
  `pipeline.yml` stops being identity, which is what it is there for.

This is a research item, not a build item, until the connection and DNS probes have shipped and a
rule exists that needs it.

---

## 7. Output: what an alert carries

The OCSF Detection Finding's evidence element (`ocsfEvidences`) gains these, when the event has
them:

- `dst_endpoint {ip, port, hostname}` for a connection
- `src_endpoint {ip, port}` for a connection
- `connection_info {protocol_name, direction}` for a connection
- `query {hostname}` for a DNS event

These are the OCSF 1.3 evidence objects, so the official validator (matrix objective E4) stays
green. `ocsf-output.md` section 5.1 notes that banken does not invent network observables from a
command line. That stays true: an observable is emitted only from a typed network field a parser
set. The `raw_data` camelCase Event carries the new keys automatically.

---

## 8. Proof and cross-source parity

### 8.1 The sink the test controls

The emulations must not reach the Internet and must not time out. The NixOS harness VM gets a
second address on the loopback interface from TEST-NET-1:

```nix
networking.interfaces.lo.ipv4.addresses = [ { address = "192.0.2.10"; prefixLength = 32; } ];
```

A connect to `192.0.2.10` is routed locally and succeeds immediately. It is NOT loopback
(`127.0.0.0/8`), and NOT in any private range the callback-port rule's `|cidr` filter excludes.
The test starts a plain TCP listener on it before each network family and stops it after (`python3
-c` with the stdlib `socket`, bound to `192.0.2.10:<port>`). The QEMU user-net address
(`10.0.2.15`) is deliberately not used: it is inside `10.0.0.0/8` and would be filtered. For the
DNS families (item 7) the sink is a tiny UDP responder on `192.0.2.10:53` (python stdlib, a fixed
answer `A 192.0.2.10` for any question). The emulation asks it directly (`dig @192.0.2.10`, or
python `socket` with a hand-built query). So the question, the answer and the connect that follows
are all under the test's control, and all attributable to alice's process.

### 8.2 SigmaHQ emulations (`tests/emulations/sigmahq_net_*.sh`, `expected` in `sigmahq-emul.nix`)

| family | benign action (as alice) | expected rule(s) | source that proves it |
| --- | --- | --- | --- |
| `sigmahq_net_back_connect` | `bash -c 'exec 3<>/dev/tcp/192.0.2.10/4444; exec 3>&-'` | `net_connection_lnx_back_connect_shell_dev` and its twin `net_connection_lnx_susp_malware_callback_port` (4444 is in the port list and the destination is not private) | auditd (item 3); sysmon, mimi (items 5, 6) |
| `sigmahq_net_callback_port` | python3 `socket.create_connection(("192.0.2.10", 2222))` | `net_connection_lnx_susp_malware_callback_port` only (python is not `/bin/bash`) | auditd (item 3); sysmon, mimi |
| `sigmahq_net_ngrok` | query the sink for `tunnel.us.ngrok.com`, then connect to the answer `192.0.2.10:443` | `net_connection_lnx_ngrok_tunnel` | mimi dns + join (item 8); sysmon only if its EID 3 carries a name (measured) |
| `sigmahq_net_localtonet` | query `x.localto.net`, connect to the answer on 443 | `net_connection_lnx_domain_localtonet_tunnel` | same |
| `sigmahq_net_minexmr` | query `pool.minexmr.com`, connect to the answer on 3333 | `net_connection_lnx_crypto_mining_indicators` | same |
| `sigmahq_benign` (existing) | unchanged | nothing | the false-positive guard now covers the network layer too |

The ports are chosen so each family trips exactly what the table says. 443 and 3333 are not in the
callback-port list, so the three hostname families fire one rule each. 4444 is in the list, so the
bash family has a twin, listed the way the harness lists every other twin.

### 8.3 Harness changes

- Gate the `net_connection_lnx_*` layer the way `proc_creation_lnx_*` is gated. The named rule(s)
  must fire, and no OTHER network rule may, beyond `BACKGROUND`. The "ambient network_connection
  noise" carve-out in the header is removed once the category gate (4.2) lands. The benign baseline
  assertion is extended to network rules: with the gate, nothing network-shaped fires on a benign
  exec, and the harness proves that negative.
- `auditctl -l | grep -q banken-net` beside the `banken-exec` wait.
- The DNS families need mimi in the sigmahq VM, running beside auditd (the `services.banken.mimi`
  switch that `tests/switch.nix` already exercises). Until item 6 lands, those three families are
  not in `expected`. The two IP families are, from item 3.

### 8.4 Fixtures and golden tests (fast path, no VM)

- `internal/parser/testdata/auditd_sample.audit` gains captured `connect` groups with the golden
  expectations: v4, v6, v4-mapped, an AF_UNIX that slipped the length filter, a `sendto`, a
  non-blocking `EINPROGRESS` one, and a truncated `saddr`. `FuzzAuditd` and the `rapid` property
  test cover `decodeSockaddr`: it never panics, and a decode either round-trips through `netip` or
  returns `ok=false`.
- A Sysmon EID 3 line captured on the S stage. Also an EID 22 line from a Windows host when one is
  available; until then a reconstructed one, marked as such, the way `sysmon-linux.md` does.
- mimi's shared golden (`testdata/mimi_event.golden.jsonl`) gains a `connect` and a `dns` line.
  `just contract` keeps both repos honest.
- `tests/fixtures/`: `netconnect.expect-<own rule>.json` only if an own rule is written. None is
  proposed here; the SigmaHQ set is the target. A `netconnect_benign.expect-none.json` with
  connects to loopback and private ranges proves the filters.
- A regression test in `internal/sigma` compiles the real `back_connect_shell_dev` text. It asserts
  the rule does NOT match a `process_creation` bash event, and DOES match a `network_connection`
  bash event to `192.0.2.10`.

### 8.5 Cross-source parity

The matrix (`tests/distros/`) already proves one behaviour from each source: a reverse shell, via
A2 auditd, M5 mimi, and S5 sysmon. Network parity is the same shape, with one new letter:

| ID | objective | checked by |
| --- | --- | --- |
| N1 | the connect audit rules load on this distro's auditd | `auditctl -l` shows `banken-net`, both lengths |
| N2 | an outbound connect is alerted off the auditd source | `back_connect_shell_dev` + callback-port fire, `data_sources=["auditd"]`, dst ip/port in the evidence |
| N3 | the same connect is alerted off mimi (M stage) | same two rules, `data_sources=["mimi"]`, `Protocol=tcp`, source tuple present |
| N4 | the same connect is alerted off Sysmon (S stage) | same two rules, `data_sources=["sysmon"]`; whether `DestinationHostname` was populated is recorded in `Info` |
| N5 | a DNS query is captured and joined (M stage) | the ngrok family fires off mimi with `HostnameSource=dns-cache` |

The parity rule is the same as for execs. A behaviour fires the same SigmaHQ rule from every source
that can express the fields. Where a source cannot, the ledger names the field, never a silent
miss. N4's hostname column is exactly such a recorded gap, until measured.

---

## 9. Scope ledger (what each source can carry)

For `SIGMAHQ.md`, so the five move from "deferred" to a truthful "supported (source)":

| field | raw auditd | Laurel | Sysmon-for-Linux EID 3 | mimi connect | mimi dns + join |
| --- | --- | --- | --- | --- | --- |
| DestinationIp | yes | yes | yes | yes | (join input) |
| DestinationPort | yes | yes | yes | yes | |
| Initiated | "true" always (only outbound is audited) | same | yes (true/false) | yes | |
| Protocol | no | no | yes | yes (tcp; udp later) | |
| SourceIp / SourcePort | no | no | yes | yes | |
| DestinationHostname | no | no | field exists; populated on Linux: unmeasured | no (join) | yes, when the answer was observed |
| QueryName / QueryResults | no | no | no (EID 22 Windows-only) | no | yes |
| Image / User / PID | yes | yes (+ParentImage) | yes | yes (+Ancestry) | yes |
| CommandLine | proctitle (128 B) | proctitle / argv if enriched | no (EID 3 has none) | no | no |
| inbound (accepted) connections | no (not audited) | no | yes | later (SYN_RECV) | |
| UDP sends to a connected socket | no (no SOCKADDR) | no | yes | later | port 53 only |

Rule closure, by source:

| rule | auditd / Laurel | Sysmon-for-Linux | mimi (connect + dns) |
| --- | --- | --- | --- |
| back_connect_shell_dev | supported | supported | supported |
| susp_malware_callback_port | supported | supported | supported |
| crypto_mining_indicators | field gap: DestinationHostname (closable by the join if mimi dns runs beside auditd) | pending measurement of EID 3 hostname | supported |
| domain_localtonet_tunnel | same | same | supported |
| ngrok_tunnel | same | same | supported |

The ledger line for the two IP rules after item 3 reads: "supported (auditd); field gap on
DestinationHostname for the other three, closed by mimi dns (item 8)". No line ever says
"supported" for a source whose proof did not fire.

---

## 10. Build sequence

The items are ordered so the schema, the floor source and the routing land first and actually fire
rules. The richer sources are follow-ons. Each item is one worker brief: a goal, the files, what to
prove, and what it closes.

1. **Event network fields + the category gate.**
   - Goal: the schema of section 2 and the gate of 4.2, with every existing parser stamping
     `Category` for what it already produces.
   - Files: `internal/event/event.go` (fields, `Field`, `Values` unchanged, `AllText`, JSON tags),
     `event_test.go`; `internal/sigma/rule.go` (`Category`, `AppliesTo(source, category)`),
     `pipeline.go`/`load.go` (route returns the category; `Rule.Category` set from the logsource),
     `matcher.go` (prefilter applies the same test), `pipeline.yml` (the two entries of 4.1),
     `pipeline_test.go`; `parser/auditd.go` (`process_creation` when `EXECVE` present, `file_event`
     for a PATH-only watch group, "" otherwise), `parser/laurel.go` (same), `parser/sysmon.go` (by
     EventID: 1, 11/23), `parser/mimi.go` (`kind: exec`); `docs/design/sigma-pipelines.md`.
   - Prove: the regression test of 8.4 (real `back_connect_shell_dev` text: no match on a bash
     exec, match on a bash connect); the port-as-int equality test of 4.3; every existing
     golden/fixture/conformance test unchanged, since the gate is permissive on empty.
   - Closes: the false "ambient" firing of the five, and the precondition for every later item.

2. **auditd `connect`/`sendto`: audit rules + `saddr` decode.**
   - Goal: section 3.1.
   - Files: new `internal/parser/sockaddr.go` (+ `_test.go`, table of
     v4/v6/mapped/unix/short/non-hex, a `rapid` property), `parser/auditd.go` (`SOCKADDR` in
     `parseAuditLine`; the fold rule of 3.1), `testdata/auditd_sample.audit` + `auditd.golden`
     (captured groups, not typed by hand), `fuzz_test.go`; `module.nix` (the six rules under
     `audit.network`, default on), `docs/deployment.md` (the rules for vendor distros, with the
     two-sentence why of `a2`/`a4` and no `success=1`), `bench/` (groups/s on a busy connect loop;
     the number goes in `docs/performance.md`).
   - Prove: golden and fuzz green; the worked example of 3.1 decodes to `192.0.2.10:4444`;
     `::ffff:10.0.0.1` renders as `10.0.0.1`; an EINPROGRESS connect becomes an event.
   - Closes: the fields for `back_connect_shell_dev` and `susp_malware_callback_port`.

3. **SigmaHQ emulations for the two IP rules + harness gate.**
   - Goal: 8.1 to 8.3 for the IP families; the ledger moves.
   - Files: `tests/sigmahq-emul.nix` (the `lo` address, the listener helper, `banken-net` wait, the
     network-layer gate, `expected` entries for `sigmahq_net_back_connect` and
     `sigmahq_net_callback_port`), the two `tests/emulations/sigmahq_net_*.sh` (header format as the
     others; `BANKEN-EMUL-SKIP` if python3 missing), `tests/emulations/SIGMAHQ.md` (two rules to
     supported (auditd); three stay deferred with the field named: DestinationHostname; the summary
     table row).
   - Prove: `nix-build tests/sigmahq-emul.nix` PASS on hokkaido with the two families firing
     exactly the listed rules and `sigmahq_benign` firing no network rule.
   - Closes: `net_connection_lnx_back_connect_shell_dev`,
     `net_connection_lnx_susp_malware_callback_port` (auditd).

4. **Laurel `SOCKADDR` mapping.**
   - Goal: parity for the Laurel source (3.2).
   - Files: `parser/laurel.go`, a captured line in `testdata/laurel_sample.jsonl` + `laurel.golden`.
   - Prove: the same two rules match the Laurel-sourced connect. A
     `tests/fixtures/netconnect_laurel.expect-...` fixture is not needed for SigmaHQ rules; a unit
     test over the compiled rule text, as in item 1, is.
   - Closes: the two IP rules (laurel).

5. **Sysmon EID 3 (+ EID 22 mapping) and matrix N4.**
   - Goal: 3.3.
   - Files: `parser/sysmon.go` (switch on EventID), `sysmon_test.go` + a captured EID 3 line from
     the S stage, `tests/distros/sysmoncheck.sh` (N4: the bash connect, the two rules off `sysmon`;
     record whether `DestinationHostname` was non-empty in the report `Info`),
     `tests/distros/README.md` (N table), `docs/design/sysmon-linux.md` section 6 open item closed.
   - Prove: matrix S stage PASS with N4 on an apt distro and a dnf distro.
   - Closes: the two IP rules (sysmon). The three hostname rules close on sysmon ONLY if the
     captured line carried a name, which the ledger then says.

6. **mimi connect probe (`mimi/3`, `kind: connect`) and matrix N3.**
   - Goal: 3.4.
   - Files (mimi repo): `mimi-ebpf/src/main.rs` (the `inet_sock_set_state` tracepoint, `SYN_SENT`
     filter, a second ring-buffer record type), `mimi-types` (the connect record; `SCHEMA =
     "mimi/3"`), `mimi/src/main.rs` (render as OCSF
     `dst_endpoint`/`src_endpoint`/`connection_info`), `testdata/mimi_event.golden.jsonl`.
   - Files (banken): `parser/mimi.go` (accept `mimi/2` and `mimi/3`; switch on `kind`),
     `mimi_test.go`, the shared golden, `tests/distros/mimicheck.sh` (N3), `tests/switch.nix` (a
     connect alert off the stream within the latency budget).
   - Prove: `just contract` green in both repos; N3 PASS on the M stage; capture-to-match latency
     for a connect measured and written beside the exec number.
   - Closes: the two IP rules (mimi), with `Protocol`/source tuple as a bonus no other source has.

7. **mimi DNS probe (`kind: dns`) + `dns_query` routing.**
   - Goal: 3.5 and 5.3.
   - Files (mimi): the spike note in `docs/` choosing the attachment (syscall pair vs socket pair,
     with the capture matrix glibc/musl/Go/resolved), `mimi-ebpf` (port-53 payload copy, bounded
     512), `mimi/src/dns.rs` (wire-format parser: question, A/AAAA/CNAME answers, compression
     pointers, bounded; unit-tested on captured packets), render `QueryName`/`QueryResults`.
   - Files (banken): `parser/mimi.go` (`kind: dns` -> `Category dns_query`), the golden.
     `pipeline.yml` already has the entry from item 1.
   - Prove: `just contract`; a unit test that a `dns_query` rule from the Windows set
     (`QueryName|endswith`) compiles, routes to `[mimi, sysmon, generic]` and matches the mimi
     event; mimi reads and never answers (the listener-only proof: the resolver's own answer is
     unchanged, asserted in the VM).
   - Closes: the `dns_query` category for every domain IOC and every `QueryName` rule.

8. **The answer join + the three hostname families + ledger to 5/5.**
   - Goal: 5.4 and the three DNS families of 8.2.
   - Files: `internal/engine/dnscache.go` (+ test: TTL floor, LRU bound, CNAME-to-question, unmap,
     no overwrite of a carried name), the call site on the event path, `tests/sigmahq-emul.nix`
     (mimi on in the VM, the UDP sink on `192.0.2.10:53`, the three `expected` entries), three
     `sigmahq_net_*.sh`, `tests/distros/mimicheck.sh` (N5), `tests/emulations/SIGMAHQ.md` (all five
     supported; the per-source closure table of section 9 pasted in; `network_connection/` row `5 |
     5`).
   - Prove: sigmahq-emul PASS with the five network families firing exactly their rules; N5 PASS;
     an alert for the ngrok family carries `HostnameSource=dns-cache` and `dst_endpoint.hostname`.
   - Closes: `net_connection_lnx_crypto_mining_indicators`,
     `net_connection_lnx_domain_localtonet_tunnel`, `net_connection_lnx_ngrok_tunnel` (mimi; and
     auditd when mimi dns runs beside it).

9. **OCSF evidence objects.**
   - Goal: section 7.
   - Files: `internal/alert/ocsf.go` (`dst_endpoint`, `src_endpoint`, `connection_info`, `query` on
     the evidence element), `ocsf_golden_test.go` (+ golden files under `tests/golden/ocsf/` for a
     connect and a dns finding), `docs/design/ocsf-output.md`.
   - Prove: goldens; the official validator (E4) accepts a connect finding.
   - Closes: nothing in the rule set; this is about what an operator sees.

10. **mimi TLS SNI (later).**
    - Goal: 6.1.
    - Files (mimi): first-payload copy on `ESTABLISHED`, `mimi/src/tls.rs` (ClientHello parse,
      `server_name` extension, bounded; unit-tested on captured hellos, including an ECH outer
      hello).
    - Files (banken): `HostnameSource=sni`, `Raw["TlsSni"]`, a test that DNS beats SNI when both
      exist and that a mismatch is kept in Raw.
    - Prove: a curl to the sink with `--resolve` (no DNS) still yields a hostname on the alert.
    - Closes: the hostname rules for processes that never resolved (hardcoded IP, DoH).

11. **SSL-library uprobes (research, later).**
    - Goal: 6.3, as a written spike with measured coverage (OpenSSL 3 shared, GnuTLS shared, a
      static Go binary, a static curl) and a privacy/bound proposal, before any probe is merged.
    - Closes: nothing yet. It is the honest answer to "good detail", and it is not the first thing
      to build.

Not scheduled:

- inbound connection events (no pinned rule needs them; the hooks are noted in 3.4)
- `CommunityId`
- DNS over TCP
- a `udp_sendmsg` probe for non-DNS UDP
- resolver-log scrapers (rejected in 5.2)

---

## 11. Open questions for Conor

1. **`audit.network` default.** This doc turns the six connect/sendto rules on by default
   (`services.banken.audit.network = true`), because the floor source should detect the floor
   rules. If the bench in item 2 shows a cost you do not want on every host, the alternative is
   default off, with the ledger saying "supported (auditd, audit.network on)". One option, one
   sentence.
2. **Where the answer join lives.** Section 5.4 puts it in banken's engine, so every source
   benefits: auditd connects get names from mimi's DNS. The alternative is inside mimi's loader,
   where mimi joins its own connects to its own answers and emits the hostname on the connect
   event. That keeps banken's engine stateless, but leaves auditd/Laurel connects nameless. This
   doc prefers the engine. Say if you would rather the sensor own it.
3. **Sysmon on Linux for network at all.** If the S stage shows EID 3 never carries a hostname on
   Linux, then Sysmon's network value on Linux is "a second tuple source". That is worth the parser
   switch (small) but not worth a reference config tuned for it. Decide after N4's first run.
4. **Item 7's attachment spike.** The syscall tracepoints are offset-free and simplest. The socket
   kprobes catch the connected-UDP resolver path. If you want "simplest first, measure, then add",
   say so, and the spike becomes "ship the syscall pair, record what it misses".
