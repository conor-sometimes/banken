package sigma_test

import (
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/internal/parser"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// TestAuditdServiceRulesFire proves the whole coverage win: SigmaHQ's
// service:auditd rules key on the raw audit field names (type, comm, exe,
// a0..aN, name, nametype, unit) that the auditd fold used to discard, so they
// loaded but could never fire. Each case here is lifted from the shape of a
// real SigmaHQ linux/auditd rule; the audit log is the records auditd emits
// for the matching activity. Parser -> matcher, end to end.
func TestAuditdServiceRulesFire(t *testing.T) {
	cases := []struct {
		name  string
		rule  string // the detection shape of a real SigmaHQ auditd rule
		audit string // the raw auditd records for one matching audit event
	}{
		{
			// lnx_auditd_load_module_insmod: type SYSCALL, comm, exe.
			name: "insmod kernel module load",
			rule: `title: insmod
detection:
  selection:
    type: 'SYSCALL'
    comm: insmod
    exe: /usr/bin/kmod
  condition: selection`,
			audit: `type=SYSCALL msg=audit(1700000000.1:1): arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=1001 auid=0 uid=0 comm="insmod" exe="/usr/bin/kmod" key="modules"
type=EXECVE msg=audit(1700000000.1:1): argc=2 a0="insmod" a1="evil.ko"`,
		},
		{
			// lnx_auditd_ld_so_preload_mod: type PATH, name (multi-valued).
			name: "ld.so.preload write",
			rule: `title: ld_preload
detection:
  selection:
    type: 'PATH'
    name: '/etc/ld.so.preload'
  condition: selection`,
			audit: `type=SYSCALL msg=audit(1700000000.2:2): arch=c000003e syscall=257 success=yes exit=3 ppid=1000 pid=1002 auid=0 uid=0 comm="bash" exe="/usr/bin/bash"
type=PATH msg=audit(1700000000.2:2): item=0 name="/etc/ld.so.preload" inode=99 nametype=CREATE`,
		},
		{
			// lnx_auditd_coinminer: a1..a7 startswith --cpu-priority (no type gate).
			name: "xmrig coinminer flag",
			rule: `title: coinminer
detection:
  cmd1:
    a1|startswith: '--cpu-priority'
  condition: cmd1`,
			audit: `type=SYSCALL msg=audit(1700000000.3:3): arch=c000003e syscall=59 ppid=1000 pid=1003 auid=0 uid=0 comm="xmrig" exe="/tmp/xmrig"
type=EXECVE msg=audit(1700000000.3:3): argc=2 a0="xmrig" a1="--cpu-priority=5"`,
		},
		{
			// lnx_auditd_disable_system_firewall: standalone SERVICE_STOP + unit.
			name: "firewall service stop",
			rule: `title: disable_firewall
detection:
  selection:
    type: 'SERVICE_STOP'
    unit:
      - 'firewalld'
      - 'iptables'
      - 'ufw'
  condition: selection`,
			audit: `type=SERVICE_STOP msg=audit(1700000000.4:4): pid=1 uid=0 auid=0 unit=firewalld comm="systemd" exe="/usr/lib/systemd/systemd" res=success`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rule, err := sigma.Compile([]byte(c.rule))
			if err != nil {
				t.Fatalf("compile rule: %v", err)
			}
			events, err := parser.Auditd{}.Parse(strings.NewReader(c.audit))
			if err != nil {
				t.Fatalf("parse audit log: %v", err)
			}
			if len(events) != 1 {
				t.Fatalf("expected 1 folded event, got %d", len(events))
			}
			if hits := sigma.NewMatcher([]*sigma.Rule{rule}).Match(events[0]); len(hits) != 1 {
				t.Fatalf("rule did not fire on its matching audit event\n  event: %+v", events[0])
			}
		})
	}
}
