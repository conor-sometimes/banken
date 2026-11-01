package alert

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
)

func TestECSSeverity(t *testing.T) {
	for _, c := range []struct {
		level string
		want  int
	}{
		{"critical", 99}, {"high", 73}, {"medium", 47}, {"low", 21}, {"", 0}, {"bogus", 0},
	} {
		if got := ecsSeverity(c.level); got != c.want {
			t.Errorf("ecsSeverity(%q) = %d, want %d", c.level, got, c.want)
		}
	}
}

func TestECSThreatFromTags(t *testing.T) {
	got := ecsThreatFromTags([]string{"attack.t1059.004", "attack.execution", "notattack", "attack.T1562.001"})
	if got == nil {
		t.Fatal("nil threat for ATT&CK tags")
	}
	if got.Framework != "MITRE ATT&CK" {
		t.Errorf("framework = %q", got.Framework)
	}
	if len(got.Technique) != 2 || got.Technique[0].ID != "T1059.004" || got.Technique[1].ID != "T1562.001" {
		t.Errorf("techniques = %+v", got.Technique)
	}
	if len(got.Tactic) != 1 || got.Tactic[0].Name != "execution" {
		t.Errorf("tactics = %+v", got.Tactic)
	}
	if ecsThreatFromTags(nil) != nil {
		t.Error("want nil threat when there are no ATT&CK tags")
	}
}

func TestEncodeECS(t *testing.T) {
	a := Alert{
		Time: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
		Kind: "sigma", Rule: "reverse_shell", RuleID: "rs-1", Title: "Reverse shell spawned",
		Desc: "a shell with its io on a socket", Level: "critical", Source: "mimi",
		Tags: []string{"attack.t1059.004"}, Message: "reverse shell",
		Event: event.Event{
			Image: "/usr/bin/bash", CommandLine: "bash -i", ParentImage: "/usr/sbin/sshd",
			PID: 1234, PPID: 1000, User: "0", CurrentDirectory: "/root",
		},
	}
	b, err := EncodeECS(testOpts)(a)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	if d["@timestamp"] != "2026-10-31T12:00:00Z" {
		t.Errorf("@timestamp = %v", d["@timestamp"])
	}
	if ecsmap(d, "ecs")["version"] != ecsVersion {
		t.Errorf("ecs.version = %v", d["ecs"])
	}
	ev := ecsmap(d, "event")
	if ev["kind"] != "alert" || ev["module"] != "banken" || ev["action"] != "reverse_shell" {
		t.Errorf("event = %+v", ev)
	}
	if ev["severity"].(float64) != 99 {
		t.Errorf("event.severity = %v, want 99", ev["severity"])
	}
	proc := ecsmap(d, "process")
	if proc["executable"] != "/usr/bin/bash" || proc["command_line"] != "bash -i" || proc["pid"].(float64) != 1234 {
		t.Errorf("process = %+v", proc)
	}
	if ecsmap(proc, "parent")["executable"] != "/usr/sbin/sshd" {
		t.Errorf("process.parent = %+v", proc["parent"])
	}
	// a numeric uid maps to user.id, not user.name
	if u := ecsmap(d, "user"); u["id"] != "0" || u["name"] != nil {
		t.Errorf("user = %+v", u)
	}
	if ecsmap(d, "host")["name"] != "golden-host" {
		t.Errorf("host = %+v", d["host"])
	}
	techs := ecsmap(d, "threat")["technique"].([]any)
	if techs[0].(map[string]any)["id"] != "T1059.004" {
		t.Errorf("threat.technique = %+v", techs)
	}
}

func ecsmap(m map[string]any, k string) map[string]any {
	v, _ := m[k].(map[string]any)
	return v
}
