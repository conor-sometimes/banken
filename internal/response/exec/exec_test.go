//go:build !linux

package exec

import (
	"context"
	"errors"
	"testing"

	"github.com/conor-sometimes/banken/internal/response"
)

// On non-Linux the executor is dry-run only: it performs nothing and arming
// enforcement is unsupported. These tests run on the Mac dev box; the real
// pidfd/cgroup/renameat2 behaviour is proven in exec_linux_test.go on Linux.

func TestNewDryRunByDefault(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.Enforcing() {
		t.Fatalf("default executor must NOT be enforcing")
	}
}

func TestEnforceUnsupportedOffLinux(t *testing.T) {
	_, err := New(Config{Enforce: true})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("New(Enforce) off Linux = %v, want ErrUnsupported", err)
	}
}

func TestDryRunActionsDoNothing(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	p := response.ProcessRef{PID: 4242, Image: "/tmp/.x/sh"}

	h, err := e.Freeze(ctx, p, response.ScopeTree)
	if err != nil || !h.DryRun {
		t.Errorf("Freeze dry-run: handle=%+v err=%v", h, err)
	}
	h, err = e.Kill(ctx, p, response.ScopeProcess)
	if err != nil || !h.DryRun {
		t.Errorf("Kill dry-run: handle=%+v err=%v", h, err)
	}
	h, err = e.Quarantine(ctx, response.FileRef{Path: "/tmp/loot"})
	if err != nil || !h.DryRun {
		t.Errorf("Quarantine dry-run: handle=%+v err=%v", h, err)
	}
	h, err = e.Collect(ctx, p)
	if err != nil || !h.DryRun {
		t.Errorf("Collect dry-run: handle=%+v err=%v", h, err)
	}
}
