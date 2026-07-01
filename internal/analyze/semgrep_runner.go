package analyze

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// SemgrepAvailable reports whether a semgrep binary is on PATH.
func SemgrepAvailable() (path string, ok bool) {
	p, err := exec.LookPath("semgrep")
	return p, err == nil
}

// runSemgrep invokes semgrep against target with the given ruleset (a
// registry name like "p/javascript" or a local YAML/dir path), returning
// raw --json output.
//
// Exit-code semantics differ between semgrep versions:
//   - v0.x: exit 1 = "findings present, not a fatal error"
//   - v1.x: exit 1 = fatal error; findings-present exit code is 0 or 2+
//
// We treat exit 1 as findings-present ONLY when stdout contains a non-empty
// JSON payload — if stdout is empty, exit 1 is a fatal error in either version.
func runSemgrep(ctx context.Context, binPath, ruleset, target string, timeout time.Duration) ([]byte, error) {
	runCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(runCtx, binPath, "--config", ruleset, "--json", "--quiet", target)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	// Check context cancellation/deadline before inspecting exit code.
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("semgrep timed out after %s scanning %s", timeout, target)
	}

	if exitErr, isExit := err.(*exec.ExitError); isExit {
		// Exit 1 with a non-empty JSON payload: findings present (v0.x semantics).
		// Exit 1 with empty stdout: fatal error in v1.x — treat as failure.
		if exitErr.ExitCode() == 1 && stdout.Len() > 0 {
			return stdout.Bytes(), nil
		}
		return nil, fmt.Errorf("semgrep exited %d: %s", exitErr.ExitCode(), stderr.String())
	} else if err != nil {
		return nil, fmt.Errorf("failed to run semgrep: %w", err)
	}
	return stdout.Bytes(), nil
}
