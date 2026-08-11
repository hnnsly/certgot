package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunCLIRejectsLegacySetupFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runCLI([]string{"-setup"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--setup") {
		t.Fatalf("expected legacy setup flag error, got %v", err)
	}
}

func TestRunCLIVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	oldVersion := version
	version = "test"
	t.Cleanup(func() { version = oldVersion })

	if err := runCLI([]string{"--version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got != "certgot test\n" {
		t.Fatalf("unexpected version output %q", got)
	}
}
