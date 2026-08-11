package main

import (
	"strings"
	"testing"
)

func TestStorageLockRejectsContentionAndRecovers(t *testing.T) {
	storagePath := t.TempDir()
	first, err := acquireStorageLock(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := acquireStorageLock(storagePath); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("expected contention error, got %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireStorageLock(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
