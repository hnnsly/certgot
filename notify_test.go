package main

import "testing"

func TestEscapeMarkdown(t *testing.T) {
	got := escapeMarkdown("a_b*[c]`d`")
	want := "a\\_b\\*\\[c]\\`d\\`"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
