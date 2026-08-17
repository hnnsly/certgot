package main

import "testing"

func TestDryRunRenewDecision(t *testing.T) {
	statuses := []certificateStatus{
		certificateMissing,
		certificateMalformed,
		certificateNotYetValid,
		certificateWrongDomain,
		certificateKeyMismatch,
		certificateExpiringSoon,
	}
	for _, status := range statuses {
		action, reason := dryRunRenewDecision(status, false)
		if action != "would-renew" || reason != certificateStatusName(status) {
			t.Fatalf("status %q: action=%q reason=%q", status, action, reason)
		}
	}
	action, reason := dryRunRenewDecision(certificateValid, false)
	if action != "skipped" || reason != "valid" {
		t.Fatalf("valid: action=%q reason=%q", action, reason)
	}
	for _, status := range append(statuses, certificateValid) {
		action, reason = dryRunRenewDecision(status, true)
		if action != "forced" || reason != "" {
			t.Fatalf("forced %q: action=%q reason=%q", status, action, reason)
		}
	}
}
