package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderJSONGolden(t *testing.T) {
	expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		golden string
		render func(*bytes.Buffer) error
	}{
		{
			name:   "doctor",
			golden: "doctor.json",
			render: func(buffer *bytes.Buffer) error {
				return renderDoctor(buffer, DoctorReport{Operation: "doctor", Checks: []DoctorCheck{
					{Name: "config", Status: "ok", Message: "config valid"},
					{Name: "provider", Status: "warning", Message: "credentials missing", Domain: "example.com", Remediation: "set env_file"},
				}}, RenderOptions{Format: OutputJSON})
			},
		},
		{
			name:   "status",
			golden: "status.json",
			render: func(buffer *bytes.Buffer) error {
				return renderStatus(buffer, StatusReport{Operation: "status", Results: []StatusRecord{
					{Domain: "valid.example.com", Status: "valid", Expiry: formatExpiry(expiry), DaysLeft: 100, Provider: "cloudflare", ReleasePath: "/var/lib/certgot/certs/valid.example.com/releases/one"},
					{Domain: "future.example.com", Status: "not-yet-valid", Provider: "cloudflare"},
					{Domain: "wrong.example.com", Status: "wrong-domain", Provider: "cloudflare"},
					{Domain: "mismatch.example.com", Status: "key-mismatch", Provider: "cloudflare"},
					{Domain: "renew.example.com", Status: "renewal", Provider: "cloudflare"},
				}}, RenderOptions{Format: OutputJSON})
			},
		},
		{
			name:   "renew",
			golden: "renew.json",
			render: func(buffer *bytes.Buffer) error {
				return renderRenew(buffer, RenewReport{Operation: "renew", Results: []RenewRecord{{Domain: "example.com", Status: "would-renew", Reason: "missing"}}}, RenderOptions{Format: OutputJSON})
			},
		},
		{
			name:   "run",
			golden: "run.json",
			render: func(buffer *bytes.Buffer) error {
				return renderRun(buffer, RunReport{Operation: "run", Results: []RunRecord{{Domain: "example.com", Status: "valid", DaysLeft: 100, Expiry: formatExpiry(expiry)}}, Summary: Summary{Checked: 1, Valid: 1}, Duration: "2s"}, RenderOptions{Format: OutputJSON})
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var actual bytes.Buffer
			if err := testCase.render(&actual); err != nil {
				t.Fatal(err)
			}
			assertGolden(t, testCase.golden, actual.Bytes())
		})
	}
}

func TestCertificateStatusPublicNames(t *testing.T) {
	tests := []struct {
		status certificateStatus
		want   string
	}{
		{certificateMissing, "missing"},
		{certificateMalformed, "malformed"},
		{certificateNotYetValid, "not-yet-valid"},
		{certificateWrongDomain, "wrong-domain"},
		{certificateKeyMismatch, "key-mismatch"},
		{certificateExpiringSoon, "renewal"},
		{certificateValid, "valid"},
		{certificateStatus("unknown"), "error"},
	}
	for _, test := range tests {
		if got := certificateStatusName(test.status); got != test.want || strings.Contains(got, " ") {
			t.Fatalf("status %q = %q, want %q", test.status, got, test.want)
		}
	}
}

func TestRenderTextGolden(t *testing.T) {
	var actual bytes.Buffer
	err := renderRun(&actual, RunReport{
		Operation: "run",
		Results:   []RunRecord{{Domain: "example.com", Status: "valid", DaysLeft: 100}},
		Summary:   Summary{Checked: 1, Valid: 1},
		Duration:  "2s",
	}, RenderOptions{Format: OutputText, Color: ColorNever})
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "run.txt", actual.Bytes())
}

func assertGolden(t *testing.T, name string, actual []byte) {
	t.Helper()
	expected, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("golden %s mismatch\nexpected:\n%s\nactual:\n%s", name, expected, actual)
	}
}
