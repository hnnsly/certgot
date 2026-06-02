package main

import "testing"

func TestParseSetupInterval(t *testing.T) {
	tests := []struct {
		raw          string
		wantDays     int
		wantInterval string
		wantErr      bool
	}{
		{raw: "1d", wantDays: 1, wantInterval: "1d"},
		{raw: "2w", wantDays: 14, wantInterval: "14d"},
		{raw: "1m", wantDays: 30, wantInterval: "30d"},
		{raw: "", wantErr: true},
		{raw: "0d", wantErr: true},
		{raw: "1y", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			gotDays, gotInterval, err := parseSetupInterval(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if gotDays != tt.wantDays || gotInterval != tt.wantInterval {
				t.Fatalf("expected (%d, %q), got (%d, %q)", tt.wantDays, tt.wantInterval, gotDays, gotInterval)
			}
		})
	}
}
