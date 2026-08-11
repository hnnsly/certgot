package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeServiceManager struct {
	units []string
	err   error
}

func (fake *fakeServiceManager) Reload(unit string) error {
	fake.units = append(fake.units, unit)
	return fake.err
}

func TestReloadUnitsUsesServiceManager(t *testing.T) {
	fake := &fakeServiceManager{}
	if err := reloadUnits(fake, []string{"nginx.service", "haproxy.service"}); err != nil {
		t.Fatal(err)
	}
	if len(fake.units) != 2 || fake.units[0] != "nginx.service" {
		t.Fatalf("unexpected reloaded units: %#v", fake.units)
	}
}

func TestValidateSystemdUnit(t *testing.T) {
	if err := validateSystemdUnit("nginx.service"); err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{"", "../nginx.service", "nginx", "nginx.timer", "-x.service"} {
		if err := validateSystemdUnit(unit); err == nil {
			t.Fatalf("expected invalid unit %q", unit)
		}
	}
}

type selectiveServiceManager struct {
	units  []string
	failOn map[string]error
}

func (manager *selectiveServiceManager) Reload(unit string) error {
	manager.units = append(manager.units, unit)
	return manager.failOn[unit]
}

func TestPendingReloadRetriesOnlyFailures(t *testing.T) {
	certRoot := filepath.Join(testSafeTempDir(t), "certs")
	domainDir := filepath.Join(certRoot, "example.com")
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		t.Fatal(err)
	}
	cfg := CertConfig{Domain: "example.com", ReloadUnits: []string{"nginx.service", "haproxy.service"}}
	first := &selectiveServiceManager{failOn: map[string]error{"haproxy.service": fmt.Errorf("access denied")}}
	var manager ServiceManager = first
	var managerErr error
	records, err := handleCertificateReloads(certRoot, cfg, CheckResult{Type: ResultSuccess, Domain: cfg.Domain}, &manager, &managerErr, func() (ServiceManager, error) {
		t.Fatal("factory should not be called")
		return nil, nil
	})
	if err == nil || len(records) != 2 {
		t.Fatalf("expected partial reload failure, records=%#v err=%v", records, err)
	}
	pending, err := loadPendingReloads(domainDir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(pending, ",") != "haproxy.service" {
		t.Fatalf("pending = %#v", pending)
	}

	second := &selectiveServiceManager{failOn: map[string]error{}}
	manager = second
	records, err = handleCertificateReloads(certRoot, cfg, CheckResult{Type: ResultValid, Domain: cfg.Domain}, &manager, &managerErr, func() (ServiceManager, error) { return second, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || strings.Join(second.units, ",") != "haproxy.service" {
		t.Fatalf("retry records=%#v units=%#v", records, second.units)
	}
	if _, err := os.Stat(pendingReloadPath(domainDir)); !os.IsNotExist(err) {
		t.Fatalf("pending state still exists: %v", err)
	}
}

func TestPendingReloadRejectsUnknownOrTamperedUnits(t *testing.T) {
	certRoot := filepath.Join(testSafeTempDir(t), "certs")
	domainDir := filepath.Join(certRoot, "example.com")
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := savePendingReloads(domainDir, []string{"nginx.service", "removed.service"}); err != nil {
		t.Fatal(err)
	}
	managerImpl := &selectiveServiceManager{failOn: map[string]error{}}
	var manager ServiceManager = managerImpl
	var managerErr error
	_, err := handleCertificateReloads(certRoot, CertConfig{Domain: "example.com", ReloadUnits: []string{"nginx.service"}}, CheckResult{Type: ResultValid}, &manager, &managerErr, func() (ServiceManager, error) { return managerImpl, nil })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(managerImpl.units, ",") != "nginx.service" {
		t.Fatalf("unexpected units: %#v", managerImpl.units)
	}
}
