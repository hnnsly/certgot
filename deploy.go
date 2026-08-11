package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type ServiceManager interface {
	Reload(unit string) error
}

type systemdServiceManager struct {
	systemctl string
}

func newSystemdServiceManager() (*systemdServiceManager, error) {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return nil, fmt.Errorf("systemctl unavailable; cannot reload configured units")
	}
	return &systemdServiceManager{systemctl: path}, nil
}

func (manager *systemdServiceManager) Reload(unit string) error {
	if err := validateSystemdUnit(unit); err != nil {
		return err
	}
	output, err := exec.Command(manager.systemctl, "reload", unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("reload %s failed: %v: %s", unit, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func validateSystemdUnit(unit string) error {
	unit = strings.TrimSpace(unit)
	if unit == "" || strings.ContainsAny(unit, "/\x00\n\r\t ") || strings.HasPrefix(unit, "-") {
		return fmt.Errorf("invalid systemd unit %q", unit)
	}
	if !strings.HasSuffix(unit, ".service") {
		return fmt.Errorf("systemd unit %q must be a .service unit", unit)
	}
	return nil
}

func reloadUnits(manager ServiceManager, units []string) error {
	for _, unit := range units {
		if err := manager.Reload(unit); err != nil {
			return err
		}
	}
	return nil
}

type pendingReloadState struct {
	Units []string `json:"units"`
}

func handleCertificateReloads(certRoot string, cfg CertConfig, result CheckResult, manager *ServiceManager, managerErr *error, factory func() (ServiceManager, error)) ([]ReloadRecord, error) {
	domainDir, err := safeCertificateDir(certRoot, cfg.Domain)
	if err != nil {
		return nil, err
	}
	var units []string
	if result.Type == ResultSuccess {
		units = uniqueStrings(cfg.ReloadUnits)
		if err := savePendingReloads(domainDir, units); err != nil {
			return nil, fmt.Errorf("save pending reloads: %w", err)
		}
	} else if result.Type == ResultValid {
		pending, loadErr := loadPendingReloads(domainDir)
		if loadErr != nil {
			return nil, fmt.Errorf("load pending reloads: %w", loadErr)
		}
		units = allowedPendingReloads(pending, cfg.ReloadUnits)
		if len(units) != len(pending) {
			if err := savePendingReloads(domainDir, units); err != nil {
				return nil, fmt.Errorf("update pending reloads: %w", err)
			}
		}
	}
	if len(units) == 0 {
		return nil, nil
	}
	if *manager == nil && *managerErr == nil {
		*manager, *managerErr = factory()
	}
	if *managerErr != nil {
		records := make([]ReloadRecord, 0, len(units))
		for _, unit := range units {
			records = append(records, ReloadRecord{Domain: cfg.Domain, Unit: unit, Status: "failed", Error: (*managerErr).Error()})
		}
		return records, *managerErr
	}
	var failed []string
	var reloadErrors []error
	records := make([]ReloadRecord, 0, len(units))
	for _, unit := range units {
		if err := (*manager).Reload(unit); err != nil {
			failed = append(failed, unit)
			reloadErrors = append(reloadErrors, fmt.Errorf("%s: %w", unit, err))
			records = append(records, ReloadRecord{Domain: cfg.Domain, Unit: unit, Status: "failed", Error: err.Error()})
			continue
		}
		records = append(records, ReloadRecord{Domain: cfg.Domain, Unit: unit, Status: "reloaded"})
	}
	if err := savePendingReloads(domainDir, failed); err != nil {
		reloadErrors = append(reloadErrors, fmt.Errorf("save pending reloads: %w", err))
	}
	return records, errors.Join(reloadErrors...)
}

func pendingReloadPath(domainDir string) string {
	return filepath.Join(domainDir, ".reload-pending.json")
}

func loadPendingReloads(domainDir string) ([]string, error) {
	path := pendingReloadPath(domainDir)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("pending reload state must not be a symlink")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state pendingReloadState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	for _, unit := range state.Units {
		if err := validateSystemdUnit(unit); err != nil {
			return nil, err
		}
	}
	return uniqueStrings(state.Units), nil
}

func savePendingReloads(domainDir string, units []string) error {
	path := pendingReloadPath(domainDir)
	units = uniqueStrings(units)
	if len(units) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	data, err := json.Marshal(pendingReloadState{Units: units})
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), 0600)
}

func allowedPendingReloads(pending, configured []string) []string {
	allowed := make(map[string]struct{}, len(configured))
	for _, unit := range configured {
		allowed[unit] = struct{}{}
	}
	var result []string
	for _, unit := range pending {
		if _, ok := allowed[unit]; ok {
			result = append(result, unit)
		}
	}
	return uniqueStrings(result)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
