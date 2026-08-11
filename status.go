package main

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

func runStatus(configPath, requestedDomain string, render RenderOptions, out io.Writer) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	if requestedDomain != "" {
		normalized, normalizeErr := normalizeDomain(requestedDomain)
		if normalizeErr != nil {
			return normalizeErr
		}
		requestedDomain = normalized
	}

	results := make([]StatusRecord, 0, len(cfg.Certificates))
	namespace := stateNamespace(ACMEOptions{DirectoryURL: cfg.ACMEDirectoryURL})
	certRoot := certificateDirectoryForNamespace(cfg.StoragePath, namespace)
	var failures []error
	for _, certCfg := range cfg.Certificates {
		if requestedDomain != "" && certCfg.Domain != requestedDomain {
			continue
		}
		domainDir, dirErr := safeCertificateDir(certRoot, certCfg.Domain)
		if dirErr != nil {
			results = append(results, StatusRecord{Domain: certCfg.Domain, Status: "error", Provider: certCfg.Provider, Error: dirErr.Error()})
			failures = append(failures, dirErr)
			continue
		}
		check := checkCertificatePairWithWindow(domainDir, certCfg.Domain, renewalWindowForConfig(cfg))
		record := StatusRecord{
			Domain:   certCfg.Domain,
			Status:   certificateStatusName(check.status),
			Expiry:   formatExpiry(check.expiry),
			DaysLeft: check.daysLeft,
			Provider: certCfg.Provider,
		}
		if check.status == certificateMissing {
			record.ReleasePath = filepath.Join(domainDir, "current")
		} else if current, currentErr := filepath.EvalSymlinks(filepath.Join(domainDir, "current")); currentErr == nil {
			record.ReleasePath = current
		} else {
			record.ReleasePath = filepath.Join(domainDir, "fullchain.pem")
		}
		results = append(results, record)
		if check.status != certificateValid {
			failures = append(failures, fmt.Errorf("%s: %s", certCfg.Domain, record.Status))
		}
	}
	if requestedDomain != "" && len(results) == 0 {
		return fmt.Errorf("domain %q not found in config", requestedDomain)
	}
	report := StatusReport{Operation: "status", Results: results}
	if namespace.Mode != "production" {
		report.Mode = namespace.Mode
	}
	if err := renderStatus(out, report, render); err != nil {
		return err
	}
	return errors.Join(failures...)
}

func statusForText(status string) string {
	return strings.ReplaceAll(status, "_", "-")
}
