package main

import (
	"errors"
	"io"
	"log/slog"
)

func runRenew(configPath, requestedDomain string, all, force, dryRun, staging bool, render RenderOptions, out io.Writer, logger *slog.Logger) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	if err := validateACMEOptions(ACMEOptions{Staging: staging, DirectoryURL: cfg.ACMEDirectoryURL}); err != nil {
		return err
	}
	var domains []string
	if !all {
		domains = []string{requestedDomain}
	}
	certificates, err := selectCertificates(cfg.Certificates, domains)
	if err != nil {
		return err
	}
	selectedDomains := make([]string, 0, len(certificates))
	for _, certCfg := range certificates {
		selectedDomains = append(selectedDomains, certCfg.Domain)
	}
	if dryRun {
		return runRenewDryRun(cfg, selectedDomains, force, staging, render, out)
	}
	return runAppWithOptions(configPath, RunOptions{
		Render:    render,
		Domains:   selectedDomains,
		Force:     force,
		Staging:   staging,
		Operation: "renew",
	}, out, logger)
}

func runRenewDryRun(cfg *Config, domains []string, force, staging bool, render RenderOptions, out io.Writer) error {
	certificates, err := selectCertificates(cfg.Certificates, domains)
	if err != nil {
		return err
	}
	namespace := stateNamespace(ACMEOptions{Staging: staging, DirectoryURL: cfg.ACMEDirectoryURL})
	report := RenewReport{Operation: "renew"}
	if namespace.Mode != "production" {
		report.Mode = namespace.Mode
	}
	certRoot := certificateDirectoryForNamespace(cfg.StoragePath, namespace)
	var failures []error
	for _, certCfg := range certificates {
		domainDir, dirErr := safeCertificateDir(certRoot, certCfg.Domain)
		if dirErr != nil {
			report.Results = append(report.Results, RenewRecord{Domain: certCfg.Domain, Status: "failed", Error: dirErr.Error()})
			failures = append(failures, dirErr)
			continue
		}
		check := checkCertificatePairWithWindow(domainDir, certCfg.Domain, renewalWindowForConfig(cfg))
		status, reason := dryRunRenewDecision(check.status, force)
		record := RenewRecord{Domain: certCfg.Domain, Status: status, Reason: reason}
		report.Results = append(report.Results, record)
	}
	if err := renderRenew(out, report, render); err != nil {
		return err
	}
	return errors.Join(failures...)
}

func dryRunRenewDecision(status certificateStatus, force bool) (action, reason string) {
	if force {
		return "forced", ""
	}
	if status == certificateValid {
		return "skipped", "valid"
	}
	return "would-renew", certificateStatusName(status)
}
