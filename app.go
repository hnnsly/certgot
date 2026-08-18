package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type RunOptions struct {
	Render        RenderOptions
	Domains       []string
	Force         bool
	Staging       bool
	Verbose       bool
	Operation     string
	RenewalWindow time.Duration
}

func runApp(configPath string) error {
	logger, err := newLogger("text", os.Stderr, false)
	if err != nil {
		return err
	}
	return runAppWithOptions(configPath, RunOptions{}, os.Stdout, logger)
}

func runAppWithOptions(configPath string, opts RunOptions, out io.Writer, logger *slog.Logger) error {
	return runAppWithDependencies(configPath, opts, out, logger, defaultApplicationDependencies())
}

func runAppWithDependencies(configPath string, opts RunOptions, out io.Writer, logger *slog.Logger, deps ApplicationDependencies) error {
	deps = deps.normalized()
	started := deps.Clock.Now()
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	cfg, err := loadConfig(absConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	certificates, err := selectCertificates(cfg.Certificates, opts.Domains)
	if err != nil {
		return err
	}
	logger.Debug("certificates selected", "operation", operationName(opts), "count", len(certificates))

	absStoragePath, err := filepath.Abs(cfg.StoragePath)
	if err != nil {
		return fmt.Errorf("resolve storage path: %w", err)
	}
	cfg.StoragePath = absStoragePath
	logger.Debug("storage resolved", "operation", operationName(opts), "storage_path", cfg.StoragePath)
	acmeOptions := ACMEOptions{Staging: opts.Staging, DirectoryURL: cfg.ACMEDirectoryURL}
	if err := validateACMEOptions(acmeOptions); err != nil {
		return err
	}
	namespace := stateNamespace(acmeOptions)
	certDir, accountDir, err := deps.Store.Prepare(cfg.StoragePath, namespace)
	if err != nil {
		return err
	}
	lock, err := deps.Store.Lock(cfg.StoragePath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			logger.Warn("could not release storage lock", "error", closeErr.Error())
		}
	}()

	user, err := getOrCreateUser(cfg.Email, accountDir)
	if err != nil {
		return fmt.Errorf("user error: %w", err)
	}

	issuer, err := deps.NewIssuer(user, acmeOptions)
	if err != nil {
		return err
	}
	if user.Registration != nil {
		if err := saveRegistration(filepath.Join(accountDir, "account.registration.json"), user.Registration); err != nil {
			return fmt.Errorf("save registration: %w", err)
		}
	}

	var results []CheckResult
	var reloads []ReloadRecord
	var domainErrors []error
	var reloadManager ServiceManager
	var reloadErr error
	renewalWindow := opts.RenewalWindow
	if renewalWindow <= 0 {
		renewalWindow = renewalWindowForConfig(cfg)
	}
	for _, certCfg := range certificates {
		domainStarted := deps.Clock.Now()
		res := issuer.Process(certCfg, certDir, opts.Force, renewalWindow)
		results = append(results, res)
		logArgs := []any{"operation", operationName(opts), "domain", res.Domain, "provider", certCfg.Provider, "result", resultStatus(res), "duration_ms", deps.Clock.Now().Sub(domainStarted).Milliseconds()}
		if res.Error != nil {
			logArgs = append(logArgs, "error", res.Error.Error())
		}
		logger.Info("certificate processed", logArgs...)
		if res.Type == ResultError {
			domainErrors = append(domainErrors, fmt.Errorf("%s: %w", res.Domain, res.Error))
		} else if namespace.Mode == "production" {
			reloadRecords, hookErr := handleCertificateReloads(certDir, certCfg, res, &reloadManager, &reloadErr, deps.NewServiceManager)
			reloads = append(reloads, reloadRecords...)
			for _, record := range reloadRecords {
				if record.Status == "failed" {
					logger.Warn("certificate reload failed", "operation", operationName(opts), "domain", record.Domain, "unit", record.Unit, "result", "failed", "error", record.Error)
				} else {
					logger.Info("certificate reload completed", "operation", operationName(opts), "domain", record.Domain, "unit", record.Unit, "result", "reloaded")
				}
			}
			if hookErr != nil {
				domainErrors = append(domainErrors, fmt.Errorf("%s reload: %w", res.Domain, hookErr))
			}
		}
	}

	var runErrors []error
	if len(domainErrors) > 0 {
		runErrors = append(runErrors, fmt.Errorf("%d certificate(s) failed: %w", len(domainErrors), errors.Join(domainErrors...)))
	}
	operation := opts.Operation
	if operation == "" {
		operation = "run"
	}
	notificationStatus := ""
	if shouldNotify(cfg, results) {
		telegram := *telegramConfig(cfg)
		resolvedToken, resolveErr := resolveEnvironmentReference(telegram.BotToken)
		if resolveErr != nil {
			notificationStatus = "failed"
			runErrors = append(runErrors, fmt.Errorf("telegram notification configuration failed: %w", resolveErr))
		} else {
			telegram.BotToken = resolvedToken
			if err := deps.Notifier.Notify(telegram, results, operation, deps.Clock.Now().Sub(started)); err != nil {
				notificationStatus = "failed"
				runErrors = append(runErrors, fmt.Errorf("telegram notification failed: %w", err))
			} else {
				notificationStatus = "sent"
				logger.Info("report sent", "operation", operation)
			}
		}
	}
	runDuration := deps.Clock.Now().Sub(started)
	runReport := buildRunReport(operation, results, reloads, runDuration)
	if namespace.Mode != "production" {
		runReport.Mode = namespace.Mode
	}
	runReport.Notification = notificationStatus
	if err := renderRun(out, runReport, opts.Render); err != nil {
		return err
	}

	logger.Info("operation completed", "operation", operation, "duration_ms", deps.Clock.Now().Sub(started).Milliseconds(), "failed", len(domainErrors))
	return errors.Join(runErrors...)
}

func operationName(opts RunOptions) string {
	if opts.Operation == "" {
		return "run"
	}
	return opts.Operation
}

func selectCertificates(certificates []CertConfig, domains []string) ([]CertConfig, error) {
	if len(domains) == 0 {
		return certificates, nil
	}
	wanted := make(map[string]struct{}, len(domains))
	for _, raw := range domains {
		domain, err := normalizeDomain(raw)
		if err != nil {
			return nil, err
		}
		wanted[domain] = struct{}{}
	}
	selected := make([]CertConfig, 0, len(wanted))
	for _, certificate := range certificates {
		if _, ok := wanted[certificate.Domain]; ok {
			selected = append(selected, certificate)
			delete(wanted, certificate.Domain)
		}
	}
	if len(wanted) > 0 {
		for domain := range wanted {
			return nil, fmt.Errorf("domain %q not found in config", domain)
		}
	}
	return selected, nil
}

func buildRunReport(operation string, results []CheckResult, reloads []ReloadRecord, duration time.Duration) RunReport {
	report := RunReport{Operation: operation, Reloads: reloads, Duration: duration.Round(time.Millisecond).String()}
	for _, result := range results {
		record := RunRecord{Domain: result.Domain, Status: resultStatus(result), DaysLeft: result.DaysLeft, Expiry: formatExpiry(result.Until)}
		if result.Error != nil {
			record.Error = result.Error.Error()
		}
		report.Results = append(report.Results, record)
		report.Summary.Checked++
		switch record.Status {
		case "valid":
			report.Summary.Valid++
		case "renewed":
			report.Summary.Renewed++
		default:
			report.Summary.Failed++
		}
	}
	return report
}

func shouldNotify(cfg *Config, results []CheckResult) bool {
	if telegramConfig(cfg) == nil {
		return false
	}
	if len(cfg.Notifications.On) == 0 {
		return false
	}
	for _, event := range cfg.Notifications.On {
		if strings.EqualFold(event, "always") {
			return true
		}
		for _, result := range results {
			if strings.EqualFold(event, "error") && result.Type == ResultError {
				return true
			}
			if strings.EqualFold(event, "renewed") && result.Type == ResultSuccess {
				return true
			}
		}
	}
	return false
}

func ensureStorageLayout(certDir, accountDir, storagePath string) error {
	if err := rejectSymlinkComponents(storagePath, certDir); err != nil {
		return fmt.Errorf("unsafe certificate storage: %w", err)
	}
	if err := rejectSymlinkComponents(storagePath, accountDir); err != nil {
		return fmt.Errorf("unsafe account storage: %w", err)
	}
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(accountDir, 0700); err != nil {
		return err
	}

	return ensureManagedStorageOwnership(storagePath)
}

func newLegoClient(user *MyUser) (*lego.Client, error) {
	return newLegoClientWithOptions(user, ACMEOptions{})
}

func newLegoClientForDirectory(user *MyUser, staging bool) (*lego.Client, error) {
	return newLegoClientWithOptions(user, ACMEOptions{Staging: staging})
}

func newLegoClientWithOptions(user *MyUser, options ACMEOptions) (*lego.Client, error) {
	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = lego.LEDirectoryProduction
	if options.Staging {
		legoConfig.CADirURL = lego.LEDirectoryStaging
	}
	if options.DirectoryURL != "" {
		legoConfig.CADirURL = options.DirectoryURL
	}
	legoConfig.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("client error: %w", err)
	}

	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("registration error: %w", err)
		}
		user.Registration = reg
	}

	return client, nil
}
