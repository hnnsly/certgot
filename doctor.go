package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
)

type DoctorOptions struct {
	Render  RenderOptions
	Offline bool
}

func runDoctor(configPath string, opts DoctorOptions, out io.Writer) error {
	checks := make([]DoctorCheck, 0, 8)
	cfg, err := loadConfig(configPath)
	if err != nil {
		checks = append(checks, DoctorCheck{
			Name:        "config",
			Status:      "error",
			Message:     "config is invalid: " + err.Error(),
			Remediation: "fix the reported YAML or validation error, then run doctor again",
		})
		reportErr := renderDoctor(out, DoctorReport{Operation: "doctor", Checks: checks}, opts.Render)
		return errors.Join(err, reportErr)
	}
	checks = append(checks, DoctorCheck{Name: "config", Status: "ok", Message: "config valid"})

	namespace := stateNamespace(ACMEOptions{DirectoryURL: cfg.ACMEDirectoryURL})
	checks = append(checks, checkStorage(cfg.StoragePath))
	checks = append(checks, checkAccountState(cfg.StoragePath, cfg.Email, namespace)...)
	checks = append(checks, checkTelegram(telegramConfigValue(cfg)))
	managedMode := isManagedMode(configPath, cfg)
	if managedMode {
		checks = append(checks, checkManagedReloadPolicy(cfg))
	}
	for _, certCfg := range cfg.Certificates {
		checks = append(checks, checkProviderCredentials(certCfg))
		checks = append(checks, checkExistingCertificate(cfg.StoragePath, certCfg, renewalWindowForConfig(cfg), namespace))
	}
	if !opts.Offline {
		checks = append(checks, checkACMEDirectory(cfg.ACMEDirectoryURL))
		if managedMode {
			checks = append(checks, checkSystemdUnits())
		}
	}

	reportErr := renderDoctor(out, DoctorReport{Operation: "doctor", Checks: checks}, opts.Render)
	var errorsFound []error
	for _, check := range checks {
		if check.Status == "error" {
			errorsFound = append(errorsFound, fmt.Errorf("%s: %s", check.Name, check.Message))
		}
	}
	return errors.Join(errors.Join(errorsFound...), reportErr)
}

func checkManagedReloadPolicy(cfg *Config) DoctorCheck {
	if err := validateManagedReloadPolicy(cfg); err != nil {
		return DoctorCheck{Name: "reload", Status: "error", Message: "managed reload_units are disabled", Remediation: err.Error()}
	}
	return DoctorCheck{Name: "reload", Status: "ok", Message: "managed reload policy valid"}
}

func checkStorage(storagePath string) DoctorCheck {
	if err := rejectSymlinkPath(storagePath); err != nil {
		return DoctorCheck{Name: "storage", Status: "error", Message: "storage path is unsafe", Remediation: err.Error()}
	}
	info, err := os.Stat(storagePath)
	if os.IsNotExist(err) {
		return DoctorCheck{Name: "storage", Status: "warning", Message: "storage is not initialized", Remediation: "run certgot setup or create the storage path with the runtime user's permissions"}
	}
	if err != nil {
		return DoctorCheck{Name: "storage", Status: "error", Message: "storage is not readable", Remediation: err.Error()}
	}
	if !info.IsDir() {
		return DoctorCheck{Name: "storage", Status: "error", Message: "storage path is not a directory", Remediation: "choose a directory for storage_path"}
	}
	return DoctorCheck{Name: "storage", Status: "ok", Message: "storage accessible"}
}

func checkAccountState(storagePath, email string, namespace StateNamespace) []DoctorCheck {
	accountDir := accountDirectoryForNamespace(storagePath, namespace)
	keyPath := filepath.Join(accountDir, "account.key")
	registrationPath := filepath.Join(accountDir, "account.registration.json")
	checks := make([]DoctorCheck, 0, 2)
	keyData, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		checks = append(checks, DoctorCheck{Name: "account-key", Status: "warning", Message: "account key not initialized", Remediation: "run certgot run or certgot setup before issuing certificates"})
	} else if err != nil {
		checks = append(checks, DoctorCheck{Name: "account-key", Status: "error", Message: "account key is not readable", Remediation: "restore account.key with permissions readable by certgot"})
	} else if key, parseErr := parsePrivateKey(keyData); parseErr != nil {
		checks = append(checks, DoctorCheck{Name: "account-key", Status: "error", Message: "account key is malformed", Remediation: "restore the matching account.key and registration backup"})
	} else if _, ok := key.(*ecdsa.PrivateKey); !ok {
		checks = append(checks, DoctorCheck{Name: "account-key", Status: "error", Message: "account key is not an EC private key", Remediation: "restore a supported EC account key"})
	} else {
		checks = append(checks, DoctorCheck{Name: "account-key", Status: "ok", Message: "account key valid"})
	}

	reg, err := loadRegistration(registrationPath)
	if err != nil {
		checks = append(checks, DoctorCheck{Name: "account-registration", Status: "error", Message: "account registration is malformed", Remediation: "restore account.registration.json from the same account backup"})
	} else if reg == nil {
		checks = append(checks, DoctorCheck{Name: "account-registration", Status: "warning", Message: "account registration not initialized", Remediation: "run certgot run after the account key is available"})
	} else if !registrationMatchesEmail(reg, email) {
		checks = append(checks, DoctorCheck{Name: "account-registration", Status: "warning", Message: "registration contact differs from config email", Remediation: "verify the account backup and configured ACME email"})
	} else {
		checks = append(checks, DoctorCheck{Name: "account-registration", Status: "ok", Message: "account registration valid"})
	}
	return checks
}

func checkProviderCredentials(cfg CertConfig) DoctorCheck {
	env := cfg.Env
	if cfg.EnvFile != "" {
		fileInfo, statErr := os.Stat(cfg.EnvFile)
		if os.IsNotExist(statErr) {
			return DoctorCheck{Name: "provider", Domain: cfg.Domain, Status: "error", Message: cfg.Provider + " env_file is missing", Remediation: "create " + cfg.EnvFile + " with KEY=value entries"}
		}
		if statErr != nil {
			return DoctorCheck{Name: "provider", Domain: cfg.Domain, Status: "error", Message: cfg.Provider + " env_file is not readable", Remediation: "check the env_file path and permissions"}
		}
		if fileInfo.Mode().Perm()&0007 != 0 {
			return DoctorCheck{Name: "provider", Domain: cfg.Domain, Status: "error", Message: cfg.Provider + " env_file is too permissive", Remediation: "chmod 0600 or 0640 " + cfg.EnvFile}
		}
		fileEnv, loadErr := loadEnvironmentFile(cfg.EnvFile)
		if loadErr != nil {
			return DoctorCheck{Name: "provider", Domain: cfg.Domain, Status: "error", Message: cfg.Provider + " env_file is invalid", Remediation: loadErr.Error()}
		}
		env = mergeEnvironment(fileEnv, cfg.Env)
	}
	providerErr := withEnvironment(env, func() error {
		_, err := dns.NewDNSChallengeProviderByName(cfg.Provider)
		return err
	})
	if providerErr != nil {
		message := cfg.Provider + " credentials are not usable"
		if len(env) == 0 {
			message = cfg.Provider + " credentials are missing"
		}
		return DoctorCheck{Name: "provider", Domain: cfg.Domain, Status: "error", Message: message, Remediation: "check provider names and required environment variables"}
	}
	return DoctorCheck{Name: "provider", Domain: cfg.Domain, Status: "ok", Message: cfg.Provider + " credentials found"}
}

func isManagedMode(configPath string, cfg *Config) bool {
	if cfg != nil && filepath.Clean(cfg.StoragePath) == managedStoragePath {
		return true
	}
	absConfigPath, err := filepath.Abs(configPath)
	return err == nil && filepath.Clean(absConfigPath) == managedConfigPath
}

func checkExistingCertificate(storagePath string, cfg CertConfig, renewalWindow time.Duration, namespace StateNamespace) DoctorCheck {
	domainDir, err := safeCertificateDir(certificateDirectoryForNamespace(storagePath, namespace), cfg.Domain)
	if err != nil {
		return DoctorCheck{Name: "certificate", Domain: cfg.Domain, Status: "error", Message: "certificate path is unsafe", Remediation: err.Error()}
	}
	check := checkCertificatePairWithWindow(domainDir, cfg.Domain, renewalWindow)
	status := certificateStatusName(check.status)
	switch check.status {
	case certificateValid:
		return DoctorCheck{Name: "certificate", Domain: cfg.Domain, Status: "ok", Message: cfg.Domain + " certificate valid"}
	case certificateExpiringSoon:
		return DoctorCheck{Name: "certificate", Domain: cfg.Domain, Status: "warning", Message: cfg.Domain + " certificate enters renewal window", Remediation: "run certgot renew --domain " + cfg.Domain}
	case certificateMissing:
		return DoctorCheck{Name: "certificate", Domain: cfg.Domain, Status: "warning", Message: cfg.Domain + " certificate missing", Remediation: "run certgot renew --domain " + cfg.Domain}
	default:
		return DoctorCheck{Name: "certificate", Domain: cfg.Domain, Status: "error", Message: cfg.Domain + " certificate " + status, Remediation: "restore a matching certificate/key pair or run certgot renew --domain " + cfg.Domain}
	}
}

func checkTelegram(rawURL string) DoctorCheck {
	if strings.TrimSpace(rawURL) == "" {
		return DoctorCheck{Name: "telegram", Status: "warning", Message: "telegram disabled", Remediation: "set telegram_url or notifications.telegram_url if reports are required"}
	}
	resolved, err := resolveEnvironmentReference(rawURL)
	if err != nil {
		return DoctorCheck{Name: "telegram", Status: "error", Message: "telegram environment reference is unavailable", Remediation: err.Error()}
	}
	if _, _, _, err := parseTelegramURL(resolved); err != nil {
		return DoctorCheck{Name: "telegram", Status: "error", Message: "telegram URL invalid", Remediation: "use telegram://BOT_TOKEN@telegram?chats=CHAT_ID"}
	}
	return DoctorCheck{Name: "telegram", Status: "ok", Message: "telegram URL valid"}
}

func checkACMEDirectory(directoryURL string) DoctorCheck {
	return checkACMEDirectoryWithClient(directoryURL, &http.Client{Timeout: 5 * time.Second})
}

func checkACMEDirectoryWithClient(directoryURL string, client *http.Client) DoctorCheck {
	if strings.TrimSpace(directoryURL) == "" {
		directoryURL = lego.LEDirectoryProduction
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryURL, nil)
	if err != nil {
		return DoctorCheck{Name: "acme", Status: "warning", Message: "ACME directory URL could not be built", Remediation: "check network configuration"}
	}
	response, err := client.Do(request)
	if err != nil {
		return DoctorCheck{Name: "acme", Status: "warning", Message: "ACME directory connectivity unavailable", Remediation: "check DNS, HTTPS egress, and firewall rules"}
	}
	_ = response.Body.Close()
	if response.StatusCode >= 400 {
		return DoctorCheck{Name: "acme", Status: "warning", Message: "ACME directory returned an unavailable status", Remediation: "retry later or use the staging directory"}
	}
	return DoctorCheck{Name: "acme", Status: "ok", Message: "ACME directory reachable"}
}

func checkSystemdUnits() DoctorCheck {
	path, err := exec.LookPath("systemd-analyze")
	if err != nil {
		return DoctorCheck{Name: "systemd", Status: "warning", Message: "systemd-analyze unavailable", Remediation: "run doctor on the managed Linux host"}
	}
	command := exec.Command(path, "verify", managedServicePath, managedTimerPath)
	if output, runErr := command.CombinedOutput(); runErr != nil {
		return DoctorCheck{Name: "systemd", Status: "error", Message: "systemd units failed verification", Remediation: strings.TrimSpace(string(output))}
	}
	return DoctorCheck{Name: "systemd", Status: "ok", Message: "systemd units valid"}
}
