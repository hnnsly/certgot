package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/lego"
)

// Clock isolates elapsed-time measurements from the application workflow.
type Clock interface {
	Now() time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

// CertificateIssuer is the ACME boundary used by the application workflow.
// Implementations own external ACME and DNS-provider interactions.
type CertificateIssuer interface {
	Process(CertConfig, string, bool, time.Duration) CheckResult
}

type ACMEOptions struct {
	Staging      bool
	DirectoryURL string
}

type CertificateIssuerFactory func(*MyUser, ACMEOptions) (CertificateIssuer, error)

type legoCertificateIssuer struct {
	client *lego.Client
}

func (issuer *legoCertificateIssuer) Process(cfg CertConfig, certDir string, force bool, renewalWindow time.Duration) CheckResult {
	return processDomainWithOptions(issuer.client, cfg, certDir, force, renewalWindow)
}

func newLegoCertificateIssuer(user *MyUser, options ACMEOptions) (CertificateIssuer, error) {
	client, err := newLegoClientWithOptions(user, options)
	if err != nil {
		return nil, err
	}
	return &legoCertificateIssuer{client: client}, nil
}

// CertificateStore is the filesystem boundary for certificate state.
type CertificateStore interface {
	Prepare(storagePath string, namespace StateNamespace) (certDir, accountDir string, err error)
	Lock(storagePath string) (io.Closer, error)
}

type StateNamespace struct {
	Key  string
	Mode string
}

func certificateDirectoryForNamespace(storagePath string, namespace StateNamespace) string {
	if namespace.Key == "" {
		return filepath.Join(storagePath, "certs")
	}
	return filepath.Join(storagePath, "certs-"+namespace.Key)
}

func accountDirectoryForNamespace(storagePath string, namespace StateNamespace) string {
	if namespace.Key == "" {
		return filepath.Join(storagePath, "accounts")
	}
	return filepath.Join(storagePath, "accounts", namespace.Key)
}

func stateNamespace(options ACMEOptions) StateNamespace {
	if options.DirectoryURL != "" {
		digest := sha256.Sum256([]byte(options.DirectoryURL))
		return StateNamespace{Key: "custom-" + hex.EncodeToString(digest[:6]), Mode: "custom"}
	}
	if options.Staging {
		return StateNamespace{Key: "staging", Mode: "staging"}
	}
	return StateNamespace{Mode: "production"}
}

func validateACMEOptions(options ACMEOptions) error {
	if options.Staging && strings.TrimSpace(options.DirectoryURL) != "" {
		return fmt.Errorf("--staging cannot be used with acme_directory_url; remove one of them")
	}
	return nil
}

type filesystemCertificateStore struct{}

func (filesystemCertificateStore) Prepare(storagePath string, namespace StateNamespace) (string, string, error) {
	if err := rejectSymlinkPath(storagePath); err != nil {
		return "", "", fmt.Errorf("unsafe storage path: %w", err)
	}
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		return "", "", fmt.Errorf("create storage root: %w", err)
	}
	if err := rejectSymlinkComponents(storagePath, storagePath); err != nil {
		return "", "", fmt.Errorf("unsafe storage path: %w", err)
	}
	certDir := certificateDirectoryForNamespace(storagePath, namespace)
	accountDir := accountDirectoryForNamespace(storagePath, namespace)
	if err := ensureStorageLayout(certDir, accountDir, storagePath); err != nil {
		return "", "", err
	}
	return certDir, accountDir, nil
}

func (filesystemCertificateStore) Lock(storagePath string) (io.Closer, error) {
	return acquireStorageLock(storagePath)
}

// Notifier is the reporting transport boundary. It intentionally receives
// already-sanitized domain results, never provider credentials.
type Notifier interface {
	Notify(rawURL string, results []CheckResult, operation string, duration time.Duration) error
}

type telegramNotifier struct{}

func (telegramNotifier) Notify(rawURL string, results []CheckResult, operation string, duration time.Duration) error {
	return sendTelegramReport(rawURL, results, operation, duration)
}

type ApplicationDependencies struct {
	Clock             Clock
	Store             CertificateStore
	NewIssuer         CertificateIssuerFactory
	Notifier          Notifier
	NewServiceManager func() (ServiceManager, error)
}

func defaultApplicationDependencies() ApplicationDependencies {
	return ApplicationDependencies{
		Clock:     wallClock{},
		Store:     filesystemCertificateStore{},
		NewIssuer: newLegoCertificateIssuer,
		Notifier:  telegramNotifier{},
		NewServiceManager: func() (ServiceManager, error) {
			return newSystemdServiceManager()
		},
	}
}

func (deps ApplicationDependencies) normalized() ApplicationDependencies {
	defaults := defaultApplicationDependencies()
	if deps.Clock == nil {
		deps.Clock = defaults.Clock
	}
	if deps.Store == nil {
		deps.Store = defaults.Store
	}
	if deps.NewIssuer == nil {
		deps.NewIssuer = defaults.NewIssuer
	}
	if deps.Notifier == nil {
		deps.Notifier = defaults.Notifier
	}
	if deps.NewServiceManager == nil {
		deps.NewServiceManager = defaults.NewServiceManager
	}
	return deps
}
