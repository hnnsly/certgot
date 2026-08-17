package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"gopkg.in/yaml.v3"
)

func processDomain(client *lego.Client, cfg CertConfig, certDir string) CheckResult {
	return processDomainWithOptions(client, cfg, certDir, false, certificateRenewalWindow)
}

func processDomainWithOptions(client *lego.Client, cfg CertConfig, certDir string, force bool, renewalWindow time.Duration) CheckResult {
	return processDomainWithProviderFactory(client, cfg, certDir, force, renewalWindow, func(cfg CertConfig) (DNSProviderConfig, error) {
		provider, err := dns.NewDNSChallengeProviderByName(cfg.Provider)
		return DNSProviderConfig{Provider: provider}, err
	})
}

type DNSProviderConfig struct {
	Provider challenge.Provider
	Options  []dns01.ChallengeOption
}

type DNSProviderFactory func(CertConfig) (DNSProviderConfig, error)

func processDomainWithProviderFactory(client *lego.Client, cfg CertConfig, certDir string, force bool, renewalWindow time.Duration, newProvider DNSProviderFactory) CheckResult {
	domainDir, err := safeCertificateDir(certDir, cfg.Domain)
	if err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: err}
	}
	if err := os.MkdirAll(domainDir, directoryModeForConfig(cfg)); err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: fmt.Errorf("create certificate directory: %w", err)}
	}
	if err := applyFileAccess(domainDir, cfg); err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: fmt.Errorf("apply certificate directory access: %w", err)}
	}

	check := checkCertificatePairWithWindow(domainDir, cfg.Domain, renewalWindow)
	if check.status == certificateValid && !force {
		return CheckResult{Type: ResultValid, Domain: cfg.Domain, DaysLeft: check.daysLeft, Until: check.expiry}
	}
	env := cfg.Env
	if cfg.EnvFile != "" {
		fileEnv, envErr := loadEnvironmentFile(cfg.EnvFile)
		if envErr != nil {
			return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: fmt.Errorf("load env file: %w", envErr)}
		}
		env = mergeEnvironment(fileEnv, cfg.Env)
	}

	var result CheckResult
	err = withEnvironment(env, func() error {
		providerConfig, providerErr := newProvider(cfg)
		if providerErr != nil {
			return providerErr
		}

		if providerErr = client.Challenge.SetDNS01Provider(providerConfig.Provider, providerConfig.Options...); providerErr != nil {
			return providerErr
		}

		request := certificate.ObtainRequest{
			Domains: []string{cfg.Domain, "*." + cfg.Domain},
			Bundle:  true,
		}
		certs, obtainErr := client.Certificate.Obtain(request)
		if obtainErr != nil {
			return obtainErr
		}
		if saveErr := saveToDisk(domainDir, certs, cfg); saveErr != nil {
			return fmt.Errorf("save failed: %w", saveErr)
		}

		newCheck := checkCertificatePairWithWindow(domainDir, cfg.Domain, renewalWindow)
		if newCheck.status != certificateValid {
			return fmt.Errorf("saved certificate is not valid: %s (expires %s; renewal window %s)", newCheck.status, newCheck.expiry.UTC().Format(time.RFC3339), renewalWindow)
		}
		result = CheckResult{Type: ResultSuccess, Domain: cfg.Domain, DaysLeft: newCheck.daysLeft, Until: newCheck.expiry}
		return nil
	})
	if err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: err}
	}
	return result
}

type certificateStatus string

const (
	certificateMissing      certificateStatus = "missing"
	certificateMalformed    certificateStatus = "malformed"
	certificateNotYetValid  certificateStatus = "not yet valid"
	certificateWrongDomain  certificateStatus = "wrong domain"
	certificateKeyMismatch  certificateStatus = "private key mismatch"
	certificateExpiringSoon certificateStatus = "expiring soon"
	certificateValid        certificateStatus = "valid"
)

type certificateCheck struct {
	status   certificateStatus
	daysLeft int
	expiry   time.Time
}

func checkCertificatePair(domainDir, domain string) certificateCheck {
	return checkCertificatePairWithWindow(domainDir, domain, certificateRenewalWindow)
}

func checkCertificatePairWithWindow(domainDir, domain string, renewalWindow time.Duration) certificateCheck {
	certPath, keyPath, err := certificatePaths(domainDir)
	if err != nil {
		return certificateCheck{status: certificateMalformed}
	}
	certData, err := os.ReadFile(certPath)
	if os.IsNotExist(err) {
		return certificateCheck{status: certificateMissing}
	}
	if err != nil {
		return certificateCheck{status: certificateMalformed}
	}
	keyData, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		return certificateCheck{status: certificateMalformed}
	}
	if err != nil {
		return certificateCheck{status: certificateMalformed}
	}

	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		return certificateCheck{status: certificateMalformed}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certificateCheck{status: certificateMalformed}
	}
	privateKey, err := parsePrivateKey(keyData)
	if err != nil {
		return certificateCheck{status: certificateMalformed}
	}
	if !publicKeysEqual(cert.PublicKey, privateKey) {
		return certificateCheck{status: certificateKeyMismatch}
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return certificateCheck{status: certificateNotYetValid, expiry: cert.NotAfter}
	}
	if !hasCertificateDomains(cert, domain) {
		return certificateCheck{status: certificateWrongDomain, expiry: cert.NotAfter}
	}
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	check := certificateCheck{status: certificateExpiringSoon, daysLeft: daysLeft, expiry: cert.NotAfter}
	if cert.NotAfter.Sub(now) > renewalWindow {
		check.status = certificateValid
	}
	return check
}

func certificatePaths(domainDir string) (string, string, error) {
	currentDir := filepath.Join(domainDir, "current")
	if _, err := os.Lstat(currentDir); err == nil {
		resolved, resolveErr := filepath.EvalSymlinks(currentDir)
		if resolveErr != nil {
			return "", "", resolveErr
		}
		resolvedRoot, rootErr := filepath.EvalSymlinks(domainDir)
		if rootErr != nil || !pathWithin(resolvedRoot, resolved) {
			return "", "", fmt.Errorf("current certificate release escapes domain directory")
		}
		return filepath.Join(currentDir, "fullchain.pem"), filepath.Join(currentDir, "privkey.pem"), nil
	} else if !os.IsNotExist(err) {
		return "", "", err
	}
	return filepath.Join(domainDir, "fullchain.pem"), filepath.Join(domainDir, "privkey.pem"), nil
}

func parsePrivateKey(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("private key is not PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key")
}

func publicKeysEqual(certKey crypto.PublicKey, privateKey crypto.PrivateKey) bool {
	var privatePublic crypto.PublicKey
	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		privatePublic = &key.PublicKey
	case *rsa.PrivateKey:
		privatePublic = &key.PublicKey
	default:
		return false
	}
	certDER, certErr := x509.MarshalPKIXPublicKey(certKey)
	privateDER, privateErr := x509.MarshalPKIXPublicKey(privatePublic)
	return certErr == nil && privateErr == nil && string(certDER) == string(privateDER)
}

func hasCertificateDomains(cert *x509.Certificate, domain string) bool {
	wantWildcard := "*." + domain
	hasBase, hasWildcard := false, false
	for _, name := range cert.DNSNames {
		switch strings.ToLower(strings.TrimSuffix(name, ".")) {
		case domain:
			hasBase = true
		case wantWildcard:
			hasWildcard = true
		}
	}
	return hasBase && hasWildcard
}

func checkCertFile(path string) (int, time.Time, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, time.Time{}, false
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return 0, time.Time{}, false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, time.Time{}, false
	}

	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	return daysLeft, cert.NotAfter, true
}

func saveToDisk(dir string, certs *certificate.Resource, cfg CertConfig) error {
	if err := validateCertificateResource(certs, cfg.Domain); err != nil {
		return fmt.Errorf("validate certificate resource: %w", err)
	}
	releasesDir := filepath.Join(dir, "releases")
	if err := os.MkdirAll(releasesDir, directoryModeForConfig(cfg)); err != nil {
		return fmt.Errorf("create certificate releases directory: %w", err)
	}
	if err := applyFileAccess(dir, cfg); err != nil {
		return fmt.Errorf("apply certificate directory access: %w", err)
	}
	if err := applyFileAccess(releasesDir, cfg); err != nil {
		return fmt.Errorf("apply releases directory access: %w", err)
	}
	releaseDir, err := os.MkdirTemp(releasesDir, ".release-")
	if err != nil {
		return fmt.Errorf("create temporary certificate release: %w", err)
	}
	keepRelease := false
	defer func() {
		if !keepRelease {
			_ = os.RemoveAll(releaseDir)
		}
	}()
	if err := os.Chmod(releaseDir, directoryModeForConfig(cfg)); err != nil {
		return fmt.Errorf("chmod temporary certificate release: %w", err)
	}
	if err := applyFileAccess(releaseDir, cfg); err != nil {
		return fmt.Errorf("apply temporary release access: %w", err)
	}

	pemPath := filepath.Join(releaseDir, "fullchain.pem")
	keyPath := filepath.Join(releaseDir, "privkey.pem")
	fullChain := append(certs.Certificate, certs.IssuerCertificate...)

	if err := writeFileAtomic(pemPath, fullChain, 0600); err != nil {
		return err
	}
	if err := writeFileAtomic(keyPath, certs.PrivateKey, 0600); err != nil {
		return err
	}

	if err := applyFileAccess(pemPath, cfg); err != nil {
		return fmt.Errorf("apply certificate access: %w", err)
	}
	if err := applyFileAccess(keyPath, cfg); err != nil {
		return fmt.Errorf("apply private key access: %w", err)
	}
	if err := syncDirectory(releaseDir); err != nil {
		return fmt.Errorf("sync certificate release: %w", err)
	}

	releaseName := strings.TrimPrefix(filepath.Base(releaseDir), ".")
	finalReleaseDir := filepath.Join(releasesDir, releaseName)
	if err := os.Rename(releaseDir, finalReleaseDir); err != nil {
		return fmt.Errorf("publish certificate release: %w", err)
	}
	keepRelease = true
	if err := syncDirectory(releasesDir); err != nil {
		return fmt.Errorf("sync certificate releases: %w", err)
	}

	currentTemp, err := os.CreateTemp(dir, ".current-")
	if err != nil {
		return fmt.Errorf("create current link: %w", err)
	}
	currentTempPath := currentTemp.Name()
	if err := currentTemp.Close(); err != nil {
		_ = os.Remove(currentTempPath)
		return fmt.Errorf("close current link: %w", err)
	}
	if err := os.Remove(currentTempPath); err != nil {
		return fmt.Errorf("prepare current link: %w", err)
	}
	if err := os.Symlink(filepath.Join("releases", releaseName), currentTempPath); err != nil {
		return fmt.Errorf("create current link: %w", err)
	}
	if err := os.Rename(currentTempPath, filepath.Join(dir, "current")); err != nil {
		_ = os.Remove(currentTempPath)
		return fmt.Errorf("publish current certificate link: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync certificate directory: %w", err)
	}

	// New installations keep the historical file names as links. Existing
	// regular files are left untouched until an explicit migration, avoiding a
	// window where one legacy file points to a different release than the other.
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		legacyPath := filepath.Join(dir, name)
		if _, err := os.Lstat(legacyPath); os.IsNotExist(err) {
			linkTemp := legacyPath + ".tmp"
			if err := os.Symlink(filepath.Join("current", name), linkTemp); err != nil {
				return fmt.Errorf("create compatibility link %s: %w", name, err)
			}
			if err := os.Rename(linkTemp, legacyPath); err != nil {
				_ = os.Remove(linkTemp)
				return fmt.Errorf("publish compatibility link %s: %w", name, err)
			}
		}
	}

	return nil
}

func validateCertificateResource(resource *certificate.Resource, domain string) error {
	if resource == nil {
		return fmt.Errorf("certificate resource is nil")
	}
	block, _ := pem.Decode(resource.Certificate)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	privateKey, err := parsePrivateKey(resource.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	if !publicKeysEqual(cert.PublicKey, privateKey) {
		return fmt.Errorf("certificate and private key do not match")
	}
	if domain != "" && !hasCertificateDomains(cert, domain) {
		return fmt.Errorf("certificate does not cover %s and *.%s", domain, domain)
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func safeCertificateDir(certDir, domain string) (string, error) {
	root, err := filepath.Abs(certDir)
	if err != nil {
		return "", fmt.Errorf("resolve certificate root: %w", err)
	}
	target, err := filepath.Abs(filepath.Join(root, domain))
	if err != nil {
		return "", fmt.Errorf("resolve certificate directory: %w", err)
	}
	if !pathWithin(root, target) {
		return "", fmt.Errorf("certificate domain %q escapes storage", domain)
	}
	if err := rejectSymlinkPath(root); err != nil {
		return "", err
	}
	if err := rejectSymlinkComponents(root, target); err != nil {
		return "", err
	}
	return target, nil
}

func pathWithin(root, target string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func rejectSymlinkComponents(root, target string) error {
	if !pathWithin(root, target) {
		return fmt.Errorf("path is outside storage root")
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	current := root
	if info, statErr := os.Lstat(current); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("storage path must not be a symlink")
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil {
			return fmt.Errorf("inspect certificate path: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("certificate path contains symlink: %s", current)
		}
	}
	return nil
}

func rejectSymlinkPath(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	current := filepath.VolumeName(absolute) + string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(absolute, current), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil {
			return fmt.Errorf("inspect storage path: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("storage path contains symlink: %s", current)
		}
	}
	return nil
}

type previousEnvironmentValue struct {
	value  string
	exists bool
}

func withEnvironment(values map[string]string, fn func() error) error {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	previous := make(map[string]previousEnvironmentValue, len(keys))
	for _, key := range keys {
		value, exists := os.LookupEnv(key)
		previous[key] = previousEnvironmentValue{value: value, exists: exists}
		if err := os.Setenv(key, values[key]); err != nil {
			return errors.Join(fmt.Errorf("set environment variable %q: %w", key, err), restoreEnvironment(previous))
		}
	}

	callbackErr := fn()
	restoreErr := restoreEnvironment(previous)
	return errors.Join(callbackErr, restoreErr)
}

func restoreEnvironment(previous map[string]previousEnvironmentValue) error {
	keys := make([]string, 0, len(previous))
	for key := range previous {
		keys = append(keys, key)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	var restoreErr error
	for _, key := range keys {
		state := previous[key]
		var err error
		if state.exists {
			err = os.Setenv(key, state.value)
		} else {
			err = os.Unsetenv(key)
		}
		if err != nil {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("restore environment variable %q: %w", key, err))
		}
	}
	return restoreErr
}

func mergeEnvironment(base, override map[string]string) map[string]string {
	merged := make(map[string]string, len(base)+len(override))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range override {
		merged[key] = value
	}
	return merged
}

func loadEnvironmentFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for lineNumber, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("invalid environment file line %d", lineNumber+1)
		}
		key = strings.TrimSpace(key)
		if !validEnvironmentName(key) {
			return nil, fmt.Errorf("invalid environment variable name on line %d", lineNumber+1)
		}
		values[key] = value
	}
	return values, nil
}

func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for index, char := range name {
		letter := (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z')
		digit := char >= '0' && char <= '9'
		if letter || char == '_' || (index > 0 && digit) {
			continue
		}
		return false
	}
	return true
}

func applyFileAccess(path string, cfg CertConfig) error {
	var stat os.FileInfo
	if cfg.Permissions != "" || cfg.Group != "" {
		var err error
		stat, err = os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat failed: %w", err)
		}
	}

	if cfg.Permissions != "" {
		mode, err := parsePermissions(cfg.Permissions)
		if err != nil {
			return err
		}
		if stat.IsDir() {
			mode = directoryModeFromFileMode(mode)
		}
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("chmod failed: %w", err)
		}
	}

	if cfg.Group != "" {
		grp, err := user.LookupGroup(cfg.Group)
		if err != nil {
			return fmt.Errorf("group %q not found: %w", cfg.Group, err)
		}

		gid, err := strconv.Atoi(grp.Gid)
		if err != nil {
			return fmt.Errorf("invalid group id: %w", err)
		}

		uid := int(stat.Sys().(*syscall.Stat_t).Uid)
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("chown failed: %w", err)
		}
	}

	return nil
}

func parsePermissions(permissions string) (os.FileMode, error) {
	mode, err := strconv.ParseUint(permissions, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid permissions format %q: %w", permissions, err)
	}
	return os.FileMode(mode), nil
}

func directoryModeForConfig(cfg CertConfig) os.FileMode {
	if cfg.Permissions == "" {
		return 0755
	}
	mode, err := parsePermissions(cfg.Permissions)
	if err != nil {
		return 0755
	}
	return directoryModeFromFileMode(mode)
}

func directoryModeFromFileMode(mode os.FileMode) os.FileMode {
	if mode&0700 != 0 {
		mode |= 0100
	}
	if mode&0070 != 0 {
		mode |= 0010
	}
	if mode&0007 != 0 {
		mode |= 0001
	}
	return mode
}

func ensureManagedStorageOwnership(storagePath string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	if err := setManagedStorageOwnership(storagePath); err != nil {
		return fmt.Errorf("apply ownership %s:%s to %s: %w", managedStorageOwner, managedStorageGroup, storagePath, err)
	}
	return nil
}

func setManagedStorageOwnership(storagePath string) error {
	if filepath.Clean(storagePath) != managedStoragePath {
		return nil
	}

	uid, gid, err := resolveUserGroupIDs(managedStorageOwner, managedStorageGroup)
	if err != nil {
		return err
	}

	return chownRecursive(storagePath, uid, gid)
}

func resolveUserGroupIDs(userName, groupName string) (int, int, error) {
	usr, err := user.Lookup(userName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup user %q: %w", userName, err)
	}

	grp, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup group %q: %w", groupName, err)
	}

	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid uid for %q: %w", userName, err)
	}

	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid gid for %q: %w", groupName, err)
	}

	return uid, gid, nil
}

func chownRecursive(rootPath string, uid, gid int) error {
	return filepath.WalkDir(rootPath, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := os.Lchown(path, uid, gid); err != nil {
			return err
		}
		return nil
	})
}

func loadConfig(path string) (*Config, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	decoder := yaml.NewDecoder(strings.NewReader(string(f)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	for index := range cfg.Certificates {
		if cfg.Certificates[index].EnvFile != "" && !filepath.IsAbs(cfg.Certificates[index].EnvFile) {
			cfg.Certificates[index].EnvFile = filepath.Join(filepath.Dir(path), cfg.Certificates[index].EnvFile)
		}
	}
	return &cfg, nil
}

func telegramConfig(cfg *Config) *TelegramConfig {
	if cfg == nil || cfg.Notifications == nil {
		return nil
	}
	return cfg.Notifications.Telegram
}

func resolveEnvironmentReference(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		name := value[2 : len(value)-1]
		if !validEnvironmentName(name) {
			return "", fmt.Errorf("invalid environment reference %q", value)
		}
		resolved, ok := os.LookupEnv(name)
		if !ok || strings.TrimSpace(resolved) == "" {
			return "", fmt.Errorf("%s is not available", name)
		}
		return resolved, nil
	}
	if strings.Contains(value, "${") || strings.ContainsAny(value, "{}") {
		return "", fmt.Errorf("invalid environment reference %q", value)
	}
	return value, nil
}

func environmentReferenceName(value string) (string, bool, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		name := value[2 : len(value)-1]
		if !validEnvironmentName(name) {
			return "", false, fmt.Errorf("invalid environment reference %q", value)
		}
		return name, true, nil
	}
	if strings.Contains(value, "${") || strings.ContainsAny(value, "{}") {
		return "", false, fmt.Errorf("invalid environment reference %q", value)
	}
	return "", false, nil
}

func validateConfig(cfg *Config) error {
	if strings.TrimSpace(cfg.Email) == "" {
		return fmt.Errorf("email is required")
	}
	if strings.TrimSpace(cfg.StoragePath) == "" {
		return fmt.Errorf("storage_path is required")
	}
	if len(cfg.Certificates) == 0 {
		return fmt.Errorf("at least one certificate is required")
	}
	if strings.TrimSpace(cfg.RenewBefore) != "" {
		window, err := time.ParseDuration(cfg.RenewBefore)
		if err != nil || window <= 0 {
			return fmt.Errorf("renew_before must be a positive duration such as 720h")
		}
	}
	if rawDirectoryURL := strings.TrimSpace(cfg.ACMEDirectoryURL); rawDirectoryURL != "" {
		directoryURL, err := url.ParseRequestURI(rawDirectoryURL)
		if err != nil || (directoryURL.Scheme != "https" && directoryURL.Scheme != "http") || directoryURL.Host == "" {
			return fmt.Errorf("acme_directory_url must be an absolute HTTP(S) URL")
		}
		cfg.ACMEDirectoryURL = directoryURL.String()
	}
	if cfg.Notifications != nil {
		if telegram := cfg.Notifications.Telegram; telegram != nil {
			name, isReference, err := environmentReferenceName(telegram.BotToken)
			if err != nil {
				return fmt.Errorf("notifications.telegram.bot_token: %w", err)
			}
			if !isReference || name == "" {
				return fmt.Errorf("notifications.telegram.bot_token must be an environment reference such as ${TELEGRAM_BOT_TOKEN}")
			}
			if telegram.ChatID == 0 {
				return fmt.Errorf("notifications.telegram.chat_id is required")
			}
			if telegram.TopicID < 0 {
				return fmt.Errorf("notifications.telegram.topic_id must be positive")
			}
		}
		allowedEvents := map[string]struct{}{"always": {}, "renewed": {}, "error": {}}
		seenEvents := make(map[string]struct{}, len(cfg.Notifications.On))
		for index, event := range cfg.Notifications.On {
			event = strings.ToLower(strings.TrimSpace(event))
			if _, ok := allowedEvents[event]; !ok {
				return fmt.Errorf("notifications.on[%d] must be always, renewed, or error", index)
			}
			if _, duplicate := seenEvents[event]; duplicate {
				return fmt.Errorf("notifications.on contains duplicate event %q", event)
			}
			seenEvents[event] = struct{}{}
			cfg.Notifications.On[index] = event
		}
	}

	seenDomains := make(map[string]struct{}, len(cfg.Certificates))
	for i := range cfg.Certificates {
		cert := &cfg.Certificates[i]
		prefix := fmt.Sprintf("certificates[%d]", i)
		if strings.TrimSpace(cert.Domain) == "" {
			return fmt.Errorf("%s.domain is required", prefix)
		}
		domain, err := normalizeDomain(cert.Domain)
		if err != nil {
			return fmt.Errorf("%s.domain: %w", prefix, err)
		}
		cert.Domain = domain
		if _, exists := seenDomains[cert.Domain]; exists {
			return fmt.Errorf("duplicate certificate domain %q", cert.Domain)
		}
		seenDomains[cert.Domain] = struct{}{}

		cert.Provider = strings.TrimSpace(cert.Provider)
		if cert.Provider == "" {
			return fmt.Errorf("%s.provider is required", prefix)
		}
		cert.Group = strings.TrimSpace(cert.Group)
		if cert.Group != "" && !validSystemGroupName(cert.Group) {
			return fmt.Errorf("%s.group is invalid", prefix)
		}
		cert.Permissions = strings.TrimSpace(cert.Permissions)
		if cert.Permissions != "" {
			mode, err := strconv.ParseUint(cert.Permissions, 8, 32)
			if err != nil {
				return fmt.Errorf("%s.permissions must be octal: %w", prefix, err)
			}
			if mode > 0777 {
				return fmt.Errorf("%s.permissions must not exceed 0777", prefix)
			}
		}
		seenUnits := make(map[string]struct{}, len(cert.ReloadUnits))
		for unitIndex, unit := range cert.ReloadUnits {
			unit = strings.TrimSpace(unit)
			if err := validateSystemdUnit(unit); err != nil {
				return fmt.Errorf("%s.reload_units: %w", prefix, err)
			}
			if _, duplicate := seenUnits[unit]; duplicate {
				return fmt.Errorf("%s.reload_units contains duplicate unit %q", prefix, unit)
			}
			seenUnits[unit] = struct{}{}
			cert.ReloadUnits[unitIndex] = unit
		}
	}
	return nil
}

func renewalWindowForConfig(cfg *Config) time.Duration {
	if cfg == nil || strings.TrimSpace(cfg.RenewBefore) == "" {
		return certificateRenewalWindow
	}
	window, err := time.ParseDuration(cfg.RenewBefore)
	if err != nil || window <= 0 {
		return certificateRenewalWindow
	}
	return window
}

func normalizeDomain(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))
	if strings.HasSuffix(domain, ".") {
		domain = strings.TrimSuffix(domain, ".")
	}
	if domain == "" {
		return "", fmt.Errorf("is required")
	}
	if strings.ContainsAny(domain, `/\\*`) || strings.Contains(domain, "..") || filepath.IsAbs(domain) {
		return "", fmt.Errorf("must be a base DNS name")
	}
	if len(domain) > 253 {
		return "", fmt.Errorf("exceeds 253 characters")
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("must contain at least two labels")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("contains an invalid label length")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("contains a label beginning or ending with hyphen")
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", fmt.Errorf("contains invalid DNS characters")
			}
		}
	}
	return domain, nil
}

func getOrCreateUser(email, dir string) (*MyUser, error) {
	keyFile := filepath.Join(dir, "account.key")
	registrationFile := filepath.Join(dir, "account.registration.json")
	var privateKey crypto.PrivateKey

	keyBytes, keyErr := os.ReadFile(keyFile)
	if keyErr == nil {
		parsedKey, parseErr := parsePrivateKey(keyBytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse account key %s: %w", keyFile, parseErr)
		}
		if _, ok := parsedKey.(*ecdsa.PrivateKey); !ok {
			return nil, fmt.Errorf("account key %s is not an EC private key", keyFile)
		}
		privateKey = parsedKey
	} else if !os.IsNotExist(keyErr) {
		return nil, fmt.Errorf("read account key %s: %w", keyFile, keyErr)
	}

	reg, err := loadRegistration(registrationFile)
	if err != nil {
		return nil, err
	}
	if privateKey == nil && reg != nil {
		return nil, fmt.Errorf("account registration exists but account key is missing")
	}

	if privateKey == nil {
		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		privateKey = newKey

		keyBytes, err := x509.MarshalECPrivateKey(newKey)
		if err != nil {
			return nil, err
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
		if err := writeFileAtomic(keyFile, pemBytes, 0600); err != nil {
			return nil, err
		}
	}

	user := &MyUser{Email: email, key: privateKey, Registration: reg}

	return user, nil
}

func registrationMatchesEmail(reg *registration.Resource, email string) bool {
	if reg == nil {
		return true
	}
	want := "mailto:" + strings.TrimSpace(email)
	for _, contact := range reg.Body.Contact {
		if strings.EqualFold(strings.TrimSpace(contact), want) {
			return true
		}
	}
	return false
}

func loadRegistration(path string) (*registration.Resource, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var reg registration.Resource
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("parse registration %s: %w", path, err)
	}
	return &reg, nil
}

func saveRegistration(path string, reg *registration.Resource) error {
	if reg == nil {
		return nil
	}
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomic(path, data, 0600)
}
