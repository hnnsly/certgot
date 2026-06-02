package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"gopkg.in/yaml.v3"
)

func processDomain(client *lego.Client, cfg CertConfig, certDir string) CheckResult {
	domainDir := filepath.Join(certDir, cfg.Domain)
	_ = os.MkdirAll(domainDir, directoryModeForConfig(cfg))
	if err := applyFileAccess(domainDir, cfg); err != nil {
		log.Printf("Warning: could not apply access control to %s: %v", domainDir, err)
	}

	pemPath := filepath.Join(domainDir, "fullchain.pem")
	daysLeft, expiry, exists := checkCertFile(pemPath)
	if exists && daysLeft > 30 {
		return CheckResult{Type: ResultValid, Domain: cfg.Domain, DaysLeft: daysLeft, Until: expiry}
	}

	for k, v := range cfg.Env {
		_ = os.Setenv(k, v)
	}
	defer func() {
		for k := range cfg.Env {
			_ = os.Unsetenv(k)
		}
	}()

	provider, err := dns.NewDNSChallengeProviderByName(cfg.Provider)
	if err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: err}
	}

	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: err}
	}

	request := certificate.ObtainRequest{
		Domains: []string{cfg.Domain, "*." + cfg.Domain},
		Bundle:  true,
	}

	certs, err := client.Certificate.Obtain(request)
	if err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: err}
	}

	if err := saveToDisk(domainDir, certs, cfg); err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: fmt.Errorf("save failed: %w", err)}
	}

	newDays, newExpiry, _ := checkCertFile(pemPath)
	return CheckResult{Type: ResultSuccess, Domain: cfg.Domain, DaysLeft: newDays, Until: newExpiry}
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
	pemPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	fullChain := append(certs.Certificate, certs.IssuerCertificate...)

	if err := writeFileAtomic(pemPath, fullChain, 0600); err != nil {
		return err
	}
	if err := writeFileAtomic(keyPath, certs.PrivateKey, 0600); err != nil {
		return err
	}

	if err := applyFileAccess(dir, cfg); err != nil {
		log.Printf("Warning: could not apply access control to %s: %v", dir, err)
	}
	if err := applyFileAccess(pemPath, cfg); err != nil {
		log.Printf("Warning: could not apply access control to %s: %v", pemPath, err)
	}
	if err := applyFileAccess(keyPath, cfg); err != nil {
		log.Printf("Warning: could not apply access control to %s: %v", keyPath, err)
	}

	return nil
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

func ensureManagedStorageOwnership(storagePath string) {
	if err := setManagedStorageOwnership(storagePath); err != nil {
		log.Printf("Warning: could not apply ownership %s:%s to %s: %v", managedStorageOwner, managedStorageGroup, storagePath, err)
	}
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
	if err := yaml.Unmarshal(f, &cfg); err != nil {
		return nil, err
	}
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
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

	seenDomains := make(map[string]struct{}, len(cfg.Certificates))
	for i, cert := range cfg.Certificates {
		prefix := fmt.Sprintf("certificates[%d]", i)
		domain := strings.TrimSpace(cert.Domain)
		if domain == "" {
			return fmt.Errorf("%s.domain is required", prefix)
		}
		if _, exists := seenDomains[domain]; exists {
			return fmt.Errorf("duplicate certificate domain %q", domain)
		}
		seenDomains[domain] = struct{}{}

		if strings.TrimSpace(cert.Provider) == "" {
			return fmt.Errorf("%s.provider is required", prefix)
		}
		if strings.TrimSpace(cert.Permissions) != "" {
			mode, err := strconv.ParseUint(cert.Permissions, 8, 32)
			if err != nil {
				return fmt.Errorf("%s.permissions must be octal: %w", prefix, err)
			}
			if mode > 0777 {
				return fmt.Errorf("%s.permissions must not exceed 0777", prefix)
			}
		}
	}
	return nil
}

func getOrCreateUser(email, dir string) (*MyUser, error) {
	keyFile := filepath.Join(dir, "account.key")
	registrationFile := filepath.Join(dir, "account.registration.json")
	var privateKey crypto.PrivateKey

	if keyBytes, err := os.ReadFile(keyFile); err == nil {
		block, _ := pem.Decode(keyBytes)
		if block != nil {
			privateKey, _ = x509.ParseECPrivateKey(block.Bytes)
		}
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

	user := &MyUser{Email: email, key: privateKey}
	reg, err := loadRegistration(registrationFile)
	if err != nil {
		return nil, err
	}
	user.Registration = reg

	return user, nil
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
