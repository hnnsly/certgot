package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"gopkg.in/yaml.v3"
)

func processDomain(client *lego.Client, cfg CertConfig, certDir string) CheckResult {
	domainDir := filepath.Join(certDir, cfg.Domain)
	_ = os.MkdirAll(domainDir, 0755)

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

	if err := os.WriteFile(pemPath, fullChain, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, certs.PrivateKey, 0600); err != nil {
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
	if cfg.Permissions != "" {
		mode, err := strconv.ParseUint(cfg.Permissions, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid permissions format %q: %w", cfg.Permissions, err)
		}
		if err := os.Chmod(path, os.FileMode(mode)); err != nil {
			return fmt.Errorf("chmod failed: %w", err)
		}
	}

	if cfg.Group != "" {
		stat, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat failed: %w", err)
		}

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
	err = yaml.Unmarshal(f, &cfg)
	return &cfg, err
}

func getOrCreateUser(email, dir string) (*MyUser, error) {
	keyFile := filepath.Join(dir, "account.key")
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

		keyBytes, _ := x509.MarshalECPrivateKey(newKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
		_ = os.WriteFile(keyFile, pemBytes, 0600)
	}

	return &MyUser{Email: email, key: privateKey}, nil
}
