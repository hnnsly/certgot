package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

func runApp(configPath string) error {
	absConfigPath, _ := filepath.Abs(configPath)
	cfg, err := loadConfig(absConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	certDir := filepath.Join(cfg.StoragePath, "certs")
	accountDir := filepath.Join(cfg.StoragePath, "accounts")
	if err := ensureStorageLayout(certDir, accountDir, cfg.StoragePath); err != nil {
		return err
	}

	user, err := getOrCreateUser(cfg.Email, accountDir)
	if err != nil {
		return fmt.Errorf("user error: %w", err)
	}

	client, err := newLegoClient(user)
	if err != nil {
		return err
	}

	var results []CheckResult
	for _, certCfg := range cfg.Certificates {
		res := processDomain(client, certCfg, certDir)
		results = append(results, res)
		fmt.Println(formatOneLineConsole(res))
	}

	ensureManagedStorageOwnership(cfg.StoragePath)

	if err := sendTelegramDirect(cfg.TelegramURL, results); err != nil {
		log.Printf("Failed to send telegram: %v", err)
	} else {
		log.Println("Report sent to Telegram")
	}

	return nil
}

func ensureStorageLayout(certDir, accountDir, storagePath string) error {
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(accountDir, 0700); err != nil {
		return err
	}

	ensureManagedStorageOwnership(storagePath)
	return nil
}

func newLegoClient(user *MyUser) (*lego.Client, error) {
	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = lego.LEDirectoryProduction
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
