package main

import (
	"crypto"
	"time"

	"github.com/go-acme/lego/v4/registration"
)

type Config struct {
	Email            string              `yaml:"email"`
	StoragePath      string              `yaml:"storage_path"`
	RenewBefore      string              `yaml:"renew_before,omitempty"`
	ACMEDirectoryURL string              `yaml:"acme_directory_url,omitempty"`
	Notifications    *NotificationConfig `yaml:"notifications,omitempty"`
	Certificates     []CertConfig        `yaml:"certificates"`
}

type NotificationConfig struct {
	On       []string        `yaml:"on,omitempty"`
	Telegram *TelegramConfig `yaml:"telegram,omitempty"`
}

type TelegramConfig struct {
	BotToken string `yaml:"bot_token"`
	ChatID   int64  `yaml:"chat_id"`
	TopicID  int64  `yaml:"topic_id,omitempty"`
}

type CertConfig struct {
	Domain      string            `yaml:"domain"`
	Provider    string            `yaml:"provider"`
	Env         map[string]string `yaml:"env,omitempty"`
	EnvFile     string            `yaml:"env_file,omitempty"`
	Permissions string            `yaml:"permissions"`
	Group       string            `yaml:"group"`
	ReloadUnits []string          `yaml:"reload_units,omitempty"`
}

type ResultType int

const (
	ResultSuccess ResultType = iota
	ResultValid
	ResultError
)

const (
	managedStoragePath       = "/var/lib/certgot"
	managedStorageOwner      = "certgot"
	managedStorageGroup      = "certgot"
	managedRuntimeUser       = "certgot"
	managedBinaryPath        = "/usr/local/bin/certgot"
	managedConfigDir         = "/etc/certgot"
	managedConfigPath        = "/etc/certgot/config.yml"
	managedSecretsDir        = "/etc/certgot/secrets"
	managedTelegramEnvPath   = "/etc/certgot/secrets/telegram.env"
	managedServicePath       = "/etc/systemd/system/certgot.service"
	managedTimerPath         = "/etc/systemd/system/certgot.timer"
	certificateRenewalWindow = 30 * 24 * time.Hour
)

type CheckResult struct {
	Type     ResultType
	Domain   string
	DaysLeft int
	Until    time.Time
	Error    error
}

type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string                        { return u.Email }
func (u *MyUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *MyUser) GetPrivateKey() crypto.PrivateKey        { return u.key }
