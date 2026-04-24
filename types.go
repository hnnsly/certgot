package main

import (
	"crypto"
	"time"

	"github.com/go-acme/lego/v4/registration"
)

type Config struct {
	Email        string       `yaml:"email"`
	TelegramURL  string       `yaml:"telegram_url"`
	StoragePath  string       `yaml:"storage_path"`
	Certificates []CertConfig `yaml:"certificates"`
}

type CertConfig struct {
	Domain      string            `yaml:"domain"`
	Provider    string            `yaml:"provider"`
	Env         map[string]string `yaml:"env"`
	Permissions string            `yaml:"permissions"`
	Group       string            `yaml:"group"`
}

type ResultType int

const (
	ResultSuccess ResultType = iota
	ResultValid
	ResultError
)

const (
	managedStoragePath  = "/var/lib/certgot"
	managedStorageOwner = "root"
	managedStorageGroup = "certgot"
	managedBinaryPath   = "/usr/local/bin/certgot"
	managedConfigDir    = "/etc/certgot"
	managedConfigPath   = "/etc/certgot/config.yml"
	managedServicePath  = "/etc/systemd/system/certgot.service"
	managedTimerPath    = "/etc/systemd/system/certgot.timer"
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
