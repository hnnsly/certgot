package main

import (
	"os"
	"path/filepath"
	"strings"
)

func defaultConfigPath() string {
	if path := strings.TrimSpace(os.Getenv("CERTGOT_CONFIG")); path != "" {
		return path
	}
	if os.Geteuid() == 0 {
		return managedConfigPath
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "certgot", "config.yml")
	}
	return managedConfigPath
}

func defaultStoragePath() string {
	if os.Geteuid() == 0 {
		return managedStoragePath
	}
	if dir := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); dir != "" {
		return filepath.Join(dir, "certgot")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "share", "certgot")
	}
	return managedStoragePath
}
