package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	WiFi struct {
		SSID     string `yaml:"ssid"`
		Password string `yaml:"password"`
	} `yaml:"wifi"`

	Tunnel struct {
		Host       string `yaml:"host"`
		PublicHost string `yaml:"public_host"`
		Port       int    `yaml:"port"`
		User       string `yaml:"user"`
		KeyFile    string `yaml:"key_file"`
		RemotePort int    `yaml:"remote_port"`
		LocalPort  int    `yaml:"local_port"`
	} `yaml:"tunnel"`

	Wish struct {
		Port           int    `yaml:"port"`
		HostKey        string `yaml:"host_key"`
		AuthorizedKeys string `yaml:"authorized_keys"`
		AdminKeys      string `yaml:"admin_keys"`
	} `yaml:"wish"`

	Server struct {
		Name string `yaml:"name"`
	} `yaml:"server"`
}

// getConfigDir returns the configuration directory
func getConfigDir() (string, error) {
	// Use XDG_CONFIG_HOME if set, otherwise ~/.config
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home directory: %v", err)
		}
		configDir = filepath.Join(home, ".config")
	}

	appConfigDir := filepath.Join(configDir, "wonderland")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(appConfigDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory %s: %v", appConfigDir, err)
	}

	// Debug output
	fmt.Printf("Config dir: %s\n", appConfigDir)
	return appConfigDir, nil
}

// getDefaultConfigPath returns the default config file path
func getDefaultConfigPath() (string, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "config.yaml"), nil
}

// LoadConfig loads configuration from the default location or specified path
func LoadConfig(customPath string) (*Config, error) {
	var configPath string
	var err error

	if customPath != "" {
		configPath = customPath
	} else {
		configPath, err = getDefaultConfigPath()
		if err != nil {
			return nil, err
		}
	}

	// Debug: show which config file we're trying to load
	fmt.Printf("Loading config from: %s\n", configPath)

	data, err := os.ReadFile(configPath)
	if err != nil {
		// Check if the file exists
		if _, statErr := os.Stat(configPath); os.IsNotExist(statErr) {
			return nil, fmt.Errorf("config file not found: %s\n\nTo get started:\n1. mkdir -p ~/.config/wonderland\n2. cp config.yaml.example ~/.config/wonderland/config.yaml\n3. Edit ~/.config/wonderland/config.yaml with your settings", configPath)
		}
		return nil, fmt.Errorf("failed to read %s: %v", configPath, err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %v", configPath, err)
	}

	// Expand paths relative to config directory if they're not absolute
	configDir := filepath.Dir(configPath)
	config.Tunnel.KeyFile = expandPath(config.Tunnel.KeyFile, configDir)
	config.Wish.HostKey = expandPath(config.Wish.HostKey, configDir)
	config.Wish.AuthorizedKeys = expandPath(config.Wish.AuthorizedKeys, configDir)
	config.Wish.AdminKeys = expandPath(config.Wish.AdminKeys, configDir) // This was missing!

	return &config, nil
}

// expandPath expands ~ to home directory and resolves relative paths
func expandPath(path string, configDir string) string {
	if path == "" {
		return path
	}

	// Handle home directory expansion
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}

	// If path is relative and doesn't start with ~, make it relative to config dir
	if !filepath.IsAbs(path) {
		return filepath.Join(configDir, path)
	}

	return path
}
