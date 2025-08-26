package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// formatAddress properly formats addresses for dialing, handling IPv6 bracketing
func formatAddress(address string, port int) string {
	// Check if it's an IPv6 address (contains colons but not already bracketed)
	if strings.Contains(address, ":") && !strings.HasPrefix(address, "[") {
		// IPv6 address without brackets - add them
		return fmt.Sprintf("[%s]:%d", address, port)
	} else if strings.HasPrefix(address, "[") {
		// Already bracketed IPv6 address
		return fmt.Sprintf("%s:%d", address, port)
	} else {
		// IPv4 address or hostname
		return fmt.Sprintf("%s:%d", address, port)
	}
}

// checkIPv6Connectivity tests if IPv6 connectivity is working
func checkIPv6Connectivity() bool {
	// Try connecting to Google's IPv6 DNS server
	conn, err := net.DialTimeout("tcp6", "[2001:4860:4860::8888]:53", 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// isIPv6Address checks if the given address is IPv6
func isIPv6Address(address string) bool {
	// Remove brackets if present
	cleanAddr := strings.Trim(address, "[]")
	ip := net.ParseIP(cleanAddr)
	return ip != nil && ip.To4() == nil && ip.To16() != nil
}

// handleConnectionError provides helpful error messages and suggestions
func handleConnectionError(err error, targetHost string, bastionOverride string, commandContext string) error {
	// Check if this is an IPv6 connectivity issue
	if isIPv6Address(targetHost) && bastionOverride == "" {
		log.Printf("Connection failed to IPv6 address: %v", err)
		log.Printf("Checking IPv6 connectivity...")

		if !checkIPv6Connectivity() {
			return fmt.Errorf(`connection failed: %v

IPv6 connectivity test failed. Your network may not support IPv6.

Suggestion: Use a bastion host with IPv4 connectivity:
  %s -b user@bastion-host:22

Where:
  - user: your username on the bastion host
  - bastion-host: IPv4 address or hostname of your bastion server
  - 22: SSH port on bastion host (optional, defaults to 22)

Example: %s -b myuser@203.0.113.1:22`, err, commandContext, commandContext)
		}
	}

	// Return original error if not IPv6 related
	return err
}

// configModel represents the state of our configuration TUI
type configModel struct {
	fields       []configField
	currentField int
	finished     bool
	err          error
}

type configField struct {
	label       string
	placeholder string
	value       string
	help        string
	required    bool
	validator   func(string) error
}

func (m configModel) Init() tea.Cmd {
	return nil
}

func (m configModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "enter":
			// Get the effective value (use placeholder if field is empty)
			field := &m.fields[m.currentField]
			effectiveValue := strings.TrimSpace(field.value)
			if effectiveValue == "" {
				effectiveValue = field.placeholder
			}

			// Validate if there's a validator
			if field.validator != nil {
				if err := field.validator(effectiveValue); err != nil {
					// Validation failed, don't advance
					return m, nil
				}
			}

			// Check if required field is effectively empty
			if field.required && effectiveValue == "" {
				// Required field is empty, don't advance
				return m, nil
			}

			// Advance to next field or finish
			if m.currentField < len(m.fields)-1 {
				m.currentField++
			} else {
				// Last field, we're done
				m.finished = true
				return m, tea.Quit
			}
		case "tab":
			// Tab always advances (no validation)
			if m.currentField < len(m.fields)-1 {
				m.currentField++
			} else {
				// On last field with Tab, finish
				m.finished = true
				return m, tea.Quit
			}
		case "shift+tab":
			if m.currentField > 0 {
				m.currentField--
			}
		case "backspace":
			if len(m.fields[m.currentField].value) > 0 {
				m.fields[m.currentField].value = m.fields[m.currentField].value[:len(m.fields[m.currentField].value)-1]
			}
		default:
			// Add character to current field
			if len(msg.String()) == 1 {
				m.fields[m.currentField].value += msg.String()
			}
		}
	}
	return m, nil
}

func (m configModel) View() string {
	var s strings.Builder

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("205")).
		MarginBottom(1)

	fieldStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("240")).
		Padding(0, 1).
		MarginBottom(1)

	activeFieldStyle := fieldStyle.Copy().
		BorderForeground(lipgloss.Color("205"))

	helpStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		MarginBottom(1)

	s.WriteString(titleStyle.Render("Wonderland Configuration Setup"))
	s.WriteString("\n")

	for i, field := range m.fields {
		var fieldStr string
		if field.value == "" && i == m.currentField {
			fieldStr = field.placeholder
		} else if field.value == "" {
			fieldStr = field.placeholder
		} else {
			fieldStr = field.value
		}

		// Show cursor on active field
		if i == m.currentField {
			fieldStr += "│"
		}

		label := field.label
		if field.required {
			label += " *"
		}

		var style lipgloss.Style
		if i == m.currentField {
			style = activeFieldStyle
		} else {
			style = fieldStyle
		}

		s.WriteString(label + "\n")
		s.WriteString(style.Render(fieldStr))
		s.WriteString("\n")

		if i == m.currentField && field.help != "" {
			s.WriteString(helpStyle.Render(field.help))
			s.WriteString("\n")
		}
	}

	s.WriteString("\nControls: Enter=Next, Tab=Next, Shift+Tab=Prev, Ctrl+C=Quit\n")
	s.WriteString("Fields marked with * are required\n")

	return s.String()
}

func main() {
	log.SetOutput(os.Stdout)

	// Initialize database
	if err := InitDB(); err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}

	var rootCmd = &cobra.Command{
		Use:   "wonderland",
		Short: "Pi 5 SSH Server with tunneling and client",
		Run: func(cmd *cobra.Command, args []string) {
			runServer() // Default to server mode
		},
	}

	// Server command
	var serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Run in server mode",
		Run: func(cmd *cobra.Command, args []string) {
			runServer()
		},
	}

	// Connect command
	var connectCmd = &cobra.Command{
		Use:   "connect <hostname>",
		Short: "Connect to a known host",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			hostname := args[0]
			bastionOverride, _ := cmd.Flags().GetString("bastion")

			// Get the host info to check if it's IPv6
			host, err := GetHost(hostname)
			if err != nil {
				log.Fatalf("Failed to get host info: %v", err)
			}

			if err := runClient(hostname, bastionOverride); err != nil {
				// Handle connection errors with IPv6 suggestions
				if enhanced := handleConnectionError(err, host.Address, bastionOverride, "wonderland connect"); enhanced != err {
					log.Fatalf("%v", enhanced)
				} else {
					log.Fatalf("Client failed: %v", err)
				}
			}
		},
	}
	connectCmd.Flags().StringP("bastion", "b", "", "Override bastion host (user@host:port)")

	// Add command
	var addCmd = &cobra.Command{
		Use:   "add <n>",
		Short: "Add a new host to known hosts",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			name := args[0]
			address, _ := cmd.Flags().GetString("address")
			port, _ := cmd.Flags().GetInt("port")
			key, _ := cmd.Flags().GetString("key")
			notes, _ := cmd.Flags().GetString("notes")
			bastionHost, _ := cmd.Flags().GetString("bastion-host")
			bastionPort, _ := cmd.Flags().GetInt("bastion-port")
			bastionUser, _ := cmd.Flags().GetString("bastion-user")

			if address == "" || key == "" {
				log.Fatalf("--address and --key are required")
			}

			if err := AddHost(name, address, port, key, notes, bastionHost, bastionPort, bastionUser); err != nil {
				log.Fatalf("Failed to add host: %v", err)
			}
			log.Printf("Host '%s' added successfully", name)
		},
	}

	addCmd.Flags().StringP("address", "a", "", "IPv6 address (required)")
	addCmd.Flags().IntP("port", "p", 22, "SSH port")
	addCmd.Flags().StringP("key", "k", "", "Public key (ssh-ed25519 AAAA...) (required)")
	addCmd.Flags().StringP("notes", "n", "", "Optional notes")
	addCmd.Flags().String("bastion-host", "", "Bastion host IPv4 address")
	addCmd.Flags().Int("bastion-port", 22, "Bastion host SSH port")
	addCmd.Flags().String("bastion-user", "", "Bastion host username")

	// List command
	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List known hosts",
		Run: func(cmd *cobra.Command, args []string) {
			if err := ListHosts(); err != nil {
				log.Fatalf("Failed to list hosts: %v", err)
			}
		},
	}

	// Remove command
	var removeCmd = &cobra.Command{
		Use:   "remove <n>",
		Short: "Remove a host from known hosts",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			name := args[0]
			if err := RemoveHost(name); err != nil {
				log.Fatalf("Failed to remove host: %v", err)
			}
			log.Printf("Host '%s' removed successfully", name)
		},
	}

	// Config command group
	var configCmd = &cobra.Command{
		Use:   "config",
		Short: "Manage configuration",
	}

	// Config new subcommand
	var configNewCmd = &cobra.Command{
		Use:   "new",
		Short: "Create a new configuration file interactively",
		Run: func(cmd *cobra.Command, args []string) {
			if err := createConfigInteractive(); err != nil {
				log.Fatalf("Failed to create config: %v", err)
			}
		},
	}

	// Invite command group
	var inviteCmd = &cobra.Command{
		Use:   "invite",
		Short: "Manage SSH invites",
	}

	// Invite new subcommand
	var inviteNewCmd = &cobra.Command{
		Use:   "new",
		Short: "Create a new SSH keypair for invites",
		Run: func(cmd *cobra.Command, args []string) {
			if err := createInviteKeypair(); err != nil {
				log.Fatalf("Failed to create invite keypair: %v", err)
			}
			log.Printf("New invite keypair created successfully")
		},
	}

	// Invite open subcommand
	var inviteOpenCmd = &cobra.Command{
		Use:   "open [invite-file]",
		Short: "Open an invite and register with the server",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			inviteFile := "invite.yaml"
			if len(args) > 0 {
				inviteFile = args[0]
			}

			bastionOverride, _ := cmd.Flags().GetString("bastion")
			nameOverride, _ := cmd.Flags().GetString("name")

			if err := openInvite(inviteFile, bastionOverride, nameOverride); err != nil {
				log.Fatalf("Failed to open invite: %v", err)
			}
			log.Printf("Invite opened and registration completed")
		},
	}
	inviteOpenCmd.Flags().StringP("bastion", "b", "", "Override bastion host (user@host:port)")
	inviteOpenCmd.Flags().StringP("name", "n", "", "Override server name")

	inviteCmd.AddCommand(inviteNewCmd, inviteOpenCmd)
	configCmd.AddCommand(configNewCmd)

	// Add commands
	rootCmd.AddCommand(serverCmd, connectCmd, addCmd, listCmd, removeCmd, inviteCmd, configCmd)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// InviteConfig represents the invite YAML structure
type InviteConfig struct {
	ServerName    string    `yaml:"server_name"`
	Host          string    `yaml:"host"`
	Port          int       `yaml:"port"`
	ServerHostKey string    `yaml:"server_host_key"`
	PrivateKey    string    `yaml:"private_key"`
	Generated     time.Time `yaml:"generated"`
}

// loadConfigIfNeeded loads config only when required for server operations
func loadConfigIfNeeded() (*Config, error) {
	config, err := LoadConfig("")
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	return config, nil
}

func createConfigInteractive() error {
	// Check if config already exists
	configPath, err := getDefaultConfigPath()
	if err != nil {
		return fmt.Errorf("failed to determine config path: %w", err)
	}

	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("config file already exists at %s", configPath)
	}

	// Get default values
	homeDir, _ := os.UserHomeDir()
	currentUser := os.Getenv("USER")
	if currentUser == "" {
		currentUser = os.Getenv("USERNAME")
	}
	if currentUser == "" {
		currentUser = "user"
	}

	// Define configuration fields
	fields := []configField{
		{
			label:       "Server Name",
			placeholder: "my-server",
			help:        "A friendly name for your server",
			required:    true,
		},
		{
			label:       "Wish Server Port",
			placeholder: "2222",
			help:        "Local port for the SSH server (default: 2222)",
			required:    true,
			validator: func(s string) error {
				if port, err := strconv.Atoi(s); err != nil || port < 1 || port > 65535 {
					return fmt.Errorf("invalid port number")
				}
				return nil
			},
		},
		{
			label:       "Host Key Path",
			placeholder: filepath.Join(homeDir, ".local", "share", "wonderland", "host_key"),
			help:        "Path to store the server host key",
			required:    true,
		},
		{
			label:       "Authorized Keys Path",
			placeholder: filepath.Join(homeDir, ".local", "share", "wonderland", "authorized_keys"),
			help:        "Path to authorized_keys file",
			required:    true,
		},
		{
			label:       "Admin Keys Path",
			placeholder: filepath.Join(homeDir, ".local", "share", "wonderland", "admin_keys"),
			help:        "Path to admin keys file",
			required:    true,
		},
		{
			label:       "Tunnel SSH Host",
			placeholder: "example.com",
			help:        "Remote server hostname/IP for SSH tunnel",
			required:    true,
		},
		{
			label:       "Tunnel SSH Port",
			placeholder: "22",
			help:        "Remote server SSH port (default: 22)",
			required:    true,
			validator: func(s string) error {
				if port, err := strconv.Atoi(s); err != nil || port < 1 || port > 65535 {
					return fmt.Errorf("invalid port number")
				}
				return nil
			},
		},
		{
			label:       "Tunnel User",
			placeholder: currentUser,
			help:        "SSH username for tunnel connection",
			required:    true,
		},
		{
			label:       "Tunnel Private Key Path",
			placeholder: filepath.Join(homeDir, ".ssh", "id_ed25519"),
			help:        "Path to SSH private key for tunnel",
			required:    true,
		},
		{
			label:       "Public Hostname",
			placeholder: "example.com",
			help:        "Public hostname for invites (usually same as tunnel host)",
			required:    true,
		},
		{
			label:       "Remote Port",
			placeholder: "2223",
			help:        "Public port for remote access",
			required:    true,
			validator: func(s string) error {
				if port, err := strconv.Atoi(s); err != nil || port < 1 || port > 65535 {
					return fmt.Errorf("invalid port number")
				}
				return nil
			},
		},
		{
			label:       "Local Port",
			placeholder: "2222",
			help:        "Local port for tunnel (usually same as Wish port)",
			required:    true,
			validator: func(s string) error {
				if port, err := strconv.Atoi(s); err != nil || port < 1 || port > 65535 {
					return fmt.Errorf("invalid port number")
				}
				return nil
			},
		},
	}

	model := configModel{
		fields: fields,
	}

	p := tea.NewProgram(model)
	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	// Check if user cancelled
	result := finalModel.(configModel)
	if !result.finished {
		return fmt.Errorf("configuration cancelled")
	}

	// Convert values, using defaults for empty non-required fields
	serverName := result.fields[0].value
	wishPortStr := result.fields[1].value
	if wishPortStr == "" {
		wishPortStr = "2222"
	}
	wishPort, _ := strconv.Atoi(wishPortStr)

	hostKeyPath := result.fields[2].value
	if hostKeyPath == "" {
		hostKeyPath = filepath.Join(homeDir, ".local", "share", "wonderland", "host_key")
	}

	authorizedKeysPath := result.fields[3].value
	if authorizedKeysPath == "" {
		authorizedKeysPath = filepath.Join(homeDir, ".local", "share", "wonderland", "authorized_keys")
	}

	adminKeysPath := result.fields[4].value
	if adminKeysPath == "" {
		adminKeysPath = filepath.Join(homeDir, ".local", "share", "wonderland", "admin_keys")
	}

	tunnelHost := result.fields[5].value
	tunnelPortStr := result.fields[6].value
	if tunnelPortStr == "" {
		tunnelPortStr = "22"
	}
	tunnelPort, _ := strconv.Atoi(tunnelPortStr)

	tunnelUser := result.fields[7].value
	if tunnelUser == "" {
		tunnelUser = currentUser
	}

	keyFile := result.fields[8].value
	if keyFile == "" {
		keyFile = filepath.Join(homeDir, ".ssh", "id_ed25519")
	}

	publicHost := result.fields[9].value
	if publicHost == "" {
		publicHost = tunnelHost
	}

	remotePortStr := result.fields[10].value
	if remotePortStr == "" {
		remotePortStr = "2223"
	}
	remotePort, _ := strconv.Atoi(remotePortStr)

	localPortStr := result.fields[11].value
	if localPortStr == "" {
		localPortStr = wishPortStr
	}
	localPort, _ := strconv.Atoi(localPortStr)

	// Create config structure matching the existing Config type
	config := Config{
		Server: struct {
			Name string `yaml:"name"`
		}{
			Name: serverName,
		},
		Wish: struct {
			Port           int    `yaml:"port"`
			HostKey        string `yaml:"host_key"`
			AuthorizedKeys string `yaml:"authorized_keys"`
			AdminKeys      string `yaml:"admin_keys"`
		}{
			Port:           wishPort,
			HostKey:        hostKeyPath,
			AuthorizedKeys: authorizedKeysPath,
			AdminKeys:      adminKeysPath,
		},
		Tunnel: struct {
			Host       string `yaml:"host"`
			PublicHost string `yaml:"public_host"`
			Port       int    `yaml:"port"`
			User       string `yaml:"user"`
			KeyFile    string `yaml:"key_file"`
			RemotePort int    `yaml:"remote_port"`
			LocalPort  int    `yaml:"local_port"`
		}{
			Host:       tunnelHost,
			PublicHost: publicHost,
			Port:       tunnelPort,
			User:       tunnelUser,
			KeyFile:    keyFile,
			RemotePort: remotePort,
			LocalPort:  localPort,
		},
	}

	// Create config directory if it doesn't exist
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to YAML
	configYAML, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write config file
	if err := os.WriteFile(configPath, configYAML, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	log.Printf("Configuration created successfully at: %s", configPath)
	return nil
}

func createInviteKeypair() error {
	// Load config to get connection details
	config, err := loadConfigIfNeeded()
	if err != nil {
		return err
	}

	log.Printf("Debug: Server name from config: '%s'", config.Server.Name)

	// Load server host key
	serverHostKeyData, err := os.ReadFile(expandPath(config.Wish.HostKey+".pub", ""))
	if err != nil {
		return fmt.Errorf("failed to read server host public key: %w", err)
	}
	serverHostKeyStr := strings.TrimSpace(string(serverHostKeyData))

	// Generate Ed25519 keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	// Convert to SSH format
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create SSH public key: %w", err)
	}

	// Format public key in authorized_keys format
	authorizedKey := string(ssh.MarshalAuthorizedKey(sshPublicKey))

	// Create private key in OpenSSH format
	privateKeyBytes, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Create invite config structure
	serverName := config.Server.Name // This should work now that you've updated the Config struct

	invite := InviteConfig{
		ServerName:    serverName,
		Host:          config.Tunnel.PublicHost,
		Port:          config.Tunnel.RemotePort,
		ServerHostKey: serverHostKeyStr,
		PrivateKey:    string(pem.EncodeToMemory(privateKeyBytes)),
		Generated:     time.Now(),
	}

	// Marshal to YAML
	inviteYaml, err := yaml.Marshal(invite)
	if err != nil {
		return fmt.Errorf("failed to marshal invite config: %w", err)
	}

	// Write invite YAML file to ./invite.yaml
	inviteFilePath := "./invite.yaml"
	if err := os.WriteFile(inviteFilePath, inviteYaml, 0600); err != nil {
		return fmt.Errorf("failed to write invite file: %w", err)
	}

	// Create directory for public keys in ~/.local/share/wonderland/
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	inviteKeysDir := filepath.Join(homeDir, ".local", "share", "wonderland")
	if err := os.MkdirAll(inviteKeysDir, 0755); err != nil {
		return fmt.Errorf("failed to create invite keys directory: %w", err)
	}

	// Append public key to invite_keys file
	inviteKeysPath := filepath.Join(inviteKeysDir, "invite_keys")
	file, err := os.OpenFile(inviteKeysPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open invite_keys file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(authorizedKey); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	log.Printf("Invite file saved to: %s", inviteFilePath)
	log.Printf("Public key appended to: %s", inviteKeysPath)

	return nil
}

func openInvite(inviteFile, bastionOverride, nameOverride string) error {
	// Load the invite file
	inviteData, err := os.ReadFile(inviteFile)
	if err != nil {
		return fmt.Errorf("failed to read invite file %s: %w", inviteFile, err)
	}

	var invite InviteConfig
	if err := yaml.Unmarshal(inviteData, &invite); err != nil {
		return fmt.Errorf("failed to parse invite file: %w", err)
	}

	log.Printf("Processing invite for server '%s' at %s:%d", invite.ServerName, invite.Host, invite.Port)

	// Parse and validate the server host key from invite
	serverHostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(invite.ServerHostKey))
	if err != nil {
		return fmt.Errorf("invalid server host key in invite: %w", err)
	}

	log.Printf("Expected server key: %s", ssh.FingerprintSHA256(serverHostKey))

	// Find SSH key file - try common locations without loading config
	var realKeyData []byte
	var username string

	// Try common SSH key locations first (avoid loading config)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	keyPaths := []string{
		filepath.Join(homeDir, ".ssh", "id_ed25519"),
		filepath.Join(homeDir, ".ssh", "id_rsa"),
		filepath.Join(homeDir, ".ssh", "id_ecdsa"),
	}

	var keyFound bool
	var usedKeyPath string
	for _, keyPath := range keyPaths {
		realKeyData, err = os.ReadFile(keyPath)
		if err == nil {
			usedKeyPath = keyPath
			keyFound = true
			break
		}
	}

	if !keyFound {
		return fmt.Errorf("no SSH key found in common locations (~/.ssh/id_ed25519, ~/.ssh/id_rsa, ~/.ssh/id_ecdsa)")
	}

	log.Printf("Using SSH key: %s", usedKeyPath)

	// Use current user as default username
	username = os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // Windows
	}
	if username == "" {
		username = "user" // fallback
	}
	log.Printf("Using username: %s", username)

	realSigner, err := ssh.ParsePrivateKey(realKeyData)
	if err != nil {
		return fmt.Errorf("failed to parse SSH key: %w", err)
	}

	// Get our real public key for registration
	realPublicKey := ssh.MarshalAuthorizedKey(realSigner.PublicKey())

	log.Printf("Using real key fingerprint: %s", ssh.FingerprintSHA256(realSigner.PublicKey()))

	// Parse the invite private key
	inviteSigner, err := ssh.ParsePrivateKey([]byte(invite.PrivateKey))
	if err != nil {
		return fmt.Errorf("failed to parse invite private key: %w", err)
	}

	log.Printf("Using invite key fingerprint: %s", ssh.FingerprintSHA256(inviteSigner.PublicKey()))

	// Determine bastion settings
	var bastionHost, bastionUser string
	var bastionPort int
	var useBastion bool

	if bastionOverride != "" {
		// Parse bastion override: "user@host:port"
		bastionHost, bastionUser, bastionPort, err = parseBastionString(bastionOverride)
		if err != nil {
			return fmt.Errorf("invalid bastion format: %w", err)
		}
		useBastion = true
		log.Printf("Using bastion override: %s@%s:%d", bastionUser, bastionHost, bastionPort)
	}

	// Create host key callback that verifies against the invite's server key
	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		serverKeyBytes := ssh.MarshalAuthorizedKey(serverHostKey)
		actualKeyBytes := ssh.MarshalAuthorizedKey(key)

		if string(serverKeyBytes) != string(actualKeyBytes) {
			return fmt.Errorf("server host key mismatch: got %s, expected %s",
				ssh.FingerprintSHA256(key), ssh.FingerprintSHA256(serverHostKey))
		}
		log.Printf("Server host key verified: %s", ssh.FingerprintSHA256(key))
		return nil
	}

	// Connect using the invite key for registration
	log.Printf("Connecting to %s:%d for registration", invite.Host, invite.Port)

	inviteConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(inviteSigner),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}

	addr := formatAddress(invite.Host, invite.Port)

	var conn *ssh.Client

	if useBastion {
		// Connect via bastion host
		log.Printf("Connecting via bastion %s@%s:%d", bastionUser, bastionHost, bastionPort)

		// Connect to bastion first using our REAL key (not invite key)
		bastionConfig := &ssh.ClientConfig{
			User: bastionUser,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(realSigner),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Trust bastion for now
			Timeout:         10 * time.Second,
		}

		bastionAddr := formatAddress(bastionHost, bastionPort)
		bastionConn, err := ssh.Dial("tcp", bastionAddr, bastionConfig)
		if err != nil {
			return fmt.Errorf("failed to connect to bastion %s: %w", bastionAddr, err)
		}
		defer bastionConn.Close()

		log.Printf("Connected to bastion")

		// Connect to target through bastion
		targetAddr := formatAddress(invite.Host, invite.Port)
		targetConn, err := bastionConn.Dial("tcp", targetAddr)
		if err != nil {
			return fmt.Errorf("failed to connect to target %s via bastion: %w", targetAddr, err)
		}

		// Create SSH connection over the tunneled connection using INVITE key
		sshConn, chans, reqs, err := ssh.NewClientConn(targetConn, targetAddr, inviteConfig)
		if err != nil {
			return fmt.Errorf("failed to establish SSH connection to target: %w", err)
		}

		conn = ssh.NewClient(sshConn, chans, reqs)

	} else {
		// Direct connection
		conn, err = ssh.Dial("tcp", addr, inviteConfig)
		if err != nil {
			return handleConnectionError(err, invite.Host, bastionOverride, "wonderland invite open")
		}
	}

	// Create a session for registration
	session, err := conn.NewSession()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create registration session: %w", err)
	}

	// Get stdin pipe for sending registration data
	sessionStdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		conn.Close()
		return fmt.Errorf("failed to get session stdin: %w", err)
	}

	// Send our real public key for registration
	log.Printf("Registering real public key with server")
	_, err = sessionStdin.Write(realPublicKey)
	if err != nil {
		sessionStdin.Close()
		session.Close()
		conn.Close()
		return fmt.Errorf("failed to send real public key: %w", err)
	}

	// Close stdin to signal end of data
	sessionStdin.Close()

	// Close the registration session and connection
	session.Close()
	conn.Close()

	// Reconnect with real key to verify registration worked
	log.Printf("Reconnecting with real key to verify registration")

	realConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(realSigner),
		},
		HostKeyCallback: hostKeyCallback, // Same verification
		Timeout:         10 * time.Second,
	}

	if useBastion {
		// Reconnect via bastion with real key
		bastionConfig := &ssh.ClientConfig{
			User: bastionUser,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(realSigner),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Trust bastion for now
			Timeout:         10 * time.Second,
		}

		bastionAddr := formatAddress(bastionHost, bastionPort)
		bastionConn, err := ssh.Dial("tcp", bastionAddr, bastionConfig)
		if err != nil {
			return fmt.Errorf("failed to reconnect to bastion %s: %w", bastionAddr, err)
		}
		defer bastionConn.Close()

		// Connect to target through bastion
		targetAddr := formatAddress(invite.Host, invite.Port)
		targetConn, err := bastionConn.Dial("tcp", targetAddr)
		if err != nil {
			return fmt.Errorf("failed to reconnect to target %s via bastion: %w", targetAddr, err)
		}

		// Create SSH connection over the tunneled connection
		sshConn, chans, reqs, err := ssh.NewClientConn(targetConn, targetAddr, realConfig)
		if err != nil {
			return fmt.Errorf("failed to reconnect with real key - registration may have failed: %w", err)
		}

		conn = ssh.NewClient(sshConn, chans, reqs)
		conn.Close()

	} else {
		// Direct reconnection
		conn, err = ssh.Dial("tcp", addr, realConfig)
		if err != nil {
			return handleConnectionError(fmt.Errorf("failed to reconnect with real key - registration may have failed: %w", err),
				invite.Host, bastionOverride, "wonderland invite open")
		}
		conn.Close()
	}

	log.Printf("Registration verified - connection successful with real key")

	// Determine hostname - use override if provided, otherwise use server name from invite
	hostname := nameOverride
	if hostname == "" {
		hostname = invite.ServerName
	}

	// Fallback to generated name if no server name in invite
	if hostname == "" {
		hostname = fmt.Sprintf("%s-%d", invite.Host, invite.Port)
		// Clean up hostname - remove invalid characters and make it more readable
		hostname = strings.ReplaceAll(hostname, ":", "-")
		hostname = strings.ReplaceAll(hostname, ".", "-")
		if len(hostname) > 15 {
			// Truncate long hostnames
			hostname = hostname[:12] + "..."
		}
	}

	// Store bastion info if used
	var bastionHostForDB string
	var bastionPortForDB int
	var bastionUserForDB string
	if useBastion {
		bastionHostForDB = bastionHost
		bastionPortForDB = bastionPort
		bastionUserForDB = bastionUser
	}

	err = AddHost(hostname, invite.Host, invite.Port, invite.ServerHostKey,
		fmt.Sprintf("Added via invite on %s", time.Now().Format("2006-01-02")),
		bastionHostForDB, bastionPortForDB, bastionUserForDB)
	if err != nil {
		log.Printf("Warning: Failed to add host to database: %v", err)
		log.Printf("   You can manually add it later with:")
		if useBastion {
			log.Printf("   wonderland add %s -a %s -p %d -k '%s' --bastion-host %s --bastion-port %d --bastion-user %s",
				hostname, invite.Host, invite.Port, invite.ServerHostKey, bastionHost, bastionPort, bastionUser)
		} else {
			log.Printf("   wonderland add %s -a %s -p %d -k '%s'", hostname, invite.Host, invite.Port, invite.ServerHostKey)
		}
	} else {
		log.Printf("Host '%s' added to database", hostname)
		if useBastion {
			log.Printf("   Bastion: %s@%s:%d", bastionUser, bastionHost, bastionPort)
		}
	}

	// Clean up the invite file
	if err := os.Remove(inviteFile); err != nil {
		log.Printf("Warning: Failed to remove invite file: %v", err)
	} else {
		log.Printf("Invite file cleaned up")
	}

	log.Printf("Registration complete! You can now connect with:")
	log.Printf("   wonderland connect %s", hostname)

	return nil
}

func runServer() {
	log.Printf("Starting Wonderland Server...")

	config, err := loadConfigIfNeeded()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	if err := StartWishServer(config); err != nil {
		log.Fatalf("Wish server setup failed: %v", err)
	}

	time.Sleep(2 * time.Second)

	if err := StartSSHTunnel(config); err != nil {
		log.Printf("SSH tunnel setup failed: %v (continuing with local access only)", err)
	}

	log.Printf("All services started!")
	log.Printf("Global access: ssh -p %d %s@%s",
		config.Tunnel.RemotePort, config.Tunnel.User, config.Tunnel.Host)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Printf("Shutting down...")
}

func runClient(hostname, bastionOverride string) error {
	log.Printf("Starting Wonderland Client...")

	config, err := loadConfigIfNeeded()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	if err := StartClient(hostname, config, bastionOverride); err != nil {
		return fmt.Errorf("client failed: %w", err)
	}

	log.Printf("Client session ended")
	return nil
}
