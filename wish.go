package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/charmbracelet/wish/bubbletea"
	"github.com/charmbracelet/wish/logging"
	cryptossh "golang.org/x/crypto/ssh"
)

// StartWishServer starts the Wish SSH server
func StartWishServer(config *Config) error {
	log.Printf("Setting up Wish SSH server on port %d", config.Wish.Port)

	// Load authorized keys
	authorizedKeys, err := loadAuthorizedKeys(config.Wish.AuthorizedKeys)
	if err != nil {
		return fmt.Errorf("failed to load authorized keys: %v", err)
	}

	log.Printf("Loaded %d authorized keys from %s", len(authorizedKeys), config.Wish.AuthorizedKeys)

	// Load admin keys
	adminKeys, err := loadAdminKeys(config.Wish.AdminKeys)
	if err != nil {
		return fmt.Errorf("failed to load admin keys: %v", err)
	}

	log.Printf("Loaded %d admin keys from %s", len(adminKeys), config.Wish.AdminKeys)

	// Load invite keys
	inviteKeys, err := loadInviteKeys(config)
	if err != nil {
		return fmt.Errorf("failed to load invite keys: %v", err)
	}

	log.Printf("Loaded %d invite keys", len(inviteKeys))

	// Load or generate host key
	hostKeyData, err := loadOrGenerateHostKey(config.Wish.HostKey)
	if err != nil {
		return fmt.Errorf("failed to load host key: %v", err)
	}

	// Create Wish server
	server, err := wish.NewServer(
		wish.WithAddress(fmt.Sprintf(":%d", config.Wish.Port)),
		wish.WithHostKeyPEM(hostKeyData),
		wish.WithPublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			// Check if user is authorized with regular keys
			isAuthorized := false
			for _, authKey := range authorizedKeys {
				if ssh.KeysEqual(key, authKey) {
					isAuthorized = true
					break
				}
			}

			if isAuthorized {
				// Regular authorized user
				userKeyFingerprint := cryptossh.FingerprintSHA256(key)
				log.Printf("User key fingerprint: %s", userKeyFingerprint)

				// Check if user is also an admin
				isAdmin := false
				for i, adminKey := range adminKeys {
					adminKeyFingerprint := cryptossh.FingerprintSHA256(adminKey)
					log.Printf("Checking admin key %d: %s", i, adminKeyFingerprint)
					if ssh.KeysEqual(key, adminKey) {
						isAdmin = true
						log.Printf("ADMIN MATCH FOUND!")
						break
					}
				}

				// Store admin status in context
				ctx.SetValue("isAdmin", isAdmin)
				ctx.SetValue("isRegistration", false)

				log.Printf("Successful authentication from %s (admin: %v)", ctx.RemoteAddr(), isAdmin)
				return true
			}

			// Check if this is a registration attempt with invite key
			isInviteKey := false
			var inviteKeyIndex int
			for i, inviteKey := range inviteKeys {
				if ssh.KeysEqual(key, inviteKey) {
					isInviteKey = true
					inviteKeyIndex = i
					break
				}
			}

			if isInviteKey {
				// This is a registration session
				log.Printf("Registration session from %s with invite key %d", ctx.RemoteAddr(), inviteKeyIndex)
				ctx.SetValue("isAdmin", false)
				ctx.SetValue("isRegistration", true)
				ctx.SetValue("inviteKeyIndex", inviteKeyIndex)
				ctx.SetValue("config", config)
				return true
			}

			// Authentication failed
			log.Printf("Failed authentication attempt from %s", ctx.RemoteAddr())
			return false
		}),
		wish.WithMiddleware(
			bubbletea.Middleware(func(s ssh.Session) (tea.Model, []tea.ProgramOption) {
				// Check if this is a registration session
				isRegistration, exists := s.Context().Value("isRegistration").(bool)
				if exists && isRegistration {
					// Handle registration
					return handleRegistration(s)
				}

				// Regular session - get admin status from context
				isAdmin, exists := s.Context().Value("isAdmin").(bool)
				log.Printf("Middleware: isAdmin=%v, exists=%v", isAdmin, exists)

				// Get PTY info from SSH session
				pty, winCh, _ := s.Pty()
				log.Printf("SSH PTY size: %dx%d", pty.Window.Width, pty.Window.Height)

				// Create model with correct initial size
				model := NewAppModel(config, isAdmin)
				model.width = pty.Window.Width
				model.height = pty.Window.Height

				// Handle window resize events from SSH
				go func() {
					for win := range winCh {
						log.Printf("SSH window resize: %dx%d", win.Width, win.Height)
						// Send window size update to Bubble Tea
						if p := s.Context().Value("program"); p != nil {
							if program, ok := p.(*tea.Program); ok {
								program.Send(tea.WindowSizeMsg{
									Width:  win.Width,
									Height: win.Height,
								})
							}
						}
					}
				}()

				return model, []tea.ProgramOption{
					tea.WithAltScreen(),
					tea.WithMouseCellMotion(),
					tea.WithInput(s),
					tea.WithOutput(s),
				}
			}),
			logging.Middleware(),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create Wish server: %v", err)
	}

	go func() {
		log.Printf("Wish server starting on port %d", config.Wish.Port)
		if err := server.ListenAndServe(); err != nil {
			log.Printf("Wish server error: %v", err)
		}
	}()

	return nil
}

// handleRegistration handles the registration process for invite key users
func handleRegistration(s ssh.Session) (tea.Model, []tea.ProgramOption) {
	log.Printf("🔄 Starting registration process for %s", s.RemoteAddr())

	// Get config and invite key index from context
	config, _ := s.Context().Value("config").(*Config)
	inviteKeyIndex, _ := s.Context().Value("inviteKeyIndex").(int)

	// Read the real public key from the session input
	log.Printf("📖 Reading real public key from client")

	// Read all data from stdin
	data, err := io.ReadAll(s)
	if err != nil {
		log.Printf("❌ Failed to read registration data: %v", err)
		s.Write([]byte(fmt.Sprintf("Registration failed: could not read data: %v\n", err)))
		s.Exit(1)
		return nil, nil
	}

	// Parse the public key
	realPublicKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		log.Printf("❌ Failed to parse real public key: %v", err)
		s.Write([]byte(fmt.Sprintf("Registration failed: invalid public key: %v\n", err)))
		s.Exit(1)
		return nil, nil
	}

	realKeyFingerprint := cryptossh.FingerprintSHA256(realPublicKey)
	log.Printf("🔑 Received real public key: %s", realKeyFingerprint)

	// Add the real public key to authorized_keys
	if err := appendToAuthorizedKeys(config.Wish.AuthorizedKeys, data); err != nil {
		log.Printf("❌ Failed to add key to authorized_keys: %v", err)
		s.Write([]byte(fmt.Sprintf("Registration failed: could not save key: %v\n", err)))
		s.Exit(1)
		return nil, nil
	}

	log.Printf("✅ Added real public key to authorized_keys")

	// Remove the invite key from invite_keys
	if err := removeInviteKey(config, inviteKeyIndex); err != nil {
		log.Printf("⚠️  Warning: failed to remove invite key: %v", err)
		// Don't fail registration for this
	} else {
		log.Printf("🗑️  Removed invite key from invite_keys")
	}

	// Send success message and close
	s.Write([]byte("✅ Registration successful! You can now reconnect with your real key.\n"))
	log.Printf("🎉 Registration completed for %s (key: %s)", s.RemoteAddr(), realKeyFingerprint)

	s.Exit(0)
	return nil, nil
}

// loadInviteKeys loads SSH public keys from the invite_keys file
func loadInviteKeys(config *Config) ([]ssh.PublicKey, error) {
	// Build path to invite_keys file in user's data directory
	inviteKeysPath := getInviteKeysPath()

	// Check if invite keys file exists
	if _, err := os.Stat(inviteKeysPath); os.IsNotExist(err) {
		log.Printf("No invite keys file found at %s - no pending invites", inviteKeysPath)
		return []ssh.PublicKey{}, nil
	}

	return loadAuthorizedKeys(inviteKeysPath)
}

// getInviteKeysPath returns the path to the invite_keys file
func getInviteKeysPath() string {
	// Use the same logic as in the client
	homeDir, _ := os.UserHomeDir()
	return fmt.Sprintf("%s/.local/share/wonderland/invite_keys", homeDir)
}

// appendToAuthorizedKeys appends a public key to the authorized_keys file
func appendToAuthorizedKeys(authorizedKeysPath string, keyData []byte) error {
	// Open file in append mode
	file, err := os.OpenFile(authorizedKeysPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open authorized_keys file: %v", err)
	}
	defer file.Close()

	// Ensure the key data ends with a newline
	keyStr := strings.TrimSpace(string(keyData))
	if !strings.HasSuffix(keyStr, "\n") {
		keyStr += "\n"
	}

	// Write the key
	_, err = file.WriteString(keyStr)
	if err != nil {
		return fmt.Errorf("failed to write key: %v", err)
	}

	return nil
}

// removeInviteKey removes an invite key by index from the invite_keys file
func removeInviteKey(config *Config, indexToRemove int) error {
	inviteKeysPath := getInviteKeysPath()

	// Read all lines from the file
	file, err := os.Open(inviteKeysPath)
	if err != nil {
		return fmt.Errorf("failed to open invite_keys file: %v", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	keyIndex := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			lines = append(lines, scanner.Text())
			continue
		}

		// Skip the line we want to remove
		if keyIndex == indexToRemove {
			log.Printf("Removing invite key at index %d", keyIndex)
			keyIndex++
			continue
		}

		lines = append(lines, scanner.Text())
		keyIndex++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading invite_keys file: %v", err)
	}

	// Write the updated content back to the file
	return os.WriteFile(inviteKeysPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// loadAuthorizedKeys loads SSH public keys from an authorized_keys file
func loadAuthorizedKeys(path string) ([]ssh.PublicKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open authorized_keys file: %v", err)
	}
	defer file.Close()

	var keys []ssh.PublicKey
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			log.Printf("Warning: failed to parse key on line %d: %v", lineNum, err)
			continue
		}

		keys = append(keys, pubKey)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading authorized_keys: %v", err)
	}

	return keys, nil
}

// loadAdminKeys loads SSH public keys from an admin_keys file
func loadAdminKeys(path string) ([]ssh.PublicKey, error) {
	// Check if admin keys file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("No admin keys file found at %s - no admin access", path)
		return []ssh.PublicKey{}, nil
	}

	return loadAuthorizedKeys(path)
}

// loadOrGenerateHostKey loads an existing host key or generates a new one
func loadOrGenerateHostKey(path string) ([]byte, error) {
	// Try to load existing key
	if keyData, err := os.ReadFile(path); err == nil {
		return keyData, nil
	}

	// Generate new key if it doesn't exist
	if err := generateHostKey(path); err != nil {
		return nil, err
	}

	// Load the newly generated key
	return os.ReadFile(path)
}

// generateHostKey generates a new Ed25519 host key pair
func generateHostKey(path string) error {
	log.Printf("Generating new host key: %s", path)

	// Generate Ed25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Convert to SSH format
	privKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}

	// Create PEM block
	privPEM := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKey,
	}

	// Write private key
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create host key file: %v", err)
	}
	defer file.Close()

	if err := pem.Encode(file, &privPEM); err != nil {
		return fmt.Errorf("failed to write host key: %v", err)
	}

	// Write public key
	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("failed to create SSH public key: %v", err)
	}

	pubPath := path + ".pub"
	pubFile, err := os.Create(pubPath)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %v", err)
	}
	defer pubFile.Close()

	fmt.Fprintf(pubFile, "%s\n", string(cryptossh.MarshalAuthorizedKey(sshPub)))

	log.Printf("Generated host key pair: %s and %s", path, pubPath)
	return nil
}
