package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
			// Check if user is authorized
			isAuthorized := false
			for _, authKey := range authorizedKeys {
				if ssh.KeysEqual(key, authKey) {
					isAuthorized = true
					break
				}
			}

			if !isAuthorized {
				log.Printf("Failed authentication attempt from %s", ctx.RemoteAddr())
				return false
			}

			// Debug: Show the user's key fingerprint
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

			log.Printf("Successful authentication from %s (admin: %v)", ctx.RemoteAddr(), isAdmin)
			return true
		}),
		wish.WithMiddleware(
			bubbletea.Middleware(func(s ssh.Session) (tea.Model, []tea.ProgramOption) {
				// Get admin status from context
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
