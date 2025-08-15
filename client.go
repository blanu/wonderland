package main

import (
	"database/sql"
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

	"github.com/charmbracelet/ssh"
	_ "github.com/mattn/go-sqlite3"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Host represents a known host entry
type Host struct {
	ID          int
	Name        string
	Address     string
	Port        int
	KeyType     string
	PublicKey   string
	Fingerprint string
	BastionHost string
	BastionPort int
	BastionUser string
	AddedAt     time.Time
	LastUsed    *time.Time
	Notes       string
}

var db *sql.DB

// getDataDir returns the XDG data directory for wonderland
func getDataDir() (string, error) {
	dataDir := os.Getenv("XDG_DATA_HOME")
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home directory: %v", err)
		}
		dataDir = filepath.Join(home, ".local", "share")
	}

	appDataDir := filepath.Join(dataDir, "wonderland")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(appDataDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create data directory %s: %v", appDataDir, err)
	}

	return appDataDir, nil
}

// InitDB initializes the SQLite database
func InitDB() error {
	dataDir, err := getDataDir()
	if err != nil {
		return err
	}

	dbPath := filepath.Join(dataDir, "hosts.db")

	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	// Create table with bastion support
	createTableSQL := `
   CREATE TABLE IF NOT EXISTS hosts (
   	id INTEGER PRIMARY KEY AUTOINCREMENT,
   	name TEXT UNIQUE NOT NULL,
   	address TEXT NOT NULL,
   	port INTEGER NOT NULL DEFAULT 22,
   	key_type TEXT NOT NULL,
   	public_key TEXT NOT NULL,
   	fingerprint TEXT NOT NULL,
   	bastion_host TEXT,
   	bastion_port INTEGER,
   	bastion_user TEXT,
   	added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
   	last_used TIMESTAMP,
   	notes TEXT
   );

   CREATE INDEX IF NOT EXISTS idx_hosts_name ON hosts(name);
   CREATE INDEX IF NOT EXISTS idx_hosts_address_port ON hosts(address, port);
   `

	if _, err := db.Exec(createTableSQL); err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	log.Printf("Database initialized: %s", dbPath)
	return nil
}

// AddHost adds a new host to the database
func AddHost(name, address string, port int, publicKeyStr, notes, bastionHost string, bastionPort int, bastionUser string) error {
	// Parse and validate the public key
	pubKey, keyType, _, _, err := cryptossh.ParseAuthorizedKey([]byte(publicKeyStr))
	if err != nil {
		return fmt.Errorf("invalid public key: %v", err)
	}

	fingerprint := cryptossh.FingerprintSHA256(pubKey)

	// Check if name already exists
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM hosts WHERE name = ?", name).Scan(&count)
	if err != nil {
		return fmt.Errorf("database error: %v", err)
	}
	if count > 0 {
		return fmt.Errorf("host name '%s' already exists", name)
	}

	// Insert new host
	_, err = db.Exec(`
   	INSERT INTO hosts (name, address, port, key_type, public_key, fingerprint, bastion_host, bastion_port, bastion_user, notes)
   	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		name, address, port, keyType, publicKeyStr, fingerprint, bastionHost, bastionPort, bastionUser, notes)

	if err != nil {
		return fmt.Errorf("failed to insert host: %v", err)
	}

	bastionInfo := ""
	if bastionHost != "" {
		bastionInfo = fmt.Sprintf(" via %s@%s:%d", bastionUser, bastionHost, bastionPort)
	}

	log.Printf("Added host '%s' at [%s]:%d%s (%s)", name, address, port, bastionInfo, fingerprint)
	return nil
}

// GetHost retrieves a host by name
func GetHost(name string) (*Host, error) {
	host := &Host{}
	var bastionHost, bastionUser sql.NullString
	var bastionPort sql.NullInt64

	err := db.QueryRow(`
   	SELECT id, name, address, port, key_type, public_key, fingerprint,
   	       bastion_host, bastion_port, bastion_user, added_at, last_used, notes
   	FROM hosts WHERE name = ?`, name).Scan(
		&host.ID, &host.Name, &host.Address, &host.Port, &host.KeyType,
		&host.PublicKey, &host.Fingerprint, &bastionHost, &bastionPort,
		&bastionUser, &host.AddedAt, &host.LastUsed, &host.Notes)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("host '%s' not found", name)
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Handle nullable bastion fields
	if bastionHost.Valid {
		host.BastionHost = bastionHost.String
	}
	if bastionPort.Valid {
		host.BastionPort = int(bastionPort.Int64)
	}
	if bastionUser.Valid {
		host.BastionUser = bastionUser.String
	}

	return host, nil
}

// ListHosts lists all known hosts
func ListHosts() error {
	rows, err := db.Query(`
   	SELECT name, address, port, key_type, fingerprint, bastion_host, bastion_port, bastion_user, added_at, last_used, notes
   	FROM hosts ORDER BY name`)
	if err != nil {
		return fmt.Errorf("database error: %v", err)
	}
	defer rows.Close()

	fmt.Printf("\n📋 Known Hosts:\n\n")
	fmt.Printf("%-15s %-40s %-5s %-20s %-10s %s\n", "NAME", "ADDRESS", "PORT", "BASTION", "LAST USED", "NOTES")
	fmt.Printf("%-15s %-40s %-5s %-20s %-10s %s\n", "----", "-------", "----", "-------", "---------", "-----")

	count := 0
	for rows.Next() {
		var name, address, keyType, fingerprint, notes string
		var port int
		var addedAt time.Time
		var lastUsed *time.Time
		var bastionHost, bastionUser sql.NullString
		var bastionPort sql.NullInt64

		err := rows.Scan(&name, &address, &port, &keyType, &fingerprint,
			&bastionHost, &bastionPort, &bastionUser, &addedAt, &lastUsed, &notes)
		if err != nil {
			return fmt.Errorf("failed to scan row: %v", err)
		}

		lastUsedStr := "never"
		if lastUsed != nil {
			lastUsedStr = lastUsed.Format("2006-01-02")
		}

		bastionStr := "-"
		if bastionHost.Valid && bastionUser.Valid {
			bastionStr = fmt.Sprintf("%s@%s:%d", bastionUser.String, bastionHost.String, bastionPort.Int64)
		}

		if len(notes) > 20 {
			notes = notes[:17] + "..."
		}

		fmt.Printf("%-15s %-40s %-5d %-20s %-10s %s\n",
			name, address, port, bastionStr, lastUsedStr, notes)
		count++
	}

	if count == 0 {
		fmt.Printf("No hosts found. Add one with:\n")
		fmt.Printf("  wonderland add myhost -a 2607:a140::1 -p 2222 -k 'ssh-ed25519 AAAA...'\n")
	} else {
		fmt.Printf("\nTotal: %d hosts\n", count)
	}

	return rows.Err()
}

// RemoveHost removes a host by name
func RemoveHost(name string) error {
	result, err := db.Exec("DELETE FROM hosts WHERE name = ?", name)
	if err != nil {
		return fmt.Errorf("database error: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %v", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("host '%s' not found", name)
	}

	return nil
}

// UpdateLastUsed updates the last used timestamp for a host
func UpdateLastUsed(name string) error {
	_, err := db.Exec("UPDATE hosts SET last_used = CURRENT_TIMESTAMP WHERE name = ?", name)
	return err
}

// parseBastionString parses "user@host:port" format
func parseBastionString(bastionStr string) (host, user string, port int, err error) {
	// Split on @
	parts := strings.Split(bastionStr, "@")
	if len(parts) != 2 {
		return "", "", 0, fmt.Errorf("format should be user@host:port")
	}

	user = parts[0]
	hostPort := parts[1]

	// Split host:port
	if strings.Contains(hostPort, ":") {
		hostPortParts := strings.Split(hostPort, ":")
		if len(hostPortParts) != 2 {
			return "", "", 0, fmt.Errorf("invalid host:port format")
		}
		host = hostPortParts[0]
		port, err = strconv.Atoi(hostPortParts[1])
		if err != nil {
			return "", "", 0, fmt.Errorf("invalid port number: %v", err)
		}
	} else {
		host = hostPort
		port = 22 // Default SSH port
	}

	return host, user, port, nil
}

// StartClient starts the SSH client to connect to a known host
func StartClient(hostName string, config *Config, bastionOverride string) error {
	log.Printf("🔌 Looking up host '%s'", hostName)

	// Get host from database
	host, err := GetHost(hostName)
	if err != nil {
		return err
	}

	// Determine bastion settings
	var bastionHost, bastionUser string
	var bastionPort int
	var useBastion bool

	if bastionOverride != "" {
		// Parse bastion override: "user@host:port"
		bastionHost, bastionUser, bastionPort, err = parseBastionString(bastionOverride)
		if err != nil {
			return fmt.Errorf("invalid bastion format: %v", err)
		}
		useBastion = true
		log.Printf("Using bastion override: %s@%s:%d", bastionUser, bastionHost, bastionPort)
	} else if host.BastionHost != "" {
		// Use stored bastion settings
		bastionHost = host.BastionHost
		bastionPort = host.BastionPort
		bastionUser = host.BastionUser
		useBastion = true
		log.Printf("Using stored bastion: %s@%s:%d", bastionUser, bastionHost, bastionPort)
	}

	log.Printf("Target host: [%s]:%d (%s)", host.Address, host.Port, host.Fingerprint)

	// Parse the stored public key for verification
	storedPubKey, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(host.PublicKey))
	if err != nil {
		return fmt.Errorf("invalid stored public key for %s: %v", hostName, err)
	}

	// Create host key callback that only accepts the stored key
	hostKeyCallback := func(hostname string, remote net.Addr, key cryptossh.PublicKey) error {
		if !ssh.KeysEqual(key, storedPubKey) {
			return fmt.Errorf("host key verification failed: server key does not match stored key for %s", hostName)
		}
		return nil
	}

	// Load SSH private key
	keyData, err := os.ReadFile(expandPath(config.Tunnel.KeyFile, ""))
	if err != nil {
		return fmt.Errorf("failed to read SSH key: %v", err)
	}

	signer, err := cryptossh.ParsePrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("failed to parse SSH key: %v", err)
	}

	var conn *cryptossh.Client

	if useBastion {
		// Connect via bastion host
		log.Printf("Connecting via bastion %s@%s:%d", bastionUser, bastionHost, bastionPort)

		// Connect to bastion first
		bastionConfig := &cryptossh.ClientConfig{
			User: bastionUser,
			Auth: []cryptossh.AuthMethod{
				cryptossh.PublicKeys(signer),
			},
			HostKeyCallback: cryptossh.InsecureIgnoreHostKey(), // Trust bastion for now
			Timeout:         10 * time.Second,
		}

		bastionAddr := fmt.Sprintf("%s:%d", bastionHost, bastionPort)
		bastionConn, err := cryptossh.Dial("tcp", bastionAddr, bastionConfig)
		if err != nil {
			return fmt.Errorf("failed to connect to bastion %s: %v", bastionAddr, err)
		}
		defer bastionConn.Close()

		log.Printf("✅ Connected to bastion")

		// Connect to target through bastion
		targetAddr := fmt.Sprintf("[%s]:%d", host.Address, host.Port)
		targetConn, err := bastionConn.Dial("tcp", targetAddr)
		if err != nil {
			return fmt.Errorf("failed to connect to target %s via bastion: %v", targetAddr, err)
		}

		// Create SSH connection over the tunneled connection
		targetConfig := &cryptossh.ClientConfig{
			User: config.Tunnel.User,
			Auth: []cryptossh.AuthMethod{
				cryptossh.PublicKeys(signer),
			},
			HostKeyCallback: hostKeyCallback,
			Timeout:         10 * time.Second,
		}

		sshConn, chans, reqs, err := cryptossh.NewClientConn(targetConn, targetAddr, targetConfig)
		if err != nil {
			return fmt.Errorf("failed to establish SSH connection to target: %v", err)
		}

		conn = cryptossh.NewClient(sshConn, chans, reqs)

	} else {
		// Direct connection
		targetConfig := &cryptossh.ClientConfig{
			User: config.Tunnel.User,
			Auth: []cryptossh.AuthMethod{
				cryptossh.PublicKeys(signer),
			},
			HostKeyCallback: hostKeyCallback,
			Timeout:         10 * time.Second,
		}

		addr := fmt.Sprintf("[%s]:%d", host.Address, host.Port)
		log.Printf("Connecting directly to %s", addr)

		conn, err = cryptossh.Dial("tcp", addr, targetConfig)
		if err != nil {
			return fmt.Errorf("failed to connect to %s: %v", addr, err)
		}
	}

	defer conn.Close()

	// Update last used timestamp
	UpdateLastUsed(hostName)

	log.Printf("✅ Connected to %s", hostName)

	// Create an SSH session
	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %v", err)
	}
	defer session.Close()

	// Get current terminal size
	var width, height int = 80, 25 // defaults
	if term.IsTerminal(int(os.Stdin.Fd())) {
		if w, h, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
			width, height = w, h
		}
	}

	log.Printf("Using terminal size: %dx%d", width, height)

	// Request a pseudo-terminal with correct size and raw mode
	// NOTE: RequestPty expects (height, width) not (width, height)!
	if err := session.RequestPty("xterm-256color", height, width, cryptossh.TerminalModes{
		cryptossh.ECHO:          1,     // Enable echo
		cryptossh.TTY_OP_ISPEED: 14400, // Input speed
		cryptossh.TTY_OP_OSPEED: 14400, // Output speed
		cryptossh.ICANON:        0,     // Disable canonical mode (no line buffering)
	}); err != nil {
		return fmt.Errorf("failed to request PTY: %v", err)
	}

	// Put local terminal in raw mode to match remote
	if term.IsTerminal(int(os.Stdin.Fd())) {
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("failed to set terminal to raw mode: %v", err)
		}
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	// Connect stdin/stdout
	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// Handle terminal resize events
	sigwinch := make(chan os.Signal, 1)
	signal.Notify(sigwinch, syscall.SIGWINCH)
	go func() {
		for range sigwinch {
			if w, h, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
				log.Printf("Terminal resized to %dx%d", w, h)
				// Send window change request to remote
				// NOTE: WindowChange also expects (height, width)!
				if err := session.WindowChange(h, w); err != nil {
					log.Printf("Failed to send window change: %v", err)
				}
			}
		}
	}()
	defer signal.Stop(sigwinch)

	log.Printf("🎮 Starting interactive session with %s...", hostName)

	// Start the shell/application on remote server
	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %v", err)
	}

	// Wait for session to end
	return session.Wait()
}
