package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

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
			runClient(hostname, bastionOverride)
		},
	}
	connectCmd.Flags().StringP("bastion", "b", "", "Override bastion host (user@host:port)")

	// Add command
	var addCmd = &cobra.Command{
		Use:   "add <name>",
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
			log.Printf("✅ Host '%s' added successfully", name)
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
		Use:   "remove <name>",
		Short: "Remove a host from known hosts",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			name := args[0]
			if err := RemoveHost(name); err != nil {
				log.Fatalf("Failed to remove host: %v", err)
			}
			log.Printf("✅ Host '%s' removed successfully", name)
		},
	}

	// Add commands
	rootCmd.AddCommand(serverCmd, connectCmd, addCmd, listCmd, removeCmd)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runServer() {
	log.Printf("🚀 Starting Wonderland Server...")

	config, err := LoadConfig("")
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

	log.Printf("🎉 All services started!")
	log.Printf("🌍 Global access: ssh -p %d %s@%s",
		config.Tunnel.RemotePort, config.Tunnel.User, config.Tunnel.Host)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Printf("🛑 Shutting down...")
}

func runClient(hostname, bastionOverride string) {
	log.Printf("🔌 Starting Wonderland Client...")

	config, err := LoadConfig("")
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	if err := StartClient(hostname, config, bastionOverride); err != nil {
		log.Fatalf("Client failed: %v", err)
	}

	log.Printf("Client session ended")
}
