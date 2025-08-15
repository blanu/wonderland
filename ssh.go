package main

import (
  "fmt"
  "io"
  "log"
  "net"
  "os"
  "time"

  cryptossh "golang.org/x/crypto/ssh"
)

// StartSSHTunnel sets up an SSH tunnel for remote access
func StartSSHTunnel(config *Config) error {
  log.Printf("Setting up SSH tunnel to %s:%d", config.Tunnel.Host, config.Tunnel.Port)

  // Load private key
  keyData, err := os.ReadFile(config.Tunnel.KeyFile)
  if err != nil {
    return fmt.Errorf("failed to read SSH key %s: %v", config.Tunnel.KeyFile, err)
  }

  signer, err := cryptossh.ParsePrivateKey(keyData)
  if err != nil {
    return fmt.Errorf("failed to parse SSH private key: %v", err)
  }

  log.Printf("SSH key loaded: %s (%s)", config.Tunnel.KeyFile, signer.PublicKey().Type())

  // SSH client configuration
  sshConfig := &cryptossh.ClientConfig{
    User: config.Tunnel.User,
    Auth: []cryptossh.AuthMethod{
      cryptossh.PublicKeys(signer),
    },
    HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
    Timeout:         15 * time.Second,
  }

  go maintainTunnel(config, sshConfig)
  return nil
}

// maintainTunnel keeps the SSH tunnel alive with reconnection
func maintainTunnel(config *Config, sshConfig *cryptossh.ClientConfig) {
  addr := fmt.Sprintf("%s:%d", config.Tunnel.Host, config.Tunnel.Port)

  for {
    log.Printf("Connecting to %s as %s", addr, config.Tunnel.User)

    conn, err := cryptossh.Dial("tcp", addr, sshConfig)
    if err != nil {
      log.Printf("Failed to connect: %v", err)
      log.Printf("Retrying in 10 seconds...")
      time.Sleep(10 * time.Second)
      continue
    }

    log.Printf("SSH connection established")

    // Set up remote port forwarding
    listener, err := conn.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", config.Tunnel.RemotePort))
    if err != nil {
      log.Printf("Failed to set up port forwarding: %v", err)
      conn.Close()
      time.Sleep(10 * time.Second)
      continue
    }

    log.Printf("SSH tunnel active: %s:%d → localhost:%d",
      config.Tunnel.Host, config.Tunnel.RemotePort, config.Wish.Port)

    // Handle connections
    handleTunnelConnections(listener, config.Wish.Port)

    log.Printf("SSH tunnel disconnected, reconnecting...")
    conn.Close()
    time.Sleep(5 * time.Second)
  }
}

// handleTunnelConnections accepts and forwards tunnel connections
func handleTunnelConnections(listener net.Listener, localPort int) {
  for {
    remoteConn, err := listener.Accept()
    if err != nil {
      log.Printf("Tunnel connection error: %v", err)
      return
    }

    go forwardConnection(remoteConn, localPort)
  }
}

// forwardConnection forwards a single connection to the local Wish server
func forwardConnection(remoteConn net.Conn, localPort int) {
  defer remoteConn.Close()

  localConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
  if err != nil {
    log.Printf("Failed to connect to local Wish server: %v", err)
    return
  }
  defer localConn.Close()

  log.Printf("Tunneling connection from %s", remoteConn.RemoteAddr())

  // Bidirectional forwarding
  done := make(chan bool, 2)

  go func() {
    defer func() { done <- true }()
    io.Copy(localConn, remoteConn)
  }()

  go func() {
    defer func() { done <- true }()
    io.Copy(remoteConn, localConn)
  }()

  <-done
}

