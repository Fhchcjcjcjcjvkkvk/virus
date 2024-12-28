package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
	"unicode"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	for {
		fmt.Println("SELECT OPTION:")
		fmt.Println("1. Password Check")
		fmt.Println("2. Password Generator")
		fmt.Println("3. Exit")
		fmt.Print("Enter your choice: ")

		var choice int
		fmt.Scanln(&choice)

		switch choice {
		case 1:
			passwordCheck()
		case 2:
			passwordGenerator()
		case 3:
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Invalid choice, try again.")
		}
	}
}

func passwordCheck() {
	fmt.Print("Enter password to check: ")
	var password string
	fmt.Scanln(&password)

	// Load the wordlist/database
	wordlist, err := loadWordlist("wordlist.txt")
	if err != nil {
		fmt.Println("Error loading wordlist:", err)
		return
	}

	// Check if the password is in the wordlist
	if _, found := wordlist[password]; found {
		fmt.Println("NOTE: PWNED!")
	} else {
		fmt.Println("NOTE: NOTHING FOUND!")
	}

	// Calculate password strength
	score := passwordStrength(password)
	fmt.Printf("Password strength: %d/4\n", score)
}

func passwordGenerator() {
	fmt.Print("Enter password length: ")
	var length int
	fmt.Scanln(&length)

	if length < 6 {
		fmt.Println("Password length should be at least 6.")
		return
	}

	// Generate a strong password
	password := generateStrongPassword(length)
	fmt.Printf("Generated password: %s\n", password)
}

// Load wordlist (database of pwned passwords)
func loadWordlist(filename string) (map[string]struct{}, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	wordlist := make(map[string]struct{})
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		wordlist[password] = struct{}{}
	}

	return wordlist, scanner.Err()
}

// Calculate password strength based on length and complexity
func passwordStrength(password string) int {
	var score int

	// Check length
	if len(password) >= 8 {
		score++
	}

	// Check for uppercase letters
	if containsUpperCase(password) {
		score++
	}

	// Check for digits
	if containsDigit(password) {
		score++
	}

	// Check for special characters
	if containsSpecialChar(password) {
		score++
	}

	return score
}

func containsUpperCase(password string) bool {
	for _, ch := range password {
		if unicode.IsUpper(ch) {
			return true
		}
	}
	return false
}

func containsDigit(password string) bool {
	for _, ch := range password {
		if unicode.IsDigit(ch) {
			return true
		}
	}
	return false
}

func containsSpecialChar(password string) bool {
	for _, ch := range password {
		if !unicode.IsLetter(ch) && !unicode.IsDigit(ch) {
			return true
		}
	}
	return false
}

// Generate a strong password from a wordlist
func generateStrongPassword(length int) string {
	// Load the wordlist
	wordlist, err := loadWordlist("wordlist.txt")
	if err != nil {
		fmt.Println("Error loading wordlist:", err)
		return ""
	}

	var password string
	words := make([]string, 0, len(wordlist))

	// Collect all words from the wordlist
	for word := range wordlist {
		words = append(words, word)
	}

	// Build the password by selecting random words from the wordlist
	for len(password) < length {
		word := words[rand.Intn(len(words))]
		password += word
	}

	// Trim the password to the desired length
	return password[:length]
}
