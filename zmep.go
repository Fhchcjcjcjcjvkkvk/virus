package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/alexmullins/zip"
)

// Function to try a password on the zip file
func tryPassword(zipPath, password string) bool {
	// Open the zip file
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		log.Printf("Error opening zip file %s: %s\n", zipPath, err)
		return false
	}
	defer r.Close()

	// Attempt to open each file in the archive with the provided password
	for _, f := range r.File {
		// Try to open the file with the given password
		rc, err := f.Open()
		if err != nil {
			log.Printf("Failed to open file %s with password '%s': %s\n", f.Name, password, err)
			continue
		}
		rc.Close() // Close the file once opened
		// If we reached here, the password worked for at least one file in the zip
		log.Printf("Successfully opened file %s with password '%s'\n", f.Name, password)
		return true
	}
	return false // If we reach here, the password did not work
}

func main() {
	// Define flags for the password file and zip file path
	passwordFileFlag := flag.String("P", "", "Path to the password list file")
	flag.Parse()

	// Ensure that the password file path and the zip file path are provided
	if *passwordFileFlag == "" || len(flag.Args()) < 1 {
		fmt.Println("Usage: go run brute.go -P <password-file> <zip-file>")
		os.Exit(1)
	}

	// Get the ZIP file path from the remaining command-line argument
	zipFilePath := flag.Args()[0]
	passwordListPath := *passwordFileFlag

	// Read the password list from the file
	passwords, err := ioutil.ReadFile(passwordListPath)
	if err != nil {
		log.Fatal("Error reading password list:", err)
	}

	// Split the password list into individual passwords (by lines)
	passwordsLines := strings.Split(string(passwords), "\n")

	// Try each password from the list
	for _, password := range passwordsLines {
		password = strings.TrimSpace(password) // Trim any whitespace from the password
		if password == "" {                    // Skip empty lines
			continue
		}

		// Debugging: Print out the current password being tested
		fmt.Printf("Trying password: '%s'\n", password)

		// Try the password on the zip file
		if tryPassword(zipFilePath, password) {
			// Password found
			fmt.Printf("KEY FOUND: '%s'\n", password)
			return
		}
	}

	// If no password worked
	fmt.Println("KEY NOT FOUND")
}
