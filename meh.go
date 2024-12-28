package main

import (
	"flag"
	"fmt"
	"github.com/alexmullins/zip"
	"io/ioutil"
	"log"
	"strings"
)

// Function to attempt extracting the ZIP file with a password
func tryPassword(zipFile, password string) bool {
	// Open the zip file
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		log.Fatalf("Failed to open zip file: %v\n", err)
		return false
	}
	defer r.Close()

	// Attempt to extract the files with the provided password
	for _, f := range r.File {
		// Open the file inside the ZIP archive
		rc, err := f.Open()
		if err != nil {
			continue // Skip files that can't be opened
		}
		defer rc.Close()

		// Try decrypting the file with the provided password
		// We use the Decrypt method provided by the alexmullins/zip package
		if err := f.SetPassword(password); err != nil {
			continue // If password is incorrect, continue with the next one
		}

		// Read the file content (this will succeed if the password is correct)
		_, err = ioutil.ReadAll(rc)
		if err == nil {
			// If no error occurred, this is the correct password
			return true
		}
	}

	// Password didn't work for this zip file
	return false
}

// Function to perform brute force on the password list
func bruteForceZip(zipFile string, passwordList []string) {
	for _, password := range passwordList {
		fmt.Printf("Trying password: %s\n", password)
		if tryPassword(zipFile, password) {
			fmt.Printf("KEY FOUND: %s\n", password)
			return
		}
	}
	fmt.Println("KEY NOT FOUND")
}

// Main function with command-line argument parsing
func main() {
	// Define the command-line flags
	zipFile := flag.String("zip", "", "Path to the ZIP file")
	passwordFile := flag.String("P", "", "Path to the password list file")

	// Parse the flags
	flag.Parse()

	// Ensure the ZIP file and password list file are specified
	if *zipFile == "" || *passwordFile == "" {
		log.Fatal("You must specify both the ZIP file and password list file.")
	}

	// Read the password list from the provided file
	passwordListBytes, err := ioutil.ReadFile(*passwordFile)
	if err != nil {
		log.Fatalf("Failed to read password list file: %v\n", err)
	}

	// Split the password list into individual passwords
	passwordList := strings.Split(string(passwordListBytes), "\n")

	// Start brute-forcing with the provided password list
	bruteForceZip(*zipFile, passwordList)
}
