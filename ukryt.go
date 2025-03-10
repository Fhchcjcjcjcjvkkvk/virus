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
		log.Println("Error opening zip file:", err)
		return false
	}
	defer r.Close()

	// Attempt to open each file in the archive with the provided password
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		rc.Close()
		return true
	}
	return false
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
		if tryPassword(zipFilePath, password) {
			fmt.Println("KEY FOUND:", password)
			return
		}
	}
	fmt.Println("KEY NOT FOUND")
}
