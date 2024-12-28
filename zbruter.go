package main

import (
	"flag"
	"fmt"
	"os"
	"time"
	"github.com/alexmullins/zip"
	"strings"
	"errors"
)

// Try extracting the zip file with the given password
func tryPassword(zipFilePath string, password string) (bool, error) {
	// Open the ZIP file
	zipFile, err := zip.OpenReader(zipFilePath)
	if err != nil {
		return false, err
	}
	defer zipFile.Close()

	// Iterate through the files in the ZIP archive
	for _, file := range zipFile.File {
		// Open the file inside the ZIP archive with the given password
		rc, err := file.Open()
		if err != nil {
			if strings.Contains(err.Error(), "password incorrect") {
				// If the error is related to wrong password, return false
				return false, nil
			}
			return false, err
		}
		rc.Close() // Close the file immediately (we don't need to extract it)
	}
	// If we reach here, the password worked
	return true, nil
}

// Brute-force the zip file with a list of passwords
func bruteForce(zipFilePath string, passwordList []string) {
	for _, password := range passwordList {
		fmt.Printf("Trying password: %s\n", password)
		success, err := tryPassword(zipFilePath, password)
		if err != nil {
			fmt.Printf("Error during extraction: %v\n", err)
			return
		}
		if success {
			fmt.Printf("KEY FOUND: %s\n", password)
			return
		}
	}
	fmt.Println("KEY NOT FOUND")
}

func main() {
	// Define command-line flags
	zipFilePath := flag.String("zip", "", "Path to the ZIP file")
	passwordListFile := flag.String("P", "", "Path to the password list file")

	// Parse the command-line flags
	flag.Parse()

	// Validate input
	if *zipFilePath == "" || *passwordListFile == "" {
		fmt.Println("Usage: go run brute.go -zip <path_to_zipfile> -P <password_list_file>")
		flag.PrintDefaults()
		return
	}

	// Read passwords from the file
	passwordList, err := readPasswordList(*passwordListFile)
	if err != nil {
		fmt.Printf("Error reading password list file: %v\n", err)
		return
	}

	// Start brute force attempt
	startTime := time.Now()
	bruteForce(*zipFilePath, passwordList)

	// Print how long the brute force attempt took
	duration := time.Since(startTime)
	fmt.Printf("Brute force completed in %s\n", duration)
}

// Function to read passwords from a file
func readPasswordList(passwordListFile string) ([]string, error) {
	file, err := os.Open(passwordListFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var passwords []string
	var password string
	for {
		_, err := fmt.Fscanf(file, "%s\n", &password)
		if err != nil {
			break
		}
		passwords = append(passwords, password)
	}

	if len(passwords) == 0 {
		return nil, errors.New("no passwords found in the file")
	}

	return passwords, nil
}
