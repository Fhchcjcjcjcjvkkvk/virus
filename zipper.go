package main

import (
	"fmt"
	"log"
	"os"
	"github.com/alexmullins/zip"
)

func main() {
	var password, verifyPassword string

	// Get password from user
	fmt.Print("Enter password: ")
	_, err := fmt.Scanln(&password)
	if err != nil {
		log.Fatal("Error reading password:", err)
	}

	// Verify password
	fmt.Print("Verify password: ")
	_, err = fmt.Scanln(&verifyPassword)
	if err != nil {
		log.Fatal("Error reading password:", err)
	}

	// Check if the passwords match
	if password != verifyPassword {
		log.Fatal("Passwords do not match!")
	}

	// Create an encrypted ZIP file with no files inside
	err = createEmptyEncryptedZip("test.zip", password)
	if err != nil {
		log.Fatal("Error creating encrypted ZIP:", err)
	}

	fmt.Println("Empty password-protected ZIP file created successfully!")
}

// createEmptyEncryptedZip creates an encrypted ZIP file with no files inside it
func createEmptyEncryptedZip(filename string, password string) error {
	// Create the ZIP file
	zipFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	// Create a new ZIP writer
	zipWriter := zip.NewWriter(zipFile)

	// Set the password protection for the ZIP file (AES-256 encryption)
	zipWriter.SetPassword(password)

	// Close the ZIP writer to finalize the empty encrypted ZIP file
	err = zipWriter.Close()
	if err != nil {
		return err
	}

	return nil
}
