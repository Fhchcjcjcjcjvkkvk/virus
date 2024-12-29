package main

import (
	"fmt"
	"net/http"
	"html/template"
)

// Credentials
const (
	Username = "admin"
	Password = "password123"
)

// Login page handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Parse the form data
		r.ParseForm()
		user := r.FormValue("username")
		pass := r.FormValue("password")

		// Check if credentials match
		if user == Username && pass == Password {
			http.Redirect(w, r, "/success", http.StatusFound)
			return
		}
		// If incorrect, show login page with an error message
		http.Error(w, "Invalid credentials, please try again.", http.StatusUnauthorized)
		return
	}

	// Display the login form
	tmpl := `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Login</title>
	</head>
	<body>
		<h2>Login</h2>
		<form action="/login" method="POST">
			<div>
				<label for="username">Username:</label>
				<input type="text" id="username" name="username" required>
			</div>
			<div>
				<label for="password">Password:</label>
				<input type="password" id="password" name="password" required>
			</div>
			<button type="submit">Login</button>
		</form>
	</body>
	</html>
	`
	t, _ := template.New("login").Parse(tmpl)
	t.Execute(w, nil)
}

// Success page handler
func successHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Login Successful</title>
	</head>
	<body>
		<h2>Login Successful!</h2>
		<p>Welcome, admin!</p>
	</body>
	</html>
	`
	t, _ := template.New("success").Parse(tmpl)
	t.Execute(w, nil)
}

func main() {
	// Define routes
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/success", successHandler)

	// Start the server
	fmt.Println("Server started at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
