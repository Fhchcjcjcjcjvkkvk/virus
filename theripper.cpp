#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <ctime>
#include <vector>

using namespace std;

// Function to check if the password is in the wordlist
bool isPasswordInWordlist(const string& password, const string& wordlistFile) {
    ifstream wordlist(wordlistFile);
    string line;
    while (getline(wordlist, line)) {
        if (line == password) {
            return true;
        }
    }
    return false;
}

// Function to score the password strength (scale 1-4)
int scorePasswordStrength(const string& password) {
    int score = 0;
    
    // Basic checks for password strength
    if (password.length() >= 8) score++;
    if (password.find_first_of("0123456789") != string::npos) score++;
    if (password.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ") != string::npos) score++;
    if (password.find_first_of("!@#$%^&*()-_=+[]{}|;:,.<>?") != string::npos) score++;
    
    return score;
}

// Function to generate a strong password based on specified length
string generateStrongPassword(int length) {
    const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";
    string password = "";
    
    srand(time(0)); // Seed the random number generator
    for (int i = 0; i < length; i++) {
        password += chars[rand() % chars.length()];
    }
    
    return password;
}

int main() {
    int choice;
    string password;
    int passwordLength;
    string wordlistFile = "wordlist.txt"; // Path to your wordlist file
    
    cout << "SELECT OPTION" << endl;
    cout << "1. Password Check" << endl;
    cout << "2. Password Generator" << endl;
    cout << "Enter your choice: ";
    cin >> choice;
    
    if (choice == 1) {
        // Password check option
        cout << "Enter password to check: ";
        cin >> password;
        
        if (isPasswordInWordlist(password, wordlistFile)) {
            cout << "NOTE: PWNED!" << endl;
        } else {
            cout << "NOTE: NOTHING FOUND!" << endl;
        }
        
        // Score the password
        int score = scorePasswordStrength(password);
        cout << "Password strength: " << score << "/4" << endl;
    } else if (choice == 2) {
        // Password generator option
        cout << "Enter password length: ";
        cin >> passwordLength;
        
        string strongPassword = generateStrongPassword(passwordLength);
        cout << "Generated Strong Password: " << strongPassword << endl;
    } else {
        cout << "Invalid choice!" << endl;
    }

    return 0;
}
