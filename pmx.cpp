#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <PoDoFo/podofo.h>
#include <getopt.h>
#include <algorithm>
#include <cmath>
#include <chrono>
#include <thread>

using namespace std;
using namespace PoDoFo;

// Function to decrypt PDF using a password
bool decrypt_pdf(const string &pdf_path, const string &password, const string &output_path) {
    try {
        PdfMemDocument doc;
        doc.Load(pdf_path.c_str(), password.c_str());
        doc.Save(output_path.c_str()); // Use Save instead of Write
        return true;
    } catch (PdfError &e) {
        return false;
    }
}

// Function for brute-force password attack (maximum length 9 characters)
bool brute_force_attack(const string &pdf_path, const string &output_path) {
    const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    string password(9, ' ');

    int total_combinations = pow(chars.size(), 9);

    for (int i = 0; i < total_combinations; ++i) {
        int temp = i;
        for (int j = 0; j < 9; ++j) {
            password[j] = chars[temp % chars.size()];
            temp /= chars.size();
        }

        if (decrypt_pdf(pdf_path, password, output_path)) {
            cout << "KEY FOUND! [" << password << "]" << endl;
            return true;
        }
    }
    return false;
}

// Function for dictionary attack
bool dictionary_attack(const string &pdf_path, const string &output_path, const string &wordlist_path) {
    ifstream wordlist(wordlist_path);
    string password;

    // Ignore non .pwds extension files and just count lines
    while (getline(wordlist, password)) {
        if (password.substr(password.find_last_of('.') + 1) != "pwds") {
            continue;
        }

        if (decrypt_pdf(pdf_path, password, output_path)) {
            cout << "KEY FOUND! [" << password << "]" << endl;
            return true;
        }
    }

    return false;
}

// Main function to handle the arguments and flow
int main(int argc, char *argv[]) {
    string pdf_path;
    string output_path;
    string wordlist_path;

    int opt;
    while ((opt = getopt(argc, argv, "P:o:")) != -1) {
        switch (opt) {
            case 'P':
                wordlist_path = optarg;
                break;
            case 'o':
                output_path = optarg;
                break;
            default:
                cerr << "Usage: " << argv[0] << " -P <wordlist.pwds> -o <output-pdf>" << endl;
                return 1;
        }
    }

    if (optind >= argc) {
        cerr << "PDF file is required." << endl;
        return 1;
    }
    pdf_path = argv[optind];

    // Step 1: Try dictionary attack silently
    if (dictionary_attack(pdf_path, output_path, wordlist_path)) {
        return 0;
    }

    // Step 2: If dictionary attack fails, start brute-force attack silently
    if (!brute_force_attack(pdf_path, output_path)) {
        cout << "KEY NOT FOUND" << endl;
    }

    return 0;
}
