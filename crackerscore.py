from zxcvbn import zxcvbn
import pprint, getpass, sys

def test_single_password():
    password = getpass.getpass("[?] Enter your password: ")
    result = zxcvbn(password)
    
    print(f"\nValue: {result['password']}")
    print(f"Password Score: {result['score']}/4")
    print(f"Crack Time: {result['crack_times_display']['offline_slow_hashing_1e4_per_second']}")
    print(f"Feedback: {result['feedback']['suggestions']}")
    # pprint.pprint(result)  # Uncomment to see the entire result if needed

def test_multiple_passwords(password_file):
    try:
        with open(password_file, 'r') as passwords:
            for password in passwords:
                result = zxcvbn(password.strip())  # strip newlines or extra spaces
                
                print('\n[+] ######################')  # for readability
                print(f"Value: {result['password']}")
                print(f"Password Score: {result['score']}/4")
                print(f"Crack Time: {result['crack_times_display']['offline_slow_hashing_1e4_per_second']}")
                print(f"Feedback: {result['feedback']['suggestions']}")
                # pprint.pprint(result)  # Uncomment to see the entire result if needed
           
    except FileNotFoundError:
        print(f"[!] Error: The file '{password_file}' was not found.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) == 2:
        test_multiple_passwords(sys.argv[1])
    elif len(sys.argv) == 1:
        test_single_password()
    else:
        print('Usage:crackerscore <file> (for a file containing passwords) or \
        \crackerscore (for a single password.)')
