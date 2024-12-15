import subprocess
import os
import sys

def run_script(script_name):
    """
    Executes the given Python script and captures the output.
    """
    if not os.path.isfile(script_name):
        print(f"Error: '{script_name}' does not exist.")
        return

    if not script_name.endswith(".py"):
        print(f"Error: '{script_name}' is not a Python file.")
        return

    try:
        # Run the Python script and capture the output
        result = subprocess.run(['python', script_name], capture_output=True, text=True)
        
        # Print stdout
        if result.stdout:
            print(result.stdout)
        
        # Print stderr
        if result.stderr:
            print(f"Error: {result.stderr}", file=sys.stderr)
    
    except Exception as e:
        print(f"Error executing the script: {str(e)}", file=sys.stderr)


def show_help():
    """
    Shows the help message explaining how to use the tool.
    """
    print("""
Eternal.py - A terminal-like Python script executor.

Commands:
  run <script_name.py>  - Executes the given Python script.
  help                 - Shows this help message.
  exit                 - Exits the tool.
  """)


def main():
    """
    Main function to interact with the user.
    """
    print("Eternal.py - Interactive Python Script Executor")
    print("Type 'help' for usage or 'exit' to quit.")

    while True:
        # Prompt user for input
        command = input("terminal > ").strip()

        if command == 'exit':
            print("Exiting the terminal.")
            break
        elif command == 'help':
            show_help()
        elif command.startswith('run '):
            script_name = command[4:].strip()
            run_script(script_name)
        else:
            print(f"Unknown command: {command}")
            print("Type 'help' for usage.")


if __name__ == "__main__":
    main()
