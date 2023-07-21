import os
import sys
import time
import pyfiglet
import subprocess

# Menu options displayed to the user
MENU_OPTIONS = {
    1: "PE scanner",
    2: "Exit"
}

def run_PE():
    while True:
        # Ask the user for the file path, remove leading/trailing spaces and quotes
        file = input("Enter the path and name of the file : ").strip().strip("'\"")
        # Execute the PE scanner with the given file
        subprocess.run(["python3", "Extract/PE_main.py", file])

        choice = input("\nDo you want to search again? (y/n)")
        if choice.lower() not in ['y', 'n']:
            print("Bad input\nExiting...")
            time.sleep(3)
            return True
        elif choice.lower() == 'n':
            return True
    return False

def exit_program():
    # Exit the program
    sys.exit()

def start():
    # Print welcome message
    print(pyfiglet.figlet_format("MalDives"))
    print(" Welcome to AI-assist Malware detector \n")

    # Print menu options
    for option, text in MENU_OPTIONS.items():
        print(f" {option}. {text}")
    print()

    # Main loop for user input
    while True:
        try:
            # Ask the user for their choice
            select = int(input("Enter your choice : "))

            if select == 1:
                # If the user selected the PE scanner
                if run_PE():
                    break

            elif select == 2:
                # If the user selected to exit
                exit_program()

            else:
                # If the user entered an invalid option
                print("Bad input\nExiting...")
                time.sleep(3)
                exit_program()

        except ValueError:
            # If the user entered a non-integer value
            print("Bad input\nExiting...")
            time.sleep(3)
            exit_program()

# Start the program
start()
