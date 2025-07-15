import os
import sys
import time
import argparse
import pyfiglet
import subprocess

MENU_OPTIONS = {
    1: "PE scanner",
    2: "Exit"
}

def scan_file(file):
    if not os.path.isfile(file):
        print(f"Invalid path: {file}")
        return
    subprocess.run([sys.executable, "Extract/PE_main.py", file])

def run_PE():
    while True:
        file = input("Enter the path and name of the file : ").strip().strip("'\"")
        scan_file(file)

        choice = input("\nDo you want to search again? (y/n)").lower()
        if choice not in ['y', 'n']:
            exit_with_message()
        elif choice == 'n':
            return

def exit_with_message():
    print("Bad input\nExiting...")
    time.sleep(2)
    sys.exit()

def menu():
    print(pyfiglet.figlet_format("MalDives"))
    print(" Welcome to AI-assist Malware detector \n")
    for option, text in MENU_OPTIONS.items():
        print(f" {option}. {text}")
    print()

    while True:
        try:
            select = int(input("Enter your choice : "))
            if select == 1:
                run_PE()
                break
            elif select == 2:
                sys.exit()
            else:
                exit_with_message()
        except ValueError:
            exit_with_message()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', help='Scan a PE file directly')
    args = parser.parse_args()

    if args.file:
        scan_file(args.file)
    else:
        menu()

if __name__ == "__main__":
    main()
