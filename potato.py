from argparse import ArgumentParser
import requests

def switch():
    parser = ArgumentParser()
    #parser.add_argument('-url','--url', help='Bruteforce a single URL endpoint {can only be used in single mode}', required=False)
    parser.add_argument('-m','--mode', help='bruteforce mode to use [single|o365|smb]', required=False,)
    parser.add_argument('-u','--username', help='username to test', required=False)
    parser.add_argument('-p','--password', help='password to test', required=False)
    parser.add_argument('-uf','--userfile', help='list of usernames to test', required=False)
    parser.add_argument('-pf','--passfile', help='list of password to test', required=False)
    parser.add_argument('-policy','--policy', help='password policy to be applied [attempts,seconds]', required=False)
    parser.add_argument('-r','--request', help='parse a request file {input file must be in txt}',required=False)
    #parser.add_argument('-t','--thread', help='Number of threads to use [only use with -c or --check]',required=False)
    parser.add_argument('-v','--verbose', help='read output to terminal',required=False, action='store_true')
    return parser.parse_args()


def cls():
    os_env = platform.platform()
    if 'Windows' in os_env:
        os.system('cls')
    else:
        os.system('clear')

def check_o365(url):
    return isO365

if __name__ == '__main__':
    cls()
