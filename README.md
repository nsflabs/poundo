```
d8888b.  .d88b.  db    db d8b   db d8888b.  .d88b.  
88  `8D .8P  Y8. 88    88 888o  88 88  `8D .8P  Y8. 
88oodD' 88    88 88    88 88V8o 88 88   88 88    88 
88~~~   88    88 88    88 88 V8o88 88   88 88    88 
88      `8b  d8' 88b  d88 88  V888 88  .8D `8b  d8' 
88       `Y88P'  ~Y8888P' VP   V8P Y8888D'  `Y88P' 
                                                    
                                                    
```                                                                                                  
             
Poundo is an intelligent bruteforcer to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain whether a user provides username(s) at runtime or not. 
Poundo attempts to access a large number of accounts (usernames) with a few commonly used passwords.


### Installation

```
$ git clone https://github.com/abdulgaphy/poundo.git
$ cd poundo/
$ pip3 install -r requirements.txt
$ chmod +x generator.py
$ python3 poundo.py -h
```
 ### Usage
 
 ```

usage: poundo.py 
                        

  optional arguments:  
    -h --host hostname, domain or url to bruteforce 
    -m --mode bruteforce mode to use [single|o365|smb]
    -u --username username to test 
    -p --password password to test 
    -uf --userfile list of usernames to test 
    -pf --passfile list of password to test  
    -policy --policy password policy to be applied [attempts,seconds]  
    -v --verbose read output to terminal

 ```

