# Poundo
```
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
                          
                                                                                                                             
        d8b   db .d8888. d88888b db       .d8b.  d8888b. .d8888.                   
        888o  88 88'  YP 88'     88      d8' `8b 88  `8D 88'  YP                   
        88V8o 88 `8bo.   88ooo   88      88ooo88 88oooY' `8bo.                     
        88 V8o88   `Y8b. 88~~~   88      88~~~88 88~~~b.   `Y8b.                   
        88  V888 db   8D 88      88booo. 88   88 88   8D db   8D                   
        VP   V8P `8888Y' YP      Y88888P YP   YP Y8888P' `8888Y' 
```                                                                                                  
             
Poundo is an intelligent bruteforcer to perform a password spray attack against users of a domain. Poundo attempts to access a large number of accounts (usernames) with a few commonly used passwords.

### Installation

```
$ git clone https://github.com/nsflabs/poundo.git
$ cd poundo/
$ pip3 install -r requirements.txt
$ python3 poundo.py -h
```
 ### Usage
 
 ```

usage: poundo.py 
                        
  optional arguments:   
    -m --mode bruteforce mode to use [o365|smb|other]
    -u --username username to test 
    -p --password password to test 
    -uf --userfile list of usernames to test 
    -pf --passfile list of password to test  
    -policy --policy password policy to be applied [attempts,seconds]
	-ip --host hostname/IP of the remote machine using the format IP:PORT
	-s --servername the computername or servername of the remote machine
	-c --client the computername of the client or local machine
	-d --domain the domain name of the remote machine in the AD
    -v --verbose read output to terminal
	
 ```
## o365
To password spray an office 365 you will need to provide a username or a list of usernames to bruteforce, password or a list of passwords to bruteforce, policy; specify a number of attempts per lockout period, and the time to wait between  each attempts.

## SMB
To spray a SMB service you will need to provide a Windows machine ip address with the open port, username or a list of usernames to bruteforce, password or a list of passwords to bruteforce, policy; specify a number of attempts per lockout period, the time to wait between  each attempts and, finally, the domain name to attack. 


