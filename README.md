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
	-c --client the computername of the client machine
    -v --verbose read output to terminal
	
 ```

