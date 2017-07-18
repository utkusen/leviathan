# coding=utf-8

import os
import glob
import time
import errno
import signal
from functools import wraps
from random import randint

from leviathan_config import BASE_DIR, GOOGLE_API_KEY, GOOGLE_CSE_ID, CENSYS_API_URL
from leviathan_config import CENSYS_UID, CENSYS_SECRET, SHODAN_API_KEY


class TimeoutError(Exception):
    pass


def timeout(seconds=30, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wraps(func)(wrapper)

    return decorator


def id_generator():
    range_start = 10 ** (7 - 1)
    range_end = (10 ** 7) - 1
    return randint(range_start, range_end)


def get_protocol_by_service(protocol, service):
    return {
        'censys': {'ftp': '"21/ftp"', 'ssh': '"22/ssh"', 'telnet': '"23/telnet"'}.get(protocol, False),
        'massscan': {'ftp': '-p21', 'ssh': '-p22', 'telnet': '-p23', 'smb': '-p445' , 'rdp': '-p3389',
                     'mysql': '-p3306'}.get(protocol, False)
    }.get(service,
          {'ftp': '21', 'ssh': '22', 'telnet': '23', 'smb': '445' , 'rdp': '3389',
           'mysql': '3306'}.get(protocol, False))


def get_output_file_by_scanner(scanner, discovery_id, protocol):
    return {
        'massscan': os.path.join(BASE_DIR, 'assets', 'discovered', 'masscan_' +
                                 protocol + '_' + str(discovery_id) + '.txt'),
        'shodan': os.path.join(BASE_DIR, 'assets', 'discovered', 'shodan_' + protocol +
                               '_' + str(discovery_id) + '.txt'),
        'censys': os.path.join(BASE_DIR, 'assets', 'discovered', 'censys_' + protocol +
                               '_' + str(discovery_id) + '.txt')
    }.get(scanner, '')


def get_protocol_info(protocol):
    return {
        'ftp': ('21', 'ftp_default_user.txt', 'generic_pass.txt'),
        'ssh': ('22', 'ssh_default_user.txt', 'generic_pass.txt'),
        'telnet': ('23', 'telnet_default_user.txt', 'telnet_default_pass.txt'),
        'rdp': ('3389', 'rdp_default_user.txt', 'generic_pass.txt'),
        'mysql': ('3306', 'mysql_default_user.txt', 'generic_pass.txt')
    }.get(protocol, (None, None, None))


def get_command(protocol, port, user_fullpath, pass_fullpath, ip):
    return {
        'telnet': ['ncrack', '-p', port, '-U', user_fullpath, '-P', pass_fullpath, '--pairwise', ip,
                   '-T5']
    }.get(protocol,
          ['ncrack', '-p', '%s:%s' % (protocol, port), '-U', user_fullpath, '-P', pass_fullpath, ip, '-T5']
          )


def get_protocol(filename):
    try:
        return filename.split('_')[1]
    except:
        return 0


def get_possible_protocols_files(filename):
    protocols = []
    files = glob.glob(filename)
    for f in files:
        protocols.append(get_protocol(f))
    return protocols, files


def select_protocol(possible_protocols):
    message = "This asset has more than one result. Please select protocol:\n"
    for idx, p in enumerate(possible_protocols):
        message += "%s for %s\n" % (str(idx), p)
    message += "Press q to exit "
    selected_protocol = raw_input(message)
    try:
        if selected_protocol == "q":
            return 0
        return possible_protocols[int(selected_protocol)]
    except:
        print "This selection is not valid: %s" % selected_protocol
        select_protocol(possible_protocols)


def automatic_dork(country_code, extension):
    return "inurl:.php?id=" + " inurl:" + extension + "." + country_code


def query_constructor(country, protocol, service):
    port = get_protocol_by_service(protocol, service)
    return {
        'censys': 'location.country_code: ' + country + ' and protocols: ' + port,
    }.get(service, "country:" + country + " port:" + port)


def config_change(api_name, value):
    with open(os.path.join(BASE_DIR, 'leviathan_config.py'), 'r') as config_file:
        file_str = config_file.read().splitlines()
    with open(os.path.join(BASE_DIR, 'leviathan_config.py'), 'w') as config_file:
        for line in file_str:
            if not line.startswith(api_name):
                config_file.write(line)
                config_file.write("\n")

        config_file.write(api_name + ' = "' + value + '"')
    return


# for custom exploits, converts discovery file into list
def discovery_parse(discovery_id):
    try:
        discovery_file = os.path.join(BASE_DIR, 'assets', 'discovered', '*' + discovery_id + '.txt')
        possible_protocols, file = get_possible_protocols_files(discovery_file)
        if file:
            with open(file[0], "r") as f:
                content = f.readlines()
            return [x.strip() for x in content]
        return []
    except IOError:
        print "There is no such file: %s" % output_file
        return 0


def get_file_by_dicovery_id(discovery_id, type):
    discovery_file = os.path.join(BASE_DIR, 'assets', type, '*' + discovery_id + '.txt')
    possible_protocols, file = get_possible_protocols_files(discovery_file)
    if file:
        return file[0]
    else:
        print "There is no such file with this discovery id: %s" % discovery_id
        return ''



def compromise_save(discovery_id, exploit_name, asset_list):
    try:
        file_name = "custom_%s_%s.txt" % (exploit_name, str(discovery_id))
        save_location = os.path.join(BASE_DIR, 'assets', 'compromised', file_name)
        with open(save_location, "a") as compromised:
            for i in asset_list:
                compromised.write(i)
                compromised.write("\n")
    except IOError:
        print "There is no such file: %s" % output_file
        return 0


def return_asset(protocol, type):
    try:
        if protocol != 'all':
            filename = os.path.join(BASE_DIR, 'assets', type, '*_' + protocol + '_*.txt')
        else:
            filename = os.path.join(BASE_DIR, 'assets', type, '*_*_*.txt')
        possible_protocols, files = get_possible_protocols_files(filename)
        for j, i in enumerate(files):
            discovery_id = i.split("_")[2].split(".")[0]
            print "ID:" + discovery_id + " | Protocol:" + possible_protocols[j] + " | Method:" + \
                  i.split("_")[0].split("/")[-1] + " | Count:" + str(file_len(i)) + " | Date:" + time.ctime(os.path.getmtime(i))
    except IOError:
        print "There is no such file: %s" % output_file
        return 0

def show_config_file():
    print """

        GOOGLE_API_KEY = %s
        GOOGLE_CSE_ID = %s
        CENSYS_API_URL = %s
        CENSYS_UID = %s
        CENSYS_SECRET = %s
        SHODAN_API_KEY = %s

    """ % (GOOGLE_API_KEY, GOOGLE_CSE_ID, CENSYS_API_URL, CENSYS_UID, CENSYS_SECRET, SHODAN_API_KEY)
    return


# Print iterations progress
def printProgressBar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='█'):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    return '\r%s |%s| %s%% %s' % (prefix, bar, percent, suffix)
    # Print New Line on Complete

def file_len(fname):
    try:
        with open(fname) as f:
            for i, l in enumerate(f):
                pass
        return i + 1
    except:
        return 0
