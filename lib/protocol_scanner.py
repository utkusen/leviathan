import os
import sys
import subprocess
from time import sleep

import requests
import shodan
from bs4 import BeautifulSoup

from leviathan_config import CENSYS_API_URL, CENSYS_UID, CENSYS_SECRET, SHODAN_API_KEY, BASE_DIR
from utils import id_generator, get_protocol_by_service, get_output_file_by_scanner, printProgressBar


def shodan_search(query, protocol):
    print "Extracting IPs for following query: " + query
    print "Please wait.."
    discovery_id = id_generator()
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        results = api.search(query)
    except:
        print "Cannot communicate with Shodan.io"    
        return 0
    ip_list = []
    output_file = ''
    i = 0
    l = len(results['matches'])
    for result in results['matches']:
        try:
            # Initial call to print 0% progress
            printProgressBar(i, l, prefix='Progress:', suffix='Complete', length=50)
            ip = result['ip_str']
            if ip in ip_list:
                continue
            ip_list.append(ip)
            output_file = get_output_file_by_scanner('shodan', discovery_id, protocol)
            try:
                with open(output_file, "a") as ips:
                    ips.write(ip)
                    ips.write("\n")
            except IOError:
                print "There is no such file: %s" % output_file
                return 0
            i += 1
            sys.stdout.write(printProgressBar(i, l, prefix='Progress:', suffix='Complete', length=50))
            sleep(0.1)
            sys.stdout.flush()    
        except KeyboardInterrupt:
            break
    print "\nResults saved under: %s" % output_file
    print "Finished"
    return 1


def censys_search(query, protocol):
    print "Extracting IPs for following query: " + query
    print "Please wait.."
    discovery_id = id_generator()
    pages = 2
    output_file = ""
    page = 1
    while page <= pages:
        try:
            print "Extracting IPs from page %s" % str(page)
            params = {'query': query, 'page': page}
            try:
                res = requests.post(CENSYS_API_URL + "/search/ipv4", json=params, auth=(CENSYS_UID, CENSYS_SECRET))
            except:
                print "Cannot communicate with Censys.io"
                return   
            payload = res.json()
            ip_list = []
            if 'results' in payload.keys():
                i = 0
                l = len(payload['results'])

                # Initial call to print 0% progress
                printProgressBar(i, l, prefix='Progress:', suffix='Complete', length=50)
                for r in payload['results']:
                    ip = r["ip"]
                    if ip in ip_list:
                        continue
                    ip_list.append(ip)
                    output_file = get_output_file_by_scanner('censys', discovery_id, protocol)
                    try:
                        with open(output_file, "a") as ips:
                            ips.write(ip)
                            ips.write("\n")
                    except IOError:
                        print "There is no such file: %s" % output_file
                        return 0
                    except Exception as e:
                        print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e), e)
                        return 0
                        

                    # Update Progress Bar
                    i += 1
                    sys.stdout.write(printProgressBar(i, l, prefix='Progress:', suffix='Complete', length=50))
                    sleep(0.1)
                    sys.stdout.flush()
                print ""
                if page == 1:
                    pages = payload['metadata']['pages']
                page += 1
            else:
                print "Can not communicate with Censys"
                return 0
        except KeyboardInterrupt:
            break
    print "Results saved under: %s" % output_file
    print "Finished"
    return 1



def mass_scan(ip, protocol):
    print "Scanning " + ip + " for " + protocol
    print "Please wait it may take time.."
    discovery_id = id_generator()
    param = get_protocol_by_service(protocol, 'massscan')
    output_file = ""
    FNULL = open(os.devnull, 'w')
    res = subprocess.call(['masscan', ip, param, '--max-rate', '100000', '-oX', 'masscan.xml'], stdout=FNULL,
                          stderr=subprocess.STDOUT)
    if not res:
        infile = open("masscan.xml", "r")
        contents = infile.read()
        soup = BeautifulSoup(contents, 'xml')
        titles = soup.find_all('address')
        output_file = get_output_file_by_scanner('massscan', discovery_id, protocol)
        for title in titles:
            try:
                with open(output_file, "a") as ips:
                    ips.write(title['addr'])
                    ips.write("\n")
            except IOError:
                print "There is no such file: %s" % output_file
                return 0
        os.remove("masscan.xml")
    else:
        print "Masscan requires root privileges. Please start Leviathan with sudo command. "
    print "Results saved under: %s" % output_file
    print "Finished"
    return 1

# country = "TR"
# protocol = "custom"
# service = "censys"
# query = query_constructor(country,protocol, service)
# censys_search(query)
# shodan_search("country:tr port:22")
# mass_scan("178.62.121.1/24","ssh")
