import os
import sys
import glob
import time
from subprocess import check_output
from collections import OrderedDict


from googleapiclient.discovery import build

from leviathan_config import GOOGLE_API_KEY, GOOGLE_CSE_ID, USER_AGENT, BASE_DIR
from utils import id_generator, timeout, printProgressBar


def google_search(search_term, api_key, cse_id, **kwargs):
    service = build("customsearch", "v1", developerKey=api_key)
    res = service.cse().list(q=search_term, cx=cse_id, **kwargs).execute()
    return res['items']


def link_extract(query, number):
    try:
        print "Extracting URLs from Google for following dork: " + query
        discovery_id = id_generator()
        results = google_search(query, GOOGLE_API_KEY, GOOGLE_CSE_ID, num=number)
        i = 0
        l = len(results)
        for result in results:
            printProgressBar(i, l, prefix='Progress:', suffix='Complete', length=50)
            filename = os.path.join(BASE_DIR, 'assets', 'discovered', 'google_web_' + str(discovery_id) + '.txt')
            with open(filename, "a") as links:
                links.write(result['link'])
                links.write("\n")
            i += 1    
            sys.stdout.write(printProgressBar(i, l, prefix='Progress:', suffix='Complete', length=50))
            time.sleep(0.1)
            sys.stdout.flush()    
        print "\nFinished"
    except Exception as e:
        print "Link extraction failed! Probably your API limit exceeded"
        print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e), e)


def sqli_scan(discovery_id):
    discovered_file = os.path.join(BASE_DIR, 'assets', 'discovered', 'google_web_' + str(discovery_id) + '.txt')
    output_file = os.path.join(BASE_DIR, 'assets', 'compromised', 'google_web_%s.txt' % discovery_id)
    try:
        with open(discovered_file, "r") as urls_file:
            url_list = urls_file.readlines()
            for url in url_list:
                try:
                    sqli_scan_by_url(url, output_file)
                except KeyboardInterrupt:
                    break
                except:
                    continue
                  
    except IOError:
        print "There is no such file: %s" % discovered_file
    print "\n"
    print "Finished. Returning back.."
    time.sleep(5)


@timeout()
def sqli_scan_by_url(url, output_file):
    print "Trying: " + url
    output = check_output(['python', 'dsss.py', '-u', url.rstrip(), '--user-agent', USER_AGENT],
                          cwd=BASE_DIR + '/lib')
    lines = output.split('\n')
    unique_lines = OrderedDict.fromkeys((line for line in lines if line))
    for line in unique_lines:
        try:
            print "**SQLi Found: " + line
            print "\n"
            with open(output_file, "a") as cracked:
                cracked.write(line)
                cracked.write("\n")
        except IOError:
            print "There is no such file: %s" % output_file



def sqli_scan_all():
    discovered_files_reg = os.path.join(BASE_DIR, 'assets', 'discovered', '*_web_*.txt')
    discovered_files = glob.glob(discovered_files_reg)
    for df in discovered_files:
        discoveryid = df.split("_")[2].split(".")[0]
        sqli_scan(discoveryid)

# sqli_scan_all()
# link_extract("inurl:.php?id=",11)
# sqli_scan("3646276")
