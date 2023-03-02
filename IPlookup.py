
import vt
import colorama
import argparse
from colorama import Fore, Style

client = vt.Client("")  # <- Enter VirusTotal API key here

ap = argparse.ArgumentParser(description="VirusTotal Bulk IP Lookup - v1, 2 March 2023 - by ZeroGravity")
ap.add_argument("-f", "--file", required=True, help="The filename containing IPs")
args = vars(ap.parse_args())

filename = (args["file"])
#Opens ips.txt file in working directory
try:
    print("VirusTotal Bulk IP Lookup - v1, 2 March 2023 - by ZeroGravity")
    print("--------------------------------------------------------------")
    with open(filename) as file:
        for line in file.readlines():
            line_fanged = line.replace("[","").replace("]","")
            ip_addr = client.get_object(f'/ip_addresses/{line_fanged}')
            stat = (ip_addr.last_analysis_stats)
            if stat.get('malicious') != 0:
                print(f'{Fore.RED}{line_fanged.rstrip()}  malicious{Fore.WHITE}') 
            else:
                print(f'{line_fanged.rstrip()}  benign')
except FileNotFoundError:
    print(f'{filename} not found.')