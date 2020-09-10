from scapy.all import Ether, ARP, srp, send
import os, sys
import requests
import pyfiglet, termcolor
from datetime import datetime

def arp_scan(ip):
    """Perform an arp scan on an ip or a range of ip

    Args:
        ip (str): The ip's victim or a range of ip

    Returns:
        list: a list of host who responded to our request
    """
    result = []
    
    # This condition calculate the number of host from the network's mask
    # Or specify 1 if it's not a range of ips
    if "/" in ip:
        mask = ip.split("/")
        number_hosts = pow(2, (32 - int(mask[1])))
    else:
        mask = ip.split("/")
        number_hosts = 1
    print(f"Starting ARP Scan on {mask[0]} with {number_hosts} hosts")

    # Make a packet for an ARP request
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)    

    # srp() sends ARP request AND wait for the response
    ans, unans = srp(request, timeout=2, retry=1, verbose=0)
    # Append ips, macs, and manufacturer in result list for those who responded
    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc, 'manu': show_manufacturer(received.hwsrc)})    

    return result

def show_manufacturer(mac):
    """Make an API request to get manufacturer name from a mac address

    Args:
        mac (string): current mac address

    Returns:
        string: manufacturer's name
    """
    # URL to the API
    mac_url = 'https://macvendors.co/api/%s'
    # Make API GET request
    r = requests.get(mac_url % mac)
    # Convert response in a json type
    json = r.json()
    return json['result']['company']

def show_help():
    # Pyfiglet make some cool banner
    custom_fig = pyfiglet.Figlet(font='slant')
    print(custom_fig.renderText('ARP spoofer'))
    
    print(f"""
    Usage:
        {os.path.basename(__file__)} -s <ip>

    Options:
        -s    Scan for a specific ip or a range of ip by specifying network's mask
              Like 192.168.1.1 for a specific ip or 192.168.1.1/24 for a range of ip

        -h    Show this screen
    """)

def main():
    # Get options and arguments
    opts = [opt for opt in sys.argv[1:] if opt.startswith("-")]
    args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]

    if not opts:
        show_help()
        sys.exit()
    
    if "-h" in opts:
        show_help()
        sys.exit()
    
    if "-s" in opts:
        t1 = datetime.now()
        result = arp_scan(args[0])

        # Header's table
        print('{0} {1:>18}'.format('IP', 'MAC'))

        # Print result in a nice align way
        for mapping in result:
            ip = mapping['IP']
            mac = mapping['MAC']
            manufacturer = mapping['manu']

            space = 34 - len(ip)
            f = '{0} {1:>%d}    {2:<2}' % (space)

            print(f.format(ip, mac, manufacturer))
        t2 = datetime.now()
        termcolor.cprint("Scanning Completed in " + str(t2-t1), "green")
    else:
        raise SystemExit(show_help())

if __name__ == "__main__":
    main()