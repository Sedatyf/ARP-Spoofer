from scapy.all import *
import os, sys
import pyfiglet

def arp_scan(ip):

    result = []
    
    if "/" in ip:
        mask = ip.split("/")
        number_hosts = pow(2, (32 - int(mask[1])))
    else:
        mask = ip.split("/")
        number_hosts = 1
    print(f"Starting ARP Scan on {mask[0]} with {number_hosts} hosts")

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)    

    ans, unans = srp(request, timeout=2, retry=1, verbose=0)
    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})    

    return result

def show_help():
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
    opts = [opt for opt in sys.argv[1:] if opt.startswith("-")]
    args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]

    if not opts:
        show_help()
        sys.exit()
    
    if "-h" in opts:
        show_help()
        sys.exit()
    
    if "-s" in opts:
        result = arp_scan(args[0])

        print('{0} {1:>18}'.format('IP', 'MAC'))

        for mapping in result:
            text = mapping['IP']
            text2 = mapping['MAC']

            space = 34 - len(text)
            f = '{0} {1:>%d}' % (space)

            print(f.format(text, text2))
    else:
        raise SystemExit(show_help())

if __name__ == "__main__":
    main()