# ARP-Spoofer
This script is in working progress. It's nearly finished! I have to improve feedbacks for users and it will be great. 

## Definition
ARP spoofing is a type of attack in which a malicious actor sends falsified ARP (Address Resolution Protocol) messages over a local area network. This results in the linking of an attacker’s MAC address with the IP address of a legitimate computer or server on the network. Once the attacker’s MAC address is connected to an authentic IP address, the attacker will begin receiving any data that is intended for that IP address. ARP spoofing can enable malicious parties to intercept, modify or even stop data in-transit. ARP spoofing attacks can only occur on local area networks that utilize the Address Resolution Protocol.

## Legal Notices
As it's said in the previous definition, this attack is totally malicious but only on a local area. Do not attend this kind of attack without clear authorization. If you're getting caught using this on your job's network or a private network, you can have serious trouble. 

**With that said, I cannot be made responsible if you have any problems after using this tool.** So use it with cautions or (this is better) with authorization from the owner's scanned device.

## Usage
You need to have **Scapy** installed on your computer as well as **requests**, **pyfiglet** and **termcolor**

You need to be **root** or at least you need to have right to perform **sudo** command
