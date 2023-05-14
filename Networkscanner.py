#we use a arp request discovery 

from colorama import init as colorama_init
from colorama import Fore
from colorama import Style


# Module Documntaion https://scapy.readthedocs.io/en/latest/
from scapy.all import *
import ipaddress
import re
from prettytable import PrettyTable

#Module for Port scanner Mutithreading
import threading
import socket
from queue import Queue
from time import sleep

# GOAL = Discover client on network
"""
ALGORITHM 

1) Create arp Request directed to broadcast MAC asking for Ip
    1.1) two main parts
    1.1.1)use ARP to Ask who has target Ip
    1.1.2)set destination MAC to Broadcast MAC
2) Send packet and recieve response 
3) Parse the response
4) Print the result 

"""
def is_ipv4(string):
        try:
            ipaddress.IPv4Network(string)
            return "Port"
        except ValueError:
            cider1 = re.compile(r'^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$')
            cider = cider1.search(string)
            if cider:
                return "Scan"
            else : 
                return "Not a valid ip address"
                

def scan(ipaddress):
   """
   this command can do all the things bt its own but we build our own 
   scapy.arping(ipaddress)
   """
   # 1.1.1) create Arp Request
   arp_request = scapy.all.ARP(pdst=ipaddress)      # ARP who has 0.0.0.0 says 192.168.29.124
   # print(arp_request.summary())                   #  this print the apr packet at it base 
   # scapy.all.ls(scapy.all.ARP())                  # print the the attributes that we can modify in the apr request to change 0.0.0.0 to our ip address dynamically
   # arp_request.show()


   # 1.1.2) Set Destination MAC to Broadcast MAC Using Ethernet frame
   broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
   # scapy.all.ls(scapy.all.Ether())                 # to list all the attributes that need / or we need to change
   # print(broadcast.summary())                      # d2:ef:52:7c:ae:86 > ff:ff:ff:ff:ff:ff (0x9000)
   # broadcast.show()

   arp_request_boroadcast =  broadcast/arp_request   # combine both apr request and broadcasr request
   #arp_request_boroadcast.show()                    # show arp request
   
   
   # 2) Send packet and recieve response 
   answered = scapy.all.srp(arp_request_boroadcast, timeout=.5, verbose=0)[0]
   #print(answered.summary())  # this is a list
   #print(unanswered.summary())
   
   # 3) Parse the response
   #print(answered)
   print("[+] No of Node present on Network : ", len(answered))
   print_result_node(answered)

def scan_network(ip_network, num_threads=10):
    network = ipaddress.ip_network(ip_network, strict=False)
    reachable_ips = []
    reachable_ips_lock = threading.Lock()
    queue_ips = Queue()

    def worker():
        while True:
            ip = queue_ips.get()
            if ip is None:
                break
            command = ["ping", "-c", "1", "-W", "1", str(ip)]
            status = subprocess.call(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if status == 0:
                with reachable_ips_lock:
                    reachable_ips.append(str(ip))
            queue_ips.task_done()

    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for ip in network.hosts():
        queue_ips.put(ip)
    queue_ips.join()

    for i in range(num_threads):
        queue_ips.put(None)
    for t in threads:
        t.join()

    return reachable_ips

def print_table(ip_list):
    if ip_list:
        table = PrettyTable([f"{Fore.GREEN}Reachable IPs{Style.RESET_ALL}"])
        for ip in ip_list:
            table.add_row([ip])
        print(table)
    else:
        print(f"{Fore.LIGHTYELLOW_EX}No reachable IP addresses found in the network.{Fore.RESET}")


def print_result_node(answered):
    t = PrettyTable([f'{Fore.GREEN}IP Address',f'Mac Address{Style.RESET_ALL}'])
    for node in answered:
        #print(node[1].show())
        #print(node[1].psrc)
        #print(node[1].hwsrc)
        t.add_row([node[1].psrc,node[1].hwsrc])    
    print(t)

target = ""
queue = Queue()
open_ports = []

def portscan(port):
    # simple code block that connect to a port and return true if the host port is up and false if if its down
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create a socket
        sock.connect((target,port)) # connet socket to the port
        return True
    except:
        return False

def get_ports(mode):
    #this funtion is used to select the which ports to scan
    if mode == 1: # scan top 1024 ports
        for port in range(1, 1024):
            queue.put(port)
    elif mode == 2:
        for port in range(1, 49152):# scan all ports
            queue.put(port)
    elif mode == 3: # scan most used ports
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 443]
        for port in ports:
            queue.put(port)
    elif mode == 4: # custom ports
        ports = input("[+] Enter your ports (seperate by blank):")
        ports = ports.split()   # split the terms by blank space 
        ports = list(map(int, ports)) # map the post into a list as type integer
        for port in ports:
            queue.put(port)

def worker():
        while not queue.empty():
            port = queue.get()
            if portscan(port):
                print("[*] Port {} is open!".format(port))
                open_ports.append(port)
            # else:
            #     print("Port {} is closed!".format(port))

def run_scanner(threads, mode):

    get_ports(mode)
    thread_list = []

    for t in range(threads):
        thread = threading.Thread(target=worker)
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()

    print("[*] Open ports are:", open_ports)
    open_ports.clear()

def port_scan_main(ipaddress):
    #these 4 line are there to check that the host is reachable or not.
    arp_request = scapy.all.ARP(pdst=ipaddress)
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_boroadcast =  broadcast/arp_request
    answered = scapy.all.srp(arp_request_boroadcast, timeout=.5, verbose=0)[0]
    if answered:
           print(f"{Fore.BLUE}[*] Host Is Up!{Style.RESET_ALL}")
           Threads = int(input("[+] Enter no of threads : "))
           t = PrettyTable([f'{Fore.GREEN}TYPE',f'Description{Style.RESET_ALL}'])
           t.add_row(["1","Select this mode to scan Ports 1 To 1024"])
           t.add_row(["2","Select This to Scan ports 1 to 49152"])
           t.add_row(["3","Select thist to scan port 20,21,22,23,25,53,80,110,443"])
           t.add_row(["4","Select this for Custom port scan"])    
           print(t)
           mode = int(input(f"{Fore.WHITE}[+] Enter Mode : {Style.RESET_ALL}"))
           global target
           target = ipaddress
           run_scanner(Threads,mode) 
    else:
            print(f"{Fore.YELLOW}[*] Host Is Down!{Style.RESET_ALL}")

def scanmain():
    print(f"{Fore.BLUE}Welcome to Network Scanner\n{Style.RESET_ALL}")

    try:
        print(f"{Fore.YELLOW}[*] If a single IP address is given, the tool will perform a port scan.")
        print(f"[*] If a single IP address is given, the tool will perform a host discovery.{Style.RESET_ALL}\n")
        while True:
            ip = input(str("[+] Please Enter Ip/Cider Address : "))
            if (is_ipv4(ip) == "Scan"):
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
                break
            elif(is_ipv4(ip) == "Port"):
                    port_scan_main(ip)
                    break
            else:
                print(f"{Fore.RED}[!] Please enter a valid ip address{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}\n[*] Redirecting to main menu...{Style.RESET_ALL}")
        sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Redirecting to main menu...{Style.RESET_ALL}")
        sleep(3)

#scapy.all.arping("192.168.29.124/16")