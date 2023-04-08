#!/bin/python
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style

'''
Tool Writeen By:
    Rahul Kumar 
'''
from MAC_Changer import macchanger
from Networkscanner import scanmain
from ARP_Spoofing import arp_spoofing_main
from Packet_Sniffer import main_sniff
from Dns_Spoofer import main_dns

def print_banner():
    banner ="""


 █████╗ ██████╗ ███╗   ███╗ ██████╗ ██████╗ ██╗   ██╗
██╔══██╗██╔══██╗████╗ ████║██╔═══██╗██╔══██╗╚██╗ ██╔╝
███████║██████╔╝██╔████╔██║██║   ██║██████╔╝ ╚████╔╝ 
██╔══██║██╔══██╗██║╚██╔╝██║██║   ██║██╔══██╗  ╚██╔╝  
██║  ██║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║   ██║   
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝                                                                                  
 
 
   """
    print(f"{Fore.LIGHTBLACK_EX}{banner}{Style.RESET_ALL}") 

def main():
    print(f"{Fore.BLUE}[***] Welcome to ARMORY [***] {Style.RESET_ALL}")
    try:
        while True:
            print_banner()
            print(f"{Fore.BLUE}[***] Please Select Your Choice [***]\n{Style.RESET_ALL}")
            print("1.  [*]  Mac Changer             [*] ")
            print("2.  [*]  Network Scanner         [*] ")
            print("3.  [*]  Arp Spoofer             [*] ")
            print("4.  [*]  Packet Sniffer          [*] ")
            print("5.  [*]  DNS Spoofer             [*] ")
            print("\n0.  [*]  To exit the program     [*] ")
            choice = input(f"{Fore.BLUE}\n[+] Please Enter Your Choice : {Style.RESET_ALL}")
            call_Mac_Changer() if choice=="1" else call_Netowork_Scanner() if choice=="2" else call_Arp_Spoofer() if choice=="3" else call_packet_sniffer() if choice=="4" else call_dns_spoofer() if choice=="5" else exit() if choice=="0" else print(f"{Fore.RED}\n[!] Please Enter valid choice{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[+] Quitting Program...{Style.RESET_ALL}")

def call_Mac_Changer():
    banner = """

███╗   ███╗ █████╗  ██████╗     ██████╗██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ███████╗██████╗ 
████╗ ████║██╔══██╗██╔════╝    ██╔════╝██║  ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝██╔══██╗
██╔████╔██║███████║██║         ██║     ███████║███████║██╔██╗ ██║██║  ███╗█████╗  ██████╔╝
██║╚██╔╝██║██╔══██║██║         ██║     ██╔══██║██╔══██║██║╚██╗██║██║   ██║██╔══╝  ██╔══██╗
██║ ╚═╝ ██║██║  ██║╚██████╗    ╚██████╗██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
                                                                                        
	"""
    print(f"{Fore.LIGHTBLACK_EX}{banner}{Style.RESET_ALL}")
    macchanger()

def call_Netowork_Scanner():
    banner = """

███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝                                                       
 

    """
    print(f"{Fore.GREEN}{banner}{Style.RESET_ALL}")
    scanmain()

def call_Arp_Spoofer():
    banner = '''
    
 █████╗ ██████╗ ██████╗     ███████╗██████╗  ██████╗  ██████╗ ███████╗███████╗██████╗ 
██╔══██╗██╔══██╗██╔══██╗    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗
███████║██████╔╝██████╔╝    ███████╗██████╔╝██║   ██║██║   ██║█████╗  █████╗  ██████╔╝
██╔══██║██╔══██╗██╔═══╝     ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██╔══██╗
██║  ██║██║  ██║██║         ███████║██║     ╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝         ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝
                                                                                          
    '''

    print(f"{Fore.BLUE}{banner}{Style.RESET_ALL}")
    arp_spoofing_main()        

def call_packet_sniffer():
    banner = '''

██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗    ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
██████╔╝███████║██║     █████╔╝ █████╗     ██║       ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║       ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║       ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
                                                                                                          
    '''
    print(f"{Fore.GREEN}{banner}{Style.RESET_ALL}")
    main_sniff()
    
def call_dns_spoofer():
    banner = '''
██████╗ ███╗   ██╗███████╗    ███████╗██████╗  ██████╗  ██████╗ ███████╗███████╗██████╗ 
██╔══██╗████╗  ██║██╔════╝    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗
██║  ██║██╔██╗ ██║███████╗    ███████╗██████╔╝██║   ██║██║   ██║█████╗  █████╗  ██████╔╝
██║  ██║██║╚██╗██║╚════██║    ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██╔══██╗
██████╔╝██║ ╚████║███████║    ███████║██║     ╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║
╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝
                                                                                 
    '''
    print(f"{Fore.GREEN}{banner}{Style.RESET_ALL}")
    main_dns()

if __name__ == "__main__":
    main()
