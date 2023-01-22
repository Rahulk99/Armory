# Python Script to change MAC Address

from colorama import init as colorama_init
from colorama import Fore
from colorama import Style


# Import Useful modules
import sys
import subprocess
import random
import time
import re
import psutil
from prettytable import PrettyTable
# Function to get the interface name

# Function to get the current MAC Address
# We will use it restore MAC address
# in case something goes wrong.
def get_current_mac(interface):
	try:
		output = subprocess.check_output(["ifconfig",interface])
		return re.search("\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",str(output)).group(0)
	except:
		pass

def get_current_ip(interface):
		output = subprocess.check_output(["ifconfig",interface])
		pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
		output1 = output.decode()
		ip = pattern.search(output1)[0]
		return ip

def restore():
		# Restore the MAC before quitting.
		print(f"{Fore.RED}[!] Resetting Configurations.{Style.RESET_ALL}")
		print(f"{Fore.RED}[!] Redirecting to main menu Program...{Style.RESET_ALL}")
		time.sleep(3)

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
		elif mac:
			t.add_row([k,mac,f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
		elif ip:
			t.add_row([k,f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}",ip])
	
	print(t)

def get_arguments():
	#show ip table
	ip_table()
	addrs = psutil.net_if_addrs()
	name = []
	for k in addrs.items():
		name.append(k[0])
	# We need the interface name
	interface = input("\n[+] Name of the interface /-- For more details refer ip table : ")
    # Check if interface was given
	if interface in name:
		return interface
	else:
		print(f"{Fore.RED}[!] Invalid Syntax. {Style.RESET_ALL}")


# Function to change the MAC Address
def change_mac(interface, new_mac_address):
	# As explained above, these lines will
	# execute these commands for us
	try:
		subprocess.call(["sudo", "ifconfig", interface,"down"])
		subprocess.call(["sudo", "ifconfig", interface,"hw", "ether", new_mac_address])
		subprocess.call(["sudo", "ifconfig", interface,"up"])
	except Exception:
		pass

# Function to generate a random MAC Address
def get_random_mac_address():
	characters = "0123456789abcdef"
	random_mac_address = "00"
	for i in range(5):
		random_mac_address += ":" + \
			 random.choice(characters) \
				 + random.choice(characters)
	return random_mac_address



# Driver Program
def macchanger():	
	print(f"{Fore.BLUE}Welcome to Mac changer\n{Style.RESET_ALL}")
	try:
		interface = get_arguments()
		current_mac = get_current_mac(interface)
		random_mac = get_random_mac_address()
		change_mac(interface, random_mac)
		try:
			new_mac_summary = subprocess.check_output(["ifconfig", interface])
			if random_mac in str(new_mac_summary):
				print("\n")
				print("\r[*] MAC Address Changed from ",f"{Fore.YELLOW}{current_mac}{Style.RESET_ALL}"," to ",f"{Fore.YELLOW}{random_mac}{Style.RESET_ALL}",end=" ")
				print("\n")
				extra = input("[+] Do you want to print the IP Table : Y?N : ")
				if(extra=="y" or extra=="Y"):
					ip_table()
				sys.stdout.flush()
				print("\n")
		except:
			restore()
			# Wait for a constant period of time
		else:
			print(f"{Fore.YELLOW}\n[*] Redirecting to main menu...{Style.RESET_ALL}")
			time.sleep(3)
	except KeyboardInterrupt:
		restore()