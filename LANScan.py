# LANScan V1 written by Th3Tr1ckst3r.
import sys
import requests
from scapy.all import ARP, Ether, srp


help_msg = """Invalid local IP entered.\n\nIf you would like to find all devices in the network, you would enter something like:\n\n192.168.0.1/24"""


def mac(mac_address):
	try:
		request = requests.get("http://macvendors.co/api/" + mac_address, headers={'user-agent' : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"}) 
		obj = request.json()
		return obj
	except KeyboardInterrupt:
		sys.exit()


def scan(target_ip):
	try:
		clients = []
		arp = ARP(pdst=target_ip)
		ether = Ether(dst="ff:ff:ff:ff:ff:ff")
		packet = ether/arp
		result = srp(packet, timeout=3, verbose=0)[0]
		for sent, received in result:
			lookup = mac(received.hwsrc)
			if lookup == {'result': {'error': 'no result'}}:
				vendor = "Unknown."
				result = "IPv4: {}, Mac Address: {}, Vendor: {}".format(received.psrc, received.hwsrc, vendor)
				clients.append(result)
			elif lookup['result'] == {'error': 'no result'}:
				vendor = "Unknown."
				result = "IPv4: {}, Mac Address: {}, Vendor: {}".format(received.psrc, received.hwsrc, vendor)
				clients.append(result)
			else:
				vendor = lookup['result']['company']
				result = "IPv4: {}, Mac Address: {}, Vendor: {}".format(received.psrc, received.hwsrc, vendor)
				clients.append(result)
		return clients
	except KeyboardInterrupt:
		sys.exit(1)
	except IndexError:
		print(help_msg)
		sys.exit(1)


def main(ip):
	try:
		print('Processing requests...\n')
		if ip == '':
			print(help_msg)
			sys.exit(1)
		results = scan(ip)
		print("Available devices on {}:\n".format(ip))
		for x in results:
			print(x)
	except KeyboardInterrupt:
		sys.exit(1)
	except IndexError:
		print(help_msg)
		sys.exit(1)


if __name__ == "__main__":
	try:
		main(sys.argv[1])
		sys.exit(1)
	except IndexError:
		print(help_msg)
		sys.exit(1)
