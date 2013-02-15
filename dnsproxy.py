#!/usr/bin/env python
# coding: utf-8
from SocketServer import BaseRequestHandler, ThreadingUDPServer
from cStringIO import StringIO
import os
import socket
import struct
import time
import logging
import fnmatch

'''
Copyright 2013 NotZappy <NotZappy@gmail.com>
Original program Copyright 2011 marlonyao <yaolei135@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

def main():
	import optparse, sys
	parser = optparse.OptionParser()
	parser.add_option('-f', '--hosts-file', dest='hosts_file', metavar='<file>', default='/etc/hosts', help='specify hosts file (default /etc/hosts)')
	parser.add_option('-H', '--host', dest='host', default='127.0.0.1', help='specify the address to listen on (default 127.0.0.1)')
	parser.add_option('-p', '--port', dest='port', default=53, type='int', help='specify the port to listen on (default 53)')
	parser.add_option('-s', '--server', dest='dns_server', metavar='<server>', help='specify the delegating dns server (required)')
	parser.add_option('-C', '--no-cache', dest='disable_cache', default=False, action='store_true', help='disable dns cache (default false)')
	parser.add_option('-l', '--log-level', dest='log_level', default=20, type='int', metavar='<level>', help='set the log level (10: debug, 20: info/default, 30: warning)')

	opts, args = parser.parse_args()
	if not opts.dns_server:
		parser.print_help()
		sys.exit(1)

	print 'dnsproxy  Copyright (C) 2013  NotZappy <NotZappy@gmail.com>'
	print ''
	print 'This program comes without ANY warranty.'
	print 'This is free software, and you are welcome to redistribute it under certain conditions.'
	print 'See the GNU General Public License v3.0 for details.'
	print ''

	logging.basicConfig(format='%(asctime)-15s  %(levelname)-10s  %(message)s', level = opts.log_level)
	logging.info('Hosts file:  ' + opts.hosts_file)
	logging.info('Host:        ' + opts.host)
	logging.info('Port:        ' + str(opts.port))
	logging.info('DNS Server:  ' + opts.dns_server)
	logging.info('Cache:       ' + ('disabled' if opts.disable_cache else 'enabled'))
	logging.info('Log level:   ' + logging.getLevelName(opts.log_level))

	dnsserver = DNSProxyServer(opts.dns_server, disable_cache=opts.disable_cache, host=opts.host, port=opts.port, hosts_file=opts.hosts_file)
	dnsserver.serve_forever()

class Struct(object):
	def __init__(self, **kwargs):
		for name, value in kwargs.items():
			setattr(self, name, value)

def parse_dns_message(data):
	message = StringIO(data)
	message.seek(4) # skip id, flag
	c_qd, c_an, c_ns, c_ar = struct.unpack('!4H', message.read(8))
	# parse question
	question = parse_dns_question(message)
	for i in range(1, c_qd): # skip other question
		parse_dns_question(message)
	records = []
	for i in range(c_an+c_ns+c_ar):
		records.append(parse_dns_record(message))
	return Struct(question=question, records=records)

def parse_dns_question(message):
	qname = parse_domain_name(message)
	qtype, qclass = struct.unpack('!HH', message.read(4))
	end_offset = message.tell()
	return Struct(name=qname, type_=qtype, class_=qclass, end_offset=end_offset)

def parse_dns_record(message):
	logging.debug('Parsing DNS record: 0x' + str(message).encode('hex'))

	r_domain_name = parse_domain_name(message)
	logging.debug(' domain name: ' + r_domain_name)

	r_type = struct.unpack('>h', message.read(2))[0]
	r_class = struct.unpack('>h', message.read(2))[0]
	logging.debug(' type: ' + str(r_type) + (' (A)' if r_type == DNS_TYPE_A else ' (AAAA)' if r_type == DNS_TYPE_AAAA else ''))
	logging.debug(' class: ' + str(r_class))

	ttl_offset = message.tell()
	ttl = struct.unpack('!I', message.read(4))[0]
	logging.debug(' TTL: ' + str(ttl))

	rd_len = struct.unpack('!H', message.read(2))[0]
	logging.debug(' RD length: ' + str(rd_len))

	rd = message.read(rd_len)
	logging.debug(' RDATA: ' + str(rd).encode('hex'))
	if r_type in (DNS_TYPE_A, DNS_TYPE_AAAA):
		logging.debug(' IP' + ('v4' if r_type == DNS_TYPE_A else 'v6') +': ' + addr_n2p(rd))
	return Struct(ttl_offset=ttl_offset, ttl=ttl, domain_name=r_domain_name, type_=r_type, class_=r_class, rd=rd)

def _parse_domain_labels(message):
	labels = []
	len = ord(message.read(1))
	while len > 0:
		if len >= 64: # domain name compression
			len = len & 0x3f
			offset = (len << 8) + ord(message.read(1))
			mesg = StringIO(message.getvalue())
			mesg.seek(offset)
			labels.extend(_parse_domain_labels(mesg))
			return labels
		else:
			labels.append(message.read(len))
			len = ord(message.read(1))
	return labels

def parse_domain_name(message):
	return '.'.join(_parse_domain_labels(message))

def dns_message2log(m, flag = 3):
	# convert a DNS message m parsed by parse_dns_message into a neat text info (logging.info)
	# flag: bitflag for question (0x1) and response (0x2), defaults to 3 (== return both question and response)
	if flag & 1:
		logging.info('Question: name "' + m.question.name + '", type ' + str(m.question.type_) + ', class ' + str(m.question.class_))
	if flag & 2 and len(m.records) > 0:
		c = 1
		for r in m.records:
			ttext = 'Record ' + str(c) + ': domain_name "' + r.domain_name + '", type ' + str(r.type_) + ', class ' + str(r.class_) + ', TTL ' + str(r.ttl) + 's, '
			if r.type_ in (DNS_TYPE_A, DNS_TYPE_AAAA):
				ttext += 'IP' + ('v4' if r.type_ == DNS_TYPE_A else 'v6') +': ' + addr_n2p(r.rd)
			else:
				ttext += 'RD 0x' + str(r.rd).encode('hex')
			logging.info(ttext)
			c += 1
	return None

def addr_p2n(addr):
	try:
		return socket.inet_pton(socket.AF_INET, addr)
	except:
		return socket.inet_pton(socket.AF_INET6, addr)

def addr_n2p(addr):
	try:
		return socket.inet_ntop(socket.AF_INET, addr)
	except:
		return socket.inet_ntop(socket.AF_INET6, addr)

DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
DNS_CLASS_IN = 1

class DNSProxyHandler(BaseRequestHandler):
	def handle(self):
		reqdata, sock = self.request
		req = parse_dns_message(reqdata)
		q = req.question
		dns_message2log(req, 1)
		if q.type_ in (DNS_TYPE_A, DNS_TYPE_AAAA) and (q.class_ == DNS_CLASS_IN):
			for packed_ip, host in self.server.host_lines:
				if fnmatch.fnmatch(q.name, host):
					logging.info(q.name + ' matches ' + host + ', returning ' + addr_n2p(packed_ip))
					# header, qd=1, an=1, ns=0, ar=0
					rspdata = reqdata[:2] + '\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
					rspdata += reqdata[12:q.end_offset]
					# answer
					rspdata += '\xc0\x0c' # pointer to domain name
					# type, 1 for ip4, 28 for ip6
					if len(packed_ip) == 4:
						rspdata += '\x00\x01' # 1 for ip4
					else:
						rspdata += '\x00\x1c' # 28 for ip6
					# class: 1, ttl: 2000(0x000007d0)
					rspdata += '\x00\x01\x00\x00\x07\xd0'
					rspdata += '\x00' + chr(len(packed_ip)) # rd_len
					rspdata += packed_ip
					sock.sendto(rspdata, self.client_address)
					return

		# lookup cache
		if not self.server.disable_cache:
			cache = self.server.cache
			cache_key = (q.name, q.type_, q.class_)
			cache_entry = cache.get(cache_key)
			if cache_entry:
				logging.info('Found (' + q.name + ', ' + str(q.type_) + ', ' + str(q.class_) + ') in cache.')
				rspdata = update_ttl(reqdata, cache_entry)
				if rspdata:
					sock.sendto(rspdata, self.client_address)
					return

		logging.info('Not in cache (or TTL expired), requesting DNS record(s) from ' + self.server.dns_server)
		rspdata = self._get_response(reqdata)
		rsp = parse_dns_message(rspdata)
		dns_message2log(rsp, 2)
		if not self.server.disable_cache:
			logging.debug('Adding record to the cache: ' + str([rspdata, time.time()]))
			cache[cache_key] = Struct(rspdata=rspdata, cache_time=int(time.time()))
		sock.sendto(rspdata, self.client_address)

	def _get_response(self, data):
		#TODO: error handling
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # socket for the remote DNS server
		sock.connect((self.server.dns_server, 53))
		sock.sendall(data)
		sock.settimeout(60)
		rspdata = sock.recv(65535)
		sock.close()
		return rspdata

def update_ttl(reqdata, cache_entry):
	rspdata, cache_time = cache_entry.rspdata, cache_entry.cache_time
	rspbytes = bytearray(rspdata)
	rspbytes[:2] = reqdata[:2] # update id
	current_time = int(time.time())
	time_interval = current_time - cache_time
	rsp = parse_dns_message(rspdata)
	for record in rsp.records:
		if record.ttl <= time_interval:
			return None
		rspbytes[record.ttl_offset:record.ttl_offset+4] = struct.pack('!I', record.ttl-time_interval)
	return str(rspbytes)

def load_hosts(hosts_file):
	logging.info('Loading hosts config.')
	def wildcard_line(line):
		line = line.strip()
		if line == '': return False # empty line (or only whitespaces)
		if line.startswith('#'): return False # comment line
		if '#' in line: line = line[:line.index('#')].strip() # inline comments
		logging.debug('Parsing hosts entry: ' + line)
		parts = line.strip().split()
		if len(parts) < 2:
			logging.warning('Invalid hosts entry: ' + line)
			return False
		ip = parts[0]
		try:
			packed_ip = addr_p2n(ip)
		except:
			logging.warning('Invalid IP in line: ' + line)
			return False
		logging.debug('IP: ' + parts[0])
		parts.pop(0)
		hostname_errors = 0
		for hostname in parts:
			logging.debug('Host: ' + hostname)
			try:
				logging.info('Appending to hostlines: ' + str([packed_ip, hostname]))
				hostlines.append([packed_ip, hostname])
			except:
				logging.warning('Appending the hostname ' + hostname + ' failed (line: ' + line + ')')
				hostname_errors += 1
				continue
		if hostname_errors == 0:
			return True
		else:
			return None

	with open(hosts_file) as hosts_in:
		hostlines = []
		for line in hosts_in:
			hostline = wildcard_line(line)
		logging.debug('Hostlines: ' + str(len(hostlines)))
		for line in hostlines:
			logging.debug(line)
		return hostlines

class DNSProxyServer(ThreadingUDPServer):
	def __init__(self, dns_server, disable_cache=False, host='127.0.0.1', port=53, hosts_file='/etc/hosts'):
		self.dns_server = dns_server
		self.hosts_file = hosts_file
		self.host_lines = load_hosts(hosts_file)
		self.disable_cache = disable_cache
		self.cache = {}
		ThreadingUDPServer.__init__(self, (host, port), DNSProxyHandler)

if __name__ == '__main__':
	main()
