
from iscpy.iscpy_dns.named_importer_lib import *
import dns, datetime
import dns.resolver

def get_transfer_ip_and_delay_from_file(soa):
	root_source = 'standard_root.zone' 
	root_source_file = root_source
	try:
		with open(root_source_file, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			servers = named_data['orphan_zones']['.']['options']['masters']
			print(servers)
			dns_query = dns.message.make_query('.', 'SOA')
			for ip in servers:
				begin = datetime.datetime.now()
				res = dns.query.udp(dns_query, ip, port = 53,timeout = 2)
				end = datetime.datetime.now()
				for i in res.answer:
					for j in i.items:
						if j.serial == soa:
							return (end - begin).microseconds/1000,ip

	except Exception as e:
		print('get root_copy file size error:'+str(e))
	return 0,'0.0.0.0'

dns_query = dns.message.make_query('.', 'SOA')

print(get_transfer_ip_and_delay_from_file(20190116))

