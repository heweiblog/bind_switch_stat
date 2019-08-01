import dns,dns.resolver

try:
	dns_query = dns.message.make_query('.', 'SOA')
	res = dns.query.udp(dns_query, '127.0.0.1', port = 53,timeout = 2)
	for i in res.answer:
		for j in i.items:
			print(j.serial)
except Exception as e:
	print('get transfer ip and delay from swotch_root.zone error:'+str(e))
