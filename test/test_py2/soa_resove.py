

import dns.resolver

def getipaddr():
	A = dns.resolver.query('.','SOA')
	for i in A.response.answer:
		for j in i.items:
			print(type(j))
			print(type(j.serial),j.serial)
			print(j)


#getipaddr()
'''
my_resolver = dns.resolver.Resolver()
my_resolver.nameservers = ['198.41.0.4']
try:
	res = my_resolver.query('com.','SOA')
	for i in res.response.answer:
		for j in i.items:
			print(type(j))
			#print(type(j.serial),j.serial)
			print(j)
except Exception as e:
	print("dns resolver error:" + str(e))
	exit(0)
'''

'''
res = dns.resolver.Resolver()
res.nameservers = ['198.41.0.4']

answers = res.query('.','SOA')
retval = []
for d in answers:
	print(d)
'''

import dns,datetime
root_list = { 
        'm': ['202.12.27.33','2001:dc3::35'],
        'b': ['199.9.14.201','2001:500:200::b'],
        'c': ['192.33.4.12','2001:500:2::c'],
        'd': ['199.7.91.13','2001:500:2d::d'],
        'e': ['192.203.230.10','2001:500:a8::e'],
        'f': ['192.5.5.241','2001:500:2f::f'],
        'g': ['192.112.36.4','2001:500:12::d0d'],
        'h': ['198.97.190.53','2001:500:1::53'],
        'a': ['198.41.0.4','2001:503:ba3e::2:30'],
        'i': ['192.36.148.17','2001:7fe::53'],
        'j': ['192.58.128.30','2001:503:c27::2:30'],
        'k': ['193.0.14.129','2001:7fd::1'],
        'l': ['199.7.83.142','2001:500:9f::42'],
}  
PORT = 53#DNS server port 
dns_query = dns.message.make_query("com", "A")

for k in root_list:
    try:
        a = datetime.datetime.now()
        response = dns.query.udp(dns_query, root_list[k][0], port = PORT, timeout = 3)
        print(type(response))
        #print(response)
        b = datetime.datetime.now()
        c = b-a
        print(c)
        print(c.microseconds/1000)
        for i in response.answer:
            #print i.to_text()
			pass
    except Exception as e:
        print(e)
