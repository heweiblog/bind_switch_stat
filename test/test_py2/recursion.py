

import subprocess

def get_root_stat():
	
	dnstap_file = 'example.dnstap'
	target_file = 'zone.txt' #'/tmp/zone.txt'
	root_ip_list = [
		'202.12.27.33',
		'2001:dc3::35',
		'199.9.14.201',
		'2001:500:200::b',
		'192.33.4.12',
		'2001:500:2::c',
		'199.7.91.13',
		'2001:500:2d::d',
		'192.203.230.10',
		'2001:500:a8::e',
		'192.5.5.241',
		'2001:500:2f::f',
		'192.112.36.4',
		'2001:500:12::d0d',
		'198.97.190.53',
		'2001:500:1::53',
		'198.41.0.4',
		'2001:503:ba3e::2:30',
		'192.36.148.17',
		'2001:7fe::53',
		'192.58.128.30',
		'2001:503:c27::2:30',
		'193.0.14.129',
		'2001:7fd::1',
		'199.7.83.42',
		'2001:500:9f::42'
	]

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
		'l': ['199.7.83.42','2001:500:9f::42']
	}

	root_stat = {'a':0, 'b':0, 'c':0, 'd':0, 'e':0, 'f':0, 'g':0, 'h':0, 'i':0, 'j':0, 'k':0, 'l':0, 'm':0}

	try:
		with open(target_file,'w') as f:
			subprocess.check_call(['dnstap-read',dnstap_file],stdout=f, cwd = '.')
	except subprocess.CalledProcessError:
		print('[%d] do dnstap-read error!' % os.getpid())
		return root_stat,0 

	root,request,respond = {},{},{}

	try:
		with open(target_file) as f:
 			line = f.readlines()
			for s in line:
				l = s.split(' ')
				if '->' in l:
					k = l[3]+l[5]+l[-1]
					request[k] = int(1000*float(l[1].split(':')[-1]))

				if '<-' in l:
					k = l[3]+l[5]+l[-1]
					if k not in respond:
						respond[k] = int(1000*float(l[1].split(':')[-1]))
					domain = l[5].split(':53')[0]
					if domain in root_ip_list:
						if domain in root:
							root[domain] += 1
						else:
							root[domain] = 1

		for k in root_list:
			for ip in root_list[k]:
				if ip in root:
					root_stat[k] += root[ip]
				
		total,count,avg_delay = 0,0,0 
		for k in respond:
			if k in request:
				delay = respond[k] - request[k]
				if delay < 0:
					delay = 60000 - request[k] + respond[k]
				count += 1
				total += delay

		if count != 0:
			avg_delay = total/count
	
		return root_stat,avg_delay

	except Exception as e:
		print(e)
		return root_stat,0


print(get_root_stat())
