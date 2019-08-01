

import subprocess

def get_top10_and_delay():
	
	dnstap_file = 'example.dnstap'
	target_file = 'zone.txt' #'/tmp/zone.txt'
	try:
		with open(target_file,'w') as f:
			subprocess.check_call(['dnstap-read',dnstap_file],stdout=f, cwd = '.')
	except subprocess.CalledProcessError:
		print('[%d] do dnstap-read error!' % os.getpid())
		return [],0 

	top,request,respond = {},{},{}

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
					domain = l[-1].split('/')[0].split('.')[-1]
					#domain = s.split('/')[0].split('.')[-1]
					if domain in top:
						top[domain] += 1
					else:
						top[domain] = 1
	except Exception as e:
		print(e)
		return [],0
	
	vals = top.values()
	vals.sort(reverse = True)

	if len(vals) > 10:
		vals = vals[:10]
	
	new_vals = []
	for i in vals:
		if i not in new_vals:
			new_vals.append(i)
	
	top10 = []
	for val in new_vals:
		k = [k for k, v in top.items() if v == val]
		for s in k:
			top10.append(s)

	total,count = 0,0
	for k in respond:
		if k in request:
			delay = respond[k] - request[k]
			if delay < 0:
				delay = 60000 - request[k] + respond[k]
			count += 1
			total += delay
	return top10,total/count

top10,delay = get_top10_and_delay()


print(top10,delay)
