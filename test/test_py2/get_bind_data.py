import multiprocessing, subprocess, time ,datetime, re

def get_stat_data():
	stat_file = '/var/named/data/named_stats.txt'
	#stat_file = '/home/heweiwei/kit/bind_stats/named_stats.txt'
	try:
		with open(stat_file,'r') as f:
			data = {}
			for line in f:
				if re.match('\+\+\+ ', line):
					match_time = re.search('[0-9]+', line)
					if match_time:
						time = match_time.group()
					else:
						time = 0
				elif re.match('--- ', line):
					pass
				elif re.match('\+\+ ', line):
					sub = re.sub(' ?\+\+ ?', '', line)
					sub = re.sub('[\(|\)|\<|/]', '-', sub)
					sub = sub.replace('\n', '').replace(' ', '-')
				elif re.match('\[', line):
					subsub = line.replace('\n', '').replace(' ', '-')
				else:
					match_value = re.search('[0-9]+', line)
					if match_value:
						value = match_value.group()
					else:
						value = 0
					category = re.sub(' +[0-9]+ ', '', line)
					category = re.sub('[\(|\)|\<|/]', '-', category)
					category = re.sub('\!', 'no-', category)
					category = category.replace('\n', '').replace(' ', '-')
					if sub in data:
						data[sub][category] = int(value)
						#data[sub][category] = value
					else:
						d = {}
						d[category] = int(value)
						#d[category] = value
						data[sub] = d
			return data
	except:
		return None


def upload_recursion_data():
	pass


def get_query(begin_data,end_data):
	if begin_data == None or end_data == None:
		print('[%d] get stat data error!' % os.getpid())
		return 0
	
def get_query(begin_data,end_data):
	if begin_data == None or end_data == None:
		print('[%d] get stat data error!' % os.getpid())
		return 0
	
	if 'QUERY' in begin_data and 'QUERY' in end_data:
		return end_data['QUERY'] - begin_data['QUERY']

	return 0

def get_answer(begin_data,end_data):
	if begin_data == None or end_data == None:
		print('[%d] get stat data error!' % os.getpid())
		return 0

	begin_answer = 0
	begin_noerror = 0
	for k in begin_data:
		if k == 'NOERROR':
			begin_noerror = begin_data[k]
		begin_answer = begin_answer + begin_data[k]

	end_answer = 0
	end_noerror = 0
	for k in end_data:
		if k == 'NOERROR':
			end_noerror = end_data[k]
		end_answer = end_answer + end_data[k]
	
	return end_answer - begin_answer,end_noerror - begin_noerror

def get_stat_file():
	home, rndc, stat_file = '/etc','rndc','/var/named/data/named_stats.txt'

	try:
		subprocess.check_call(['rm', '-rf', stat_file], cwd = home)
	except subprocess.CalledProcessError:
		print('[%d] do rndc stats error!' % os.getpid())
		return False

	try:
		subprocess.check_call([rndc, 'stats'], cwd = home)
	except subprocess.CalledProcessError:
		print('[%d] do rndc stats error!' % os.getpid())
		return False

	return True

def upload_root_data():
	operator, vendor, node_id, server_id = 'ct','yamu','nan01','sh01'

	if get_stat_file() == False:
		print('[%d] gennerate stat file error!' % os.getpid())
		return
	time.sleep(10)
	begin_data = get_stat_data()
	print(begin_data)
	if get_stat_file() == False:
		print('[%d] gennerate stat file error!' % os.getpid())
		return
	end_data = get_stat_data()
	print(end_data)

	querys = 0
	if 'Incoming-Requests' in begin_data and 'Incoming-Requests' in end_data:
		if 'QUERY' in begin_data['Incoming-Requests'] and 'QUERY' in end_data['Incoming-Requests']:
			querys = end_data['Incoming-Requests']['QUERY'] - begin_data['Incoming-Requests']['QUERY']

	respond,noerror = get_answer(begin_data['Outgoing-Rcodes'],end_data['Outgoing-Rcodes'])
	print(querys,respond,noerror)

	root_resove_data = {
		'operator': operator,
		'vendor' : vendor,
		"timestamp" : time.strftime('%Y-%m-%d %H:%M:%S'),
		"data" : {
			'id': node_id,
			'server-id': server_id,
			'begin-date': (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'), 
			'end-date': time.strftime('%Y-%m-%d %H:%M:%S'),
			'qps': querys/10,
			'update-date': time.strftime('%Y-%m-%d %H:%M:%S'),
			'delay':5,
			'resolution-count': respond,
			'response-success-rate': '100%' if querys == 0 else str(respond*100/querys)+'%',
			'resolution-success-rate': '100%' if querys == 0 else str(noerror*100/querys)+'%',
			'top10': ['com','net','cn','org','gov','edu','top','mil','vip','int']
		}
	}

	print(root_resove_data)

upload_root_data()
#print(get_stat_data())
