
import gzip, json, codecs,datetime,time

def write_gz():
	root_resove_data = {
		'operator': 'vt',
		'vendor' : 'yamu',
		"timestamp" : time.strftime('%Y-%m-%d %H:%M:%S'),
		"data" : {
			'id': '0001',
			'server-id': '0002',
			'begin-date': (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'), 
			'end-date': time.strftime('%Y-%m-%d %H:%M:%S'),
			'qps': 3000/300,
			'update-date': time.strftime('%Y-%m-%d %H:%M:%S'),
			'delay': 0.033,
			'resolution-count': 3000,
			'response-success-rate': '100%',
			'resolution-success-rate': '100%',
			'top10': ['com','top']
		}
	}
	
	print(root_resove_data)

	#data = json.dump(root_resove_data, sort_keys=True, indent=4, separators=(',', ': '))
	#data = json.dumps(root_resove_data)
	#print(data)

	with gzip.open("json.gz", "wb") as fp:
	#fp.write(data)
		data = json.dump(root_resove_data, fp, sort_keys=True, indent=4, separators=(',', ': '))
	
	fd0 = gzip.open('json.gz', 'rb')
	fd = codecs.getreader("utf-8")(fd0)
	data = fd.readline()
	print(data)
	
write_gz()
