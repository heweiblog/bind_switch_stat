# -*- coding: utf-8 -*-

import re, json

STAT_FILE = '/var/named/data/named_stats.txt'
#STAT_FILE = '/home/heweiwei/kit/bind_stats/named_stats.txt'
#TMP_FILE = '/tmp/named.txt'

'''
root_resove_data = {
	'operator': 'ct',
	'vendor' : 'yamu',
	#"timestamp" : "20190705", #上传时间or生成文件时间
	"data" : {
		#'id' #从配置文件获取
		#'server-id' #配置文件获取
		#'begin-date' #开始统计时间
		#'end-date' #结束统计时间
		#'qps' #5 min 内qps
		#'update-date' #更新时间 eg'2019-0706 15:22:22'
		'delay':5,
		#'resolution-count' #5 min 解析量
		#'response-success-rate' # 响应成功率 eg'97%'
		#'resolution-success-rate' #解析成功率
		#'top10' # eg ['com,'net','cn','org','gov','edu','top','mil','vip','int']
	}
}

root_run_data = {
	'operator': 'ct',
	'vendor' : 'yamu',
	#"timestamp" : "20190705", #上传时间or生成文件时间
	"data" : {
		#'id' #从配置文件获取
		#'server-id' #配置文件获取
		#'ip' #副本服务对信通院/ICANN下载根区时所用的IP
		#'source' #更新来源IP地址 即根指向ip
		#'update-date' #更新时间 eg'2019-0706 15:22:22'
		#'result' #成功 or 失败 
		#'size' # 副本文件大小
		#'soa' # 更新SOA
		'delay':10,
	}
}

recursion_resove_data = {
	'operator': 'ct',
	'vendor' : 'yamu',
	#"timestamp" : "20190705", #上传时间or生成文件时间
	"data" : {
		#'id' #从配置文件获取
		#'server-id' #配置文件获取
		#'begin-date' #开始统计时间
		#'end-date' #结束统计时间
		#'qps' #5 min 内qps
		#'update-date' #更新时间 eg'2019-0706 15:22:22'
		'delay':5,
		#'resolution-count-v4' #5 min ipv4 解析量
		#'resolution-count-v6' #5 min ipv6 解析量
		#'response-success-rate' # 响应成功率 eg'97%'
		#'resolution-success-rate' #解析成功率
		#'query-7706-count' #计算递归服务查询根区副本的查询次数（实施了根区副本的递归，通过根区副本日志计算递归查询次数）
		#'query-7706-delay' #计算递归服务查询根区副本的查询时间（实施了根区副本的递归，通过根区副本日志计算递归查询平均时延）
		#'query-root-count' #eg ['a':12,'f':25...]
		#'query-root-delay' #eg ['e':1000,'a':2000...]
	}
}
'''

def get_stat_data():
	try:
		with open(STAT_FILE,'r') as f:
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
					else:
						d = {}
						d[category] = int(value)
						data[sub] = d
			return data
	except:
		return None


data = get_stat_data()
print(data)

#with open('data.json', 'w') as f:
	#json.dump(data, f, sort_keys=True, indent=4, separators=(',', ': '))
