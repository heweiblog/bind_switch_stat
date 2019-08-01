# _*_ coding: utf-8 _*_

import json

data = {
	"operator": "ct",
	"vendor" : "xx",
	"timestamp" : "20190705",
	"data" : {
		"id" : 1,
		"age" : 18,
		"city" : "shanghai",
		"top" : ["com","cn"]
	}
}

print(type(data))
print(data)

with open('data.json', 'w') as f:
	json.dump(data, f, sort_keys=True, indent=4, separators=(',', ': '))

with open("data.json",'r') as f:
	d = json.load(f)
	print(type(d),type(d['data']['age']))
	print(d)
