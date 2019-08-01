

with open('file_str_trplace.txt','r+') as f:
	r = f.read()
	r = r.replace('1.1.1.1', '2.2.2.2')
	f.seek(0, 0)    
	f.write(r)
