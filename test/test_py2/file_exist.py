

try:
	with open('ddd','r') as f:
		l = f.readlines()
		for i in range(len(l)):
			print(l[i])
except Exception as e:
	print(str(e))
