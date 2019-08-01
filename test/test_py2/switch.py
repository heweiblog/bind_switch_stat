
def a():
	print('a')
def b(str='b'):
	print(str)
def c():
	print('c')

s = {1:a,2:b,3:c}

s[2]('sdfg')
s[1]()
s[3]()
