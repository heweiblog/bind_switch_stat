import threading
import time

def hello(name,cname):
	print (name,cname)
'''
	global timer
	timer = threading.Timer(2.0, hello, ["Hawk"])
	timer.start()
'''
if __name__ == "__main__":
	timer = threading.Timer(2.0, hello, ("Hawk","dsfg"))
	timer.start()
