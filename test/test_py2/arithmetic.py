#!/usr/bin/python

import time,hashlib,random,string,base64,zlib,osa,sys,argparse
from ConfigParser import ConfigParser, NoSectionError, NoOptionError

# generate dns id
sequence = 0
sequence += 1
dnsId = time.strftime('%Y%m%d', time.localtime()) + ('%03d' % (sequence % 1000)) + '33300001'
print('gengnerate DNSID',dnsId)

gPwd = '1234567890abcDEF'
gAESKey = '1234567890abcDEF'
gAESIV = '1234567890abcDEF'


randVal = ''.join(random.sample(string.letters, 20))


hashed_pwd = gPwd + randVal
pwdHash = base64.b64encode(hashed_pwd)
print('source code',hashed_pwd,pwdHash)

hashed_pwd = hashlib.md5(gPwd + randVal).hexdigest()
pwdHash = base64.b64encode(hashed_pwd)
print('md5',hashed_pwd,pwdHash)

hashed_pwd = hashlib.sha1(gPwd + randVal).hexdigest()
pwdHash = base64.b64encode(hashed_pwd)
print('sha',hashed_pwd,pwdHash)

result = '<p>ok</p>'
_compressed_result = zlib.compress(result)
print('ok compressed_result',_compressed_result)

from Crypto.Cipher import AES

pads = (AES.block_size - (len(_compressed_result) % AES.block_size))
padding = chr(pads) * pads
_encrypted_result = AES.new(gAESKey, AES.MODE_CBC, gAESIV).encrypt(_compressed_result + padding)

result = base64.b64encode(_encrypted_result)
_hashed_result = hashlib.md5(_compressed_result + gPwd).hexdigest()
print('_hashed_result md5',_hashed_result)
_hashed_result = hashlib.sha1(_compressed_result + gPwd).hexdigest()
print('_hashed_result sha1',_hashed_result)

resultHash = base64.b64encode(_hashed_result)
print('resultHash',resultHash)

ackhost,ackport = '127.0.0.1',1024
print('http://%s:%d/DNSWebService/dnsCommandAck?wsdl' % (ackhost, ackport))
commandVersion = 'v0.1'
print({'dnsID':dnsId,'randVal':randVal,'pwdHash':pwdHash,'result':result,'resultHash':resultHash,'commandVersion':commandVersion})

import lxml.etree
ele = lxml.etree.fromstring('<p>0</p>'.encode('utf-8'))
print(ele)

def xmlget(root, xpath):
	lst = root.xpath(xpath)
	if lst and lst[0].text:
		return lst[0].text
	return None

#print(int(xmlget(ele, 'resultCode')))

def gen_command_result(rcode):
	lookaside = {
		0 : 'Done', 
		1 : 'De-cryption error', 
		2 : 'Certification error', 
		3 : 'De-compression error', 
		4 : 'Invalid type', 
		5 : 'Malformed content', 
		900 : 'Other error, try again'
	}

	xml = u'''<?xml version="1.0" encoding="UTF-8"?>
<return>
	<resultCode>%d</resultCode>
	<msg>%s</msg>
</return>
''' % (rcode, lookaside[rcode])

	return xml

xml = gen_command_result(1)
print('gen_command_result(1)',xml)

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config', type = str, default = '../etc/drmsd.ini', help = 'config file')
print('parser',parser)

args = parser.parse_args()
print('args',args)

config = ConfigParser()
config.read(args.config)
print('config',config)

port = config.getint('network', 'port')
print('port',port)

ackhost = config.get('network', 'ackhost')
print('ackhost',ackhost)

ackport = config.getint('network', 'ackport')
print('ackport',ackport)

try: gPwd = config.get('security', 'secret')
except (NoSectionError, NoOptionError):
	sys.exit(1)
	pass
print('gPwd',gPwd)

try: gAESKey = config.get('security', 'aes_key')
except (NoSectionError, NoOptionError):
	print('config file "%s" missing "security.aes_key" option' % args.config)
	sys.exit(1)
	pass
print('gAESKey',gAESKey)

try: gAESIV = config.get('security', 'aes_iv')
except (NoSectionError, NoOptionError):
	print('config file "%s" missing "security.aes_iv" option' % args.config)
	sys.exit(1)
	pass
print('aAESIV',gAESIV)

try: home = config.get('named-conf', 'home')
except (NoSectionError, NoOptionError):
	home = '/etc'
	pass
print('home',home)

try: rndc = config.get('named-conf', 'rndc')
except (NoSectionError, NoOptionError):
	rndc = 'rndc'
	pass
print('rndc',rndc)

switch = config.get('named-conf', 'switch')
print('switch',switch)

std = config.get('named-conf', 'std')
print('std',std)

local = config.get('named-conf', 'local')
print('local',local)

from spyne.protocol.soap import Soap11
from spyne import ServiceBase
from spyne.util.wsgi_wrapper import WsgiMounter
from spyne.application import Application

class DRMSService(ServiceBase):
	pass

application = Application([DRMSService], 
	tns = 'http://webservice.ack.dns.act.com/', 
	in_protocol = Soap11(validator = 'lxml'), 
	out_protocol = Soap11())

from wsgiref.simple_server import make_server

#wsgi_app = WsgiApplication(application)
wsgi_app = WsgiMounter({'DNSWebService' : application})
server = make_server('0.0.0.0', port, wsgi_app)
print('server start',port)
server.serve_forever()
pass


