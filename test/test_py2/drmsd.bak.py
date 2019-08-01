
from __future__ import print_function

import os, sys, time, logging, random, string, logging.handlers
import multiprocessing, subprocess
from threading import Timer
import argparse
from ConfigParser import ConfigParser, NoSectionError, NoOptionError
from Crypto.Cipher import AES

import base64, hashlib, zlib
import lxml.etree
import pexpect

from spyne import ServiceBase
from spyne.protocol.soap import Soap11
from spyne.decorator import rpc
from spyne.model.primitive import Integer, Int, Long, Unicode
from spyne.model.complex import Iterable
from spyne.application import Application
#from spyne.server.wsgi import WsgiApplication
from spyne.util.wsgi_wrapper import WsgiMounter
from spyne.util.etreeconv import root_etree_to_dict

import osa

import daemon

gPwd = '1234567890abcDEF'
gAESKey = '1234567890abcDEF'
gAESIV = '1234567890abcDEF'

sequence = 0

def genDnsId(orgType, provId, distSrc):
	global sequence
	_id = time.strftime('%Y%m%d', time.localtime()) + \
	      ('%03d' % (sequence % 1000)) + '33300001'

	sequence += 1
	return _id

def cmdAck(dnsId, result, hashAlgorithm, compressionFormat, encryptAlgorithm):
	randVal = ''.join(random.sample(string.letters, 20))

	global gPwd, gAESKey, gAESIV

	if hashAlgorithm == 0: _hashed_pwd = gPwd + randVal
	elif hashAlgorithm == 1: _hashed_pwd = hashlib.md5(gPwd + randVal).hexdigest()
	elif hashAlgorithm == 2: _hashed_pwd = hashlib.sha1(gPwd + randVal).hexdigest()
	else: return False

	pwdHash = base64.b64encode(_hashed_pwd)

	if compressionFormat == 0: _compressed_result = result
	elif compressionFormat == 1: _compressed_result = zlib.compress(result)
	else: return False

	if (gAESKey is not None) and (gAESIV is not None) and (encryptAlgorithm == 1):
		pads = (AES.block_size - (len(_compressed_result) % AES.block_size))
		padding = chr(pads) * pads

		_encrypted_result = AES.new(gAESKey, AES.MODE_CBC, gAESIV).encrypt(_compressed_result + padding)
	else: _encrypted_result = _compressed_result

	result = base64.b64encode(_encrypted_result)

	if hashAlgorithm == 0: _hashed_result = _compressed_result + gPwd
	elif hashAlgorithm == 1: _hashed_result = hashlib.md5(_compressed_result + gPwd).hexdigest()
	elif hashAlgorithm == 2: _hashed_result = hashlib.sha1(_compressed_result + gPwd).hexdigest()
	else: return False

	resultHash = base64.b64encode(_hashed_result)

	commandVersion = 'v0.1'

	global ackhost, ackport

	cl = osa.Client('http://%s:%d/DNSWebService/dnsCommandAck?wsdl' % (ackhost, ackport))
	r = cl.service.dns_commandack(dnsId, randVal, pwdHash, result, 
			resultHash, encryptAlgorithm, hashAlgorithm, 
			compressionFormat, commandVersion)

	ele = lxml.etree.fromstring(r.encode('utf-8'))
	if int(xmlget(ele, 'resultCode')) != 0:
		return False

	return True

def opServeDName(dname, serve):
	child = pexpect.spawn('/usr/bin/cli /etc/cli.conf')

	child.expect('[NAP6800 system ]')

	child.sendline('config')
	child.expect('[NAP6800 config ]')

	child.sendline('sys_bwlist switch on')
	child.expect('[NAP6800 config ]')

	child.sendline('sys_bwlist rule %s 0.0.0.0/0 %s 0' % ('del' if serve else 'add', dname))
	child.expect('[NAP6800 config ]')

	return True

def clearDName(dname):
	child = pexpect.spawn('/usr/bin/cli /etc/cli.conf')

	child.expect('[NAP6800 system ]')

	child.sendline('config')
	child.expect('[NAP6800 config ]')

	for qtype in ('a', 'aaaa', 'a6', 'ptr', 'cname', 'txt', 
			'ns', 'mx', 'srv', 'naptr', 'hinfo'):
		child.sendline('cache-op dname_cache del %s %s' % (qtype, dname))
		child.expect('[NAP6800 config ]')
		continue

	return True

def switch_named_file(target,source):
	global home, rndc, logger

	if os.path.exists(home+"/"+target) == False:
		logger.error('[%d] file[%s] not exist error!' % os.getpid(),target)
		return False

	try:
		subprocess.check_call(['ln', '-f', '-s', target, source], cwd = home)
	except subprocess.CalledProcessError:
		logger.error('[%d] create link path error!' % os.getpid())
		return False

	try:
		subprocess.check_call([rndc, 'reconfig'], cwd = home)
	except subprocess.CalledProcessError:
		logger.error('[%d] rndc reconfig error!' % os.getpid())
		return False

	try:
		subprocess.check_call([rndc, 'flush'], cwd = home)
	except subprocess.CalledProcessError:
		logger.error('[%d] rndc flush error!' % os.getpid())
		return False

	logger.warn('[%d] root switch to `%s`' % (os.getpid(), target))
	return True

def switch_rootca(stdon, delay, dnsId, commandType, commandId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	global std, local, logger, switch

	def __do_command(target):
		ret = switch_named_file(target,switch)
		if ret:
			logger.info('switch root direction = %s success!!!' % target)
		else:
			logger.info('switch root direction = %s failed!!!' % target)

		result = gen_commandack_result(dnsId, commandId, commandType, 0 if ret else 2)
		ret = cmdAck(dnsId, result, hashAlgorithm, compressionFormat, encryptAlgorithm)
		if not ret:
			logger.error('cmdAck error: cmd - switch root, target - %s' % target)
			pass

		return True

	logger.warnng('[%d] root direction will switch in %d seconds' % (os.getpid(), delay))
	Timer(delay, __do_command, ((std if stdon else local, ))).start()
	return None

# named.conf must have include "switch_root.zone" and chown -R root:named /etc/switch_root.zone
def switch_root_source(is_exigency, delay, dnsId, commandType, commandId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	global standard_source, exigency_source, logger, root_source

	def __do_command(target):
		ret = switch_named_file(target,root_source)

		result = gen_commandack_result(dnsId, commandId, commandType, 0 if ret else 2)
		ret = cmdAck(dnsId, result, hashAlgorithm, compressionFormat, encryptAlgorithm)
		if not ret:
			logger.error('cmdAck error: cmd - switch root, target - %s' % target)
			pass

		return True

	logger.warning('[%d] root source will switch in %d seconds' % (os.getpid(), delay))
	Timer(delay, __do_command, ((exigency_source if is_exigency else standard_source, ))).start()
	return None

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

def gen_commandack_result(dnsId, cmdId, cmdType, resultCode):
	xml = u'''\
<?xml version="1.0" encoding="UTF-8"?>
<dnsCommandAck>
	<dnsId>%s</dnsId>
	<commandAck>
		<commandId>%s</commandId>
		<type>%d</type>
		<resultCode>%d</resultCode>
		<appealContent></appealContent>
		<msgInfo></msgInfo>
	</commandAck>
	<timeStamp>%s</timeStamp>
</dnsCommandAck>
''' % (dnsId, cmdId, cmdType, resultCode, time.strftime('%Y-%m-%d %H:%M:%S'))
	return xml

def certificate(pwdHash, randVal, hashAlgorithm):
	global gPwd

	if hashAlgorithm == 0: raw = gPwd + randVal
	elif hashAlgorithm == 1: raw = hashlib.md5(gPwd + randVal).hexdigest()
	elif hashAlgorithm == 2: raw = hashlib.sha1(gPwd + randVal).hexdigest()
	else: return False

	return pwdHash == base64.b64encode(raw)

def deCMDPre(command, compressionFormat, commandHash, hashAlgorithm, encryptAlgorithm):
	raw = base64.b64decode(command)

	global gAESKey, gAESIV, gPwd
	if (gAESKey is not None) and (gAESIV is not None) and (encryptAlgorithm == 1):
		decrypted = AES.new(gAESKey, AES.MODE_CBC, gAESIV).decrypt(raw)
		data = decrypted[:-ord(decrypted[-1])]
	else: data = raw

	if hashAlgorithm == 0: hashed = data + gPwd
	elif hashAlgorithm == 1: hashed = hashlib.md5(data + gPwd).hexdigest()
	elif hashAlgorithm == 2: hashed = hashlib.sha1(data + gPwd).hexdigest()
	else: return None

	if base64.b64encode(hashed) != commandHash:
		return None

	if compressionFormat == 0: cmd = data
	elif compressionFormat == 1: cmd = zlib.decompress(data)

	return cmd

def xmlget(root, xpath):
	lst = root.xpath(xpath)
	if lst and lst[0].text:
		return lst[0].text

	return None

def respond2(cmd, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	ele = lxml.etree.fromstring(cmd)

	_commandId = xmlget(ele, 'commandId')
	_type = xmlget(ele, 'type')
	_domain = xmlget(ele, 'domain')
	_urgency = xmlget(ele, 'urgency')
	_reason = xmlget(ele, 'action/reason')
	_attachment = xmlget(ele, 'action/attachment')
	_log = xmlget(ele, 'action/log')
	_report = xmlget(ele, 'action/report')
	_effectTime = xmlget(ele, 'time/effectTime')
	_expiredTime = xmlget(ele, 'time/expiredTime')
	_dnsid = xmlget(ele, 'range/dnsId')
	_effectiveScope = xmlget(ele, 'range/effectiveScope')
	_owner = xmlget(ele, 'privilege/owner')
	_visible = xmlget(ele, 'privilege/visible')
	_check = xmlget(ele, 'privilege/check')
	_operationType = int(xmlget(ele, 'operationType'))
	_timeStamp = xmlget(ele, 'timeStamp')

	if _urgency == 1: delay = 24 * 60 * 60
	elif _urgency == 2: delay = 2 * 60 * 60
	elif _urgency == 3: delay = 30 * 60
	elif _urgency == 4: delay = 10 * 60
	else: return gen_command_result(4)

	def __do_command_1(domain, serve):
		global logger
		ret = opServeDName(domain, serve)

		result = gen_commandack_result(dnsId, _commandId, 2, 0 if ret else 2)
		ret = cmdAck(dnsId, result, hashAlgorithm, compressionFormat, encryptAlgorithm)
		if not ret:
			logger.error('cmdAck error: cmd - stop domain')
			pass

		return True

	def __do_command_2(domain):
		global logger
		ret = clearDName(domain)

		result = gen_commandack_result(dnsId, _commandId, 2, 0 if ret else 2)
		ret = cmdAck(dnsId, result, hashAlgorithm, compressionFormat, encryptAlgorithm)
		if not ret:
			logger.error('cmdAck error: cmd - clear domain')
			pass

		return True

	if _type == '1':
		if _operationType == 0:
			Timer(delay, __do_command_1, _domain, False)
		elif _operationType == 1:
			Timer(delay, __do_command_1, _domain, True)
		else: return gen_command_result(4)
	elif _type == '2':
		if _operationType == 0:
			Timer(delay, __do_command_2, _domain)
		elif _operationType == 1:
			pass
		else: return gen_command_result(4)
	else: return gen_command_result(4)

	return gen_command_result(0)

def respond18(cmd, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	global logger

	ele = lxml.etree.fromstring(cmd)
	_commandId = xmlget(ele, 'commandId')
	_type = xmlget(ele, 'type')
	_urgency = xmlget(ele, 'urgency')
	_effectiveScope = xmlget(ele, 'range/effectiveScope')
	_check = xmlget(ele, 'privilege/check')
	_timestamp = xmlget(ele, 'timeStamp')
	_datasources = xmlget(ele, 'datasources')
	
	if _type != None:
		logger.info('switch root.ca type=%s' % _type)
		switch_rootca(True if _type != '1' else False, 
			(2 * 60 * 60) if _urgency == '1' else (10 * 60), 
			dnsId, 8, _commandId, hashAlgorithm, 
			compressionFormat, encryptAlgorithm)

	if _datasources != None:
		logger.info('switch root source datasources=%s' % _datasources)
		switch_root_source(True if _datasources != '1' else False, 
			(2 * 60 * 60) if _urgency == '1' else (10 * 60), 
			dnsId, 8, _commandId, hashAlgorithm, 
			compressionFormat, encryptAlgorithm)

	return gen_command_result(0)

class DRMSService(ServiceBase):
	@rpc(Unicode, Unicode, Unicode, Unicode, Unicode, 
			Int, Long, Int, 
			Int, Int, Unicode, 
			_out_variable_name = 'return', 
			_returns = Unicode)
	def dns_command(ctx, dnsId, randVal, pwdHash, command, commandHash, 
			commandType, commandSequence, encryptAlgorithm, 
			hashAlgorithm, compressionFormat, commandVersion):

		global logger

		if not certificate(pwdHash, randVal, hashAlgorithm):
			logger.warning('certificate failed')
			return gen_command_result(2)

		cmd = deCMDPre(command, compressionFormat, commandHash, hashAlgorithm, encryptAlgorithm)
		if not cmd:
			logger.warning('deCMDPre failed')
			return gen_command_result(5)

		command_func = {2:respond2,18:respond18}

		if commandType in command_func:
			return command_func[commandType](cmd, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)

		return gen_command_result(900)

	def stupid_xmlget(self, d, tag):
		if isinstance(d, (list, tuple)):
			for e in d:
				try: r = __get(e, tag)
				except KeyError:
					continue

				return r
			pass
		elif isinstance(d, dict):
			if tag in d:
				return d[tag]

			for e in d.itervalues():
				try: r = __get(e, tag)
				except KeyError:
					continue

				return r
			pass

		raise KeyError()
		pass

def main_task():
	application = Application([DRMSService], 
			tns = 'http://webservice.ack.dns.act.com/', 
			in_protocol = Soap11(validator = 'lxml'), 
			out_protocol = Soap11())

	from wsgiref.simple_server import make_server
	global port

	#wsgi_app = WsgiApplication(application)
	wsgi_app = WsgiMounter({'DNSWebService' : application})
	server = make_server('0.0.0.0', port, wsgi_app)
	server.serve_forever()
	pass

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config', type = str, default = '/etc/drmsd.ini', help = 'config file')

args = parser.parse_args()

config = ConfigParser()
config.read(args.config)

port = config.getint('network', 'port')
ackhost = config.get('network', 'ackhost')
ackport = config.getint('network', 'ackport')

try: gPwd = config.get('security', 'secret')
except (NoSectionError, NoOptionError):
	print('config file "%s" missing "security.secret" option' % args.config, 
			file = sys.stderr, flush = True)
	sys.exit(1)
	pass

try: gAESKey = config.get('security', 'aes_key')
except (NoSectionError, NoOptionError):
	print('config file "%s" missing "security.aes_key" option' % args.config)
	sys.exit(1)
	pass

try: gAESIV = config.get('security', 'aes_iv')
except (NoSectionError, NoOptionError):
	print('config file "%s" missing "security.aes_iv" option' % args.config)
	sys.exit(1)
	pass

try: home = config.get('named-conf', 'home')
except (NoSectionError, NoOptionError):
	home = '/etc'
	pass

try: rndc = config.get('named-conf', 'rndc')
except (NoSectionError, NoOptionError):
	rndc = 'rndc'
	pass

switch = config.get('named-conf', 'switch')
std = config.get('named-conf', 'std')
local = config.get('named-conf', 'local')

root_source = config.get('source', 'root_source')
standard_source = config.get('source', 'standard_source')
exigency_source = config.get('source', 'exigency_source')

assert os.path.isdir(home)

with daemon.DaemonContext():
	logger = logging.getLogger('drmsd')
	logger.setLevel(level = logging.INFO)
	handler = logging.FileHandler("/var/log/drmsd.log")
	handler.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	logger.info('main process start at: %s' % time.ctime())

	while True:
		p = multiprocessing.Process(target = main_task, args = ())
		p.start()
		p.join()
		pass

	logger.info('main process end at: %s' % time.ctime())
	pass
