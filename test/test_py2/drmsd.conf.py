
from __future__ import print_function

import os, sys, time, random, string, logging, logging.handlers
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

from conf.conf import Conf

global logger

sequence = 0


def genDnsId(orgType, provId, distSrc):
	global sequence
	_id = time.strftime('%Y%m%d', time.localtime()) + \
	      ('%03d' % (sequence % 1000)) + '33300001'
	sequence += 1
	return _id


def cmdAck(dnsId, result, hashAlgorithm, compressionFormat, encryptAlgorithm):
	randVal = ''.join(random.sample(string.letters, 20))

	if hashAlgorithm == 0: _hashed_pwd = Conf['security']['gPwd'] + randVal
	elif hashAlgorithm == 1: _hashed_pwd = hashlib.md5(Conf['security']['gPwd'] + randVal).hexdigest()
	elif hashAlgorithm == 2: _hashed_pwd = hashlib.sha1(Conf['security']['gPwd'] + randVal).hexdigest()
	else: return False

	pwdHash = base64.b64encode(_hashed_pwd)

	if compressionFormat == 0: _compressed_result = result
	elif compressionFormat == 1: _compressed_result = zlib.compress(result)
	else: return False

	if (Conf['security']['gAESKey'] is not None) and (Conf['security']['gAESIV'] is not None) and (encryptAlgorithm == 1):
		pads = (AES.block_size - (len(_compressed_result) % AES.block_size))
		padding = chr(pads) * pads

		_encrypted_result = AES.new(Conf['security']['gAESKey'], AES.MODE_CBC, Conf['security']['gAESIV']).encrypt(_compressed_result + padding)
	else: _encrypted_result = _compressed_result

	result = base64.b64encode(_encrypted_result)

	if hashAlgorithm == 0: _hashed_result = _compressed_result + Conf['security']['gPwd']
	elif hashAlgorithm == 1: _hashed_result = hashlib.md5(_compressed_result + Conf['security']['gPwd']).hexdigest()
	elif hashAlgorithm == 2: _hashed_result = hashlib.sha1(_compressed_result + Conf['security']['gPwd']).hexdigest()
	else: return False

	resultHash = base64.b64encode(_hashed_result)

	commandVersion = 'v0.1'

	cl = osa.Client('http://%s:%d/DNSWebService/dnsCommandAck?wsdl' % (Conf['network']['ackhost'], Conf['network']['ackport']))
	r = cl.service.dns_commandack(dnsId, randVal, pwdHash, result, 
			resultHash, encryptAlgorithm, hashAlgorithm, 
			compressionFormat, commandVersion)

	ele = lxml.etree.fromstring(r.encode('utf-8'))
	if int(xmlget(ele, 'resultCode')) != 0:
		return False

	return True


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
	if hashAlgorithm == 0: 
		raw = Conf['security']['gPwd'] + randVal
	elif hashAlgorithm == 1: 
		raw = hashlib.md5(Conf['security']['gPwd'] + randVal).hexdigest()
	elif hashAlgorithm == 2: 
		raw = hashlib.sha1(Conf['security']['gPwd'] + randVal).hexdigest()
	else: 
		return False

	return pwdHash == base64.b64encode(raw)


def deCMDPre(command, compressionFormat, commandHash, hashAlgorithm, encryptAlgorithm):
	raw = base64.b64decode(command)

	if (Conf['security']['gAESKey'] is not None) and (Conf['security']['gAESIV'] is not None) and (encryptAlgorithm == 1):
		decrypted = AES.new(Conf['security']['gAESKey'], AES.MODE_CBC, Conf['security']['gAESIV']).decrypt(raw)
		data = decrypted[:-ord(decrypted[-1])]
	else: data = raw

	if hashAlgorithm == 0: hashed = data + Conf['security']['gPwd']
	elif hashAlgorithm == 1: hashed = hashlib.md5(data + Conf['security']['gPwd']).hexdigest()
	elif hashAlgorithm == 2: hashed = hashlib.sha1(data + Conf['security']['gPwd']).hexdigest()
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


def switch_named_file(target,source):
	home = '/etc'

	if os.path.exists(home+"/"+target) == False:
		logger.error('[%d] file[%s] not exist error!' % os.getpid(),target)
		return False

	try:
		subprocess.check_call(['ln', '-f', '-s', target, source], cwd = home)
	except subprocess.CalledProcessError:
		logger.error('[%d] create link path error!' % os.getpid())
		return False

	try:
		subprocess.check_call(['rndc', 'reconfig'], cwd = home)
	except subprocess.CalledProcessError:
		logger.error('[%d] rndc reconfig error!' % os.getpid())
		return False

	try:
		subprocess.check_call(['rndc', 'flush'], cwd = home)
	except subprocess.CalledProcessError:
		logger.error('[%d] rndc flush error!' % os.getpid())
		return False

	logger.warn('[%d] root switch to `%s`' % (os.getpid(), target))
	return True


def switch_rootca(stdon, delay, dnsId, commandType, commandId, hashAlgorithm, compressionFormat, encryptAlgorithm):

	def __do_command(target):
		ret = switch_named_file(target,Conf['named-conf']['switch'])

		result = gen_commandack_result(dnsId, commandId, commandType, 0 if ret else 2)
		ret = cmdAck(dnsId, result, hashAlgorithm, compressionFormat, encryptAlgorithm)
		if not ret:
			logger.error('cmdAck error: cmd - switch root, target - %s' % target)
			pass

		return True

	logger.warning('[%d] root direction will switch in %d seconds' % (os.getpid(), delay))
	Timer(delay, __do_command, ((Conf['named-conf']['std'] if stdon else Conf['named-conf']['local'], ))).start()
	return None

# named.conf must have include "switch_root.zone" and chown -R root:named /etc/switch_root.zone
def switch_root_source(is_exigency, delay, dnsId, commandType, commandId, hashAlgorithm, compressionFormat, encryptAlgorithm):

	def __do_command(target):
		ret = switch_named_file(target,Conf['named-conf']['root_source'])

		result = gen_commandack_result(dnsId, commandId, commandType, 0 if ret else 2)
		ret = cmdAck(dnsId, result, hashAlgorithm, compressionFormat, encryptAlgorithm)
		if not ret:
			logger.error('cmdAck error: cmd - switch root, target - %s' % target)
			pass

		return True

	logger.warning('[%d] root source will switch in %d seconds' % (os.getpid(), delay))
	Timer(delay, __do_command, ((Conf['source']['exigency_source'] if is_exigency else Conf['source']['standard_source'], ))).start()
	return None


def respond18(cmd, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):

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

		if not certificate(pwdHash, randVal, hashAlgorithm):
			logger.warning('certificate failed')
			return gen_command_result(2)

		cmd = deCMDPre(command, compressionFormat, commandHash, hashAlgorithm, encryptAlgorithm)
		if not cmd:
			logger.warning('deCMDPre failed')
			return gen_command_result(5)

		command_func = {18:respond18}

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

	#wsgi_app = WsgiApplication(application)
	wsgi_app = WsgiMounter({'DNSWebService' : application})
	server = make_server('0.0.0.0', Conf['network']['port'], wsgi_app)
	server.serve_forever()
	pass


with daemon.DaemonContext():

	logger = logging.getLogger('drmsd')
	logger.setLevel(level = logging.INFO)
	handler = logging.FileHandler("./drmsd.log")
	handler.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	logger.info('main process start at: %s' % time.ctime())

	while True:
		p = multiprocessing.Process(target = main_task, args = ())
		p.start()
		p.join()

	logger.info('main process end at: %s' % time.ctime())


