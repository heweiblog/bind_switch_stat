#!/usr/bin/python3
# -*- coding: utf-8 -*-

from spyne import ServiceBase
from spyne.protocol.soap import Soap11
from spyne.decorator import rpc
from spyne.model.primitive import Integer, Int, Long, Unicode
from spyne.model.complex import Iterable
from spyne.application import Application
from spyne.server.wsgi import WsgiApplication
from spyne.util.wsgi_wrapper import WsgiMounter
from spyne.util.etreeconv import root_etree_to_dict
from wsgiref.simple_server import make_server

import logging,logging.handlers

class DRMSService(ServiceBase):
	@rpc(Unicode, Unicode, Unicode, Unicode, Unicode, 
			Int, Long, Int, 
			Int, Int, Unicode, 
			_out_variable_name = 'return', 
			_returns = Unicode)
	def dns_command(ctx, dnsId, randVal, pwdHash, command, commandHash, 
			commandType, commandSequence, encryptAlgorithm, 
			hashAlgorithm, compressionFormat, commandVersion):

		logger.info('1')


def main_task():
	listen_port = 18899

	logger = logging.getLogger('drmsd')
	logger.setLevel(level = logging.INFO)
	handler = logging.FileHandler("/home/heweiwei/drms/test/cxfreeze/service.log")
	handler.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	application = Application([DRMSService],'http://webservice.ack.dns.act.com/', 
			in_protocol = Soap11(validator = 'lxml'), 
			out_protocol = Soap11())

	wsgi_app = WsgiMounter({'DNSWebService' : application})
	server = make_server('0.0.0.0', listen_port, wsgi_app)
	logger.info('server at port 18899 start')
	server.serve_forever()

