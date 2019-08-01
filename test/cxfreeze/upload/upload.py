#!/usr/bin/python3
# -*- coding: utf-8 -*-

import time
import logging,logging.handlers

def upload_task():

	logger = logging.getLogger('drmsd')
	logger.setLevel(level = logging.INFO)
	handler = logging.FileHandler("/home/heweiwei/drms/test/cxfreeze/upload.log")
	handler.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	logger.info('upload task start')

	i = 0
	while True:
		time.sleep(10)
		i += 1
		logger.info('number is {}'.format(i))
		
