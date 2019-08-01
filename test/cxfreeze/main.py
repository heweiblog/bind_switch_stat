#!/usr/bin/python3
# -*- coding: utf-8 -*-


import os, time, daemon, multiprocessing
from log import logger
from conf import Conf
from upload import upload
from service import server

if __name__ == '__main__':
	logger.info('{} main start at {}'.format(os.getpid(),time.ctime()))
	logger.info(Conf)

	with daemon.DaemonContext():
		p = multiprocessing.Process(target = server.main_task, args = ())
		p1 = multiprocessing.Process(target = upload.upload_task, args = ())
		p.start()
		p1.start()
		p.join()
		p1.join()

	logger.info('main process end at: %s' % time.ctime())

