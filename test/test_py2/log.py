import logging
logger = logging.getLogger(__name__)
logger.setLevel(level = logging.INFO)
handler = logging.FileHandler("log.txt")
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.info("Start print log")
# log level >= info
logger.debug("Do something")
logger.warning("Something maybe fail.")
logger.error("Something maybe error.")
a= 3
b = 'sdf'

try:
	with open('dsgfg','r') as f:
		l = f.readlines()
except Exception as e:
	logger.error('open file error '+str(e))

#logger.info("Finish %d %s" % a , b)
