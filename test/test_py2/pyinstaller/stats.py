
#import socket
import sys, collections, datetime

PY3 = (sys.version_info[0] >= 3)

DTRR = collections.namedtuple('DTRR', ['date', 'time', 'msgtype', 'local', 
			      'direction', 'peer', 'socktype', 'size', 
			      'question'])

class Delay(object):
	__slots__ = ('_in', '_out')

	def __init__(self, _in = None, _out = None):
		self._in = _in
		self._out = _out
		return None

	def setIn(self, _in):
		self._in = _in
		return None

	def setOut(self, _out):
		self._out = _out
		return None

	def isMature(self):
		if not isinstance(self._in, (int, float)):
			return False

		if not isinstance(self._out, (int, float)):
			return False

		return True

	def calcDelay(self):
		return (self._out - self._in)
# end of class Delay

gPtrs = {}
gStdRoots = set((
	'a.root-servers.net', 
	'b.root-servers.net', 
	'c.root-servers.net', 
	'd.root-servers.net', 
	'e.root-servers.net', 
	'f.root-servers.net', 
	'g.root-servers.net', 
	'h.root-servers.net', 
	'i.root-servers.net', 
	'j.root-servers.net', 
	'k.root-servers.net', 
	'l.root-servers.net', 
	'm.root-servers.net'
))

gRoots = set(gStdRoots)

# key: (question, local, peer)
# val: Delay
itr_cqs = collections.defaultdict(Delay)
itr_rqs = dict((k, collections.defaultdict(Delay)) for k in gRoots)

ath_aqs = {}

ath_topn = collections.defaultdict(int)

def make_time(date, time):
	p = datetime.datetime.strptime('%s %s' % (date, time), 
			'%d-%b-%Y %H:%M:%S.%f')
	return p.timestamp() if PY3 else float(p.strftime('%s.%f'))

def root_ptr(ip):
	try: n = gPtrs[ip]
	except KeyError:
		#try: n = socket.gethostbyaddr(ip)[0].lower()
		#except: return None
		#else: gPtrs[ip] = n
		return None

	return n if n in gRoots else None

def iterator_parser(dtrr):
	gkey = (dtrr.question, dtrr.local, dtrr.peer)
	if dtrr.msgtype == 'CQ':
		itr_cqs[gkey].setIn(make_time(dtrr.date, dtrr.time))
	elif dtrr.msgtype == 'CR':
		itr_cqs[gkey].setOut(make_time(dtrr.date, dtrr.time))
	elif dtrr.msgtype == 'RQ':
		try: r = root_ptr(dtrr.peer.rsplit(':', 1)[0])
		except: pass
		else:
			if r is not None:
				itr_rqs[r][gkey].setIn(make_time(dtrr.date, dtrr.time))
				pass
			pass
		pass
	elif dtrr.msgtype == 'RR':
		try: r = root_ptr(dtrr.peer.rsplit(':', 1)[0])
		except: pass
		else:
			if (r is not None) and (r in itr_rqs):
				itr_rqs[r][gkey].setOut(make_time(dtrr.date, dtrr.time))
				pass
			pass

		pass

	return None

def iterator_stats_calc(cqss, rqss):
	global itr_cqs, itr_rqs

	for k, v in itr_cqs.items():
		if not v.isMature():
			continue

		cqss.append(v.calcDelay())
		continue

	for k, v in itr_rqs.items():
		rqss[k] = []
		for _k, _v in v.items():
			if not _v.isMature():
				continue

			rqss[k].append(_v.calcDelay())
			continue
		continue

	itr_cqs = {}
	itr_rqs = dict((k, collections.defaultdict(Delay)) for k in gRoots)

	return None

def auth_parser(dtrr):
	gkey = (dtrr.question, dtrr.local, dtrr.peer)
	if dtrr.msgtype == 'AQ':
		ath_aqs[gkey].setIn(make_time(dtrr.date, dtrr.time))
		try:
			qname = dtrr.question.split('/', 1)[0]
			for t in reversed(qname.rsplit('.', 2)):
				if t:
					ath_topn[t] += 1
					break
				pass
		except: pass
	elif dtrr.msgtype == 'AR':
		ath_aqs[gkey].setOut(make_time(dtrr.date, dtrr.time))
		pass
	return None

def auth_stats_calc(topn, n, aqss):
	global ath_aqs, ath_topn

	for k, v in ath_aqs.items():
		if not v.isMature():
			continue

		aqss.append(v.calcDelay())
		continue

	ath_aqs = {}

	lst = [(k, v) for k, v in ath_topn.items()]
	lst.sort(key = lambda x: x[1])
	topn.extend(lst[:n])

	ath_topn = collections.defaultdict(int)

	return None
