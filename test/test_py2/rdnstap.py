
import sys
import subprocess

sys.path.append('..')
import stats

p = subprocess.Popen(['/usr/bin/dnstap-read', './example.dnstap'], stdout = subprocess.PIPE, close_fds = True)
for ln in p.stdout:
	#print(ln.decode('ascii'), end = '')
	_t = ln.decode('ascii').split()
	if not _t:
		continue

	dtrr = stats.DTRR._make(_t)
	stats.iterator_parser(dtrr)
	pass

cqss, rqss = [], {}
stats.iterator_stats_calc(cqss, rqss)
print(cqss, rqss)

total = 0
for i in cqss:
	total += i

avrage = int(1000*(total/len(cqss)))
print(avrage)


