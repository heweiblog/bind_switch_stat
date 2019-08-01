#!/usr/bin/env python
#encoding:utf-8

import os
import sys
import time
 
from daemon import Daemon
 
class TomcatDaemon(Daemon):
  def run(self):
    sys.stdout.write('Daemon started with pid {}\n'.format(os.getpid()))
    while True:

      tomcat = os.popen('ps -fe | grep "/root/tomcat/bin/" | grep -v "grep" | wc -l').read().strip()
      #筛选出进程中含有tomcat且不含有grep，计算出现行数。修改上面的进程监控语句以适应其他应用需求
      if (tomcat == '0'):
        os.system('cd /root/tomcat/bin/;  ./startup.sh')

      sys.stdout.write('Daemon Alive! {}\n'.format(time.ctime()))
      sys.stdout.flush()
 
      time.sleep(5)
 
if __name__ == '__main__':
  PIDFILE = '/tmp/daemon-example.pid'
  LOG = '/tmp/daemon-example.log'
  daemon = TomcatDaemon(pidfile=PIDFILE, stdout=LOG, stderr=LOG)
 
  if len(sys.argv) != 2:
    print('Usage: {} [start|stop]'.format(sys.argv[0]), file=sys.stderr)
    raise SystemExit(1)
 
  if 'start' == sys.argv[1]:
    daemon.start()
  elif 'stop' == sys.argv[1]:
    daemon.stop()
  elif 'restart' == sys.argv[1]:
    daemon.restart()
  else:
    print('Unknown command {!r}'.format(sys.argv[1]), file=sys.stderr)
    raise SystemExit(1)
