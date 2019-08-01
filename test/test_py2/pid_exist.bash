#!/bin/sh
ps -fe|grep yirdns |grep -v grep
if [ $? -ne 0 ]
then
echo "start process....."
else
echo "runing....."
fi
