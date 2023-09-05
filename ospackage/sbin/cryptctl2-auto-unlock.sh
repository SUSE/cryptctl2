#!/bin/bash

while [ $# -gt 0 ]
do
	/usr/sbin/cryptctl2 --action check-auto-unlock --deviceID $1
	if [ $? == 0 ]; then
		/usr/bin/systemctl start cryptctl2-auto-unlock@$1
		break
	fi
        shift
done

