#!/bin/bash

if [ -f /etc/redhat-release ]; then
    yum install python3 python3-pip
else
    apt-get install python3 python3-pip    
fi

pip3 install python-iptables sdp-transform flask waitress configparser pid
cp floki.py /usr/local/bin/
chmod x /usr/local/bin/floki.py

mkdir -p /etc/floki/
cp floki.conf /etc/floki/

cp floki.service /lib/systemd/system/
systemctl daemon-reload