#!/bin/bash

POSTGRESQL_HOME_PATH=/usr/

if [ $# -gt 0 ] ; then
	POSTGRESQL_HOME_PATH=$1
fi

if [ $# -gt 1 ] ; then
	shift
fi

PATH=/bin:/usr/bin:/sbin:/usr/sbin:$POSTGRESQL_HOME_PATH/bin


if [ ! -d venv ] ; then
	python3 -m venv venv;
	if [ $? != 0 ] ; then
		sudo apt install -y python3-venv;
		python3 -m venv venv;
	fi
fi

if [ "`pip3 -V | grep venv`" == "" ] ; then
	source venv/bin/activate
fi

pip3 install -r requirements.txt
if [ $? != 0 ]; then
	sudo apt install -y python3-pip;
	sudo apt install -y libpcap-dev; # because using pypcap library, it need libpcap-dev library
	pip3 install -r requirements.txt;
fi

sudo LD_LIBRARY_PATH=$POSTGRESQL_HOME_PATH/lib venv/bin/python3 main.py $@
