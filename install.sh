#! /bin/bash
CURDIR="`pwd`"
INSTALL_DIR="/usr/lib/systemd/system"

function gen_file()
{
	file="$1"
	mode="$2"
	cat $file | sed -e "s:CURDIR:$CURDIR:g;s:CURMOD:$mode:g"
}


if [ "X$1" == "Xserver" ];
then
	gen_file ./ssproxy.tmp server.py > $INSTALL_DIR/sserver.service
	systemctl enable sserver
	systemctl start sserver

elif [ "X$1" == "Xclient" ];
then
	gen_file ./ssproxy.tmp local.py > $INSTALL_DIR/ssproxy.service
	systemctl enable ssproxy
	systemctl start ssproxy
else
	echo "Usage:$0 [server|client]"
fi;
