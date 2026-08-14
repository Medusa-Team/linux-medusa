#!/bin/sh

/bin/sh -c '
	echo $$ >/constable.pid
	exec /sbin/constable -c /etc/medusa.conf /etc/constable.conf
' >/dev/console 2>&1 &
