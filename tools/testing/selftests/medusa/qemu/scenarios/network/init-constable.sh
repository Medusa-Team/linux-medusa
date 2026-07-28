#!/bin/sh

/sbin/constable -F socket_bind_access=online_required \
	-c /etc/medusa.conf /etc/constable.conf >/dev/console 2>&1 &
echo $! >/constable.pid
