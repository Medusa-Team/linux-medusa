#!/bin/sh

/sbin/constable \
	--domain-rule 'create:*:*:33161=deny' \
	-c /etc/medusa.conf /etc/constable.conf >/dev/console 2>&1 &
echo $! >/constable.pid
