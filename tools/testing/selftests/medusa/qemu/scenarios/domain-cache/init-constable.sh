#!/bin/sh

/sbin/constable \
	--domain-rule 'ptrace:*:*:*=deny' \
	--domain-rule 'sendsig:*:*:*=deny' \
	-c /etc/medusa.conf /etc/constable.conf >/dev/console 2>&1 &
echo $! >/constable.pid
