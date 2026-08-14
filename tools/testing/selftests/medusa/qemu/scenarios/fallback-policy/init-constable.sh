#!/bin/sh

/sbin/constable -F ipc_msgsnd=baseline_deny \
	-c /etc/medusa.conf /etc/constable.conf >/dev/console 2>&1 &
echo $! >/constable.pid
