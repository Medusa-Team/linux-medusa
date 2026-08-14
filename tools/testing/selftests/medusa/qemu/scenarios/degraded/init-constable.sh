#!/bin/sh

mount -t sysfs sysfs /sys
mount -t cgroup2 none /sys/fs/cgroup
mkdir /sys/fs/cgroup/constable-test

/sbin/medusa-test-helper --freezer-controller >/dev/console 2>&1 &
while [ ! -e /freezer-ready ]; do
	sleep 0.01
done

/bin/sh -c '
	echo $$ >/sys/fs/cgroup/constable-test/cgroup.procs
	echo $$ >/constable.pid
	exec /sbin/constable -c /etc/medusa.conf /etc/constable.conf
' >/dev/console 2>&1 &
