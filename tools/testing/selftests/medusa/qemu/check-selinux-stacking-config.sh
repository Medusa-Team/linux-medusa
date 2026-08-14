#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: $0 KERNEL_CONFIG" >&2
	exit 2
fi

config="$1"
if [ ! -f "$config" ]; then
	echo "missing kernel config: $config" >&2
	exit 2
fi

if ! grep -Fxq 'CONFIG_SECURITY_SELINUX=y' "$config"; then
	echo "CONFIG_SECURITY_SELINUX must be enabled" >&2
	exit 1
fi

lsm="$(sed -n 's/^CONFIG_LSM="\(.*\)"$/\1/p' "$config")"
case ",$lsm," in
	*,selinux,*) ;;
	*)
		echo "CONFIG_LSM does not contain selinux" >&2
		exit 1
		;;
esac
case ",$lsm," in
	*,medusa,*) ;;
	*)
		echo "CONFIG_LSM does not contain medusa" >&2
		exit 1
		;;
esac

case "$lsm" in
	*selinux*medusa*) ;;
	*)
		echo "CONFIG_LSM must initialize selinux before medusa" >&2
		exit 1
		;;
esac

echo "Medusa SELinux stacking config passed"
