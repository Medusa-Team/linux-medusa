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

if ! grep -Fxq 'CONFIG_SECURITY_APPARMOR=y' "$config"; then
	echo "CONFIG_SECURITY_APPARMOR must be enabled" >&2
	exit 1
fi

lsm="$(sed -n 's/^CONFIG_LSM="\(.*\)"$/\1/p' "$config")"
case ",$lsm," in
	*,apparmor,*) ;;
	*)
		echo "CONFIG_LSM does not contain apparmor" >&2
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
	*apparmor*medusa*) ;;
	*)
		echo "CONFIG_LSM must initialize apparmor before medusa" >&2
		exit 1
		;;
esac

echo "Medusa stacking config passed"
