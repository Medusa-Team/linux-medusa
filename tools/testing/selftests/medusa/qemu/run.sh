#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
	echo "usage: $0 KERNEL_IMAGE CONSTABLE_STATIC BUSYBOX_STATIC [SCENARIO]" >&2
	exit 2
fi

kernel_image="$(realpath "$1")"
constable="$(realpath "$2")"
busybox="$(realpath "$3")"
scenario="${4:-cache}"
self_dir="$(cd "$(dirname "$0")" && pwd)"
kernel_tree="$(cd "$self_dir/../../../../.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/medusa-qemu.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

case "$scenario" in
	*[!a-zA-Z0-9_-]*|'')
		echo "invalid scenario name: $scenario" >&2
		exit 2
		;;
esac

scenario_dir="$self_dir/scenarios/$scenario"
if [ ! -d "$scenario_dir" ]; then
	echo "unknown scenario: $scenario" >&2
	exit 2
fi

base_dir=
if [ -f "$scenario_dir/base" ]; then
	base="$(sed -n '1p' "$scenario_dir/base")"
	case "$base" in
		*[!a-zA-Z0-9_-]*|'')
			echo "invalid base scenario name: $base" >&2
			exit 2
			;;
	esac
	base_dir="$self_dir/scenarios/$base"
	if [ ! -d "$base_dir" ]; then
		echo "unknown base scenario: $base" >&2
		exit 2
	fi
fi

scenario_file()
{
	if [ -f "$scenario_dir/$1" ]; then
		echo "$scenario_dir/$1"
	elif [ -n "$base_dir" ] && [ -f "$base_dir/$1" ]; then
		echo "$base_dir/$1"
	else
		return 1
	fi
}

for command in cc gzip qemu-system-x86_64 realpath timeout; do
	if ! command -v "$command" >/dev/null; then
		echo "missing required command: $command" >&2
		exit 2
	fi
done

for input in "$kernel_image" "$constable" "$busybox"; do
	if [ ! -f "$input" ]; then
		echo "missing input file: $input" >&2
		exit 2
	fi
done

mkdir -p "$work_dir/input"
cp "$constable" "$work_dir/input/constable"
cp "$busybox" "$work_dir/input/busybox"
cp "$self_dir/init-constable.sh" "$work_dir/input/init-constable.sh"
cp "$(scenario_file medusa.conf)" "$work_dir/input/medusa.conf"
cp "$self_dir/constable.conf" "$work_dir/input/constable.conf"
: >"$work_dir/input/constable.pid"
if medusa_reload="$(scenario_file medusa-reload.conf)"; then
	cp "$medusa_reload" \
		"$work_dir/input/medusa-reload.conf"
fi
if expected_lsms="$(scenario_file expected-lsms)"; then
	cp "$expected_lsms" "$work_dir/input/expected-lsms"
fi

guest_cc="${GUEST_CC:-cc}"
init_c="$(scenario_file init.c || true)"
guest_c="$(scenario_file guest.c || true)"
if [ -n "$init_c" ] || [ -n "$guest_c" ]; then
	if ! command -v "$guest_cc" >/dev/null; then
		echo "missing guest compiler: $guest_cc" >&2
		exit 2
	fi
fi

if [ -n "$init_c" ]; then
	if [ -n "${INIT_TEST_BINARY:-}" ]; then
		cp "$(realpath "$INIT_TEST_BINARY")" "$work_dir/input/init"
	else
		"$guest_cc" -static -O2 -Wall -Wextra \
			-o "$work_dir/input/init" "$init_c"
	fi
else
	cp "$(scenario_file init)" "$work_dir/input/init"
fi

if [ -n "$guest_c" ]; then
	if [ -n "${GUEST_TEST_BINARY:-}" ]; then
		cp "$(realpath "$GUEST_TEST_BINARY")" "$work_dir/input/medusa-guest"
	else
		"$guest_cc" -static -O2 -Wall -Wextra \
			-o "$work_dir/input/medusa-guest" "$guest_c"
	fi
fi

cc -O2 -o "$work_dir/gen_init_cpio" "$kernel_tree/usr/gen_init_cpio.c"

{
	echo "dir /bin 0755 0 0"
	echo "dir /sbin 0755 0 0"
	echo "dir /etc 0755 0 0"
	echo "dir /dev 0755 0 0"
	echo "dir /proc 0555 0 0"
	echo "dir /sys 0555 0 0"
	echo "dir /tmp 1777 0 0"
	echo "file /bin/busybox $work_dir/input/busybox 0755 0 0"
	for applet in awk cat chmod chown chroot cp dd dmesg echo fgrep grep \
		kill killall link ln mkdir mkfifo mknod mv pidof poweroff ps \
		mount readlink rm rmdir sed sh sleep stat touch true truncate \
		unlink; do
		echo "slink /bin/$applet busybox 0755 0 0"
	done
	echo "file /sbin/constable $work_dir/input/constable 0755 0 0"
	echo "file /sbin/init $work_dir/input/init 0755 0 0"
	echo "file /sbin/init-constable.sh $work_dir/input/init-constable.sh 0755 0 0"
	echo "file /constable.pid $work_dir/input/constable.pid 0644 0 0"
	echo "file /etc/medusa.conf $work_dir/input/medusa.conf 0644 0 0"
	echo "file /etc/constable.conf $work_dir/input/constable.conf 0644 0 0"
	if [ -f "$work_dir/input/medusa-reload.conf" ]; then
		echo "file /etc/medusa-reload.conf $work_dir/input/medusa-reload.conf 0644 0 0"
	fi
	if [ -f "$work_dir/input/expected-lsms" ]; then
		echo "file /etc/expected-lsms $work_dir/input/expected-lsms 0644 0 0"
	fi
	if [ -f "$work_dir/input/medusa-guest" ]; then
		echo "file /bin/medusa-guest $work_dir/input/medusa-guest 0755 0 0"
	fi
	echo "nod /dev/console 0600 0 0 c 5 1"
	echo "nod /dev/null 0666 0 0 c 1 3"
	echo "nod /dev/medusa 0600 0 0 c 111 0"
} >"$work_dir/initramfs.list"

"$work_dir/gen_init_cpio" "$work_dir/initramfs.list" |
	gzip -9 >"$work_dir/initramfs.cpio.gz"

timeout "${QEMU_TIMEOUT:-90}" qemu-system-x86_64 \
	-machine pc,accel="${QEMU_ACCEL:-tcg}" \
	-cpu "${QEMU_CPU:-max}" \
	-m 1024 \
	-kernel "$kernel_image" \
	-initrd "$work_dir/initramfs.cpio.gz" \
	-append "console=ttyS0 rdinit=/sbin/init panic=-1 audit=1" \
	-nographic \
	-no-reboot 2>&1 | tee "$work_dir/console.log"

check_expected()
{
	while IFS= read -r expected || [ -n "$expected" ]; do
		case "$expected" in
			''|'#'*) continue ;;
			'!'*)
				unexpected="${expected#!}"
				if grep -Fq "$unexpected" "$work_dir/console.log"; then
					echo "scenario '$scenario' observed forbidden result:" \
						"$unexpected" >&2
					exit 1
				fi
				continue
				;;
		esac
		if ! grep -Fq "$expected" "$work_dir/console.log"; then
			echo "scenario '$scenario' missing expected result: $expected" >&2
			exit 1
		fi
	done <"$1"
}

if [ -n "$base_dir" ] && [ -f "$base_dir/expected" ]; then
	check_expected "$base_dir/expected"
fi
check_expected "$scenario_dir/expected"

echo "Medusa QEMU scenario '$scenario' passed"
