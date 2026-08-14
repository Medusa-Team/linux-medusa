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

for command in cc gzip qemu-system-x86_64 readelf realpath timeout; do
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
if scenario_init_constable="$(scenario_file init-constable.sh)"; then
	cp "$scenario_init_constable" "$work_dir/input/init-constable.sh"
else
	cp "$self_dir/init-constable.sh" "$work_dir/input/init-constable.sh"
fi
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
if apparmor_profile="$(scenario_file apparmor.profile)"; then
	if [ -n "${APPARMOR_POLICY:-}" ]; then
		cp "$(realpath "$APPARMOR_POLICY")" \
			"$work_dir/input/apparmor.policy"
	else
		apparmor_parser="${APPARMOR_PARSER:-apparmor_parser}"
		if ! command -v "$apparmor_parser" >/dev/null; then
			echo "missing AppArmor parser: $apparmor_parser" >&2
			exit 2
		fi
		"$apparmor_parser" --skip-kernel-load --skip-cache --stdout \
			"$apparmor_profile" >"$work_dir/input/apparmor.policy"
	fi
fi
if scenario_file selinux-policy >/dev/null; then
	if [ -z "${SELINUX_POLICY:-}" ]; then
		echo "SELINUX_POLICY is required by scenario '$scenario'" >&2
		exit 2
	fi
	cp "$(realpath "$SELINUX_POLICY")" "$work_dir/input/selinux.policy"
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

require_x86_64_elf()
{
	local binary="$1"
	local label="$2"
	local machine

	machine="$(readelf -h "$binary" 2>/dev/null |
		sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')"
	if [ "$machine" != "Advanced Micro Devices X86-64" ]; then
		echo "$label must be an x86-64 ELF executable; found:" \
			"${machine:-unrecognized format}" >&2
		exit 2
	fi
}

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

require_x86_64_elf "$work_dir/input/constable" "Constable"
require_x86_64_elf "$work_dir/input/busybox" "BusyBox"
require_x86_64_elf "$work_dir/input/init" "scenario init"
if [ -f "$work_dir/input/medusa-guest" ]; then
	require_x86_64_elf "$work_dir/input/medusa-guest" "scenario guest"
fi

cc -O2 -o "$work_dir/gen_init_cpio" "$kernel_tree/usr/gen_init_cpio.c"

{
	echo "dir /bin 0755 0 0"
	echo "dir /sbin 0755 0 0"
	echo "dir /etc 0755 0 0"
	echo "dir /dev 0755 0 0"
	echo "dir /proc 0555 0 0"
	echo "dir /sys 0555 0 0"
	echo "dir /sys/fs 0755 0 0"
	echo "dir /sys/fs/cgroup 0755 0 0"
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
	if [ -n "$init_c" ]; then
		echo "file /sbin/medusa-test-helper $work_dir/input/init 0755 0 0"
	fi
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
	if [ -f "$work_dir/input/apparmor.policy" ]; then
		echo "file /etc/apparmor.policy $work_dir/input/apparmor.policy 0600 0 0"
	fi
	if [ -f "$work_dir/input/selinux.policy" ]; then
		echo "file /etc/selinux.policy $work_dir/input/selinux.policy 0600 0 0"
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
	-append "console=ttyS0 rdinit=/sbin/init panic=-1 audit=1 audit_backlog_limit=8192" \
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

check_expected_order()
{
	local after=0
	local expected
	local found

	while IFS= read -r expected || [ -n "$expected" ]; do
		case "$expected" in
			''|'#'*) continue ;;
		esac
		found="$(
			awk -v after="$after" -v expected="$expected" \
				'NR > after && index($0, expected) { print NR; exit }' \
				"$work_dir/console.log"
		)"
		if [ -z "$found" ]; then
			echo "scenario '$scenario' missing ordered result after line" \
				"$after: $expected" >&2
			exit 1
		fi
		after="$found"
	done <"$1"
}

if [ -n "$base_dir" ] && [ -f "$base_dir/expected" ]; then
	check_expected "$base_dir/expected"
fi
check_expected "$scenario_dir/expected"
if [ -n "$base_dir" ] && [ -f "$base_dir/expected-order" ]; then
	check_expected_order "$base_dir/expected-order"
fi
if [ -f "$scenario_dir/expected-order" ]; then
	check_expected_order "$scenario_dir/expected-order"
fi

echo "Medusa QEMU scenario '$scenario' passed"
