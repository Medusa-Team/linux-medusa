#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

if [ "$#" -ne 2 ]; then
	echo "usage: $0 MDP OUTPUT_POLICY" >&2
	exit 2
fi

mdp="$(realpath "$1")"
output="$(realpath -m "$2")"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/medusa-selinux-policy.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

if ! command -v checkpolicy >/dev/null; then
	echo "missing required command: checkpolicy" >&2
	exit 2
fi
if [ ! -x "$mdp" ]; then
	echo "missing executable mdp: $mdp" >&2
	exit 2
fi

"$mdp" -m "$work_dir/policy.conf" "$work_dir/file_contexts"

awk '
	/^policycap / { next }
	{ print }
	$0 == "type base_t;" {
		print "type medusa_test_t;"
	}
	$0 == "role base_r types { base_t };" {
		print "role base_r types { medusa_test_t };"
		print "allow base_t medusa_test_t:process *;"
		print "allow medusa_test_t medusa_test_t:process *;"
		print "allow medusa_test_t base_t:file" \
		      " { entrypoint execute read open getattr map };"
		print "allow medusa_test_t base_t:chr_file" \
		      " { write ioctl getattr };"
		print "allow medusa_test_t base_t:fd use;"
		print "allow medusa_test_t self:" \
		      "{ socket unix_stream_socket unix_dgram_socket" \
		      " tcp_socket udp_socket } *;"
	}
' "$work_dir/policy.conf" >"$work_dir/test-policy.conf"

checkpolicy -U allow -M -o "$output" "$work_dir/test-policy.conf"
