# SPDX-License-Identifier: GPL-2.0-only

profile medusa-stacking /bin/medusa-guest {
	network,
	/tmp/medusa-apparmor-allowed/ w,
	audit deny /tmp/medusa-apparmor-denied/ w,
}
