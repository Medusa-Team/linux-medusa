// SPDX-License-Identifier: GPL-2.0

#include <linux/completion.h>
#include <linux/namei.h>
#include <linux/umh.h>

#include "l4/auth_server.h"
#include "l3/arch.h"

static const char *auth_server_loader = CONFIG_MEDUSA_AUTH_SERVER_LOADER;
DECLARE_COMPLETION(auth_server_ready);

void set_auth_server_ready(void)
{
	med_pr_info("Authorization server ready");
	complete_all(&auth_server_ready);
}

void wait_for_auth_server(void)
{
	med_pr_info("Waiting for authorization server to be ready");
	wait_for_completion(&auth_server_ready);
}

static bool auth_server_loader_exists(void)
{
	struct path path;

	if (kern_path(auth_server_loader, LOOKUP_FOLLOW, &path))
		return false;

	path_put(&path);
	return true;
}

void start_auth_server(void)
{
	char * const argv[] = { "/bin/sh", "-c", auth_server_loader, NULL };
	char * const envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	int error;

	if (!auth_server_loader_exists()) {
		med_pr_err("Could not start authorization server because the "
			   "specified loader does not exist!");
		return;
	}

	med_pr_info("Trying to start authorization server");
	error = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (error) {
		med_pr_err("Error starting authorization server: %d", error);
		// TODO: stop if production Medusa
		return;
	}
	wait_for_auth_server();
	med_pr_info("Authorization server started");
}
