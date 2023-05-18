// SPDX-License-Identifier: GPL-2.0

#include <linux/completion.h>
#include <linux/namei.h>
#include <linux/umh.h>

#include "l4/auth_server.h"
#include "l3/arch.h"

static char *auth_server_loader = CONFIG_MEDUSA_AUTH_SERVER_LOADER;
DECLARE_COMPLETION(auth_server_ready);

void set_auth_server_ready(void)
{
	med_pr_info("Authorization server ready");
	complete_all(&auth_server_ready);
}

void wait_for_auth_server(void)
{
	unsigned long timeout = MAX_SCHEDULE_TIMEOUT;

	if (IS_ENABLED(CONFIG_SECURITY_MEDUSA_CONTINUE_BOOTING))
		timeout = CONFIG_SECURITY_MEDUSA_CONTINUE_BOOTING_TIMEOUT * 1000;

	med_pr_info("Waiting for authorization server to be ready");
	timeout = wait_for_completion_timeout(&auth_server_ready,
					      msecs_to_jiffies(timeout));
	if (!timeout)
		med_pr_err("Start of the authorization server via `%s' failed",
			   auth_server_loader);
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
	char *argv[] = { "/bin/sh", "-c", auth_server_loader, NULL };
	char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	int error;

	if (!auth_server_loader_exists()) {
		med_pr_info("Could not start authorization server because the "
			    "specified loader `%s' does not exist!",
			    auth_server_loader);
		return;
	}

	med_pr_info("Trying to start authorization server");
	error = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (error)
		med_pr_err("Error starting authorization server: %d", error);
}
