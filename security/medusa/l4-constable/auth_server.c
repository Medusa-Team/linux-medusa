#include <linux/completion.h>

#include "l4/auth_server.h"
#include "l3/arch.h"


DECLARE_COMPLETION(auth_server_ready);

void wait_for_auth_server()
{
    med_pr_info("Waiting for authorization server to be ready");
    wait_for_completion(&auth_server_ready);
}

void set_auth_server_ready()
{
    med_pr_info("Authorization server ready");
    complete_all(&auth_server_ready);
}