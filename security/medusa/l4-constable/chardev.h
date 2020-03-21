#ifndef _CHARDEV_H
#define _CHARDEV_H

typedef enum {
	AUTHS_NOT_REACHED = -2,
	AUTHS_ERR = -1,
	AUTHS_FORCE_ALLOW = 0,
	AUTHS_DENY = 1,
	AUTHS_SKIP = 2,
	AUTHS_ALLOW = 3,
	AUTHS_DBG_ALLOW = 10
} authserver_answer_t

#endif /* _CHARDEV_H */
