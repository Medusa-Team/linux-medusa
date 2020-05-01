#include <linux/medusa/l3/registry.h>
#include <linux/mm.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/namei.h>

#include "kobject_process.h"

struct path_access {
	MEDUSA_ACCESS_HEADER;
	char action[NAME_MAX+1];
};

MED_ATTRS(path_access) {
	MED_ATTR_RO (path_access, action, "action", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(path_access, "path_access", process_kobject, "process",
		process_kobject, "process");

int __init path_acctype_init(void) {
	MED_REGISTER_ACCTYPE(path_access,
	MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

/**
 * prepend() - prepend a @str in front of current @buf pointer
 * @buf: buffer pointer
 * @buflen: allocated length of the buffer
 * @str: string to prepend
 * @strlen: length of string to prepend
 *
 * Note 1: To also prepend terminating %NULL character of @str, @strlen
 *         must be incremented by this character (i.e. by one)!
 * Note 2: Function is taken from fs/d_path.c
 */
static int prepend(char **buf, int buflen, const char *str, int strlen)
{
	buflen -= strlen;
	if (buflen < 0)
		return -ENAMETOOLONG;
	*buf -= strlen;
	memcpy(*buf, str, strlen);
	return 0;
}

/**
 * medusa_get_path_from_string() - put @str to the end of a newly allocated
 *                                 buffer
 * @str: string to place to the end of the buffer
 *
 * Return: Newly allocated buffer with @str inserted to the end of it,
 * or %NULL on allocation failure.
 *
 * Note: Buffers allocated with this function should be freed by calling
 *       medusa_put_path() function.
 */
inline char *medusa_get_path_from_string(const char *str)
{
	char *buf = __getname();
	if (buf) {
		buf += PATH_MAX;
		prepend(&buf, PATH_MAX, str, strlen(str)+1);
	}
	return buf;
}

/**
 * medusa_put_path() - free buffer used for pathname string
 * @pathbuf: buffer to free
 *
 * Free buffer allocated with __getname() and filled by d_absolute_path(),
 * which fills the buffer starting from its end. __putname() should receive the
 * same pointer as obtained from __getname().
 */
inline void medusa_put_path(char **pathbuf)
{
	if (!*pathbuf)
		return;
	__putname(*pathbuf - PATH_MAX + strlen(*pathbuf) + 1);
	*pathbuf = NULL;
}

/**
 * medusa_get_path() - return a pointer to the full path
 * @path: path to report
 * @last: if not %NULL, last element of the path
 * @lasttype: type of the last element of the path
 *
 * Return: Pointer into the full pathname string or error code if an error
 *         occurs. A buffer to which a pointer is returned is allocated from the
 *         slab, so callers have to free it by calling medusa_put_path().
 */
char *medusa_get_path(const struct path *path, const struct qstr *last,
		      int lasttype)
{
	const char *lastname = NULL;
	char *lastptr;
	char *buf = NULL;
	char *pathbuf = NULL;

	int lastlen = 0;
	int buflen = PATH_MAX;

	buf = __getname();
	if (!buf)
		return ERR_PTR(-ENOMEM);

	/**
	 * DOC: Last element of the path
	 *
	 * d_absolute_path() prepends a path starting from the end of a buffer.
	 * If @last element of the path is given, we should prepare a space
	 * in the buffer for adding @last after d_absolute_path() call is made.
	 * Ending '/' characters in @last element should be removed, as we
	 * always want to obtain all paths in the same normalized form.
	 * If type of @last is '.' or '..', do not append anything to the path.
	 */
	if (lasttype == LAST_NORM) {
		lastlen = READ_ONCE(last->len);
		lastname = smp_load_acquire(&last->name);

		lastptr = (char*)lastname + lastlen - 1;
		while (*lastptr == '/') {
			lastlen--;
			lastptr--;
		}

		if (lastlen)
			buflen -= lastlen + 1;
	}

	pathbuf = d_absolute_path(path, buf, buflen);
	if (IS_ERR(pathbuf)) {
		__putname(buf);
		return pathbuf;
	}

	if (lasttype == LAST_NORM) {
		buflen = strlen(pathbuf);
		pathbuf[buflen] = '/';
		memcpy(pathbuf+buflen+1, lastname, lastlen);
		buf[PATH_MAX-1] = '\0';
	} else if (lasttype == LAST_DOTDOT) {
		int diff = 0;
		char *slash = strrchr(pathbuf, '/');
		if (slash) {
			diff = strlen(slash);
			*slash = '\0';
			while (slash >= pathbuf) {
				*(slash + diff) = *slash;
				slash--;
			}
			pathbuf += diff;
		}
	}

	return pathbuf;
}

/**
 * medusa_path_access() - make decision about path redirection
 * @action: path access type string descripion ('mkdir', 'unlink', 'symlink',
 *          ...)
 * @path_to_redirect: in/out param; stores pointer to a buffer, where a path is
 *      stored (string), which is the object of decision. If redirection
 *      shouldn't be relized, @path_to_redirect must be set to %NULL using
 *      medusa_put_path() function call. This call will free buffer in correct
 *      way and set its argument to %NULL. If @path_to_redirect on return is not
 *      %NULL, underlaying path string is used for redirection to it.
 *
 * Return: Decision answer, which can be one of:
 *         * %MED_FAKE_ALLOW - force caller function to terminate with a SUCCESS
 *               after return
 *         * %MED_DENY - deny executing caller function after return
 *         * other values(s), i.e. %MED_ALLOW - allow executing caller function
 *               after return
 *
 * After returning to caller:
 *      If return value is not (%MED_DENY || %MED_FAKE_ALLOW) and
 *      @path_to_redirect is not %NULL, caller's path access is redirected to
 *      path pointed by @path_to_redirect output parameter. If return value is
 *      %MED_DENY or %MED_FAKE_ALLOW, value of output parameter
 *      @path_to_redirect *must be* %NULL.
 */
medusa_answer_t medusa_path_access(const char *action, char **path_to_redirect)
{
	//struct path_access access;
	//struct process_kobject process;
	medusa_answer_t retval;

	if (strncmp(*path_to_redirect, "/tmp/medusa_path",strlen("/tmp/medusa_path")) == 0) {
		med_pr_debug("MEDUSA PATH_ACCESS 1: act='%s', path_to_redirect='%s'",
			     action, *path_to_redirect);

		if (strcmp(*path_to_redirect, "/tmp/medusa_path_deny") == 0)
			retval = MED_DENY;
		else if (strcmp(*path_to_redirect, "/tmp/medusa_path_allow") == 0)
			retval = MED_ALLOW;
		else if (strcmp(*path_to_redirect, "/tmp/medusa_path_fake_allow") == 0)
			retval = MED_FAKE_ALLOW;
		else if (strcmp(*path_to_redirect, "/tmp/medusa_path_redirect") == 0) {
			retval = MED_ALLOW;
			medusa_put_path(path_to_redirect);
			*path_to_redirect = medusa_get_path_from_string("/tmp/redirected");
			goto out;
		}
		medusa_put_path(path_to_redirect);
out:
		med_pr_debug("MEDUSA PATH_ACCESS 2: act='%s', path_redirected_to='%s', retval=%d\n",
			     action, *path_to_redirect, retval);
		return retval;
	}

	/*
	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (MEDUSA_MONITORED_ACCESS_S(path_access, task_security(current))) {
		memset(&access, '\0', sizeof(struct path_access));
		strncpy(access.action, action, NAME_MAX);
		access.action[strlen(action)] = '\0';
		process_kern2kobj(&process, current);
		retval = MED_DECIDE(path_access, &access, &process, &process);
		return retval;
	}
	*/
	return MED_ALLOW;
}

int medusa_monitored_path(void)
{
	return MEDUSA_MONITORED_ACCESS_S(path_access, task_security(current));
}

void medusa_monitor_path(int flag)
{
	if (flag)
		MEDUSA_MONITOR_ACCESS_S(path_access, task_security(current));
	else
		MEDUSA_UNMONITOR_ACCESS_S(path_access, task_security(current));
}
__initcall(path_acctype_init);
