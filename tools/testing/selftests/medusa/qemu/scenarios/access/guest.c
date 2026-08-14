// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

union semun {
	int val;
	struct semid_ds *buf;
	unsigned short *array;
};

static int failures;

static void result(const char *name, bool passed)
{
	printf("MEDUSA_RESULT access %s %s\n", name,
	       passed ? "PASS" : "FAIL");
	if (!passed) {
		printf("MEDUSA_DETAIL access %s errno=%d (%s)\n",
		       name, errno, strerror(errno));
		failures++;
	}
}

static void expected_eacces(const char *name, long value)
{
	bool passed = value < 0 && errno == EACCES;

	printf("MEDUSA_RESULT access %s %s\n", name,
	       passed ? "PASS" : "FAIL");
	if (!passed) {
		printf("MEDUSA_DETAIL access %s expected=EACCES value=%ld errno=%d (%s)\n",
		       name, value, errno, strerror(errno));
		failures++;
	}
}

static bool prime_path(const char *path, int flags)
{
	int fd = open(path, flags);

	if (fd < 0)
		return false;
	return close(fd) == 0;
}

static void test_filesystem(void)
{
	int fd;
	pid_t pid;
	int status;

	result("mkdir", mkdir("/tmp/access", 0755) == 0);
	result("validate_directory",
	       prime_path("/tmp/access", O_RDONLY | O_DIRECTORY));
	fd = open("/tmp/access/file", O_CREAT | O_RDWR, 0644);
	result("create_open", fd >= 0);
	if (fd >= 0) {
		result("write", write(fd, "medusa", 6) == 6);
		result("fcntl", fcntl(fd, F_SETFL, O_APPEND) == 0);
		result("close", close(fd) == 0);
	}
	result("chmod", chmod("/tmp/access/file", 0600) == 0);
	result("chown", chown("/tmp/access/file", 0, 0) == 0);
	result("truncate", truncate("/tmp/access/file", 2) == 0);
	result("symlink",
	       symlink("/tmp/access/file", "/tmp/access/symlink") == 0);
	result("link", link("/tmp/access/file", "/tmp/access/hardlink") == 0);
	result("rename",
	       rename("/tmp/access/hardlink", "/tmp/access/renamed") == 0);
	result("unlink_renamed", unlink("/tmp/access/renamed") == 0);
	result("unlink_symlink", unlink("/tmp/access/symlink") == 0);
	result("mknod_fifo",
	       mknod("/tmp/access/fifo", S_IFIFO | 0600, 0) == 0);
	result("unlink_fifo", unlink("/tmp/access/fifo") == 0);
	result("mkdir_empty", mkdir("/tmp/access/empty", 0755) == 0);
	result("validate_empty_directory",
	       prime_path("/tmp/access/empty", O_RDONLY | O_DIRECTORY));
	result("rmdir", rmdir("/tmp/access/empty") == 0);
	result("mkdir_jail", mkdir("/tmp/access/jail", 0755) == 0);
	result("validate_jail_directory",
	       prime_path("/tmp/access/jail", O_RDONLY | O_DIRECTORY));

	pid = fork();
	if (pid == 0)
		_exit(chroot("/tmp/access/jail") == 0 ? 0 : 1);
	result("chroot", pid > 0 && waitpid(pid, &status, 0) == pid &&
	       WIFEXITED(status) && WEXITSTATUS(status) == 0);

	result("unlink_file", unlink("/tmp/access/file") == 0);
	result("rmdir_jail", rmdir("/tmp/access/jail") == 0);
	result("rmdir_root", rmdir("/tmp/access") == 0);
}

static void test_processes(void)
{
	pid_t pid;
	int status;

	result("validate_exec", prime_path("/bin/true", O_RDONLY));

	pid = fork();
	if (pid == 0)
		_exit(0);
	result("fork", pid > 0 && waitpid(pid, &status, 0) == pid &&
	       WIFEXITED(status) && WEXITSTATUS(status) == 0);

	pid = fork();
	if (pid == 0) {
		execl("/bin/true", "true", NULL);
		_exit(127);
	}
	result("exec", pid > 0 && waitpid(pid, &status, 0) == pid &&
	       WIFEXITED(status) && WEXITSTATUS(status) == 0);

	pid = fork();
	if (pid == 0) {
		alarm(2);
		pause();
		_exit(1);
	}
	if (pid > 0)
		kill(pid, SIGTERM);
	result("signal", pid > 0 && waitpid(pid, &status, 0) == pid &&
	       WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);

	pid = fork();
	if (pid == 0)
		_exit(setresuid(1, 1, 1) == 0 ? 0 : 1);
	result("credentials", pid > 0 && waitpid(pid, &status, 0) == pid &&
	       WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_message_queue(void)
{
	struct {
		long type;
		char text[8];
	} message = { 1, "medusa" };
	struct msqid_ds info;
	key_t key = 0x4d010001;
	int id = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
	int associated;

	result("msg_create", id >= 0);
	errno = 0;
	associated = id >= 0 ? msgget(key, 0600) : -1;
	expected_eacces("msg_associate_expected_deny", associated);
	result("msg_send",
	       id >= 0 && msgsnd(id, &message, sizeof(message.text), 0) == 0);
	memset(message.text, 0, sizeof(message.text));
	result("msg_receive",
	       id >= 0 &&
	       msgrcv(id, &message, sizeof(message.text), 1, 0) >= 0);
	result("msg_stat", id >= 0 && msgctl(id, IPC_STAT, &info) == 0);
	result("msg_remove", id >= 0 && msgctl(id, IPC_RMID, NULL) == 0);
}

static void test_semaphores(void)
{
	struct sembuf operation = { 0, 1, 0 };
	union semun argument = { .val = 0 };
	key_t key = 0x4d010002;
	int id = semget(key, 1, IPC_CREAT | IPC_EXCL | 0600);
	int associated;

	result("sem_create", id >= 0);
	errno = 0;
	associated = id >= 0 ? semget(key, 1, 0600) : -1;
	expected_eacces("sem_associate_expected_deny", associated);
	result("sem_op", id >= 0 && semop(id, &operation, 1) == 0);
	result("sem_remove",
	       id >= 0 && semctl(id, 0, IPC_RMID, argument) == 0);
}

static void test_shared_memory(void)
{
	struct shmid_ds info;
	key_t key = 0x4d010003;
	int id = shmget(key, 4096, IPC_CREAT | IPC_EXCL | 0600);
	int associated;
	void *memory;

	result("shm_create", id >= 0);
	errno = 0;
	associated = id >= 0 ? shmget(key, 4096, 0600) : -1;
	expected_eacces("shm_associate_expected_deny", associated);
	memory = id >= 0 ? shmat(id, NULL, 0) : (void *)-1;
	result("shm_attach", memory != (void *)-1);
	if (memory != (void *)-1) {
		strcpy(memory, "medusa");
		result("shm_detach", shmdt(memory) == 0);
	}
	result("shm_stat", id >= 0 && shmctl(id, IPC_STAT, &info) == 0);
	result("shm_remove", id >= 0 && shmctl(id, IPC_RMID, NULL) == 0);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	test_filesystem();
	test_processes();
	test_message_queue();
	test_semaphores();
	test_shared_memory();
	printf("MEDUSA_RESULT access complete %s\n",
	       failures ? "FAIL" : "PASS");
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
