Medusa LSM hook coverage roadmap
================================

This file tracks security operations that should be exposed to Medusa policy.
Medusa must use semantic LSM hooks rather than intercepting raw syscall
numbers.  A single LSM hook can therefore cover several syscall variants, and
new syscalls using an existing kernel operation may be covered automatically.

Before wiring a hook
--------------------

Every newly enforced hook must:

* preserve normal Linux error codes and compose correctly with other LSMs;
* avoid asking the authorization server about the server itself;
* define fail-open or fail-closed behaviour explicitly;
* emit an audit record when validation or authorization fails open;
* include kernel-cache, delegated allow, delegated deny, disconnect, and
  authorization-server restart tests;
* use kernel object identity rather than a userspace pathname where possible;
* have a QEMU test proving that the policy event reached Constable;
* document whether the hook may sleep and whether it can run in atomic context;
* include a performance test when the hook is on a frequent path.

Priority 1: complete existing process controls
----------------------------------------------

Delegated signal authorization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Syscall families:

* ``kill``, ``tkill``, ``tgkill``;
* ``pidfd_send_signal``.

LSM hooks:

* ``task_kill``.

Existing code:

* ``acctype_sendsig.c`` is registered but not delegated by the active hook;
* the active hook currently performs only a virtual-space check.

Tasks:

* [x] Route the existing ``sendsig`` event through ``task_kill``.
* [x] Preserve the current virtual-space check as a local fast-path constraint.
* [ ] Test cross-space allow and deny decisions.
* [ ] Test signal delivery to and from the authorization server.
* [ ] Test PID namespaces and ``pidfd_send_signal``.

Ptrace authorization
~~~~~~~~~~~~~~~~~~~~

Syscall families:

* ``ptrace``;
* process inspection paths that use ptrace access checks.

LSM hooks:

* ``ptrace_access_check``;
* ``ptrace_traceme``.

Existing code:

* ``acctype_ptrace.c`` is registered but not wired.

Tasks:

* [x] Port and wire the existing ``ptrace`` access type.
* [x] Cover attach, ``PTRACE_TRACEME``, and read-only inspection modes.
* [ ] Test cross-container and cross-user-namespace denial.

Fork and clone authorization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Syscall families:

* ``fork``, ``vfork``;
* ``clone``, ``clone3``.

LSM hooks:

* ``task_alloc`` for clone-time authorization and context initialization;
* ``task_free`` for cleanup.

Existing code:

* task contexts are allocated and inherited;
* ``acctype_fork.c`` is registered but is not called.

Tasks:

* [x] Separate context allocation from the delegated ``fork`` decision.
* [x] Decide whether authorization happens against the parent, proposed child,
      or both.
* [x] Avoid recursion when Constable creates a process or thread.
* [ ] Test all relevant ``clone3`` namespace flags.

Priority 2: close filesystem coverage gaps
------------------------------------------

Explicit file creation
~~~~~~~~~~~~~~~~~~~~~~

Syscall families:

* ``open``, ``openat``, and ``openat2`` with ``O_CREAT``;
* ``creat``.

LSM hooks:

* ``inode_create``;
* ``path_mknod`` remains responsible for special files.

Existing code:

* ``acctype_create.c`` is wired through ``inode_create``;
* the parent directory is the stable object because the child inode does not
  exist yet;
* ``file_open`` remains a separate post-creation/open authorization point.

Tasks:

* [x] Port ``create`` to the Linux 7.1 ``inode_create`` hook signature.
* [x] Authorize before the inode is created.
* [x] Test create, exclusive create, and create-through-open paths.

Read, write, and execute permission
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Syscall families include:

* ``read``, ``readv``, ``pread64``, ``preadv`` and ``preadv2``;
* ``write``, ``writev``, ``pwrite64``, ``pwritev`` and ``pwritev2``;
* descriptor access after ``open`` and after descriptor inheritance or
  transfer.

LSM hooks:

* ``file_permission``;
* ``inode_permission`` where pathname/inode permission checks are required.

Existing code:

* ``acctype_permission.c`` and ``acctype_readwrite.c`` exist;
* the corresponding active hooks are disabled.

Tasks:

* [ ] Define which checks belong to ``file_permission`` versus
      ``inode_permission``.
* [ ] Ensure cached decisions avoid a userspace round trip for every I/O.
* [ ] Test inherited descriptors, ``SCM_RIGHTS``, and files opened before a
      policy-generation change.
* [ ] Benchmark common read/write workloads.

Readlink and lookup
~~~~~~~~~~~~~~~~~~~

Syscall families:

* ``readlink``, ``readlinkat``;
* pathname lookup performed by many filesystem syscalls.

LSM hooks:

* ``inode_readlink``;
* ``inode_permission`` or another supported semantic lookup hook.

Existing code:

* ``acctype_readlink.c`` and ``acctype_lookup.c`` are registered but unwired.

Tasks:

* [ ] Wire ``readlink`` first as the bounded operation.
* [ ] Define the security value of per-component lookup authorization.
* [ ] Do not enable lookup delegation until caching and performance tests
      exist.

Priority 3: container and namespace support
-------------------------------------------

Namespace lifecycle
~~~~~~~~~~~~~~~~~~~

Syscall families:

* ``clone3`` with namespace flags;
* ``unshare``;
* ``setns``.

Relevant LSM hooks and kernel integration points must be reviewed for Linux
7.1; not every namespace transition currently has a dedicated LSM hook.

Tasks:

* [ ] Add cgroup v2 identity to process objects and protocol requests.
* [ ] Add user, mount, PID, network, IPC, and UTS namespace identifiers.
* [ ] Never use a namespace-local PID as the protocol's primary identity.
* [ ] Define policy inheritance when creating and joining namespaces.
* [ ] Invalidate cached decisions when a policy domain or container exits.
* [ ] Test rootless user namespaces and nested containers.

Mount namespace operations
~~~~~~~~~~~~~~~~~~~~~~~~~~

Syscall families:

* ``mount``, ``umount2``, ``move_mount``;
* ``open_tree``, ``fsopen``, ``fsconfig``, ``fsmount``, ``fspick``;
* ``pivot_root`` and ``chroot``.

LSM hooks:

* ``sb_mount``, ``sb_umount``, ``sb_remount``;
* ``sb_pivotroot``;
* ``move_mount``;
* filesystem-context hooks such as ``fs_context_parse_param``.

Tasks:

* [ ] Introduce a mount/filesystem policy object with stable identity.
* [ ] Include mount and user namespace identity in requests and cache keys.
* [ ] Test bind mounts, idmapped mounts, overlayfs, and container rootfs setup.

Cross-container process isolation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tasks:

* [ ] Prevent signals across policy domains unless explicitly allowed.
* [ ] Prevent ptrace and process inspection across policy domains.
* [ ] Define visibility rules for ``/proc`` operations.
* [ ] Prove isolation using two cgroup-v2 workloads with distinct namespaces.

Priority 4: networking
----------------------

Syscall families:

* ``socket`` and ``socketpair``;
* ``bind``, ``connect``, ``listen``, ``accept`` and ``accept4``;
* ``sendto``, ``sendmsg``, ``sendmmsg``;
* ``recvfrom``, ``recvmsg``, ``recvmmsg``;
* relevant socket options and shutdown operations.

LSM hooks:

* ``socket_create`` and ``socket_post_create``;
* ``socket_bind``, ``socket_connect``, ``socket_listen``, ``socket_accept``;
* ``socket_sendmsg``, ``socket_recvmsg``;
* socket blob allocation, clone, and free hooks;
* selected ``socket_setsockopt`` and ``socket_shutdown`` hooks if policy
  semantics require them.

Existing code:

* create, bind, connect, listen, accept, send, and receive access types exist;
* the active socket hook block is commented out;
* socket security blobs require a modern LSM-stacking review.

Tasks:

* [ ] Port socket blobs to the current shared LSM blob infrastructure.
* [ ] Define local, IPv4, IPv6, and netlink object representations.
* [ ] Include network namespace and cgroup identity in decisions.
* [ ] Start with create/bind/connect/listen/accept.
* [ ] Add send/receive only after caching and performance behaviour is clear.
* [ ] Test policy tightening in response to a simulated network incident.

Priority 5: executable memory and privileged operations
-------------------------------------------------------

Executable memory
~~~~~~~~~~~~~~~~~

Syscall families:

* ``mmap``;
* ``mprotect`` and ``pkey_mprotect``;
* executable file mappings.

LSM hooks:

* ``mmap_file``;
* ``file_mprotect``;
* ``mmap_addr`` where low-address mappings matter.

Tasks:

* [ ] Define policy events for executable mappings and W-to-X transitions.
* [ ] Distinguish executable files, anonymous JIT memory, and shared memory.
* [ ] Test denial without breaking normal dynamic linking.

Capabilities and credential transitions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Syscall families include:

* capability-gated operations throughout the kernel;
* ``capset``;
* GID transitions through ``setgid``, ``setregid`` and ``setresgid``.

LSM hooks:

* ``capable``;
* ``capset``;
* ``task_fix_setgid``.

Existing code:

* ``acctype_capable.c`` is unfinished and must not be enabled as-is;
* UID transitions are wired, while GID transitions are not.

Tasks:

* [ ] Implement and test GID transitions before general capability policy.
* [ ] Design a non-recursive cached capability decision path.
* [ ] Include user-namespace identity and distinguish namespaced capabilities.
* [ ] Benchmark capability-heavy workloads.

Kernel attack surface
~~~~~~~~~~~~~~~~~~~~~

Syscall families:

* ``bpf``;
* ``perf_event_open``;
* ``init_module``, ``finit_module``, ``delete_module``;
* ``kexec_load`` and ``kexec_file_load``;
* ``reboot`` and other host-global administration operations.

Relevant LSM hooks include:

* ``kernel_module_request``;
* ``kernel_read_file`` and ``kernel_load_data`` families;
* BPF and perf-event security hooks;
* ``locked_down`` where appropriate.

Tasks:

* [ ] Define separate policy events instead of one generic privileged event.
* [ ] Distinguish host-global operations from container-scoped operations.
* [ ] Default host-global operations from container domains to deny.

Lower-priority operations
-------------------------

Review policy value and current LSM hook availability for:

* ``ioctl`` and device-specific commands;
* file locking;
* scheduling and priority changes;
* resource-limit changes;
* keyrings and secret-management operations;
* fanotify and inotify administration;
* POSIX message queues;
* io_uring setup, registration, and operation-specific authorization.

Protocol prerequisites
----------------------

Before enabling high-frequency or container-scale hooks:

* [x] replace hard-coded protocol constants with versioned definitions;
* [x] support multiple parallel outstanding decisions;
* [x] add request cancellation for exiting tasks;
* [ ] add request cancellation for destroyed objects;
* [x] make timeout and fail-open/fail-closed policy explicit per event;
* [ ] make fallback policy explicit per domain;
* [ ] include policy generation, cgroup, and namespace identity in cache keys;
* [x] avoid kernel pointers in the protocol ABI and non-sleepable cache keys;
* [ ] add stable identifiers for every non-process object class;
* [x] define backpressure and authorization-server overload behaviour;
* [ ] fuzz request and response decoding.

Non-goals
---------

* Do not restore generic raw-syscall interception.
* Do not replace seccomp, AppArmor, SELinux, or container runtime isolation.
* Do not permit an untrusted container to register as the host authorization
  server.
