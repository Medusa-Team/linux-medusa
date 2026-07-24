Medusa regression coverage on Linux 7.1
=======================================

This file is a coverage inventory, not a claim that every registered Medusa
event is enforced.  In particular, a successful syscall is only a behaviour
check unless the scenario also requires a ``MEDUSA_EVENT`` console marker.

Kernel unit coverage
--------------------

The KUnit configuration runs 39 tests in seven suites:

* virtual-space read, write, visibility, intersection, and bitmap boundaries;
* subject and object action bitmaps and monitored/unmonitored contexts;
* policy-generation rollover and forced stale-context invalidation;
* task initialization and inheritance plus inode and all SysV IPC contexts;
* authorization-server registration, removal, and generation changes;
* cached/delegated allow, deny, error/fail-open, and unsupported verdicts;
* protocol-v3 answer lengths, verdicts, unknown IDs, and stale IDs;
* cache allocator growth across a size-class boundary.

QEMU scenario coverage
----------------------

``cache``
  Demonstrates one delegated ``mkdir`` followed by a kernel-cached decision
  after Constable clears the directory monitoring bit.

``access``
  Exercises create/open/write/fcntl/chmod/chown/truncate, symlink/link/rename/
  unlink, mknod, mkdir/rmdir, chroot, exec, fork, signals, setresuid, and the
  message-queue, semaphore, and shared-memory operations exposed by the active
  LSM hooks.  The scenario requires Constable markers for ``ipc_perm``,
  ``ipc_ctl``, ``ipc_semop``, ``ipc_shmat``, ``ipc_msgsnd``, and
  ``ipc_msgrcv``.  Other successful operations are behaviour
  characterizations, not proof of delegation.

``lifecycle``
  Covers initial registration, disconnect, fail-open operation, replacement
  registration, enforcement of a reloaded deny policy, positive audit output
  for a server-requested IPC operation, and the known missing audit record on
  the disconnected stale-context path.  Negative expected-result lines make
  the missing record an explicit assertion.

Wired access paths
------------------

The Linux 7.1 LSM table currently calls Medusa for:

* executable credentials (``pexec`` and ``fexec``);
* path unlink, mkdir, rmdir, mknod, truncate, symlink, link, rename, chmod,
  chown, and chroot;
* file open, fcntl, and truncate;
* set-user-ID credential changes;
* signal virtual-space checks;
* SysV IPC permission, associate, control, semop, shmat, msgsnd, and msgrcv;
* task, inode, and SysV IPC security-context allocation.

Task allocation initializes or inherits a context, but does not call the
registered ``fork`` access type.  Signal delivery performs a virtual-space
check, but there is no registered delegated ``sendsig`` event.

Registered but not wired
------------------------

The following access types are announced to Constable but have no active Linux
7.1 LSM call site: ``after_exec``, ``capable``, ``create``, ``fork``, ``init``,
``lookup``, ``notify_change``, ``permission``, ``readlink``, ``sexec``,
``ptrace``, and all socket create/bind/connect/listen/accept/send/receive
events.  The socket hook block is commented out.  ``syscall`` is likewise not
part of the normal tested configuration.

Consequently, file creation in ``access`` is currently observed through the
post-create open path; it does not prove the registered ``create`` event.
Process creation verifies context inheritance and syscall behaviour; it does
not prove a delegated ``fork`` decision.

Known defects kept separate from expected behaviour
---------------------------------------------------

* If an object or process is validated while no authorization server exists,
  the current fail-open path marks it permanently unmonitored.  A later server
  generation does not automatically re-monitor it.
* Re-associating with an existing message queue, semaphore set, or shared
  memory object returns ``EACCES`` even when ``ipc_perm`` is allowed.
  ``ipc_associate`` is not observed.
* The disconnected stale-context validation path returns before the access
  callback's audit block, so its fail-open decision has no Medusa audit record.
* Multiple ``getfile`` callbacks can overwrite one another's object snapshot;
  the Constable path-tree callback and an explicit policy callback are not
  safely composable.

These findings are test expectations for the revival branch.  Fixes should be
separate commits that deliberately update the corresponding expected results.
