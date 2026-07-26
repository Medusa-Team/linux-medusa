Medusa delegated-decision locking contract
===========================================

Medusa's userspace decision path blocks the calling task.  A hook being in
task context therefore proves only that scheduling is technically possible;
it does not prove that an arbitrarily long authorization-server or human wait
is deadlock-safe.

The ``delegation`` field in ``/sys/kernel/security/medusa/events`` records the
worst known context for each event:

``none``
  The event is announced to protocol v3 but no installed LSM hook reaches it.

``sleepable``
  The active call path is process context and no subsystem lock known to
  create a Constable lock inversion spans the decision.  This classification
  still does not permit recursion into Medusa or access to the blocked task's
  mutable state.

``lock_bound``
  The task may schedule, but a VFS inode or rename lock spans the decision.
  Constable and any interactive prompt broker must not touch the affected
  filesystem or wait for a service which might need the same lock.

``conditional``
  The event is reachable through more than one context, or its implementation
  must drop RCU/spinlock state and hold an object reference before delegating.
  The runtime non-sleepable-context check remains authoritative.

This metadata is deliberately conservative and machine-readable.  Adding a
new call site requires updating both this table and the boot-time event
inventory in ``l1/medusa.c``.

Active hook matrix
------------------

============================= ============================= ============== ================================================
Event                         LSM hook or dependency         Delegation     State spanning a delegated decision
============================= ============================= ============== ================================================
``pexec``, ``fexec``           ``bprm_creds_for_exec``       sleepable      Exec preparation; no VFS inode lock at this hook
``getprocess``                 validation dependency         conditional    Inherits the context of its caller
``getfile``                    validation dependency         conditional    Inherits exec, open, truncate, or path context
``getipc``                    validation dependency         conditional    IPC ref held after RCU/spinlock release
``truncate``                  ``path_truncate`` and          sleepable      Mount writer and inode write-access reference;
                              ``file_truncate``                             hook runs before ``do_truncate()`` inode locking
``fcntl``                     ``file_fcntl``                sleepable      File reference; hook precedes command-specific locks
``open``                      ``file_open``                 conditional    Existing-file opens are sleepable; create/atomic-open
                                                                           paths can retain the parent inode ``i_rwsem``
``setresuid``                 ``task_fix_setuid``           sleepable      Prepared credentials, not yet committed
``mknod``, ``mkdir``,         corresponding ``path_*``      lock_bound     Parent directory ``i_rwsem``
``symlink``, ``link``
``unlink``, ``rmdir``         corresponding ``path_*``      lock_bound     Parent directory ``i_rwsem``
``rename``                    ``path_rename``               lock_bound     Rename mutex and one or two parent inode ``i_rwsem`` locks
``chmod``, ``chown``          corresponding ``path_*``      lock_bound     Target inode ``i_rwsem``
``chroot``                    ``path_chroot``               sleepable      Stable path reference; no inode lock at the hook
``ipc_perm``                  ``ipc_permission``            conditional    RCU and a sometimes-held IPC object spinlock are
                                                                           released when ownership is provable; IPC ref retained
``ipc_associate``             IPC associate hooks           conditional    IPC object spinlock and RCU released; IPC ref retained
``ipc_msgsnd``,               message queue hooks           conditional    IPC object spinlock and RCU released; IPC ref retained
``ipc_msgrcv``
``ipc_ctl``                   IPC control hooks             conditional    RCU released; IPC ref retained
``ipc_semop``                 ``sem_semop``                 conditional    RCU released; IPC ref retained
``ipc_shmat``                 ``shm_shmat``                 conditional    RCU released; IPC ref retained
============================= ============================= ============== ================================================

Runtime rules
-------------

The character-device transport refuses the slow path unless ``in_task()`` is
true, preemption is enabled, and interrupts are enabled.  Such refusal is an
unavailable decision and selects the event's installed fallback policy.

SysV IPC access functions take an object reference before dropping their RCU
read section.  Hooks entered with the current task's IPC object spinlock held
also release that lock before delegation and reacquire/revalidate it
afterwards.  If lock ownership cannot be established safely, Medusa must not
sleep.  Some IPC paths can retain the namespace IPC IDs ``rwsem``; Constable
must therefore never use SysV IPC while servicing a request.

The authorization server is exempt from recursive Medusa decisions.  A
separate graphical prompt process is not automatically exempt.  It must use
an independently pre-authorized communication and executable/file set;
otherwise the prompt can recursively wait on the decision it is meant to
answer.

Renewable leases do not relax this contract.  A progress message proves only
that Constable is alive.  Interactive renewal is safest for ``sleepable``
events.  Supporting human waits for ``lock_bound`` or ``conditional`` events
requires a design which moves the decision before the lock, snapshots stable
object identity, or explicitly proves the prompt path cannot acquire a
conflicting lock.

Lockdep validation
------------------

The QEMU ``lockdep`` scenario inherits the complete ``access`` operation
suite.  Its kernel must enable ``PROVE_LOCKING``, ``DEBUG_SPINLOCK``, and
``DEBUG_ATOMIC_SLEEP``.  The scenario requires a Constable event marker for
every exercised active access type and rejects atomic-sleep, recursive-lock,
and circular-locking diagnostics.

Passing that scenario proves the exercised kernel configuration and paths; it
does not turn a static ``lock_bound`` classification into ``sleepable`` and it
does not prove arbitrary Constable or desktop-service behavior deadlock-free.
