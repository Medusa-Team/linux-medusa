Medusa regression coverage on Linux 7.1
=======================================

This file is a coverage inventory, not a claim that every registered Medusa
event is enforced.  In particular, a successful syscall is only a behaviour
check unless the scenario also requires a ``MEDUSA_EVENT`` console marker.

Kernel unit coverage
--------------------

The KUnit configuration runs 81 tests in twelve suites:

* virtual-space read, write, visibility, intersection, and bitmap boundaries;
* subject and object action bitmaps and monitored/unmonitored contexts;
* policy-generation rollover and forced stale-context invalidation;
* task initialization and inheritance plus inode and all SysV IPC contexts;
* path-guard initialization, invalid inputs, add/lookup/remove behavior,
  duplicate suppression, independent entries, and teardown;
* authorization-server registration, removal, and generation changes;
* delegated allow and deny, installed baseline fallback, online-required
  fallback, and unsupported verdicts;
* authoritative object validation accepts only a supported Constable reply,
  never an unavailable-policy fallback or incomplete server result;
* protocol-v3 answer lengths, verdicts, unknown IDs, and stale IDs;
* cache allocator growth across a size-class boundary;
* dynamic task, inode, and SysV IPC LSM blob offsets;
* bounded audit-answer formatting and LSM return-value translation;
* decision-source, authorization-server contact, and unavailability audit
  metadata, including request ID and policy generation;
* independent pending-request IDs, out-of-order replies, policy generations,
  duplicate and unknown replies, bounded capacity, disconnect cleanup,
  timeout races, and renewable liveness leases;
* authorization-server health and circuit-breaker transitions;
* teardown-safe authorization-server status snapshots, handshake, READY and
  aborted-handshake transitions, optional health callbacks, and stable
  observability names;
* per-event final-verdict attribution, unsigned counter wrap, and cumulative
  protocol-counter snapshots;
* monitoring-bit evaluation, kernel-cache hit, and enforced-event accounting;
* stable protocol-error audit kind names.

Pending decision engine
-----------------------

Delegated decisions no longer store their answer in the calling task's
security blob.  Each slow-path call owns a pending request with an independent
completion, monotonically allocated 64-bit ID, and policy generation.  A
bounded global table permits 1,024 concurrent requests.  Completion removes
the request before waking its waiter, so unknown, duplicate, and stale-
generation replies cannot complete a different request.  Disconnect removes
and completes every remaining request with ``MED_ERR``.

Renewable decision leases
-------------------------

The five-second decision interval is a liveness lease, not a maximum decision
duration.  Protocol command ``MEDUSA_COMM_AUTHREQUEST_PROGRESS`` renews the
lease of one pending request by its 64-bit request ID.  Constable exposes
``mcp_renew_authrequest()`` so an interactive handler can renew before each
lease expires while it waits for a human decision.  Renewal carries no
verdict and cannot alter installed policy.

If a request is silent for a complete lease, the pending request is removed
and the authorization server's circuit breaker opens.  Existing waiters wake
and apply their event-specific installed fallback; unrelated new operations
immediately use their own installed fallback without filling the pending
table.  A new Constable registration closes the breaker.  Lease duration is
configured by ``CONFIG_SECURITY_MEDUSA_DECISION_LEASE_MS`` and defaults to
5,000 milliseconds.

The degraded QEMU scenario also connects a minimal protocol-v3 server, completes
the dynamically announced class and event handshake, and holds one real
delegated request for eight seconds.  The server renews that request after
three and six seconds before sending its final answer.  The test requires the
waiting operation to remain blocked past the original five-second lease,
exactly one matched reply, at least two lease renewals, and no pending request
after the server closes.  This complements the silent-server case in the same
scenario, which must still expire after one lease and enter degraded mode.

The minimal server deliberately does not implement object fetch/update.  After
a reconnect, its renewed request can therefore be an object revalidation
request rather than the eventual access event.  The integration assertion is
about transport liveness and matched completion; it does not claim that a
progress frame installs policy or refreshes an object context.

Long waits remain subject to the hook-specific locking contract in
``LOCKING.rst``.  In particular, a progress message proves Constable liveness;
it does not make a VFS-lock-bound or conditional IPC hook safe for an
arbitrarily slow human interaction.

Unavailable decision fallback
-----------------------------

Every event type has one atomically replaceable fallback policy.  Baseline
allow preserves the legacy default while still consulting a healthy
authorization server.  Baseline deny is authoritative and cannot be weakened
by a userspace allow.  Online-required denies only its event when no answer is
available.  Absence of Constable and transport failure no longer unmonitor
kernel objects, so an outage does not discard the installed monitoring state.

The decision result separately records its answer, source, unavailability
reason, whether Constable was actually contacted, request ID, and policy
generation.  Every unavailable-policy fallback increments an event-local
counter and emits a structured audit record containing the event and object
class names, active protocol, runtime trigger bit, verdict provenance, request
metadata, and precise failure reason.  Repeated records are limited
independently for each event to ten per five seconds; the next emitted record
reports how many were suppressed while the counter continues accounting for
every decision.  Stable numeric class and event IDs remain protocol-v4 work.

Lease expiry, queue overload, a non-sleepable call site, an unhealthy server,
transport failure, and absence of Constable have distinct audit reason names.
The migrated ``mkdir`` and ``ipc_msgsnd`` operation-specific audit paths also
carry request ID and policy generation while retaining the compatible
``as_request`` field.

Process, file, SysV IPC, and socket context validation requires a supported,
authoritative Constable reply and verifies that userspace installed a valid
context.  A lease timeout, open circuit, disconnected server, or installed
fallback verdict therefore cannot be mistaken for a successful context
refresh.

Read-only securityfs observability
----------------------------------

When Medusa is enabled it creates three root-readable files:

``/sys/kernel/security/medusa/status``
  Reports the running kernel, protocol, and audit schema versions;
  disconnected, handshaking, and READY state; policy readiness; server health
  and precise circuit-breaker reason; active and last READY generations; live
  pending count and limit; configured decision lease; and cumulative reply,
  renewal, malformed-frame, invalid-answer, unknown-command, unknown-request,
  and stale-request counts.

``/sys/kernel/security/medusa/events``
  Reports every announced event, whether an installed hook or required
  validation path actively reaches it, its subject and object classes, runtime
  trigger bit and bitmap owner, installed fallback policy, monitoring-bit
  evaluations and cache hits, and cumulative central-engine totals for
  delegation, baseline and online-required verdicts, allow, deny, lease
  timeout, invalid reply, and degraded fallback.

``/sys/kernel/security/medusa/classes``
  Reports every announced object class, whether an active event consumes it,
  and its announced and actively reachable event counts.

All three files have mode ``0400`` and no write operation.  The status snapshot
takes an authorization-server reference while holding the registry lock, then
queries optional health callbacks only after releasing that lock.  Event
records are generated while the registry is locked so unregister cannot leave
a dangling definition in a partial line.  Medusa's own delegated ``file_open``
path exempts these three diagnostic files so an outage cannot hide its state;
normal VFS permissions and other stacked LSMs still apply.  Protocol-v3 event
names and runtime trigger bits are descriptive rather than stable numeric
identities.  Event ``cached`` counts are the exact monitoring-bit cache hits
that bypass the central engine.  Virtual-space denials and validation failures
that return before that check are deliberately not mislabelled as cache hits.
The QEMU lifecycle scenario proves that ``ipc_msgsnd`` and the process and IPC
classes are active, socket policy remains announcement-only, and an unmonitored
``pexec`` is counted as a cached evaluation.

Protocol-error audit
--------------------

``AUDIT.rst`` defines the versioned, machine-readable decision and protocol
audit ABI. Rejected authorization answers and progress messages use:

``Medusa: audit_schema=1 record=protocol_error protocol=... policy_generation=... error_kind=... command_present=... command=... request_present=... request_id=... error=... error_sequence=... suppressed=...``

``error_kind`` is one of ``malformed_message``, ``invalid_answer``,
``unknown_command``, ``unknown_request``, or ``stale_request``.  Presence bits
distinguish an unavailable command or request ID from a real zero value.
``error`` is the negative kernel errno, and ``error_sequence`` is the wrapping
boot-lifetime count for that kind.

Each kind has an independent three-record-per-five-second limiter.  The first
occurrence of one kind is therefore visible even while another kind is being
suppressed.  The next emitted record reports the accumulated ``suppressed``
count; securityfs counters continue to include every rejected frame.

Constable's protocol-v3 READY answer follows schema processing and completion
of its optional policy ``_init()`` handler, so ``policy_readiness=ready`` has a
defined meaning.  A device open that has not sent READY remains
``protocol_state=handshaking`` with no active generation; disconnect retains
the last generation that successfully became ready.  Kernel-cached fast-path
accesses do not enter ``med_decide_result()``.  The hook-level monitoring
check nevertheless increments ``evaluations`` and attributes a cleared
monitoring bit to ``cached``; ``decisions`` counts only paths which reached
the central decision engine.

Protocol v3 carries the complete request ID on the supported x86-64 migration
target.  Fixed-width, architecture-independent framing remains protocol-v4
work.  The progress command is an optional extension to protocol v3;
automatic feature negotiation remains protocol-v4 work, so old kernels must
not be sent progress frames.

Degraded decisions use ``record=decision`` and carry registry-stable event and
class string identifiers, policy and protocol generation, an explicit request
presence bit, verdict and source, unavailability reason, Constable-contact
state, and rate-limit accounting. A result without an allocated request can no
longer validate a kernel object merely because it claims Constable contact.

Sleeping and SysV IPC
---------------------

The character-device slow path can block and therefore accepts decisions only
from task context with interrupts enabled and no active atomic section.  It
returns ``MED_ERR`` before allocating or queueing a request otherwise.

The complete active-event matrix and lock-order contract are in
``LOCKING.rst``.  The same worst-case classification is exposed as the
machine-readable ``delegation`` field in the securityfs event inventory.

Several SysV IPC hooks arrive with ``kern_ipc_perm.lock`` held.  On SMP with
``CONFIG_DEBUG_SPINLOCK``, Medusa checks that the current task owns the lock,
takes an object reference, releases the lock and RCU read section before
delegating, then reacquires the lock and revalidates the object afterward.
Without inspectable ownership, a lock-bound request must remain on the kernel
path; the slow-path guard prevents sleeping while a UP spinlock preemption
count or another atomic constraint is active.

QEMU scenario coverage
----------------------

``cache``
  Demonstrates one delegated ``ipc_msgsnd`` followed by a kernel-cached
  decision after Constable clears the message queue's monitoring bit.

``access``
  Exercises create/open/write/fcntl/chmod/chown/truncate, symlink/link/rename/
  unlink, mknod, mkdir/rmdir, chroot, exec, fork, signals, setresuid, and the
  message-queue, semaphore, and shared-memory operations exposed by the active
  LSM hooks.  It requires a Constable marker for every active access type
  exercised; an operation-level success without its event marker is not
  delegation proof.  A sentinel ``mkdir`` executes three source-ordered
  global callbacks, then its subject and object path-tree callbacks.  The
  first global callback updates ``file.user`` and the second fetches and
  verifies that value before the callbacks return ``ALLOW``, ``FORCE_ALLOW``,
  ``DENY``, ``ALLOW``, and ``ALLOW``.  Ordered markers and the syscall's
  ``EACCES`` prove the global-to-path-tree order, update/fetch visibility,
  continued evaluation after denial, and preservation of the accumulated
  result.  Validation dependencies have central-engine counter and
  dedicated lifecycle coverage because nested logging from a protocol-v3
  validation callback can overwrite its legacy shared callback snapshot.

``lockdep``
  Inherits the complete ``access`` scenario and rejects atomic-sleep,
  scheduling-while-atomic, circular/recursive-lock, inconsistent-state,
  unlock-balance, and spinlock diagnostics.  Build the tested kernel by
  merging ``tools/testing/selftests/medusa/qemu/lockdep.config`` into the
  Medusa test configuration.

``lifecycle``
  Covers initial registration, disconnect, baseline-permitted operation,
  replacement
  registration, enforcement of a reloaded deny policy, positive audit output
  for a server-requested IPC operation, and preserved kernel monitoring state
  across the disconnect.

``degraded``
  Freezes Constable after proving a delegated denial, verifies that one
  request waits for a full lease and uses baseline allow, verifies that the
  open circuit immediately applies the same installed baseline to the next
  request, and checks the decision-source, precise timeout reason, request,
  policy-generation, event, and class audit metadata.
  The scenario also mounts securityfs, checks healthy, degraded, and recovered
  status snapshots, inserts an incomplete raw-device handshake between
  disconnect and reconnect, verifies generation retention plus malformed,
  unknown-command, and unknown-request protocol counts, checks per-event
  delegation, baseline, timeout, and degraded attribution, and proves that the
  status file cannot be opened after dropping to uid 65534.
  It then terminates the frozen server, registers a replacement, and proves
  that delegated denial is restored.  Finally, it creates 32 independent
  message queues, stops the replacement server, and requires at least eight
  simultaneous pending requests before killing it.  All blocked operations
  must wake through their installed baseline allow within three seconds, the
  pending table must return to zero, concurrent securityfs readers must retain
  complete snapshots, and a second replacement must restore the delegated
  denial under a newer policy generation.  Together with the KUnit
  ``baseline_deny`` tests, this covers both sides of degraded policy: failure
  cannot relax an installed baseline denial or turn an unrelated
  baseline-permitted operation into a blanket denial.

``stacking.config``
  Enables AppArmor before Medusa in ``CONFIG_LSM``.  The ``stacking`` scenario
  requires both names in the kernel's runtime LSM list and inherits the full
  lifecycle scenario. A confined helper proves an audited AppArmor ``mkdir``
  denial while Constable remains connected and a subsequent operation
  succeeds. A negative assertion verifies that AppArmor's short-circuited
  denial is not attributed to Medusa. The reconnected Constable then proves an
  audited Medusa ``ipc_msgsnd`` denial while AppArmor permits the unconfined
  init process.

``selinux-stacking.config``
  Enables SELinux before Medusa in ``CONFIG_LSM``. The ``selinux-stacking``
  scenario requires both names in the runtime LSM list and inherits the full
  lifecycle scenario. It loads an enforcing policy generated from the
  kernel's minimal dummy policy, transitions only the guest helper into a
  restricted domain, and proves an audited SELinux directory denial while
  Constable remains connected. The replacement Constable then proves the same
  independent Medusa ``ipc_msgsnd`` denial used by the other lifecycle runs.

Stacked hook and audit composition
----------------------------------

All active Medusa authorization hooks return the LSM default value ``0`` for
allow/fail-open or a negative errno for denial and object-lifetime errors.
They therefore follow the LSM core's first-nondefault short-circuit semantics:
with either reference order, an earlier AppArmor or SELinux denial prevents the
later Medusa hook from running. Medusa's ``common_audit_data`` is allocated per
call, and its private pointer occupies the standard LSM-specific union; it does
not reuse another LSM's audit state. Stacked-LSM and Medusa denials
consequently produce separate, correctly attributed ``AUDIT_AVC`` records.

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

* Re-associating with an existing message queue, semaphore set, or shared
  memory object returns ``EACCES`` even when ``ipc_perm`` is allowed.
  ``ipc_associate`` is not observed.
* Multiple ``getfile`` callbacks can overwrite one another's object snapshot;
  the Constable path-tree callback and an explicit policy callback are not
  safely composable.

These findings are test expectations for the revival branch.  Fixes should be
separate commits that deliberately update the corresponding expected results.
