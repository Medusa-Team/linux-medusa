============================
Guarded policy generations
============================

Phase 7 keeps mining, review, remote distribution, and attack detection in
userspace.  The kernel implements only the bounded mechanisms needed to make a
reviewed transition safe.

Live replacement
================

After reaching ``READY``, a server that negotiated
``MEDUSA_FEATURE_ATOMIC_POLICY_REPLACE`` may send ``POLICY_BEGIN`` with the
current generation plus one, exactly one ``POLICY_EVENT`` for every announced
event, and ``POLICY_COMMIT`` with the same generation.

The registry copies the active fallback slot to an RCU-safe inactive slot.
Staging modifies only that slot.  Commit release-publishes the complete slot
and advances ``medusa_authserver_magic`` in one registry critical section.
The generation change lazily invalidates every monitored process, inode, IPC,
and socket context without restarting Constable.  Explicit
``MAGIC_NOT_MONITORED`` caches retain their intended state.  Pending requests
from the parent generation are cancelled at commit and select their installed
fallback.

``POLICY_ABORT`` discards an incomplete replacement and returns
``POLICY_READY`` for the unchanged parent.  Disconnect also discards staging.
A skipped, repeated, stale, or rollback generation is rejected.

While staging, the parent fallback slot remains authoritative.  Concurrent
parent-generation replies, progress leases, and object operations remain
valid, so multi-frame installation cannot expose a partial generation.

Reply cache update
==================

A server that negotiated ``MEDUSA_FEATURE_REPLY_CACHE_UPDATE`` may add one
``MEDUSA_TLV_CACHE_UPDATE`` to an ``ALLOW`` reply.  Its value selects the
subject, object, or both.  The kernel clears only the current event's
monitoring bit in ``med_sact`` or ``med_oact`` and invokes the registered class
update callback before returning to the hook.  Denial and error replies cannot
carry cache updates.  Unknown attributes, invalid bit ranges, and failed class
updates leave the cache monitored and cannot broaden the one-shot verdict.

This is intentionally a simplified cache operation.  Arbitrary object changes
continue to use the separately validated object update message.

Research safety boundary
========================

The kernel does not parse mined artifacts, verify remote signatures, approve
policy, generalize paths, or decide that an emergency policy is monotonic.
Those gates belong to the versioned userspace artifact and distribution
workflow.  The kernel accepts a generation only from the single privileged
protocol-v4 connection and exposes it through the existing audit and
securityfs schemas.

The ``adaptive-replay`` disposable-QEMU scenario boots a matching kernel and
Constable, replays a recorded allowed IPC operation, proves its second
occurrence is cached, atomically commits the next generation without changing
the Constable PID, and runs a withheld IPC negative twice.  Both negatives
must be denied and delegated, proving that a denial cannot mutate the cache.
