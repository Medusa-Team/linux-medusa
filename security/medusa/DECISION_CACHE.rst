Non-sleepable domain decision cache
===================================

Some LSM hooks execute under RCU, a spinlock, an inode lock, or another
constraint that forbids a synchronous request to Constable.  Protocol v4's
``MEDUSA_FEATURE_DOMAIN_DECISION_CACHE`` installs bounded rules for those
hooks as part of the existing atomic policy-generation transaction.

Identity and matching
---------------------

Every process security blob has a 64-bit ``policy_domain``.  It is inherited
across fork and is exposed as a writable process-object attribute so the
trusted authorization server can assign a domain.  Domain value
``MEDUSA_POLICY_DOMAIN_ANY`` is reserved for rule wildcards and cannot be
assigned to a process.  Object kernel pointers and namespace-local PIDs are not
cache object keys; the kernel resolves the event type from its negotiated event
identifier.

A rule key contains the event, subject domain, object domain, and an
event-specific 64-bit selector.  Exact fields take precedence over wildcard
fields; ties are ordered subject, object, then selector. Duplicate keys in one
generation are rejected.  Ptrace encodes ``operation << 32 | mode``.  Signal
authorization uses the signal number.

Publication and failure
-----------------------

Constable sends zero or more ``MEDUSA_TLV_DOMAIN_RULE`` values in each
``POLICY_EVENT``.  The kernel validates and bounds the complete staged rule
set, builds an open-addressed immutable table, and publishes it only after the
policy generation becomes active.  Readers use RCU and neither allocate nor
sleep.  A generation mismatch or cache miss selects the event's installed
fallback policy; it never reuses a stale answer.

The initial limit is 4096 rules per generation. Disconnect removes the active
table after advancing the policy generation. Malformed, duplicate, oversized,
or unsupported rule sets cannot partially publish.

Constable accepts:

``--domain-rule event:subject:object:selector=allow|deny``

Each key can be an integer (decimal or ``0x`` form) or ``*``. For example,
``--domain-rule ptrace:*:*:*=deny`` denies every monitored ptrace operation
without a userspace round trip.
