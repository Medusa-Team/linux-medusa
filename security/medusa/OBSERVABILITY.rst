Medusa observability and context-inspection boundary
====================================================

Purpose
-------

Medusa exposes enough state to diagnose authorization-server health and
decision provenance without creating a second policy interface.  The current
securityfs ABI is deliberately limited to the root-readable, read-only
``status``, ``events``, and ``classes`` snapshots documented in
``TESTING.rst``.

This document records the Phase 4 evaluation of an interface for inspecting an
arbitrary process, inode, or IPC object's virtual-space context.  The decision
is **not to add such an interface to securityfs or protocol v3**.  A safe
object-query facility requires the stable identities, framing, authorization,
and generation semantics planned for protocol v4.

Historical MedusaFS comparison
------------------------------

The 2020 MedusaFS prototype used a writable ``get_vs`` securityfs file.  One
write accepted a pathname, resolved it with ``kern_path()``, and stored the
selected dentry in a global variable.  A later read followed that dentry to an
inode and formatted the raw virtual-space bitmap.  The same prototype created
world-writable per-event ``audit`` files.

That design is useful historical evidence, but it is not a safe ABI to revive:

* one global pathname selection mixes concurrent readers and can disclose one
  caller's result to another;
* pathname resolution depends on the caller's mount namespace and credentials,
  can itself traverse Medusa-controlled objects, and cannot identify an
  already-open object without a second lookup;
* a dentry retained across separate write and read calls needs explicit path
  lifetime management and remains subject to rename, unlink, and inode-reuse
  races;
* reading a security blob directly does not provide the class-specific locking
  and lifetime rules required for tasks, inodes, and SysV IPC objects;
* a raw bitmap has meaning only together with its policy generation and the
  userspace mapping from bits to policy-space names;
* exposing arbitrary labels reveals policy topology and cross-namespace object
  state, while repeated lookups provide an avoidable denial-of-service surface;
* native blob layouts and fixed protocol-v3 fields would turn an inspection
  helper into another unstable ABI.

The mode ``0666`` audit controls are also incompatible with the current rule
that policy-affecting state is never writable by an unprivileged reader.

Phase 4 decision
----------------

No arbitrary object selector is added in Phase 4.  Operators can use:

* versioned audit records for the context and source of actual decisions;
* ``status``, ``events``, and ``classes`` for kernel, transport, fallback,
  counter, and enforcement-surface snapshots; and
* Constable's non-mutating policy inspection output for named virtual spaces,
  handlers, and compiled policy reachability.

This split avoids claiming that a transient kernel bitmap is a durable policy
identity.  It also keeps securityfs read-only and prevents diagnostic path
lookups from becoming a recursive authorization path.

Requirements for a future query API
-----------------------------------

A protocol-v4 object-query design may proceed only if it satisfies all of the
following:

* require an explicit privilege check suitable for MAC administration; file
  mode alone is not the authorization contract;
* use a complete framed request and response with version, payload length,
  request ID, object class ID, and active policy generation;
* identify processes with pidfds and files with existing file descriptors or
  file handles rather than a shared pathname selector;
* identify IPC objects together with their IPC namespace and class, and reject
  stale or reused IDs;
* take class-specific object references and locks, copy a bounded snapshot, and
  release all locks before formatting or sending it;
* report that a context is absent, stale, or belongs to another generation
  instead of silently revalidating or mutating the object;
* expose stable, bounded values rather than native kernel structures or
  pointers;
* keep query state per request, permit concurrent readers, and never retain a
  caller-selected object in global mutable state;
* provide no write/update operation through the diagnostic command;
* apply rate or resource bounds so label enumeration cannot starve decisions;
* emit an audit record for each privileged query, including caller, object
  class, result, and generation, without logging sensitive object contents.

Constable may translate returned generation-scoped bit identifiers to policy
space names because it owns the compiled policy mapping.  The kernel must not
accept those names as policy updates through the diagnostic path.

Upstream boundary
-----------------

The current three securityfs files are diagnostic snapshots, not a policy
control plane.  Adding object inspection is therefore not a prerequisite for
the Linux 7.1 correctness baseline.  It is a separately reviewable protocol-v4
feature whose threat model and UAPI must be agreed before implementation.
