Medusa 6.11 baseline
====================

This document records the behaviour of the legacy Medusa implementation before
the kernel-version migration begins.  It is descriptive, not a claim that the
current interfaces are suitable for upstream Linux.

Architecture
------------

Medusa is split into four layers:

``l1``
  Linux Security Module hooks and security blobs.
``l2``
  Kernel object and event definitions plus the fast-path access checks.
``l3``
  The object/event registry, policy-generation tracking, and dispatch to an
  authorization server.
``l4-constable``
  A character-device transport for the userspace Constable server.

Subjects and objects carry virtual-space and action bitmaps.  An L2 hook can
resolve a request locally when those cached labels are sufficient.  A monitored
event that cannot be resolved locally is passed synchronously through L3 and L4
to Constable.  Constable can also fetch and update registered kernel objects.

Policy generations
------------------

``medusa_authserver_magic`` identifies the current authorization-server
generation.  Cached object state is valid only when its ``magic`` value matches
that generation.  Registering or unregistering an authorization server advances
the generation and therefore invalidates old cached state lazily.

Protocol v3
-----------

The packed native protocol is declared in ``include/l4/comm.h``.  Its greeting
advertises version 3.  Startup sends kernel class and event definitions, then a
ready request.  Runtime commands cover authorization request/answer and
fetch/update operations.

This ABI is architecture-sensitive despite its packed records: object payloads
contain layouts supplied by the running kernel, integers are mostly native
endian, names have fixed limits, and identifiers are encoded as 64-bit pointer
values.  Type value ``0x05`` means an opaque byte sequence in the kernel header;
the legacy Constable header calls the same value a 16-bit bitmap.  That mismatch
must be resolved when a replacement protocol is designed.

Security behaviour
------------------

The baseline deliberately preserves these semantics:

* no registered authorization server: unmonitor the involved objects and allow;
* transport failure (``MED_ERR``): allow, because L2 already accepted the
  virtual-space relation;
* an unknown answer from a reachable server: deny;
* the authorization server is exempt from decisions that would recurse into
  itself;
* decisions delegated to Constable block synchronously;
* boot may be configured to continue after the early server startup timeout.

Consequently the current implementation is fail-open for server absence and
communication failure.  It is not safe to describe it as a complete mandatory
access-control boundary until those semantics, recursion exemptions, lifecycle
races, and denial-of-service behaviour have dedicated tests and a documented
threat model.

Baseline configuration and tests
--------------------------------

The checked-in ``.kunitconfig`` enables Medusa and its L3 model tests for UML.
The historical development configuration uses 96 virtual-space bits and 128
action bits, starts ``/sbin/init-constable.sh`` before ``/sbin/init``, and
continues booting after a five-second startup timeout.

The immutable pre-revival revision is tagged ``medusa-v6.11-legacy``.  Changes
after that tag should first make the baseline reproducible; protocol redesign
and LSM stacking belong to later phases.

The Linux 7.1 test inventory, wired/unwired access list, and known defects are
recorded in ``security/medusa/TESTING.rst``.

The hard-link destination allowlist and its ``path_guard`` userspace object
class are documented in ``security/medusa/PATH_GUARD.rst``.

The securityfs boundary and the Phase 4 decision to defer arbitrary
virtual-space/context queries until a safe protocol-v4 object-query ABI are
documented in ``security/medusa/OBSERVABILITY.rst``.
