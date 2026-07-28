===================
Medusa audit schema
===================

This document defines the machine-readable Medusa audit ABI.  It covers
records emitted directly by the decision engine and protocol parser.  The
older hook-specific records beginning with ``Medusa: op=`` remain diagnostic
output and are not part of this stable schema.

Versioning
==========

Every stable record starts with::

  Medusa: audit_schema=1 record=<record-type>

Fields are separated by one ASCII space and values never contain whitespace.
Parsers must select records by ``audit_schema`` and ``record``, accept fields
in any order, ignore unknown fields, and reject duplicate fields.  New fields
may be appended without changing ``audit_schema``.  Removing a field, changing
its meaning or encoding, or changing an identifier requires a new schema
version.

Decimal integers are unsigned unless a field explicitly documents otherwise.
Boolean values are ``0`` or ``1``.  Enumerated strings and identifiers use
lower-case ASCII letters, digits, and underscores.

Identifiers
===========

``event_id``, ``subject_class_id``, and ``object_class_id`` are the names
announced by the Medusa registry.  They are string identifiers, not kernel
addresses or registration-order numbers.  A name used by schema version 1
must not be reused for a different semantic operation or object shape.

``event_bit`` is included for diagnostics and correlation with the current
securityfs inventory.  Protocol v3 assigns it from registration order, so it
is not a stable event identifier.

Decision records
================

Decision records have this form::

  Medusa: audit_schema=1 record=decision protocol=<version> \
  policy_generation=<generation> event_id=<event> event_bit=<bit> \
  subject_class_id=<class> object_class_id=<class> \
  request_present=<bool> request_id=<id> verdict=<verdict> \
  verdict_source=<source> unavailable=<reason> \
  authserver_contacted=<bool> degraded_sequence=<sequence> \
  suppressed=<count>

``request_present`` determines whether ``request_id`` is meaningful.  A zero
request ID with ``request_present=0`` must not be interpreted as a request.
``authserver_contacted`` means that the transport accepted and queued the
request for the authorization server, not merely that a server connection
existed.

``verdict`` is ``ALLOW``, ``DENY``, or ``ERROR``.  ``verdict_source`` is one
of ``auth_server``, ``baseline``, ``online_required``, or ``invalid_reply``.
``unavailable=none`` means that the authorization server was not required or
returned an authoritative answer.  Other values identify the reason the
installed fallback was selected.

The decision engine currently emits these records for degraded decisions.
They are independently rate limited per event.  ``degraded_sequence`` counts
all degraded decisions for that event, including suppressed records, and
``suppressed`` reports records omitted since the previous emitted record.

Hook-specific records
=====================

The older hook records beginning with ``Medusa: op=`` remain diagnostic rather
than a stable ABI, but every emitted record carries ``decision_source`` and
the same request, generation, availability, and authorization-server contact
metadata.  Delegated and fallback sources use the values above.  Local
decisions additionally use:

``cache``
  The event's monitoring bit was clear, so the installed kernel context
  allowed the operation without entering the central decision engine.
  Supported socket hooks emit this record when the process audit flag is set;
  this is the audit-only network benchmark path and never contacts Constable.

``virtual_space``
  The kernel virtual-space relationship directly denied the operation.

``path_guard``
  The path-guard table directly resolved a hard-link operation.

``validation``
  Kernel object or subject context validation failed before event delegation.

These values distinguish local allow and deny paths from a baseline selected
by the central decision engine.  ``as_request`` remains for compatibility and
is derived from actual transport contact rather than merely attempting a
decision.

Protocol-error records
======================

Protocol parser failures have this form::

  Medusa: audit_schema=1 record=protocol_error protocol=<version> \
  policy_generation=<generation> error_kind=<kind> \
  command_present=<bool> command=<hex-command> \
  request_present=<bool> request_id=<id> error=<negative-errno> \
  error_sequence=<sequence> suppressed=<count>

The presence fields determine whether the corresponding values are meaningful.
``error_kind`` is ``malformed_message``, ``invalid_answer``,
``unknown_command``, ``unknown_request``, or ``stale_request``.  ``error`` is
a signed negative errno.  Each error kind has an independent rate limiter;
``error_sequence`` counts every occurrence of that kind.

Security properties
===================

Audit records report decisions; they do not configure policy.  Medusa exposes
no writable per-event audit switch.  The existing securityfs files are
root-readable snapshots and have no write operation.  A future runtime audit
control must require privilege, validate a complete update before publishing
it, and audit the control change.  The status snapshot publishes
``audit_schema_version=1`` so consumers can discover the running schema
without parsing an error or forcing a degraded decision.
