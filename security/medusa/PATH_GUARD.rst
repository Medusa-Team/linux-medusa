.. SPDX-License-Identifier: GPL-2.0

=================
Medusa path guard
=================

Path guard restricts hard-link creation for selected inodes to an
administrator-managed set of absolute paths.  The inode security blob stores
cryptographic path digests rather than path strings.  The ``link`` access type
checks the requested destination before running the normal Medusa decision.

The protocol-visible kobject class is named ``path_guard``.  Its fields are:

``path``
  Absolute path used as the fetch key or as the path to append/remove.

``dev`` and ``ino``
  Device and inode identifiers returned by fetch and consumed by update.

``action``
  ``append`` adds an allowed path and ``remove`` removes it.

The earlier experimental class and identifiers had an unsuitable placeholder
name.  Phase 4 replaces them without a compatibility alias.  That class never
had a registered enforcing event, and Constable's active-inventory validation
therefore never accepted it as an enforceable policy event.

Concurrency and failure behavior
================================

Each inode owns a spinlock protecting its path digest table.  Hash computation
and allocation happen before taking the lock; duplicate insertion is checked
again while locked.  Lookup, removal, inode teardown, and the empty-table fast
path use the same lock.

Path guard initializes at the late initcall level, after built-in Crypto API
algorithms have registered and before KUnit executes.  It does not announce its
userspace class if the selected transformation or entry cache cannot be
created.

An allocation or hashing failure rejects an update.  A path-guard check returns
an error to the link hook rather than silently treating the path as allowed.
KUnit first asserts that initialization completed, then covers successful
hashing, lookup, duplicate insertion, missing removal, removal, independent
entries, repeatable teardown, and invalid input.
