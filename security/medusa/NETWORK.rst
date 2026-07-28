Medusa network enforcement
==========================

Status
------

Phase 6 restores a bounded, syscall-level network policy surface.  It does not
restore the 2019 implementation verbatim and it does not claim packet-level
mediation.

The supported access types are:

=========================== ========================= ==============================
Access type                 Linux 7.1 LSM hook        Stable policy inputs
=========================== ========================= ==============================
``socket_create``           ``socket_create``         family, type, protocol
``socket_bind_access``      ``socket_bind``           socket, requested local address
``socket_connect_access``   ``socket_connect``        socket, requested peer address
``socket_listen_access``    ``socket_listen``         socket, effective backlog
``socket_accept_access``    ``socket_accept``         listening socket
``socket_sendmsg_access``   ``socket_sendmsg``        socket, byte count, flags and
                                                       an explicit destination, if any
``socket_recvmsg_access``   ``socket_recvmsg``        socket, byte count and flags
=========================== ========================= ==============================

All seven hooks run on the socket syscall path in task context and may use the
synchronous Constable decision path.  ``accept`` is a decision about the
listening socket before the protocol has populated the accepted socket; it does
not expose the eventual peer as a policy input.  ``recvmsg`` runs before data is
received, so neither its name buffer nor its contents identify the sender.
Connected ``sendmsg`` calls do not carry an explicit destination.

Address model
-------------

``bind``, ``connect``, and an explicitly addressed ``sendmsg`` support
``AF_INET``, ``AF_INET6``, and ``AF_UNIX``.  An address is a fixed, zero-filled
record with a family, its original bounded length, and one of:

* IPv4 address and network-byte-order port;
* IPv6 address, network-byte-order port, scope ID, and flow information;
* the exact bounded Unix-domain name bytes.

Unix addresses are byte strings, not assumed to be NUL-terminated paths.  This
preserves abstract names, including their leading zero, and never reads beyond
the supplied ``addrlen``.  Unsupported families remain outside the restored
subset and are allowed without announcing a Medusa decision.

The socket object reports its family, type, protocol, network namespace cookie,
owner UID, and Medusa virtual-space state.  In the restored subset that state
is a kernel-owned, read-only default context: ``getsocket`` may authorize its
generation validation, but protocol v4 cannot mutate the decision snapshot and
the socket class deliberately offers no unsafe inode-based update operation.
Socket decisions are triggered by the process subject; socket virtual spaces
still participate in the local intersection check.

A requested bind address is event data, not durable socket identity: the LSM
bind hook precedes the protocol bind operation and cannot know whether that
operation later succeeds.  The socket class therefore does not claim that a
previously requested address is the socket's current local address.

Blob ownership and namespaces
-----------------------------

Medusa uses its ``lbs_sock`` offset in the LSM composite ``sk_security`` blob.
Allocation, clone, and free hooks initialize or copy only Medusa's assigned
slice.  Medusa never allocates, replaces, or frees ``sk_security`` itself.

The network namespace cookie is a diagnostic and policy-disambiguation input.
It distinguishes otherwise identical socket tuples in different network
namespaces for the lifetime of the namespace.  Policy must not treat it as a
persistent identifier across boots.

Delegation and fallback
-----------------------

These socket hooks are classified ``sleepable``.  They use the same event
fallback policy as other delegated Medusa operations when Constable is absent,
unhealthy, timed out, or recursion-exempt.  Online-required policy is accepted
for this restored syscall-level set because all installed call sites can sleep.

This does not authorize synchronous delegation from ``socket_sock_rcv_skb`` or
any other softirq, atomic, or lock-held packet path.  Packet/SKB, Unix
peer-socket, SCTP, MPTCP, Netlink, XFRM, and secmark hooks are explicitly out of
scope until they receive separate semantics and non-sleeping policy designs.

Historical audit
----------------

The 2019 thesis and repository history implemented create/post-create, bind,
connect, listen, accept, send, receive, and socket blob lifecycle hooks.  The
thesis describes testing with an authorization server, but contains no
reproducible policy fixtures or operation-by-operation allow/deny results.
Repository history likewise contains implementation code rather than preserved
policy examples, so the original policy examples cannot be reproduced as an
evidence-bearing test suite.

The historical code is not safe to reactivate unchanged:

* it allocated, replaced, and freed ``sk_security`` directly, conflicting with
  Linux 7.1 composite blobs and LSM stacking;
* it copied a full ``sun_path`` regardless of ``addrlen`` and assumed a
  NUL-terminated pathname;
* oversized IPv4/IPv6 array declarations and uninitialized unions could expose
  padding or stale stack data to userspace;
* bind state was recorded before the protocol bind completed, including on
  denied decisions;
* connected sends bypassed the event, while receive treated an output buffer as
  a known peer address;
* socket fetch/update reconstructed live sockets through inode internals, which
  is not a stable lifetime or namespace-safe control interface.

The restored implementation consequently keeps address data on the access
event, makes socket fetch/update unavailable, and tests current Linux 7.1
semantics rather than treating the historical source as a specification.
