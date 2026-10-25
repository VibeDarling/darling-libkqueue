# Independent read/write registrations

Build `socket-independent-filters.c` as an arm64 Mach-O against the Darling SDK
and libSystem; run with the rebuilt kernel library in a private prefix. The
unfixed backend reports successful READ+WRITE registration but overwrites READ
with WRITE in the single epoll instance. The initial expectation fails while
ordinary recv can still read the peer's byte. The read-only native control
passes, isolating coexistence rather than basic socket readiness.

The regression exercises both registration orders; direction-specific user
data; write disable/re-enable; read modification; write deletion while read
stays active; read deletion while write stays active; normal socket close with
peer EOF; closing a kqueue while registrations remain active or disabled; and
20 teardown cycles with descriptor accounting. Closing the queue must not close
the application socket. Regular-file READ registrations are also closed while
active and disabled, checking that surrogate event descriptors do not leak. Closing the socket must release internal duplicates so
the peer sees EOF. A mask-only repair with one knote, or a duplicate-fd repair
that leaks on queue close, fails these checks.

Provenance: existing libkqueue source and its `_dup_4libkqueue`/closed-fd hooks,
authored native API tests, and official macOS .NET 10.0.13 API-boundary calls
(rung 4). No guest application internals inspected. The previous change
7ef17ba removed the separate descriptor keys without providing per-filter
identity for the shared epoll entry. Keep that change's corrected 64-bit
FIONREAD handling. This is target ARM64 validation, not broad platform coverage.
