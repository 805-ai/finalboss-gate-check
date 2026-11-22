# The kernel test, case by case

Run of November 18, 2026. 100 fresh cloud machines, Ubuntu 24.04 with its own 6.8 kernel, the FinalBoss gate installed with one command on each.
Every line below is word for word from each machine's own record (`akern/STEP5_A_KERNEL.json` inside `record/box_out/NNN_a1_out_nokeys.tgz`).
Regenerate this table yourself: `python3 check.py --cases`.

Per machine: 21 scored cases. 16 moves the kernel had to stop, 3 moves with a permit that had to go through, 2 fail-safes. Two more lines state the test's scope and are not scored.
Across 100 machines: 1,600 had to be stopped, 1,600 stopped. 300 had a permit, 300 went through. 2,100 scored, 2,100 passed.

| ID | What was tried | Kind | Had to | Result on 100 machines |
|---|---|---|---|---|
| A01 | control: permitted TCP 127.0.0.1:42807 delivers | Had a permit, had to go through | DELIVERED | DELIVERED on 100 |
| A02 | TCP to 127.0.0.2 (not the permitted destination) | Had to be stopped | DENIED | DENIED on 100 |
| A03 | UDP unconnected sendto 127.0.0.2 | Had to be stopped | DENIED | DENIED on 100 |
| A04 | UDP connected then send to 127.0.0.2 | Had to be stopped | DENIED | DENIED on 100 |
| A05 | raw IP socket (IP_HDRINCL) hand-built UDP to 127.0.0.2 | Had to be stopped | DENIED | DENIED on 100 |
| A06 | AF_PACKET socket from inside the gated cgroup (LSM socket_create refuses the family; without the LSM hooks nothing governs it) | Had to be stopped | DENIED | DENIED on 100 |
| A07 | AF_UNIX to an accomplice outside the cgroup (scope line, not scored) | Had a permit, had to go through (not scored) | DELIVERED | DELIVERED on 100 |
| A08 | socket connected OUTSIDE the cgroup, passed in via SCM_RIGHTS, worker sends on it (LSM socket_sendmsg refuses a foreign socket) | Had to be stopped | DENIED | DENIED on 100 |
| A09 | thread of the permitted process connects to 127.0.0.2 (same TGID) | Had to be stopped | DENIED | DENIED on 100 |
| A10 | forked child (new TGID) connects to 127.0.0.2 | Had to be stopped | DENIED | DENIED on 100 |
| A11 | forked child sends on the inherited PERMITTED socket while the permit is live (flow of the permitted TGID) | Had a permit, had to go through | DELIVERED | DELIVERED on 100 |
| A14 | control: io_uring CONNECT + SEND to the permitted 127.0.0.1:42807 delivers (the plumbing works inside the cgroup) | Had a permit, had to go through | DELIVERED | DELIVERED on 100 |
| A14a | io_uring IORING_OP_CONNECT to 127.0.0.2 (connect4 under io_connect) | Had to be stopped | DENIED | DENIED on 100 |
| A14b | io_uring IORING_OP_SENDMSG, unconnected UDP to 127.0.0.2 (sendmsg4 under io_sendmsg) | Had to be stopped | DENIED | DENIED on 100 |
| A14c | io_uring IORING_OP_SOCKET(AF_PACKET) + a hand-built frame on lo (LSM socket_create under io_socket; without the LSM hooks nothing governs it) | Had to be stopped | DENIED | DENIED on 100 |
| A14d | io_uring IORING_OP_SOCKET(AF_INET) then IORING_OP_CONNECT to 127.0.0.2 (sock_create + connect4 under io_uring) | Had to be stopped | DENIED | DENIED on 100 |
| A12 | established permitted connection: send after REVOKE | Had to be stopped | DENIED | DENIED on 100 |
| A14e | established permitted connection: io_uring IORING_OP_SEND after REVOKE (the egress hook under io_send) | Had to be stopped | DENIED | DENIED on 100 |
| A13 | IPv6 TCP to [::1]:33707 (no IPv6 permit for the worker) | Had to be stopped | DENIED | DENIED on 100 |
| A13b | v4-mapped IPv6 socket to ::ffff:127.0.0.2 (the IPv4 path inside connect6) | Had to be stopped | DENIED | DENIED on 100 |
| A15 | ptrace into the permitted process | Scope line (not scored) | STATED | STATED on 100 |
| A16 | fb_core_gate_permits filled to capacity: next grant refused, decisions still deny | Fail-safe | REFUSED | REFUSED on 100 |
| A17 | one object truncated: loader fails, nothing attached | Fail-safe | FAIL_CLOSED | FAIL_CLOSED on 100 |

Words used: DENIED = the kernel refused the move. DELIVERED = it went through. REFUSED = the full permit table turned the next grant away and kept denying. FAIL_CLOSED = a broken gate program was refused by the loader and nothing was attached. STATED = recorded as a scope fact, not scored.
