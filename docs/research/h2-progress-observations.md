# Owned H2 progress observations

The opt-in server phase witness now includes fixed aggregate accept-future and
TLS application-I/O counters. The client collects matching I/O metadata only in
ordinary tests. Neither witness contains endpoint strings, headers, identities,
payload buffers, key material or arbitrary error messages. Errors retain only a
static category. Debug never formats the wrapped stream. Storage and counters
are bounded; counters saturate instead of overflowing. Concurrent snapshots are
not an atomic ordered trace.

An I/O write count means the local TLS application API accepted those bytes.
A read count means that local API returned bytes. This is not encrypted socket
traffic, a packet capture, peer acknowledgment or application delivery. It does
not locate the cause of the retained Windows CI stall by itself. Local queued
headers/Open, driver polls and completed H2 preface are distinct from an accepted
server request and actual target connection.

Accept observations distinguish actual polls, Pending, accepted requests, EOF,
errors and cancellation of a polled accept future. Losing another branch of the
existing select can legitimately cancel that future while the connection stays
alive; the cancellation counter is not a connection-failure classifier. Polls
forward the original context and return the original result exactly once. No new
waker adapter, retry, delay, backoff, timeout or transport ordering is introduced.

Only an explicitly supplied server witness wraps TLS and updates counters. With
no witness the original bare TLS stream and accept path remain. Stream and task
owners, establishment/session deadlines, target-acceptance and no-replay gates
are unchanged. The existing timeout panic includes these bounded observations
so a future genuine Windows failure can distinguish local progress boundaries.

Ordinary duplex/H2 fixtures test short/vectored I/O, Pending, EOF, original error
propagation, redaction and exact owned cancellation while an unrelated stream
keeps working. Synthetic I/O observations and local reproduction are not Windows
CI success, installed lifecycle, independent capture or beta-exit acceptance.
