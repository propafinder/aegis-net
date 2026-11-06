"""Bounded owned AF_PACKET metadata pump. No socket creation or raw retention.

The caller creates/binds a fresh private capture socket and transfers ownership.
Live snapshot is metadata only; acceptance requires the final stop receipt.
PACKET_STATISTICS reads reset kernel counters, so only stop reads them once.
"""
import hashlib
import ipaddress
import re
import select
import socket
import struct
import threading
import time

SOL_PACKET = 263
PACKET_STATISTICS = 6
FIELDS = {'src', 'dst', 'sport', 'dport', 'seq', 'flags', 'ttl',
          'sha256', 'clear_marker_present'}


def _metadata(row, frame):
    if row is None:
        return None
    if type(row) is not dict or set(row) != FIELDS:
        raise ValueError('metadata_only_schema')
    for name in ('src', 'dst'):
        if type(row[name]) is not str or str(ipaddress.IPv4Address(row[name])) != row[name]:
            raise ValueError('metadata_ipv4')
    for name, maximum in (('sport', 65535), ('dport', 65535), ('seq', 0xffffffff),
                          ('flags', 255), ('ttl', 255)):
        if type(row[name]) is not int or not 0 <= row[name] <= maximum:
            raise ValueError('metadata_integer')
    if type(row['clear_marker_present']) is not bool:
        raise ValueError('metadata_marker_boolean')
    if type(row['sha256']) is not str or not re.fullmatch('[a-f0-9]{64}', row['sha256']):
        raise ValueError('metadata_digest')
    if row['sha256'] != hashlib.sha256(frame).hexdigest():
        raise ValueError('metadata_frame_digest')
    return dict(row)


class CaptureObserver:
    def __init__(self, sock, decode, *, raw=False, record_limit=512,
                 frame_limit=2048, batch_limit=64, max_duration=45,
                 poll_interval=0.01, wait=None, clock=None):
        if raw is not False or not callable(decode):
            raise ValueError('metadata_only_callback_required')
        for value, maximum in ((record_limit, 512), (frame_limit, 2048),
                               (batch_limit, 64)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError('capture_resource_bound')
        if (type(max_duration) not in (int, float) or not 0 < max_duration <= 90 or
                type(poll_interval) not in (int, float) or not 0 < poll_interval <= 0.1):
            raise ValueError('capture_time_bound')
        self.sock = sock
        self.decode = decode
        self.record_limit = record_limit
        self.frame_limit = frame_limit
        self.batch_limit = batch_limit
        self.max_duration = max_duration
        self.poll_interval = poll_interval
        self.wait = select.select if wait is None else wait
        self.clock = time.monotonic if clock is None else clock
        self._records = []
        self._frames = 0
        self._bytes = 0
        self._failure = None
        self._overflow = False
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread = None
        self._result = None
        self._closed = False
        self._deadline = None

    @property
    def failure(self):
        with self._lock:
            return self._failure

    def _fail(self, label):
        with self._lock:
            if self._failure is None:
                self._failure = label

    def start(self):
        if self._thread is not None or self._result is not None:
            raise ValueError('capture_start_once')
        self._deadline = self.clock() + self.max_duration
        try:
            self.sock.setblocking(False)
            self._thread = threading.Thread(target=self._pump,
                                            name='aegis-relay-metadata-observer', daemon=True)
            self._thread.start()
            if not self._ready.wait(timeout=1):
                self._fail('capture_ready_timeout')
                self._stop.set()
            return self
        except BaseException as error:
            self._fail('capture_start_' + type(error).__name__)
            self._stop.set()
            self._close()
            raise

    def _receive(self):
        frame = None
        try:
            # recvmsg exposes truncation; silently accepting a partial frame
            # could hide a marker or classify truncated packet metadata.
            frame, _, flags, _ = self.sock.recvmsg(65550, 0, socket.MSG_DONTWAIT)
            if flags & socket.MSG_TRUNC or not frame:
                raise ValueError('capture_truncated_or_empty_frame')
            with self._lock:
                self._frames += 1
                self._bytes += len(frame)
                if self._frames > self.frame_limit:
                    self._overflow = True
                    raise ValueError('capture_frame_limit')
            row = _metadata(self.decode(frame), frame)
            if row is not None:
                with self._lock:
                    if len(self._records) >= self.record_limit:
                        self._overflow = True
                        raise ValueError('capture_metadata_limit')
                    self._records.append(row)
            return True
        except BlockingIOError:
            return False
        finally:
            # No frame, payload or callback return is stored on this object.
            frame = None

    def _pump(self):
        self._ready.set()
        try:
            while not self._stop.is_set():
                if self.clock() >= self._deadline:
                    raise TimeoutError('capture_pump_deadline')
                if not self.wait([self.sock], [], [], self.poll_interval)[0]:
                    continue
                for _ in range(self.batch_limit):
                    if self._stop.is_set():
                        break
                    if self.clock() >= self._deadline:
                        raise TimeoutError('capture_pump_deadline')
                    if not self._receive():
                        break
                # A continuously ready socket cannot monopolize the pump, nor
                # bypass its frame/resource/time bounds with ignored frames.
                self._stop.wait(self.poll_interval)
        except BaseException as error:
            self._fail('capture_pump_' + type(error).__name__)

    def snapshot(self):
        with self._lock:
            return {'records': [dict(row) for row in self._records],
                    'frames_received': self._frames, 'frame_bytes_received': self._bytes,
                    'metadata_overflow': self._overflow, 'thread_error': self._failure,
                    'raw_frames_retained': False, 'loss_counters_observed': False}

    def _close(self):
        if not self._closed:
            try:
                self.sock.close()
                self._closed = True
            except BaseException as error:
                self._fail('capture_close_' + type(error).__name__)

    def stop(self, timeout=2):
        if type(timeout) not in (int, float) or not 0 < timeout <= 2:
            self._fail('capture_stop_bound')
            timeout = 2
        if self._result is not None:
            return {**self._result, 'records': [dict(r) for r in self._result['records']]}
        self._stop.set()
        terminal = self._thread is not None
        statistics = None
        try:
            if self._thread is None:
                self._fail('capture_never_started')
            else:
                self._thread.join(timeout=timeout)
                terminal = not self._thread.is_alive()
                if not terminal:
                    self._fail('capture_thread_stop_timeout')
                elif self.failure is None:
                    # Quiescent producer may have residual queued frames. This
                    # drain shares the same <=2048 limit; no drain-forever loop.
                    while self._receive():
                        if self.clock() >= self._deadline:
                            raise TimeoutError('capture_final_drain_deadline')
            if terminal:
                raw = self.sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 12)
                if type(raw) is not bytes or len(raw) not in (8, 12):
                    raise ValueError('capture_unknown_kernel_statistics')
                packets, drops = struct.unpack('=II', raw[:8])
                statistics = {'tp_packets': packets, 'tp_drops': drops,
                              'kernel_readback_bytes': len(raw)}
                if drops:
                    self._fail('capture_kernel_packet_loss')
                # Fresh, exclusively owned socket; no intermediate counter
                # reads. Reset/unsupported counts or undrained final frames
                # cannot prove complete metadata, even with zero kernel drops.
                with self._lock:
                    received = self._frames
                if packets != received:
                    self._fail('capture_kernel_counter_mismatch')
        except BaseException as error:
            self._fail('capture_stop_' + type(error).__name__)
        finally:
            self._close()
            # A KeyboardInterrupt during join must not invent terminal proof.
            terminal = self._thread is not None and not self._thread.is_alive()
        result = self.snapshot()
        result.update(kernel_counter_matches_received=(statistics is not None and statistics['tp_packets'] == result['frames_received']),
                      packet_statistics=statistics,
                      loss_counters_observed=statistics is not None,
                      thread_terminal_confirmed=terminal, owned_fd_closed=self._closed)
        result['clean'] = (terminal and self._closed and self.failure is None and
                           statistics is not None and not result['metadata_overflow'] and
                           statistics['tp_drops'] == 0)
        self._result = result
        return {**result, 'records': [dict(row) for row in result['records']]}
