#!/usr/bin/env python3
"""Actual bounded pump source; fake socket/select only, no live capture or I/O."""
import hashlib
import importlib.util
from pathlib import Path
import socket
import struct
import threading
import time
import unittest

SOURCE=Path(__file__).with_name('relay_capture_observer.py')
spec=importlib.util.spec_from_file_location('relay_capture_observer_inert',SOURCE)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
FRAME=b'inert encrypted frame fixture'

def decode(frame):
    return {'src':'192.0.2.2','dst':'192.0.2.3','sport':1234,'dport':24443,
            'seq':7,'flags':2,'ttl':64,'sha256':hashlib.sha256(frame).hexdigest(),
            'clear_marker_present':False}

class FakeSocket:
    def __init__(self,frames=(),statistics=None,continuous=False,truncated=False):
        self.frames=list(frames);self.continuous=continuous;self.truncated=truncated
        self.statistics=struct.pack('=II',len(self.frames),0) if statistics is None else statistics
        self.closed=False;self.reads=0;self.statistics_reads=0;self.blocking=None
    def setblocking(self,value):self.blocking=value
    def recvmsg(self,size,ancillary,flags):
        assert size==65550 and ancillary==0 and flags==socket.MSG_DONTWAIT
        if self.closed:raise OSError('fake closed socket')
        if not self.frames and not self.continuous:raise BlockingIOError()
        self.reads+=1;frame=self.frames.pop(0) if self.frames else FRAME
        return frame,[],socket.MSG_TRUNC if self.truncated else 0,None
    def getsockopt(self,level,option,size):
        assert (level,option,size)==(263,6,12);self.statistics_reads+=1
        if isinstance(self.statistics,BaseException):raise self.statistics
        return self.statistics
    def close(self):self.closed=True
    def wait(self,*args):return ([self] if self.frames or self.continuous else [],[],[])

def observer(sock,callback=decode,**kwargs):
    return m.CaptureObserver(sock,callback,wait=sock.wait,poll_interval=.001,**kwargs).start()

def until(test):
    deadline=time.monotonic()+1
    while not test():
        if time.monotonic()>=deadline:raise AssertionError('inert pump did not terminate within1s')
        time.sleep(.001)

class CaptureTests(unittest.TestCase):
    def test_success_metadata_only_and_actual_stats8(self):
        sock=FakeSocket([FRAME,FRAME]);o=observer(sock);until(lambda:o.snapshot()['frames_received']==2)
        live=o.snapshot();self.assertFalse(live['loss_counters_observed']);self.assertEqual(sock.statistics_reads,0)
        r=o.stop();self.assertTrue(r['clean']);self.assertEqual(r['packet_statistics'],{'tp_packets':2,'tp_drops':0,'kernel_readback_bytes':8});self.assertTrue(sock.closed);self.assertFalse(sock.blocking);self.assertFalse(r['raw_frames_retained']);self.assertEqual(len(r['records']),2)
        r['records'].clear();self.assertEqual(len(o.stop()['records']),2);self.assertEqual(sock.statistics_reads,1)
    def test_stats12_ignored_frame_still_counted(self):
        sock=FakeSocket([FRAME],struct.pack('=III',1,0,0));o=observer(sock,lambda _:None);until(lambda:o.snapshot()['frames_received']==1);r=o.stop();self.assertTrue(r['clean']);self.assertEqual(r['records'],[]);self.assertEqual(r['packet_statistics']['kernel_readback_bytes'],12)
    def test_stats8_and12_wrong_counts_cannot_claim_completeness(self):
        for width in (8,12):
            for packets in (0,2):
                raw=struct.pack('=II',packets,0) if width==8 else struct.pack('=III',packets,0,0)
                sock=FakeSocket([FRAME],statistics=raw);o=observer(sock);until(lambda:o.snapshot()['frames_received']==1);r=o.stop()
                self.assertFalse(r['clean']);self.assertFalse(r['kernel_counter_matches_received']);self.assertEqual(r['thread_error'],'capture_kernel_counter_mismatch');self.assertTrue(r['loss_counters_observed']);self.assertTrue(sock.closed)
    def test_kernel_drop_refuses(self):
        sock=FakeSocket(statistics=struct.pack('=II',1,1));r=observer(sock).stop();self.assertFalse(r['clean']);self.assertEqual(r['thread_error'],'capture_kernel_packet_loss');self.assertTrue(sock.closed)
    def test_unknown_and_error_statistics_refuse(self):
        for statistics in (b'xxxx',b'x'*16,OSError('inert unknown stats')):
            sock=FakeSocket(statistics=statistics);r=observer(sock).stop();self.assertFalse(r['clean']);self.assertFalse(r['loss_counters_observed']);self.assertTrue(sock.closed)
    def test_record_overflow_retains_bounded_metadata(self):
        sock=FakeSocket([FRAME,FRAME]);o=observer(sock,record_limit=1);until(lambda:o.failure is not None);r=o.stop();self.assertFalse(r['clean']);self.assertTrue(r['metadata_overflow']);self.assertEqual(len(r['records']),1);self.assertLessEqual(sock.reads,2);self.assertTrue(sock.closed)
    def test_continuously_ready_ignored_frames_bounded(self):
        sock=FakeSocket(continuous=True);o=observer(sock,lambda _:None,frame_limit=4);until(lambda:o.failure is not None);r=o.stop();self.assertFalse(r['clean']);self.assertTrue(r['metadata_overflow']);self.assertLessEqual(sock.reads,5);self.assertEqual(r['records'],[]);self.assertTrue(sock.closed)
    def test_continuously_ready_clock_deadline(self):
        class Clock:
            value=0
            def __call__(self):self.value+=.1;return self.value
        sock=FakeSocket(continuous=True);o=observer(sock,lambda _:None,clock=Clock(),max_duration=.35);until(lambda:o.failure is not None);r=o.stop();self.assertFalse(r['clean']);self.assertIn('TimeoutError',r['thread_error']);self.assertLess(sock.reads,10);self.assertTrue(sock.closed)
    def test_raw_callback_data_never_retained(self):
        sock=FakeSocket([FRAME]);o=observer(sock,lambda frame:{'raw':frame});until(lambda:o.failure is not None);r=o.stop();self.assertFalse(r['clean']);self.assertEqual(r['records'],[]);self.assertFalse(r['raw_frames_retained']);self.assertTrue(sock.closed)
    def test_truncated_frame_refused(self):
        sock=FakeSocket([FRAME],truncated=True);o=observer(sock);until(lambda:o.failure is not None);r=o.stop();self.assertFalse(r['clean']);self.assertEqual(r['records'],[]);self.assertTrue(sock.closed)
    def test_callback_keyboardinterrupt_retained(self):
        def callback(_):raise KeyboardInterrupt()
        sock=FakeSocket([FRAME]);o=observer(sock,callback);until(lambda:o.failure is not None);r=o.stop();self.assertFalse(r['clean']);self.assertIn('KeyboardInterrupt',r['thread_error']);self.assertTrue(r['thread_terminal_confirmed']);self.assertTrue(sock.closed)
    def test_final_residual_drain_bounded(self):
        sock=FakeSocket([FRAME,FRAME]);o=m.CaptureObserver(sock,decode,wait=lambda *args:([],[],[]),poll_interval=.001).start();r=o.stop();self.assertTrue(r['clean']);self.assertEqual(len(r['records']),2);self.assertEqual(r['frames_received'],2);self.assertTrue(sock.closed)
    def test_unfinished_callback_no_terminal_claim_fd_closed(self):
        entered=threading.Event();release=threading.Event()
        def callback(frame):entered.set();release.wait(timeout=1);return decode(frame)
        sock=FakeSocket([FRAME]);o=observer(sock,callback);self.assertTrue(entered.wait(timeout=1));r=o.stop(timeout=.01);self.assertFalse(r['clean']);self.assertFalse(r['thread_terminal_confirmed']);self.assertTrue(sock.closed);self.assertIsNone(r['packet_statistics']);release.set();o._thread.join(timeout=1);self.assertFalse(o._thread.is_alive())
    def test_start_failure_closes_owned_fd(self):
        sock=FakeSocket()
        def fail(_):raise OSError('inert nonblocking failure')
        sock.setblocking=fail;o=m.CaptureObserver(sock,decode)
        with self.assertRaises(OSError):o.start()
        self.assertTrue(sock.closed);self.assertIn('OSError',o.failure)
    def test_join_interrupt_cannot_claim_terminal(self):
        class Thread:
            def join(self,timeout):raise KeyboardInterrupt()
            def is_alive(self):return True
        sock=FakeSocket();o=m.CaptureObserver(sock,decode);o._thread=Thread();r=o.stop();self.assertFalse(r['clean']);self.assertFalse(r['thread_terminal_confirmed']);self.assertTrue(sock.closed);self.assertIn('KeyboardInterrupt',r['thread_error'])
    def test_invalid_stop_bound_still_closes_fd(self):
        sock=FakeSocket();r=observer(sock).stop(timeout=3);self.assertFalse(r['clean']);self.assertEqual(r['thread_error'],'capture_stop_bound');self.assertTrue(sock.closed)
    def test_metadata_digest_mismatch_refused(self):
        def callback(frame):row=decode(frame);row['sha256']='0'*64;return row
        sock=FakeSocket([FRAME]);o=observer(sock,callback);until(lambda:o.failure is not None);r=o.stop();self.assertFalse(r['clean']);self.assertEqual(r['records'],[]);self.assertTrue(sock.closed)

if __name__=='__main__':unittest.main(verbosity=2)
