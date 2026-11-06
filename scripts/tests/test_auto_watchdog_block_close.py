"""Main exit cannot substitute for kernel proof that all descendants are dead."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, MagicMock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
import aegis_auto_guardian_watchdog as watchdog

class BlockClose(unittest.TestCase):
    def close(self, empties):
        clock=[0.0];closed=[];reads=[];events=Mock();kill=Mock();leaf=MagicMock();block=Mock()
        leaf.__truediv__=Mock(side_effect=lambda name:events if name=='cgroup.events' else kill)
        def read():
            self.assertEqual(closed,[],'OFD must remain held until whole-leaf proof or bounded refusal')
            reads.append(clock[0]);return 'populated 0\n'if empties and len(reads)>=3 else 'populated 1\n'
        events.read_text.side_effect=read
        def wait(*,timeout):
            self.assertLessEqual(timeout,2.0);clock[0]+=1.5
        block.wait.side_effect=wait
        with patch.object(watchdog.time,'monotonic',side_effect=lambda:clock[0]), \
             patch.object(watchdog.time,'sleep',side_effect=lambda delay:clock.__setitem__(0,clock[0]+delay)), \
             patch.object(watchdog.os,'close',side_effect=lambda fd:closed.append(fd)):
            if empties:watchdog._close_fresh_block(block,77,leaf)
            else:
                with self.assertRaisesRegex(watchdog.Refused,'cgroup_populated'):watchdog._close_fresh_block(block,77,leaf)
        self.assertEqual(closed,[77]);kill.write_text.assert_called_once_with('1\n')
        self.assertLessEqual(clock[0],2.0+1e-9);self.assertGreaterEqual(len(reads),3)
        leaf.rmdir.assert_called_once()
    def test_reaped_main_still_waits_for_descendants_with_original_ofd(self):self.close(True)
    def test_populated_descendants_at_original_deadline_never_succeed(self):self.close(False)

if __name__=='__main__':unittest.main()
