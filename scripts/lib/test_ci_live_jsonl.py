#!/usr/bin/env python3
"""Exercise ONLY exact workflow reader/wait functions; no workflow/client execution."""
import argparse, ast, json, tempfile, textwrap, unittest
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument("--workflow", type=Path, required=True)
args = p.parse_args()
lines = args.workflow.read_text().splitlines()
start = next(i for i, s in enumerate(lines) if s.strip().startswith("def read_jsonl("))
end = next(i for i in range(start + 1, len(lines)) if lines[i].strip().startswith("def first_event("))
module = ast.parse(textwrap.dedent("\n".join(lines[start:end])))
assert all(isinstance(n, ast.FunctionDef) for n in module.body)
assert [n.name for n in module.body] == ["read_jsonl", "wait_for_event"]
class Clock:
    def __init__(self, append): self.now = 0.0; self.calls = 0; self.append = append
    def time(self): return self.now
    def sleep(self, delay):
        self.calls += 1
        if self.calls > 3: raise AssertionError("controlled event should appear on first append; no unbounded wait")
        self.now += delay
        if self.calls == 1: self.append()
def functions(clock):
    ns = {"json": json, "time": clock}
    exec(compile(module, str(args.workflow) + ":exact-reader-ast", "exec"), ns)
    return ns["read_jsonl"], ns["wait_for_event"]
class ActualWorkflowReader(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="aegis-live-jsonl-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "events.jsonl"
    def staged_wait(self, record, prefix):
        prior = b'{"event_code":"prior","fields":{"count":1}}\n'
        self.path.write_bytes(prior + record[:prefix])
        def append():
            with self.path.open("ab") as file: file.write(record[prefix:] + b"\n")
        clock = Clock(append)
        _, wait = functions(clock)
        event, records = wait(self.path, "wanted", timeout=5.0)
        self.assertEqual(clock.calls, 1, "unterminated complete JSON must not be admitted before LF")
        self.assertEqual(event["event_code"], "wanted")
        self.assertEqual([r["event_code"] for r in records], ["prior", "wanted"])
        self.assertEqual(self.path.read_bytes(), prior + record + b"\n")
    def test_actual_wait_defers_partial_property_prefix_until_append(self):
        record = b'{"event_code":"wanted","fields":{"pad":"' + b'a' * 320 + b'","next":1}}'
        self.staged_wait(record, record.index(b',"next"') + 1)
    def test_actual_wait_defers_split_utf8_prefix_until_append(self):
        record = json.dumps({"event_code":"wanted","fields":{"text":"я"}}, ensure_ascii=False, separators=(",",":")).encode()
        self.staged_wait(record, record.index("я".encode()) + 1)
    def test_actual_wait_requires_lf_even_for_complete_json_tail(self):
        record = b'{"event_code":"wanted","fields":{}}'
        self.staged_wait(record, len(record))
    def test_actual_wait_refuses_committed_corrupt_record(self):
        self.path.write_bytes(b'{"event_code":"prior"}\n{"event_code":\n')
        clock = Clock(lambda: self.fail("committed corruption must not be retried"))
        _, wait = functions(clock)
        with self.assertRaises(json.JSONDecodeError): wait(self.path, "wanted", timeout=5.0)
        self.assertEqual(clock.calls, 0)
    def test_actual_offline_reader_refuses_malformed_tail(self):
        self.path.write_bytes(b'{"event_code":"prior"}\n{"event_code":')
        read, _ = functions(Clock(lambda: None))
        with self.assertRaises(json.JSONDecodeError): read(self.path)
    def test_actual_offline_reader_keeps_existing_valid_records(self):
        self.path.write_bytes(b'{"event_code":"prior"}\n\n{"event_code":"wanted"}\n')
        read, _ = functions(Clock(lambda: None))
        self.assertEqual([x["event_code"] for x in read(self.path)], ["prior", "wanted"])
if __name__ == "__main__": unittest.main(argv=["exact-workflow-live-reader"], verbosity=2)
