import unittest

from ignirelay_lab.log_parser import actions_for_event, parse_jsonl


class LogParserTests(unittest.TestCase):
    def test_sample_log_matches_required_schema(self) -> None:
        records = parse_jsonl("samples/structured_log_sample.jsonl")
        self.assertEqual(len(records), 2)
        self.assertEqual(actions_for_event(records, "evt-sample"), ["tx", "store"])


if __name__ == "__main__":
    unittest.main()
