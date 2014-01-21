import unittest
from wirepy.lib import timestamp


class TestTimestamp(unittest.TestCase):

    def test_type(self):
        timestamp.set_type(timestamp.UTC)
        self.assertEqual(timestamp.get_type(), timestamp.UTC)

    def test_precision(self):
        timestamp.set_precision(timestamp.PREC_FIXED_SEC)
        self.assertEqual(timestamp.get_precision(),
                         timestamp.PREC_FIXED_SEC)

    def test_seconds_type(self):
        timestamp.set_seconds_type(timestamp.SECONDS_HOUR_MIN_SEC)
        self.assertEqual(timestamp.get_seconds_type(),
                         timestamp.SECONDS_HOUR_MIN_SEC)

    def test_errors(self):
        self.assertRaises(timestamp.InvalidTimestampValue,
                          timestamp.set_type, -1)
        self.assertRaises(timestamp.InvalidTimestampValue,
                          timestamp.set_seconds_type, -1)
