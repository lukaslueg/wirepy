import unittest
from wirepy.lib import glib2


class TestString(unittest.TestCase):

    def test_empty(self):
        s = glib2.String('')
        self.assertEqual(len(s), 0)
        self.assertEqual(str(s), '')

    def test_str(self):
        crib = 'foobar'
        s = glib2.String(crib)
        self.assertEqual(len(s), len(crib))
        self.assertEqual(s.string, crib)
        self.assertEqual(str(s), crib)
        self.assertGreaterEqual(s.allocated_len, len(crib))
        del s
