import unittest
from wirepy.lib import dfilter


class TestDisplayFilter(unittest.TestCase):

    def test_compile(self):
        dfilter.DisplayFilter('eth')
        dfilter.DisplayFilter('ip.src==192.168.100.2')

    def test_compile_empty(self):
        # The null filter results in a null-pointer which is still a valid
        # value for this struct
        df = dfilter.DisplayFilter('')
        self.assertEqual(df.cdata, dfilter.iface.NULL)

    def test_compile_error(self):
        self.assertRaises(dfilter.DisplayFilterError, dfilter.DisplayFilter,
                          '_B0RK_')
        self.assertRaises(dfilter.DisplayFilterError, dfilter.DisplayFilter,
                          'ip.proto == -1')
