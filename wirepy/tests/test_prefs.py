import unittest

from wirepy.lib import prefs, epan

epan.epan_init()


class TestPreferences(unittest.TestCase):

    def test_set_pref(self):
        p = prefs.read_prefs()
        self.assertRaises(prefs.PrefSyntaxError, p.set_pref, '_B0RK_')
        self.assertRaises(prefs.NoSuchPreference, p.set_pref, 'foo.bar:""')
        p.set_pref('column.format: "No.", "%m"')
        self.assertEqual(p.num_cols, 1)
        #self.assertEqual(len(p.col_list), 1)

    def test_global_prefs(self):
        p = prefs.get_global_prefs()
        self.assertTrue(p.is_global_prefs)
