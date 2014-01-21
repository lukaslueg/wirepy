import unittest
from wirepy.lib import wsutil

wsutil.init_process_policies()


class TestWSUtil(unittest.TestCase):

    def test_started_with_privs(self):
        self.assertTrue(isinstance(wsutil.started_with_special_privs(), bool))

    def test_running_with_privs(self):
        self.assertTrue(isinstance(wsutil.running_with_special_privs(), bool))

    def test_cur_username(self):
        self.assertTrue(isinstance(wsutil.get_cur_username(), str))

    def test_cur_groupname(self):
        self.assertTrue(isinstance(wsutil.get_cur_groupname(), str))
