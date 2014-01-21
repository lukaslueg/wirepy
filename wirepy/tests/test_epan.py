import os
import unittest
from wirepy.lib import epan, ftypes, prefs, wtap
from wirepy.lib.wireshark import mod

epan.epan_init()
epan.init_dissection()
prefs.read_prefs()


class TestFunctions(unittest.TestCase):

    def test_version(self):
        self.assertTrue(isinstance(epan.get_version(), str))

    def test_compiled_version(self):
        v = epan.get_compiled_version_info('foobar')
        self.assertTrue(isinstance(v, str))
        self.assertTrue(v.startswith('foobar'))

    def test_iter_protocols(self):
        cribs = ['eth', 'smb', 'x11']
        for p in epan.iter_protocols():
            self.assertTrue(isinstance(p, epan.Protocol))
            if p.filter_name in cribs:
                cribs.remove(p.filter_name)
            if len(cribs) == 0:
                break
        else:
            self.fail('Protocols eth, smb and x11 should always be there')

    def test_iter_fields(self):
        for f in epan.iter_fields():
            self.assertTrue(isinstance(f, epan.Field))
            if f.abbrev == 'eth.src':
                break
        else:
            self.fail('Field eth.src should always be there')


class TestProtocol(unittest.TestCase):

    def test_by_filter_name(self):
        p = epan.Protocol.by_filter_name('eth')
        self.assertTrue(isinstance(p, epan.Protocol))
        self.assertRaises(epan.InvalidProtocolError,
                          epan.Protocol.by_filter_name, 'foobarprotocol')

    def test_by_id(self):
        pid = mod.proto_get_id_by_filter_name('eth'.encode())
        self.assertTrue(isinstance(epan.Protocol.by_id(pid), epan.Protocol))

    def test_repr(self):
        for n in ('eth', 'smb', 'x11'):
            p = epan.Protocol.by_filter_name(n)
            self.assertTrue(isinstance(repr(p), str))

    def test_attributes(self):
        p = epan.Protocol.by_filter_name('eth')
        self.assertTrue(p.is_private or True)
        self.assertTrue(p.can_toggle_protection or True)
        self.assertEqual(p.name, 'Ethernet')
        self.assertEqual(p.short_name, 'Ethernet')
        self.assertEqual(p.long_name, 'Ethernet')
        self.assertTrue(p.is_enabled or True)
        self.assertEqual(p.filter_name, 'eth')

    def test_iter_fields(self):
        p = epan.Protocol.by_filter_name('eth')
        cribs = ['eth.src', 'eth.dst']
        for field in p:
            self.assertTrue(isinstance(field, epan.Field))
            if field.abbrev in cribs:
                cribs.remove(field.abbrev)
            if len(cribs) == 0:
                break
        else:
            self.fail('Fields src and dst should always be in protocol eth')


class TestField(unittest.TestCase):

    def test_by_name(self):
        self.assertTrue(isinstance(epan.Field('eth.src'), epan.Field))
        self.assertRaises(epan.InvalidFieldError, epan.Field, 'foobarfield')

    def test_getitem(self):
        fieldname = 'eth.src'
        parent = epan.Field('eth')
        child = parent[fieldname]
        self.assertEqual(child.abbrev, fieldname)

    def test_getitemerror(self):
        field = epan.Field('eth')
        self.assertRaises(KeyError, field.__getitem__, '_B0RK_')

    def test_repr(self):
        for n in ('eth.src', 'eth.dst', 'eth.addr'):
            f = epan.Field(n)
            self.assertTrue(isinstance(f, epan.Field))
            self.assertTrue(isinstance(repr(f), str))

    def test_attributes(self):
        f = epan.Field('eth.len')
        self.assertEqual(f.name, 'Length')
        self.assertEqual(f.abbrev, 'eth.len')
        self.assertEqual(f.type_, ftypes.FieldType.UINT16)
        self.assertEqual(f.display, epan.Field.BASE_DEC)
        self.assertEqual(f.base, epan.Field.BASE_DEC)
        self.assertTrue(isinstance(f.bitmask, int))
        self.assertTrue(isinstance(f.id_, int))
        self.assertTrue(isinstance(f.parent, int))
        self.assertIsNone(f.same_name_next)
        self.assertIsNone(f.same_name_prev)

        f = epan.Field('eth.src')
        self.assertTrue(isinstance(f.blurb, str))

        f = epan.Field('ieee17221.message_type')
        self.assertTrue(isinstance(f.same_name_next or f.same_name_prev,
                                   epan.Field))

    def test_iter(self):
        l = list(epan.Field('ip.flags.sf'))
        self.assertGreater(len(l), 0)
        self.assertTrue(all(isinstance(v, epan.FieldValue) for v in l))


class TestFieldValues(unittest.TestCase):

    def test_tfs(self):
        field = epan.Field('ip.flags.sf')
        valuelist = list(field)
        self.assertEqual(len(valuelist), 1)
        tfs = valuelist[0]
        self.assertTrue(isinstance(tfs, epan.TrueFalseString))
        self.assertEqual(tfs.true_string, 'Evil')
        self.assertEqual(tfs.false_string, 'Not evil')

    def test_range(self):
        field = epan.Field('ip.opt.ra')
        valuelist = list(sorted(field))
        self.assertEqual(len(valuelist), 2)
        self.assertTrue(all(isinstance(v.string, str) for v in valuelist))
        v = valuelist[1]  # Reserved
        self.assertEqual(v.value_min, 1)
        self.assertEqual(v.value_max, 65535)
        v = valuelist[0]  # Shall examine
        self.assertEqual(v.value_min, 0)
        self.assertEqual(v.value_max, 0)

    def test_string(self):
        field = epan.Field('dns.nsec3.algo')
        valuelist = list(sorted(field))
        self.assertEqual(len(valuelist), 2)
        self.assertTrue(all(isinstance(v.string, str) for v in valuelist))
        self.assertTrue(all(isinstance(v.value, int) for v in valuelist))
        v = valuelist[0]
        self.assertEqual(v.value, 0)
        self.assertEqual(v.string, 'Reserved')
        v = valuelist[1]
        self.assertEqual(v.value, 1)
        self.assertEqual(v.string, 'SHA-1')

    def test_vse(self):
        field = epan.Field('ftp.response.code')
        values_it = iter(field)
        vse = next(values_it)
        self.assertTrue(isinstance(vse, epan.ExtValueString))
        self.assertEqual(vse.name, 'response_table')
        self.assertGreater(vse.num_entries, 0)
        values = list(values_it)
        self.assertEqual(len(values), vse.num_entries)
        self.assertTrue(all((isinstance(v, epan.StringValue) for v in values)))


class TestDissect(unittest.TestCase):
    testpath = os.path.dirname(os.path.abspath(__file__))
    testfile = os.path.join(testpath, 'sample_files/http.cap.gz')

    def setUp(self):
        self.wt = wtap.WTAP.open_offline(self.testfile)

    def _walk_tree(self, node):
        self.assertTrue(isinstance(node, epan.ProtoNode))
        fi = node.field_info
        if fi is not None:
            self.assertTrue(isinstance(fi, epan.FieldInfo))
            self.assertTrue(isinstance(fi.rep, str))
            repr(fi)
            self.assertTrue(isinstance(fi.value, ftypes.Value))
        if node.next is not None:
            self._walk_tree(node.next)
        if node.first_child is not None:
            self._walk_tree(node.first_child)

    def testRun(self):
        with self.wt:
            for frame in self.wt:
                edt = epan.Dissect()
                edt.run(self.wt, frame)
                self.assertTrue(isinstance(edt.tree, epan.ProtoNode))
                repr(edt.tree)
                self._walk_tree(edt.tree)
