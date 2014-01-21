import unittest
from wirepy.lib import epan, ftypes

epan.epan_init()


class TestModule(unittest.TestCase):

    def test_iter_ftypes(self):
        cribs = [ftypes.FieldType.NONE, ftypes.FieldType.ABSOLUTE_TIME,
                 ftypes.FieldType.ETHER]
        for ft in ftypes.iter_ftypes():
            self.assertTrue(isinstance(ft, ftypes.FieldType))
            repr(ft)
            if ft in cribs:
                cribs.remove(ft)
            if len(cribs) == 0:
                break
        else:
            self.fail('Types NONE, ABSOLUTE_TIME and ETHER should be there')


class TestFieldType(unittest.TestCase):

    def test_invalid_new(self):
        self.assertRaises(ftypes.InvalidFieldType, ftypes.FieldType, -1)

    def test_ftype(self):
        ft = ftypes.FieldType(ftypes.FieldType.BOOLEAN)
        self.assertFalse(ft.can_slice)
        self.assertTrue(ft.can_eq)
        self.assertTrue(ft.can_ne)
        self.assertFalse(ft.can_gt)
        self.assertFalse(ft.can_ge)
        self.assertFalse(ft.can_lt)
        self.assertFalse(ft.can_le)
        self.assertFalse(ft.can_contains)
        self.assertFalse(ft.can_matches)

    def test_value_from_unparsed(self):
        ft = ftypes.FieldType(ftypes.FieldType.BOOLEAN)
        self.assertTrue(isinstance(ft.value_from_unparsed('0'), ftypes.Value))

        ft = ftypes.FieldType(ftypes.FieldType.IPv4)
        self.assertTrue(isinstance(ft.value_from_unparsed('127.0.0.1'),
                                   ftypes.Value))
        with self.assertRaises(ftypes.CantParseValue) as ctx:
            ft.value_from_unparsed('')
        self.assertTrue('is not a valid hostname' in ctx.exception.messages[0])


class TestBooleanValues(unittest.TestCase):

    def test_cmp(self):
        v1 = ftypes.FieldType(ftypes.FieldType.BOOLEAN).value_from_unparsed('0')
        v2 = ftypes.FieldType(ftypes.FieldType.BOOLEAN).value_from_unparsed('1')
        self.assertEqual(v1, v1)
        self.assertNotEqual(v1, v2)
        for f in ('__gt__', '__ge__', '__lt__', '__le__'):
            self.assertRaises(ftypes.OperationNotPossible, getattr(v1, f), v2)


class TestStringValues(unittest.TestCase):

    def setUp(self):
        self.ft = ftypes.FieldType(ftypes.FieldType.STRING)
        self.value = self.ft.value_from_unparsed('foobar')

    def test_repr(self):
        repr(self.value)
        self.assertEqual(self.value.to_string_repr(self.value.REPR_DISPLAY),
                         'foobar')
        self.assertEqual(self.value.to_string_repr(self.value.REPR_DFILTER),
                         '"foobar"')

    def test_len(self):
        self.assertEqual(len(self.value), len('foobar'))

    def test_type(self):
        self.assertEqual(self.value.type_.name, 'FT_STRING')


class TestInt32Values(unittest.TestCase):

    def setUp(self):
        self.ft = ftypes.FieldType(ftypes.FieldType.INT32)
        self.value = self.ft.value_from_unparsed('4711')

    def test_repr(self):
        repr(self.value)
        self.assertEqual(self.value.to_string_repr(self.value.REPR_DISPLAY),
                         '4711')
        self.assertEqual(self.value.to_string_repr(self.value.REPR_DFILTER),
                         '4711')

    def test_len(self):
        self.assertRaises(ftypes.OperationNotPossible, self.value.len)
        self.assertEqual(len(self.value), 4)

    def test_cmp(self):
        v1 = self.ft.value_from_unparsed('100')
        v2 = self.ft.value_from_unparsed('200')
        self.assertEqual(v1, v1)
        self.assertNotEqual(v1, v2)
        self.assertTrue(v1 < v2)
        self.assertTrue(v1 <= v2)
        self.assertTrue(v2 > v1)
        self.assertTrue(v2 >= v1)
