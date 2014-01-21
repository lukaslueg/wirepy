import unittest
import cffi
from wirepy.lib import cdata, wireshark

test_iface = cffi.FFI()
test_iface.cdef('''
                typedef struct {
                    int barint;
                } barobject;

                typedef struct _fooobject fooobject;

                struct _fooobject {
                    int fooint;
                    char *foostring;
                    unsigned char foobool;
                    char **foostringarray;
                    int *foointarray;
                    unsigned char *fooboolarray;
                    int fooarraysize;
                    barobject *foobar;
                    fooobject *next;
                    barobject **foobars;
                };
                ''')
wireshark.iface.include(test_iface)


class TestCData(object):

    def _make_class(self):

        class Foo(cdata.CDataObject):
            fooarraysize = cdata.Attribute()
            if hasattr(self, 'testattr'):
                testattr = self.testattr
            _mod_defs = ('FT_', )

            def __init__(self, testvalue=None):
                if isinstance(testvalue, test_iface.CData):
                    self.cdata = testvalue
                else:
                    self.cdata = wireshark.iface.new('fooobject*')
                    if testvalue is not None:
                        self.testattr = testvalue
        return Foo

    def _make_object(self, testvalue=None):
        return self.klass(testvalue)

    def setUp(self):
        self.klass = self._make_class()
        self.inst = self._make_object()


class TestModDefs(TestCData, unittest.TestCase):

    def test_defs(self):
        self.assertTrue('FT_NONE' in dir(self.inst))


class TestAttribute(TestCData, unittest.TestCase):
    pass


class TestIntAttribute(TestAttribute):
    testattr = cdata.Attribute(structmember='fooint')

    def test_read(self):
        self.assertEqual(self.inst.testattr, 0)

    def test_write(self):
        self.inst.testfield = 12345
        self.assertEqual(self.inst.testfield, 12345)

    def test_delete(self):
        self.assertRaises(cdata.AttributeAccessError, delattr, self.inst,
                          'testattr')


class TestStumpAttribute(TestAttribute):
    testattr = cdata.Attribute(structmember='fooint', can_read=False,
                               can_write=False)

    def test_read(self):
        self.assertRaises(cdata.AttributeAccessError, getattr, self.inst,
                          'testattr')

    def test_write(self):
        self.assertRaises(cdata.AttributeAccessError, setattr, self.inst,
                          'testattr', 123)


class TestBytesAttribute(TestAttribute):
    testattr = cdata.BytesAttribute(structmember='fooboolarray',
                                    sizeattr='fooarraysize')

    def test_read(self):
        self.assertEqual(self.inst.testattr, None)

    def test_write(self):
        crib = b'\x47\x11\x49\x11'
        self.inst.testattr = crib
        self.inst.fooarraysize = len(crib)
        self.assertEqual(self.inst.testattr, crib)
        self.inst.testattr = None
        self.assertEqual(self.inst.testattr, None)

    def test_delete(self):
        self.inst.testattr = b'\x11\x12'
        del self.inst.testattr
        self.assertEqual(self.inst.testattr, None)


class TestStringAttribute(TestAttribute):
    testattr = cdata.StringAttribute(structmember='foostring')

    def test_read(self):
        self.assertEqual(self.inst.testattr, None)

    def test_write(self):
        self.inst.testattr = 'foostring'
        self.assertEqual(self.inst.testattr, 'foostring')
        self.inst.testattr = None
        self.assertEqual(self.inst.testattr, None)

    def test_delete(self):
        self.inst.testattr = 'foostring'
        del self.inst.testattr
        self.assertEqual(self.inst.testattr, None)


class TestBoolAttribute(TestAttribute):
    testattr = cdata.BooleanAttribute(structmember='foobool')

    def test_read(self):
        self.assertEqual(self.inst.testattr, False)

    def test_write(self):
        self.inst.testattr = True
        self.assertEqual(self.inst.testattr, True)

    def test_delete(self):
        self.assertRaises(cdata.AttributeAccessError, delattr, self.inst,
                          'testattr')


class TestIntListAttribute(TestAttribute):
    testattr = cdata.IntListAttribute(structmember='foointarray',
                                      sizeattr='fooarraysize')

    def test_empty(self):
        self.assertEqual(self.inst.testattr, None)

    def test_write(self):
        self.inst.fooarraysize = 2
        self.inst.testattr = [4711, 4911]
        obj = self.inst.testattr
        self.assertTrue(isinstance(obj, cdata.AttributeList))
        self.assertEqual(obj[0], 4711)
        self.assertEqual(obj[1], 4911)

    def test_sizeerror(self):
        self.inst.fooarraysize = 5
        self.assertRaises(cdata.AttributeSizeError, setattr, self.inst,
                          'testattr', [4711, 4911])

    def test_indexerror(self):
        self.inst.fooarraysize = 2
        self.inst.testattr = [4711, 4911]
        self.assertRaises(IndexError, self.inst.testattr.__setitem__,
                          3, 4711)


class TestFixedIntListAttribute(TestAttribute):
    testattr = cdata.IntListAttribute(structmember='foointarray',
                                      sizeattr=5)

    def test_write(self):
        self.inst.testattr = list(range(5))
        self.assertEqual(list(range(5)), list(self.inst.testattr))

    def test_sizeerror(self):
        self.assertRaises(cdata.AttributeSizeError, setattr, self.inst,
                          'testattr', [1, 2, 3])


class TestBoolListAttribute(TestAttribute):
    testattr = cdata.BooleanListAttribute('fooarraysize', 'fooboolarray')

    def test_empty(self):
        self.assertEqual(self.inst.testattr, None)

    def test_write(self):
        self.inst.fooarraysize = 4
        self.inst.testattr = [True, False, 0, object()]
        obj = self.inst.testattr
        self.assertTrue(isinstance(obj, cdata.BooleanAttributeList))
        self.assertEqual(obj[0], True)
        self.assertEqual(obj[1], False)
        self.assertEqual(obj[2], False)
        self.assertEqual(obj[3], True)

    def test_sizeerror(self):
        self.inst.fooarraysize = 5
        self.assertRaises(cdata.AttributeSizeError, setattr, self.inst,
                          'testattr', [True, False])

    def test_indexerror(self):
        self.inst.fooarraysize = 1
        self.inst.testattr = [True]
        self.assertRaises(IndexError, self.inst.testattr.__setitem__,
                          1, True)


class TestStringListAttribute(TestAttribute):
    testattr = cdata.StringListAttribute('fooarraysize', 'foostringarray')

    def test_empty(self):
        self.assertEqual(self.inst.testattr, None)

    def test_write(self):
        self.inst.fooarraysize = 2
        self.inst.testattr = ['foo', 'bar']
        obj = self.inst.testattr
        self.assertTrue(isinstance(obj, cdata.StringAttributeList))
        self.assertEqual(obj[0], 'foo')
        self.assertEqual(obj[1], 'bar')

    def test_sizeerror(self):
        self.inst.fooarraysize = 5
        self.assertRaises(cdata.AttributeSizeError, setattr, self.inst,
                          'testattr', ['foo', 'bar'])

    def test_indexerror(self):
        self.inst.fooarraysize = 2
        self.inst.testattr = ['foo', 'bar']
        self.assertRaises(IndexError, self.inst.testattr.__setitem__,
                          3, 'foo')


class TestInstanceAttribute(TestAttribute):

    class Foocls(cdata.CDataObject):
        _struct = 'barobject'
        barint = cdata.Attribute()

        def __init__(self, init):
            if isinstance(init, test_iface.CData):
                self.cdata = init
            elif isinstance(init, int):
                self.cdata = test_iface.new('barobject*')
                self.barint = init
            else:
                raise TypeError(type(init))

    testattr = cdata.InstanceAttribute(Foocls, structmember='foobar')

    def test_empty(self):
        self.assertEqual(self.inst.testattr, None)

    def test_write(self):
        inst = self.Foocls(5)
        self.inst.testattr = inst
        self.assertEqual(self.inst.testattr.barint, 5)


class TestInstanceListAttribute(TestAttribute):
    testattr = cdata.InstanceListAttribute(TestInstanceAttribute.Foocls,
                                           structmember='foobars',
                                           sizeattr='fooarraysize')

    def test_empty(self):
        self.assertEqual(self.inst.testattr, None)

    def test_write(self):
        self.inst.fooarraysize = 5
        self.inst.testattr = [TestInstanceAttribute.Foocls(i)
                              for i in range(5)]
        objs = list(self.inst.testattr)
        self.assertEqual(len(objs), 5)
        self.assertEqual([obj.barint for obj in objs], list(range(5)))


class TestSelfReferringInstanceAttribute(TestAttribute):
    testattr = cdata.InstanceAttribute(None, structmember='next')

    def test_empty(self):
        self.assertEqual(self.inst.testattr, None)

    def test_write(self):
        obj = self._make_object()
        self.inst.testattr = obj
        self.assertEqual(self.klass, type(self.inst.testattr))
