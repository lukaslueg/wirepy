import atexit
import functools
from .cdata import (CDataObject, Attribute, BooleanAttribute, ROAttribute,
                    ROStringAttribute, InstanceAttribute)
from .wireshark import iface, mod
from . import glib2, ftypes, timestamp, wsutil


class EPANError(Exception):
    pass


class FieldError(EPANError):
    pass


class InvalidFieldError(FieldError):
    pass


class ProtocolError(EPANError):
    pass


class InvalidProtocolError(ProtocolError):
    pass


class FieldValue(object):
    pass


class TrueFalseString(FieldValue):
    '''A true_false_string'''

    def __init__(self, true_string, false_string):
        self.true_string = true_string
        self.false_string = false_string

    def __repr__(self):
        return '<TrueFalse true="%s" false="%s">' % (self.true_string,
                                                     self.false_string)


@functools.total_ordering
class RangeValue(FieldValue):
    '''A range_string'''

    def __init__(self, value_min, value_max, string):
        self.value_min = value_min
        self.value_max = value_max
        self.string = string

    def __repr__(self):
        return '<Range min=%i max=%i str="%s">' % (self.value_min,
                                                   self.value_max, self.string)

    def __eq__(self, other):
        if isinstance(other, RangeValue):
            return ((other.value_min, other.value_max, other.string) ==
                    (self.value_min, self.value_max, self.string))
        else:
            False

    def __lt__(self, other):
        if isinstance(other, RangeValue):
            return ((other.value_max, other.value_min, other.string) >
                    (self.value_max, other.value_min, other.string))
        return False


@functools.total_ordering
class StringValue(FieldValue):
    '''A value_string'''

    def __init__(self, cdata):
        self.cdata = cdata

    def __repr__(self):
        return '<String value=%i string="%s">' % (self.value, self.string)

    def __eq__(self, other):
        if isinstance(other, StringValue):
            return (self.value, self.string) == (other.value, other.string)
        return False

    def __lt__(self, other):
        if isinstance(other, StringValue):
            return (self.value, self.string) < (other.value, other.string)
        return False

    @property
    def value(self):
        return self.cdata.value

    @property
    def string(self):
        return iface.string(self.cdata.strptr)


class ExtValueString(FieldValue, CDataObject):
    '''A value_string_ext'''

    _struct = '_value_string_ext'
    num_entries = ROAttribute('_vs_num_entries')
    name = ROStringAttribute('_vs_name')
    # TODO add more

    def __init__(self, cdata):
        self.cdata = cdata

    def __repr__(self):
        return '<ExtValueString num_entries=%i name="%s"' % (self.num_entries,
                                                             self.name)

    @property
    def strings(self):
        return self.cdata._vs_p

    def try_val_to_str_ext(self, val):
        m = mod.try_val_to_str_ext(val, self.cdata)
        return StringValue(m) if m != iface.NULL else None


class Field(CDataObject):
    '''A _header_field_info'''

    _struct = '_header_field_info'
    _mod_defs = ('^BASE_', )
    name = ROStringAttribute(doc='Full name of this field.')
    abbrev = ROStringAttribute(doc='Abbreviated name of this field.')
    type_ = InstanceAttribute(structmember='type', klass=ftypes.FieldType,
                              doc='Field type.')
    display = Attribute(doc=('One of BASE or field bit-width if '
                             'FT_BOOLEAN and non-zero bitmask.'))
    # strings
    bitmask = Attribute(doc='Bitmask of interesting fields.')
    blurb = ROStringAttribute(doc='Brief description of field.')
    id_ = Attribute('id', doc='Field ID.')
    # parent = cdata.Attribute(
    bitshift = Attribute(doc='Bits to shift.')
    same_name_next = InstanceAttribute(None, doc=('Next Field with same '
                                                  'abbrev.'))
    same_name_prev = InstanceAttribute(None, doc=('Previous Field with '
                                                  'same abbrev'))

    def __init__(self, init):
        if not mod.WIREPY_EPAN_INITIALIZED:
            raise RuntimeError('EPAN must be initialized')
        if isinstance(init, int):
            c = mod.proto_registrar_get_nth(init)
        elif isinstance(init, str):
            c = mod.proto_registrar_get_byname(init.encode())  # TODO py2/py3k
        elif isinstance(init, iface.CData):
            c = init
        else:
            raise TypeError(type(init))
        if c == iface.NULL:
            raise InvalidFieldError
        self.cdata = c

    def __getitem__(self, name):
        try:
            f = Field(name)
        except InvalidFieldError:
            raise KeyError
        assert f.parent == self.id_  # Should this always raise a KeyError?
        return f

    def __repr__(self):
        return '<Field id_=%i abbrev="%s" name="%s">' % (self.id_, self.abbrev,
                                                         self.name)

    @staticmethod
    def _iter_string_vals(strings):
        vals = iface.cast('value_string*', strings)
        i = 0
        while vals[i].strptr != iface.NULL:
            yield StringValue(vals[i])
            i += 1

    def _iter_integer_vals(self):
        if self.display & self.BASE_EXT_STRING:
            vse = ExtValueString(iface.cast('value_string_ext*',
                                            self.strings))
            vse.try_val_to_str_ext(0)  # "prime" the vse
            yield vse
            for v in self._iter_string_vals(vse.strings):
                yield v
        elif self.display & self.BASE_RANGE_STRING == 0:
            for v in self._iter_string_vals(self.strings):
                yield v
        else:
            rs = iface.cast('range_string*', self.strings)
            i = 0
            while rs[i].strptr != iface.NULL:
                yield RangeValue(rs[i].value_min, rs[i].value_max,
                                 iface.string(rs[i].strptr))
                i += 1

    def __iter__(self):
        if self.type_ == ftypes.FieldType.PROTOCOL or \
                self.strings == iface.NULL:
            raise StopIteration
        if self.type_is_integer:
            for v in self._iter_integer_vals():
                yield v
        elif self.type_ == ftypes.FieldType.BOOLEAN:
            tfs = iface.cast('true_false_string*', self.strings)
            yield TrueFalseString(iface.string(tfs.true_string),
                                  iface.string(tfs.false_string))
        else:
            # Should not happen, but wireshark has a few of them...
            pass
            #raise NotImplementedError

    @property
    def base(self):
        return self.display & self.BASE_DISPLAY_E_MASK

    @property
    def type_is_integer(self):
        """True if type is one of FT_INT or FT_UINT"""
        return self.base != self.BASE_CUSTOM and \
            self.type_ in (ftypes.FieldType.INT8, ftypes.FieldType.INT16,
                           ftypes.FieldType.INT32, ftypes.FieldType.INT32,
                           ftypes.FieldType.INT64, ftypes.FieldType.UINT8,
                           ftypes.FieldType.UINT16, ftypes.FieldType.UINT32,
                           ftypes.FieldType.UINT64)

    @property
    def strings(self):
        '''value_string, range_string or true_false_string, typically converted
        by VALS(), RVALS() or TFS(). If this is an FT_PROTOCOL then it points
        to the associated protocol_t structure'''  # TODO
        return self.cdata.strings

    @property
    def parent(self):
        '''parent protocol'''
        return self.cdata.parent  # TODO either a field or a protocol


class Protocol(object):

    def __init__(self, id):
        self.id = id

    def __iter__(self):
        cookie = iface.new('void **cookie')
        f = mod.proto_get_first_protocol_field(self.id, cookie)
        while f != iface.NULL:
            yield Field(f)
            f = mod.proto_get_next_protocol_field(cookie)

    def __getitem__(self, fieldname):
        for field in self:
            if field.abbrev == fieldname:
                return field
        raise KeyError

    def __repr__(self):
        s = '<Protocol id=%i filter_name="%s" name="%s"' % (self.id,
                                                            self.filter_name,
                                                            self.name)
        if self.is_private:
            s += ' is_private'
        if self.is_enabled:
            s += ' is_enabled'
        return s + '>'

    @classmethod
    def by_id(cls, id):
        return cls(id)

    @classmethod
    def by_filter_name(cls, name):
        id = mod.proto_get_id_by_filter_name(name.encode())
        if id == -1:
            raise InvalidProtocolError
        return cls.by_id(id)

    @property
    def is_private(self):
        return bool(mod.proto_is_private(self.id))

    @property
    def can_toggle_protection(self):
        return bool(mod.proto_can_toggle_protocol(self.id))

    @property
    def name(self):
        return iface.string(mod.proto_get_protocol_name(self.id))

    @property
    def short_name(self):
        proto_t = mod.find_protocol_by_id(self.id)
        return iface.string(mod.proto_get_protocol_short_name(proto_t))

    @property
    def long_name(self):
        proto_t = mod.find_protocol_by_id(self.id)
        return iface.string(mod.proto_get_protocol_long_name(proto_t))

    @property
    def is_enabled(self):
        proto_t = mod.find_protocol_by_id(self.id)
        return bool(mod.proto_is_protocol_enabled(proto_t))

    @property
    def filter_name(self):
        return iface.string(mod.proto_get_protocol_filter_name(self.id))

    def set_decoding(self, enabled):
        mod.proto_set_decoding(self.id, enabled)

    def set_cant_toggle(self):
        mod.proto_set_cant_toggle(self.id)


class FieldInfo(CDataObject):
    _struct = 'field_info'
    _mods = ('ETT_',)
    BIG_ENDIAN = mod.FI_BIG_ENDIAN
    GENERATED = mod.FI_GENERATED
    HIDDEN = mod.FI_HIDDEN
    LITTLE_ENDIAN = mod.FI_LITTLE_ENDIAN
    URL = mod.FI_URL
    start = Attribute(doc='Current start of data in data source.')
    length = Attribute(doc='Current data length in data source.')
    appendix_start = Attribute(doc='Start of appendix data.')
    appendix_length = Attribute(doc='Length of appendix data.')
    tree_type = Attribute(doc='One of FieldInfo.ETT_ or -1')
    hfinfo = InstanceAttribute(Field, doc='Registered field information.')

    def __init__(self, cdata):
        self.cdata = cdata

    def __repr__(self):
        rep = '<FieldInfo start=%i length=%i rep="%s"'
        return rep % (self.start, self.length, self.rep)

    @property
    def rep(self):
        '''string for GUI tree'''
        if self.cdata.rep == iface.NULL:
            # make a generic label
            cdata_obj = iface.new('char []', mod.ITEM_LABEL_LENGTH)
            mod.proto_item_fill_label(self.cdata, cdata_obj)
            # TODO: mark as [generated] as advised
            return iface.string(cdata_obj)
        else:
            # TODO: safe to access the item_label_t this way?
            return iface.string(self.cdata.rep.representation)

    @property
    def flags(self):
        '''bitfield like FI_GENERATED, ...'''
        return self.cdata.flags  # TODO parse this here?

    @property
    def data_source(self):
        '''data source tvbuff'''
        return self.cdata.ds_tvb  # TODO a tvbuff_t

    @property
    def value(self):
        '''an fvalue_t'''
        return ftypes.Value(iface.addressof(self.cdata.value))


class TreeData(CDataObject):
    _struct = 'tree_data_t'
    #interesting_hfids
    visible = BooleanAttribute()
    fake_protocols = BooleanAttribute()
    count = Attribute()

    def __init__(self, cdata_obj):
        self.cdata = cdata_obj

    def __repr__(self):
        r = '<TreeData count=%i' % (self.count, )
        if self.visible:
            r += ' visible'
        if self.fake_protocols:
            r += ' fake_protocols'
        return r + '>'


class ProtoNode(CDataObject):
    _struct = 'proto_node'
    first_child = InstanceAttribute(None, doc='The first child in the tree.')
    last_child = InstanceAttribute(None, doc='The last child in the tree.')
    next = InstanceAttribute(None, doc='The sibling of this node.')
    parent = InstanceAttribute(None, doc='The parent of this node.')
    field_info = InstanceAttribute(FieldInfo, structmember='finfo',
                                   doc='A FieldInfo describing this field.')
    tree_data = InstanceAttribute(TreeData)

    def __init__(self, cdata):
        self.cdata = cdata

    def __repr__(self):
        r = '<ProtoNode'
        if self.is_hidden:
            r += ' hidden'
        if self.first_child is not None:
            r += ' with_children'
        if self.next is not None:
            r += ' with_sibling'
        if self.field_info is not None:
            r += ' field_info="%s"' % (repr(self.field_info), )
        return r + '>'

    @property
    def is_hidden(self):
        '''True if this node should be hidden'''
        return bool(mod.wrapped_proto_item_is_hidden(self.cdata))


class ProtoTree(ProtoNode):
    pass


class ProtoItem(ProtoNode):
    pass


class Dissect(CDataObject):
    '''Object encapsulation for type epan_dissect_t'''

    _struct = 'epan_dissect_t'
    tree = InstanceAttribute(ProtoTree)
    # TODO tvb, a packet_info - should be of great value but very detailed

    def __init__(self, cdata_obj=None, create_proto_tree=True,
                 proto_tree_visible=True):
        if cdata_obj is None:
            cdata_obj = iface.new('epan_dissect_t*')
            self.init(cdata_obj, create_proto_tree, proto_tree_visible)
            self.cdata = iface.gc(cdata_obj, self.cleanup)
        else:
            self.cdata = cdata_obj

    @staticmethod
    def init(cdata_obj, create_proto_tree, proto_tree_visible):
        '''initialize an existing single packet dissection'''
        mod.epan_dissect_init(cdata_obj, create_proto_tree, proto_tree_visible)

    def fake_protocols(self, fake_protocols):
        '''Indicate whether we should fake protocols or not'''
        mod.epan_dissect_fake_protocols(self.cdata, fake_protocols)

    def run(self, wtap, frame, column_info=None):
        '''run a single packet dissection'''
        header = wtap.packetheader.cdata
        data = wtap.buf_ptr
        frame_data = frame.cdata
        if column_info is not None:
            column_info = column_info.cdata
        else:
            column_info = iface.NULL
        mod.epan_dissect_run(self.cdata, header, data, frame_data, column_info)

    def prime_cinfo(self, cinfo):
        mod.col_custom_prime_edt(self.cdata, cinfo.cdata)

    def prime_dfilter(self, dfp):
        '''Prime a proto_tree using the fields/protocols used in a dfilter.'''
        mod.epan_dissect_prime_dfilter(self.cdata, dfp.cdata)

    def fill_in_columns(self, fill_col_exprs=True, fill_fd_columns=True):
        '''fill the dissect run output into the packet list columns'''
        # TODO  fill_fd_columns == fill FrameData-columns
        if not timestamp.is_initialized():
            # we need this because wireshark will assert-fail in
            # col_fill_in_frame_data()
            raise RuntimeError('Timestamps need to be initialized.')
        mod.epan_dissect_fill_in_columns(self.cdata, fill_col_exprs,
                                         fill_fd_columns)

    @staticmethod
    def cleanup(cdata_obj):
        '''releases resources attached to the packet dissection. DOES NOT free
        the actual pointer'''
        mod.epan_dissect_cleanup(cdata_obj)

    @staticmethod
    def free(cdata_obj):
        '''Free a single packet dissection.

           This is basically the same as .cleanup() with another call to
           g_free() on the pointer.
        '''
        mod.epan_dissect_free(cdata_obj)


def iter_fields():
    for id_ in range(mod.proto_registrar_n()):
        yield Field(id_)


def iter_protocols():
    cookie = iface.new('void **')
    i = mod.proto_get_first_protocol(cookie)
    while i != -1:
        yield Protocol(i)
        i = mod.proto_get_next_protocol(cookie)


def get_version():
    return iface.string(mod.epan_get_version())


def get_compiled_version_info(string=''):
    s = glib2.String(string)
    mod.epan_get_compiled_version_info(s.cdata)
    return str(s)


def report_open_failure_message(filename, err, for_writing):
    print(('open_failure', filename, err, for_writing))


def report_read_failure_message(filename, err):
    print(('read_failure', filename, err))


def report_write_failure_message(filename, err):
    print(('write_failure', filename, err))


def report_failure_message(msg):
    print('failure', msg)


def epan_init(init_timestamp=True):
    if mod.WIREPY_EPAN_INITIALIZED:
        # a second call to epan_init() will raise an assertion error inside
        # wireshark
        return
    if 'with Python' in get_compiled_version_info():
        raise RuntimeError('Wireshark is no good')

    @iface.callback('void(const char *, int, gboolean)')
    def open_failure_message_cb(filename, err, for_writing):
        report_open_failure_message(filename, err, for_writing)

    @iface.callback('void(const char *, int)')
    def read_failure_message_cb(filename, err):
        report_read_failure_message(filename, err)

    @iface.callback('void(const char*, int)')
    def write_failure_message_cb(filename, err):
        report_write_failure_message(filename, err)

    @iface.callback('void(const char *, int)')
    def failure_message_cb(msg, size):
        report_failure_message(iface.string(msg, size))

    mod.failure_message = failure_message_cb

    # One MUST call init_process_policies before epan_init
    wsutil.init_process_policies()

    mod.wrapped_epan_init(open_failure_message_cb,
                          read_failure_message_cb,
                          write_failure_message_cb)
    mod.WIREPY_EPAN_INITIALIZED = True
    atexit.register(mod.epan_cleanup)

    if init_timestamp:
        timestamp.set_type(timestamp.RELATIVE)
        timestamp.set_precision(timestamp.PREC_FIXED_SEC)
        timestamp.set_seconds_type(timestamp.SECONDS_DEFAULT)


def init_dissection():
    '''Initialize all data structures used for dissection.'''
    mod.init_dissection()


def cleanup_dissection():
    '''extern void init_dissection'''  # TODO
    mod.cleanup_dissection()
