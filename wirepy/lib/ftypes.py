from .wireshark import iface, mod
from . import cdata

# libwireshark segfaults if ftypes_initialize() has not been called
# which is only exposed through epan_init()


class FTypeError(Exception):
    pass


class OperationNotPossible(FTypeError):
    pass


class CantParseValue(FTypeError):

    def __init__(self, messages):
        self.messages = messages


class InvalidFieldType(FTypeError):
    pass


# TODO Memoize this, it's just an integer after all
class FieldType(object):
    '''A ftenum_t'''
    ABSOLUTE_TIME = mod.FT_ABSOLUTE_TIME  #: Absolute time
    BOOLEAN = mod.FT_BOOLEAN  #: Bool
    BYTES = mod.FT_BYTES  #: Raw bytes
    DOUBLE = mod.FT_DOUBLE  #: Double
    ETHER = mod.FT_ETHER  #: Ethernet
    ETHER_LEN = mod.FT_ETHER_LEN  #: Ethernet
    EUI64 = mod.FT_EUI64  #: 64-Bit extended unique identifier
    EUI64_LEN = mod.FT_EUI64_LEN  #: eui64_len
    FLOAT = mod.FT_FLOAT  #: Float
    FRAMENUM = mod.FT_FRAMENUM  #: Frame number
    GUID = mod.FT_GUID  #: GUID
    GUID_LEN = mod.FT_GUID_LEN  #: GUID
    INT16 = mod.FT_INT16  #: 16 bit wide integer
    INT24 = mod.FT_INT24  #: 24 bit wide integer
    INT32 = mod.FT_INT32  #: 32 bit wide integer
    INT64 = mod.FT_INT64  #: 64 bit wide integer
    INT8 = mod.FT_INT8  #: 8 bit wide integer
    IPXNET = mod.FT_IPXNET  #: IPX
    IPXNET_LEN = mod.FT_IPXNET_LEN  #: IPX
    IPv4 = mod.FT_IPv4  #: IPv4
    IPv4_LEN = mod.FT_IPv4_LEN  #: IPv4
    IPv6 = mod.FT_IPv6  #: IPv6
    IPv6_LEN = mod.FT_IPv6_LEN  #: IPv6
    NONE = mod.FT_NONE  #: Special
    OID = mod.FT_OID  #: OID
    PCRE = mod.FT_PCRE  #: PCRE
    PROTOCOL = mod.FT_PROTOCOL  #: Protocol
    RELATIVE_TIME = mod.FT_RELATIVE_TIME  #: Relative time
    STRING = mod.FT_STRING  #: String
    STRINGZ = mod.FT_STRINGZ  #: String
    UINT16 = mod.FT_UINT16  #: Unsigned 16 bit wide integer
    UINT24 = mod.FT_UINT24  #: Unsigned 24 bit wide integer
    UINT32 = mod.FT_UINT32  #: Unsigned 32 bit wide integer
    UINT64 = mod.FT_UINT64  #: Unsigned 64 bit wide integer
    UINT8 = mod.FT_UINT8  #: Unsigned 8 bit wide integer
    UINT_BYTES = mod.FT_UINT_BYTES  #: Raw bytes
    UINT_STRING = mod.FT_UINT_STRING  #: Raw bytes
    NUM_TYPES = mod.FT_NUM_TYPES  #: The number of field types

    def __init__(self, ftenum):
        if ftenum not in range(self.NUM_TYPES):
            raise InvalidFieldType(ftenum)
        self.ftenum = ftenum

    def __repr__(self):
        r = '<FieldType name="%s" pretty_name="%s"' % (self.name,
                                                       self.pretty_name)
        for prop in ('can_eq', 'can_ne', 'can_gt', 'can_ge', 'can_lt',
                     'can_le', 'can_contains', 'can_matches'):
            if getattr(self, prop):
                r += ' ' + prop
        return r + '>'

    def __int__(self):
        return self.ftenum

    def __hash__(self):
        return hash(self.ftenum)

    def __eq__(self, other):
        return int(self) == int(other)

    def value_from_unparsed(self, s, allow_partial_value=False):
        '''Create a new Value from an unparsed string representation'''
        logs = mod.LogFuncWrapper()
        with logs:
            fvalue_t = mod.fvalue_from_unparsed(self.ftenum, str(s).encode(),
                                                allow_partial_value,
                                                mod.logfunc_wrapper)
        if fvalue_t == iface.NULL:
            raise CantParseValue(logs.messages)
        # TODO what to do if value has been parsed and there are messages?
        # stick them into python's warning system?
        return Value(fvalue_t)

    @property
    def name(self):
        '''The name of this FieldType'''
        return iface.string(mod.ftype_name(self.ftenum))

    @property
    def pretty_name(self):
        '''A more human-friendly name of this FieldType'''
        return iface.string(mod.ftype_pretty_name(self.ftenum))

    # TODO do we really need these? It's only a null-check...
    @property
    def can_slice(self):
        return bool(mod.ftype_can_slice(self.ftenum))

    @property
    def can_eq(self):
        return bool(mod.ftype_can_eq(self.ftenum))

    @property
    def can_ne(self):
        return bool(mod.ftype_can_ne(self.ftenum))

    @property
    def can_gt(self):
        return bool(mod.ftype_can_gt(self.ftenum))

    @property
    def can_ge(self):
        return bool(mod.ftype_can_ge(self.ftenum))

    @property
    def can_lt(self):
        return bool(mod.ftype_can_lt(self.ftenum))

    @property
    def can_le(self):
        return bool(mod.ftype_can_le(self.ftenum))

    @property
    def can_contains(self):
        return bool(mod.ftype_can_contains(self.ftenum))

    @property
    def can_matches(self):
        return bool(mod.ftype_can_matches(self.ftenum))


def iter_ftypes():
    for i in range(FieldType.NUM_TYPES):
        yield FieldType(i)


class Type(cdata.CDataObject):
    '''A _ftype_t'''

    _struct = '_ftype_t*'
    ftype = cdata.InstanceAttribute(FieldType)
    name = cdata.StringAttribute()
    pretty_name = cdata.StringAttribute()
    wire_size = cdata.Attribute()

    def __init__(self, cdata):
        self.cdata = cdata

    def __repr__(self):
        return '<Type name="%s">' % (self.name, )

    def new(self):
        fv = iface.new('fvalue_t*')
        fv.ftype = self.cdata
        if self.new_value is not None:
            self.new_value(fv)
        return Value(fv)

    @property
    def new_value(self):
        return self.cdata.new_value

    @property
    def free_value(self):
        return self.cdata.free_value

    @property
    def from_unparsed(self):
        return self.cdata.val_from_unparsed

    @property
    def from_string(self):
        return self.cdata.val_from_string

    @property
    def to_string_repr(self):
        return self.cdata.val_to_string_repr

    @property
    def len_string_repr(self):
        f = self.cdata.len_string_repr
        return None if f == iface.NULL else f

    @property
    def set(self):
        return self.cdata.set_value

    @property
    def set_uinteger(self):
        return self.cdata.set_value_uinteger

    # TODO

    @property
    def get_value(self):
        return self.cdata.get_value or None

    @property
    def len(self):
        return self.cdata.len or None

    @property
    def cmp_eq(self):
        return self.cdata.cmp_eq or None

    @property
    def cmp_ne(self):
        return self.cdata.cmp_ne or None

    @property
    def cmp_gt(self):
        return self.cdata.cmp_gt or None

    @property
    def cmp_ge(self):
        return self.cdata.cmp_ge or None

    @property
    def cmp_lt(self):
        return self.cdata.cmp_lt or None

    @property
    def cmp_le(self):
        return self.cdata.cmp_le or None


class Value(object):
    '''A fvalue_t'''
    REPR_DISPLAY = mod.FTREPR_DISPLAY
    REPR_DFILTER = mod.FTREPR_DFILTER

    def __init__(self, cdata):
        self.cdata = cdata

    def __repr__(self):
        try:
            r = 'displayed as "%s"' % (self.to_string_repr(self.REPR_DISPLAY), )
        except OperationNotPossible:
            try:
                r = 'filtered as "%s"' % (self.to_string_repr(self.REPR_DFILTER), )
            except OperationNotPossible:
                r = ''
        return '<Value of type %s %s>' % (self.type_.name, r)

    def __len__(self):
        '''The length in bytes of this value. Falls back to the wire_size if
        the true length is not available'''
        try:
            return self.len()
        except OperationNotPossible:
            return self.type_.wire_size

    def __eq__(self, other):
        if isinstance(other, Value):
            return self.cmp_eq(other.cdata)
        else:
            return False

    def __ne__(self, other):
        if isinstance(other, Value):
            return self.cmp_ne(other.cdata)
        else:
            return False

    def __gt__(self, other):
        if isinstance(other, Value):
            return self.cmp_gt(other.cdata)
        else:
            return False

    def __ge__(self, other):
        if isinstance(other, Value):
            return self.cmp_ge(other.cdata)
        else:
            return False

    def __lt__(self, other):
        if isinstance(other, Value):
            return self.cmp_lt(other.cdata)
        else:
            return False

    def __le__(self, other):
        if isinstance(other, Value):
            return self.cmp_le(other.cdata)
        else:
            return False

    @property
    def type_(self):
        return Type(self.cdata.ftype)

    def new(self):
        '''Allocate and initialize a Value'''
        # TODO: you get the real pointer...
        self.type.new_value(cdata)
        return Value(cdata)

    def free(self):
        self.type.free_value(self.cdata)

    def to_string_repr(self, rtype=None):
        '''A human-readable string representation of this value. Raises
        OperationNotPossible if the value cannot be represented in the given
        rtype.'''  # TODO
        if rtype is None:
            rtype = self.REPR_DISPLAY
        l = self.len_string_repr(rtype)
        if l == -1:
            raise OperationNotPossible
        buf = iface.new('char[]', l + 1)
        self.type_.to_string_repr(self.cdata, rtype, buf)
        return iface.string(buf, l)

    def len_string_repr(self, rtype):
        '''Returns the length of the string required to hold the string
        representation of the field value.

        Returns -1 if the string cannot be represented in the given rtype.

        The length DOES NOT include the terminating NUL.'''
        f = self.type_.len_string_repr
        if f is None:
            raise OperationNotPossible
        return f(self.cdata, rtype)

    def len(self):
        func = self.type_.len
        if func is None:
            raise OperationNotPossible
        return func(self.cdata)

    def cmp_eq(self, other):
        func = self.type_.cmp_eq
        if func is None:
            raise OperationNotPossible
        return bool(func(self.cdata, other))

    def cmp_ne(self, other):
        func = self.type_.cmp_ne
        if func is None:
            raise OperationNotPossible
        return bool(func(self.cdata, other))

    def cmp_gt(self, other):
        func = self.type_.cmp_gt
        if func is None:
            raise OperationNotPossible
        return bool(func(self.cdata, other))

    def cmp_ge(self, other):
        func = self.type_.cmp_ge
        if func is None:
            raise OperationNotPossible
        return bool(func(self.cdata, other))

    def cmp_lt(self, other):
        func = self.type_.cmp_lt
        if func is None:
            raise OperationNotPossible
        return bool(func(self.cdata, other))

    def cmp_le(self, other):
        func = self.type_.cmp_le
        if func is None:
            raise OperationNotPossible
        return bool(func(self.cdata, other))

    def cmp_bitwise_and(self, other):
        return bool(self.type_.cmp_bitwise_and(self.cdata, self))
