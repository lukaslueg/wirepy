'''Wireshark displays generic information about a packet's content in it's GUI
using a set of columns. Each column has one of several pre-defined column-types
which ``libwireshark`` knows about and fills with content while dissecting a
packets. This allows dissectors of all kinds to provide information about a
packet, no matter where in the protocol this information is ultimately
retrieved from.

For example, :py:attr:`Type.PROTOCOL` provides the name of the deepest protocol
found within a frame; a raw ethernet frame may provide "eth" for PROTOCOL, a IP
packet within the ethernet packet overrules this to "ip", a TCP packet within
the IP-packet again overrules to 'tcp' and a HTTP packet within the TCP packet
finally overrules to 'http'.

.. note::
    Wireshark uses columns in concert with it's preferences, the API reading
    column-settings directly from the global preferences object. To make this
    concept more flexible, we avoid this binding.
'''

from .wireshark import iface, mod
from . import dfilter
from .cdata import (CDataObject, Attribute, BooleanAttribute, StringAttribute,
                    InstanceAttribute, IntListAttribute, StringListAttribute,
                    InstanceListAttribute)


class ColumnError(Exception):
    '''Base class for all column-related errors.'''
    pass


class InvalidColumnType(ColumnError):
    '''An invalid column-type was provided.'''
    pass


class Type(object):
    '''A column-type.'''  # TODO
    _802IQ_VLAN_ID = mod.COL_8021Q_VLAN_ID  #: 802.1Q vlan ID
    ABS_DATE_TIME = mod.COL_ABS_DATE_TIME  #: Absolute date and time
    ABS_TIME = mod.COL_ABS_TIME  #: Absolute time
    CIRCUIT_ID = mod.COL_CIRCUIT_ID  #: Circuit ID
    DSTIDX = mod.COL_DSTIDX
    #: !! DEPRECATED !! - Dst port idx - Cisco MDS-specific
    SRCIDX = mod.COL_SRCIDX
    #: !! DEPRECATED !! - Src port idx - Cisco MDS-specific
    VSAN = mod.COL_VSAN  #: VSAN - Cisco MDS-specific
    CUMULATIVE_BYTES = mod.COL_CUMULATIVE_BYTES  #: Cumulative number of bytes
    CUSTOM = mod.COL_CUSTOM  #: Custom column (any filter name's contents)
    DCE_CALL = mod.COL_DCE_CALL
    #: DCE/RPC connection orientated call id OR datagram sequence number
    DCE_CTX = mod.COL_DCE_CTX
    #: !! DEPRECATED !! - DCE/RPC connection oriented context id
    DELTA_TIME = mod.COL_DELTA_TIME  #: Delta time
    DELTA_CONV_TIME = mod.COL_DELTA_CONV_TIME
    #: Delta time to last frame in conversation
    REST_DST = mod.COL_RES_DST  #: Resolved destination
    UNRES_DST = mod.COL_UNRES_DST  #: Unresolved destination
    REST_DST_PORT = mod.COL_RES_DST_PORT  #: Resolved destination port
    UNRES_DST_PORT = mod.COL_UNRES_DST_PORT  #: Unresolved destination port
    DEF_DST = mod.COL_DEF_DST  #: Destination address
    DEF_DST_PORT = mod.COL_DEF_DST_PORT  #: Destination port
    EXPERT = mod.COL_EXPERT  #: Expert info
    IF_DIR = mod.COL_IF_DIR  #: FW-1 monitor interface/direction
    OXID = mod.COL_OXID  #: !! DEPRECATED !! - Fibre Channel OXID
    RXID = mod.COL_RXID  #: !! DEPRECATED !! - Fibre Channel RXID
    FR_DLCI = mod.COL_FR_DLCI  #: !! DEPRECATED !! - Frame Relay DLCI
    FREQ_CHAN = mod.COL_FREQ_CHAN  #: IEEE 802.11 (and WiMax?) - Channel
    BSSGP_TLLI = mod.COL_BSSGP_TLLI  #: !! DEPRECATED !! - GPRS BSSGP IE TLLI
    HPUX_DEVID = mod.COL_HPUX_DEVID
    #: !! DEPRECATED !! - HP-UX Nettl Device ID
    HPUX_SUBSYS = mod.COL_HPUX_SUBSYS
    #: !! DEPRECATED !! - HP-UX Nettl Subsystem
    DEF_DL_DST = mod.COL_DEF_DL_DST  #: Data link layer destination address
    DEF_DL_SRC = mod.COL_DEF_DL_SRC  #: Data link layer source address
    RES_DL_DST = mod.COL_RES_DL_DST  #: Unresolved DL destination
    UNRES_DL_DST = mod.COL_UNRES_DL_DST  #: Unresolved DL destination
    RES_DL_SRC = mod.COL_RES_DL_SRC  #: Resolved DL source
    UNRES_DL_SRC = mod.COL_UNRES_DL_SRC  #: Unresolved DL source
    RSSI = mod.COL_RSSI  #: IEEE 802.11 - received signal strength
    TX_RATE = mod.COL_TX_RATE  #: IEEE 802.11 - TX rate in Mbps
    DSCP_VALUE = mod.COL_DSCP_VALUE  #: IP DSCP Value
    INFO = mod.COL_INFO  #: Description
    COS_VALUE = mod.COL_COS_VALUE  #: !! DEPRECATED !! - L2 COS Value
    RES_NET_DST = mod.COL_RES_NET_DST  #: Resolved net destination
    UNRES_NET_DST = mod.COL_UNRES_NET_DST  #: Unresolved net destination
    RES_NET_SRC = mod.COL_RES_NET_SRC  #: Resolved net source
    UNRES_NET_SRC = mod.COL_UNRES_NET_SRC  #: Unresolved net source
    DEF_NET_DST = mod.COL_DEF_NET_DST  #: Network layer destination address
    DEF_NET_SRC = mod.COL_DEF_NET_SRC  #: Network layer source address
    NUMBER = mod.COL_NUMBER  #: Packet list item number
    PACKET_LENGTH = mod.COL_PACKET_LENGTH  #: Packet length in bytes
    PROTOCOL = mod.COL_PROTOCOL  #: Protocol
    REL_TIME = mod.COL_REL_TIME  #: Relative time
    REL_CONV_TIME = mod.COL_REL_CONV_TIME  #: blurp
    DEF_SRC = mod.COL_DEF_SRC  #: Source address
    DEF_SRC_PORT = mod.COL_DEF_SRC_PORT  #: Source port
    RES_SRC = mod.COL_RES_SRC  #: Resolved source
    UNRES_SRC = mod.COL_UNRES_SRC  #: Unresolved source
    RES_SRC_PORT = mod.COL_RES_SRC_PORT  #: Resolved source port
    UNRES_SRC_PORT = mod.COL_UNRES_SRC_PORT  #: Unresolved source Port
    TEI = mod.COL_TEI  #: Q.921 TEI
    UTC_DATE_TIME = mod.COL_UTC_DATE_TIME  #: UTC date and time
    UTC_TIME = mod.COL_UTC_TIME  #: UTC time
    CLS_TIME = mod.COL_CLS_TIME
    #: Command line specific time (default relative)

    NUM_COL_FMTS = mod.NUM_COL_FMTS
    MAX_INFO_LEN = mod.COL_MAX_INFO_LEN
    MAX_LEN = mod.COL_MAX_LEN

    def __init__(self, fmt):
        '''Get a reference to specific column-type.

        :param fmt:
            One of the defined column-types, e.g. :py:attr:`Number`
        '''
        if fmt not in range(self.NUM_COL_FMTS):
            raise InvalidColumnType(fmt)
        self.fmt = fmt

    def __repr__(self):
        r = '<Type description="%s" format="%s">' % (self.format_desc,
                                                     self.format_string)
        return r

    def __int__(self):
        return self.fmt

    def __eq__(self, other):
        return int(other) == int(self)

    def __hash__(self):
        return hash(self.fmt)

    @classmethod
    def from_string(cls, format_string):
        fmt = mod.get_column_format_from_str(format_string.encode())
        if fmt == -1:
            raise InvalidColumnType(format_string)
        return cls(fmt)

    @classmethod
    def iter_column_formats(cls):
        '''Iterate over all available column formats.

        :returns:
            An iterator that yields instances of :py:class:`Type`.
        '''
        for fmt in range(cls.NUM_COL_FMTS):
            yield cls(fmt)

    @property
    def format_desc(self):
        return iface.string(mod.col_format_desc(self.fmt))

    @property
    def format_string(self):
        return iface.string(mod.col_format_to_string(self.fmt))

    @property
    def MAX_BUFFER_LEN(self):
        if self.fmt == self.INFO:
            return self.MAX_INFO_LEN
        else:
            return self.MAX_LEN


class Format(CDataObject):
    '''A fmt_data'''

    _struct = 'fmt_data'
    title = StringAttribute(doc='Title of the column.')
    type_ = InstanceAttribute(Type, structmember='fmt',
                              doc=('The column\'s type, one of '
                                   ':py:class:`Type`.'))
    custom_field = StringAttribute(doc='Field-name for custom columns.')
    custom_occurrence = Attribute(doc=('Optional ordinal of occcurrence '
                                       'of the custom field.'))
    visible = BooleanAttribute(doc=('True if the column should be '
                                    'hidden in GUI.'))
    resolved = BooleanAttribute(doc=('True to show a more human-'
                                     'readable name.'))

    def __init__(self, type_=None, init=None, title=None, custom_field=None,
                 custom_occurrence=None, visible=None, resolved=None):
        '''
        param init:
            The underlying fmt_data-object to wrap or None to create a new one.
        '''
        self.cdata = init if init is not None else iface.new('fmt_data*')
        if title is not None:
            self.title = title
        if type_ is not None:
            self.type_ = type_
        if custom_field is not None:
            self.custom_field = custom_field
        if custom_occurrence is not None:
            self.custom_occurrence = custom_occurrence
        if visible is not None:
            self.visible = visible
        if resolved is not None:
            self.resolved = resolved

    def __repr__(self):
        return '<Format title="%s" type_="%s">' % (self.title, self.type_)


class ColumnInfo(CDataObject):
    _struct = 'column_info'
    num_cols = Attribute()
    fmts = IntListAttribute('num_cols', 'col_fmt')
    firsts = IntListAttribute(Type.NUM_COL_FMTS, 'col_first')
    lasts = IntListAttribute(Type.NUM_COL_FMTS, 'col_last')
    titles = StringListAttribute('num_cols', 'col_title')
    custom_fields = StringListAttribute('num_cols', 'col_custom_field')
    custom_occurrences = IntListAttribute('num_cols', 'col_custom_occurrence')
    custom_field_ids = IntListAttribute('num_cols', 'col_custom_field_id')
    custom_dfilters = InstanceListAttribute(dfilter.DisplayFilter,
                                            sizeattr='num_cols',
                                            structmember='col_custom_dfilter')
    fences = IntListAttribute('num_cols', 'col_fence')
    writeable = BooleanAttribute()

    def __init__(self, init):
        '''Create a new ColumnInfo-descriptor.

        :param init:
            Either a cdata-object to be wrapped or an iterable of
            :py:class:`Format` instances.
        '''
        if isinstance(init, iface.CData):
            self.cdata = init
        else:
            self.cdata = iface.new('column_info*')
            self.num_cols = len(init)
            self.firsts = [-1 for i in range(Type.NUM_COL_FMTS)]
            self.lasts = [-1 for i in range(Type.NUM_COL_FMTS)]
            self.fmts = [fmt.type_ for fmt in init]
            self.titles = [fmt.title for fmt in init]
            self.custom_fields = [fmt.custom_field if fmt.type_ == Type.CUSTOM
                                  else None for fmt in init]
            self.custom_occurrences = [fmt.custom_occurrence
                                       if fmt.type_ == Type.CUSTOM else 0
                                       for fmt in init]
            self.custom_field_ids = [-1 for fmt in init]
            self.custom_dfilters = [dfilter.DisplayFilter(fmt.custom_field)
                                    if fmt.type_ == Type.CUSTOM else None
                                    for fmt in init]
            self.fences = [0 for fmt in init]

            self._matx = []
            for i in range(self.num_cols):
                self._matx.append(iface.new('gboolean[]', Type.NUM_COL_FMTS))
            self._matxp = iface.new('gboolean*[]', self._matx)
            self.cdata.fmt_matx = self._matxp
            for i in range(self.num_cols):
                mod.get_column_format_matches(self.cdata.fmt_matx[i],
                                              self.fmts[i])

            self._col_data = [iface.NULL for fmt in init]
            self._col_datap = iface.new('gchar*[]', self._col_data)
            self.cdata.col_data = self._col_datap

            self._col_buf = [iface.new('gchar[]', fmt.type_.MAX_BUFFER_LEN)
                             for fmt in init]
            self._col_bufp = iface.new('gchar*[]', self._col_buf)
            self.cdata.col_buf = self._col_bufp

            self._col_expr = [iface.new('gchar[]', Type.MAX_LEN)
                              for fmt in init] + [iface.NULL]
            self._col_exprp = iface.new('gchar*[]', self._col_expr)
            self.cdata.col_expr.col_expr = self._col_exprp

            self._col_expr_val = [iface.new('gchar[]', Type.MAX_LEN)
                                  for fmt in init] + [iface.NULL]
            self._col_expr_valp = iface.new('gchar*[]', self._col_expr_val)
            self.cdata.col_expr.col_expr_val = self._col_expr_valp

            for i in range(self.num_cols):
                for j in range(Type.NUM_COL_FMTS):
                    if self._matxp[i][j]:
                        if self.firsts[j] == -1:
                            self.firsts[j] = i
                        self.lasts[j] = i

    def __len__(self):
        '''Equal to the number of columns in this descriptor'''
        return self.num_cols

    @property
    def have_custom_cols(self):
        ''''''
        # TODO do we really need this through the API ?
        return bool(mod.have_custom_cols(self.cdata))
