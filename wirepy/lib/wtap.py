'''The wiretap-library is used to read capture files of various formats and
encapsulation types.
'''
import os
from .cdata import CDataObject, Attribute, InstanceAttribute, StringAttribute
from .wireshark import iface, mod
from . import glib2


class WTAPError(Exception):
    '''Base-class for all wtap-errors.'''
    pass


class InvalidFileType(WTAPError):
    pass


class InvalidEncapsulationType(WTAPError):
    pass


class FileError(WTAPError):
    errno_to_class = {}

    def __init__(self, err_info, for_writing):
        self.err_info = err_info
        self.for_writing = for_writing
        #TODO err_info leaked and has has to be free()'d *sometimes*

    @staticmethod
    def from_errno(errno):
        return FileError.errno_to_class.get(errno, FileError)


def _register_err(cls):
    '''Decorator to register an error-class into the errno_to_class-dict on
    class FileError'''
    # Let's avoid using a metaclass for this
    if not issubclass(cls, FileError):
        raise TypeError('Decorated class is not a subclass of FileError')
    errno = getattr(cls, 'errno')
    if errno is None:
        raise TypeError('Decorated class has no errno-attribute')
    if errno in FileError.errno_to_class:
        raise ValueError('Error %i already registered' % (errno, ))
    else:
        if errno in FileError.errno_to_class:
            raise ValueError(errno)
        FileError.errno_to_class[errno] = cls
    return cls


@_register_err
class NotRegularFile(FileError):
    '''The file being opened for reading isn't a plain file (or pipe)'''
    errno = mod.WTAP_ERR_NOT_REGULAR_FILE


@_register_err
class RandomOpenPipe(FileError):
    '''The file is being opened for random access and it's a pipe'''
    errno = mod.WTAP_ERR_RANDOM_OPEN_PIPE


@_register_err
class UnknownFormat(FileError):
    '''The file being opened is not a capture file in a known format'''
    errno = mod.WTAP_ERR_FILE_UNKNOWN_FORMAT


@_register_err
class Unsupported(FileError):
    "Supported file type, but there's something in the file we can't support"
    errno = mod.WTAP_ERR_UNSUPPORTED


@_register_err
class CantWriteToPipe(FileError):
    '''Wiretap can't save to a pipe in the specified format'''
    errno = mod.WTAP_ERR_CANT_WRITE_TO_PIPE


@_register_err
class CantOpen(FileError):
    '''The file couldn't be opened, reason unknown'''
    errno = mod.WTAP_ERR_CANT_OPEN


@_register_err
class UnsupportedFileType(FileError):
    '''Wiretap can't save files in the specified format'''
    errno = mod.WTAP_ERR_UNSUPPORTED_FILE_TYPE


@_register_err
class UnsupportedEncap(FileError):
    '''Wiretap can't read or save files in the specified format with the
    specified encapsulation'''
    errno = mod.WTAP_ERR_UNSUPPORTED_ENCAP


@_register_err
class EncapPerPacketUnsupported(FileError):
    '''The specified format doesn't support per-packet encapsulations'''
    errno = mod.WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED


@_register_err
class CantClose(FileError):
    '''The file couldn't be closed, reason unknown'''
    errno = mod.WTAP_ERR_CANT_CLOSE


@_register_err
class CantRead(FileError):
    '''An attempt to read failed, reason unknown'''
    errno = mod.WTAP_ERR_CANT_READ


@_register_err
class ShortRead(FileError):
    '''An attempt to read read less data than it should have'''
    errno = mod.WTAP_ERR_SHORT_READ


@_register_err
class BadFile(FileError):
    '''The file appears to be damaged or corrupted or otherwise bogus'''
    errno = mod.WTAP_ERR_BAD_FILE


@_register_err
class ShortWrite(FileError):
    '''An attempt to write wrote less data than it should have'''
    errno = mod.WTAP_ERR_SHORT_WRITE


@_register_err
class UncompressTruncated(FileError):
    '''Sniffer compressed data was oddly truncated'''
    errno = mod.WTAP_ERR_UNC_TRUNCATED


@_register_err
class UncompressOverflow(FileError):
    '''Uncompressing Sniffer data would overflow buffer'''
    errno = mod.WTAP_ERR_UNC_OVERFLOW


@_register_err
class UncompressBadOffset(FileError):
    '''LZ77 compressed data has bad offset to string'''
    errno = mod.WTAP_ERR_UNC_BAD_OFFSET


@_register_err
class RandomOpenStdin(FileError):
    '''We're trying to open the standard input for random access'''
    errno = mod.WTAP_ERR_RANDOM_OPEN_STDIN


@_register_err
class CompressionUnsupported(FileError):
    '''The filetype doesn't support output compression'''
    errno = mod.WTAP_ERR_COMPRESSION_NOT_SUPPORTED


@_register_err
class CantSeek(FileError):
    '''An attempt to seek failed, reason unknown'''
    errno = mod.WTAP_ERR_CANT_SEEK


@_register_err
class Decompress(FileError):
    '''Error decompressing'''
    errno = mod.WTAP_ERR_DECOMPRESS


@_register_err
class Internal(FileError):
    ''''''
    errno = mod.WTAP_ERR_INTERNAL


class EncapsulationType(object):
    '''An encapsulation type like "ether"'''

    def __init__(self, encap):
        # encap -1 == PER_PACKET, 0 == UNKNOWN, ...
        if encap not in range(-1, mod.wtap_get_num_encap_types()):
            errmsg = '%i is not a valid encapsulation' % (encap, )
            raise InvalidEncapsulationType(errmsg)
        self.encap = encap

    def __repr__(self):
        r = '<EncapsulationType string="%s" short_string="%s">'
        return r % (self.string, self.short_string)

    @classmethod
    def from_short_string(cls, short_string):
        encap = mod.wtap_short_string_to_encap(short_string.encode())
        if encap == -1:
            errmsg = 'Encapsulation-type "%s" unknown' % (short_string, )
            raise InvalidEncapsulationType(errmsg)
        return cls(encap)

    @property
    def string(self):
        return iface.string(mod.wtap_encap_string(self.encap))

    @property
    def short_string(self):
        return iface.string(mod.wtap_encap_short_string(self.encap))


class Frame(CDataObject):
    _struct = 'frame_data'
    frame_number = Attribute('num', doc='The frame number.')
    interface_id = Attribute(doc='Identifier of the interface.')
    pack_flags = Attribute()
    pkt_len = Attribute(doc='Packet length.')
    cap_len = Attribute(doc='Amount actually captured.')
    cum_bytes = Attribute(doc='Cumulative bytes into the capture')
    file_offset = Attribute('file_off', doc='File offset.')
    subnum = Attribute(doc=('Subframe number, for protocols that '
                            'require this.'))
    link_type = InstanceAttribute(EncapsulationType, structmember='lnk_t',
                                  doc='Per-packet encapsulation/datalink type')
    comment = StringAttribute('opt_comment')

    def __init__(self, cdata):
        self.cdata = cdata

    def __repr__(self):
        r = '<Frame frame_number=%i, pkt_len=%i, cap_len=%i>'
        return r % (self.frame_number, self.pkt_len, self.cap_len)

    @classmethod
    def new(cls, num, pkthdr, offset, cum_bytes):
        '''Constructor for a new Frame-instance'''
        fd = iface.gc(iface.new('frame_data *'), cls.destroy)
        cls.init(fd, num, pkthdr, offset, cum_bytes)
        return cls(fd)

    @staticmethod
    def init(cdata, num, pkthdr, offset, cum_bytes):
        return mod.frame_data_init(cdata, num, pkthdr, offset, cum_bytes)

    @staticmethod
    def destroy(cdata):
        return mod.frame_data_destroy(cdata)

    def compare(self, other, field):
        mod.frame_data_compare(self.cdata, other, field)

    def set_before_dissect(self, elapsed_time, first_ts, prev_dis, prev_cap):
        mod.frame_data_set_before_dissect(self.cdata, elapsed_time, first_ts,
                                          prev_dis, prev_cap)

    def set_after_dissect(self, cum_bytes, prev_dis_ts):
        mod.frame_data_set_after_dissect(self.cdata, cum_bytes, prev_dis_ts)

    @property
    def proto_data(self):
        '''Per-frame proto data'''
        return self.cdata.pfd  # TODO a GSList of some type

    @property
    def flags(self):
        ''''''  # TODO
        return self.cdata.flags

    @property
    def color_filter(self):
        '''Per-packet matching color_t_filter_t object'''  # TODO
        return self.cdata.color_filter

    @property
    def abs_ts(self):
        '''Absolute timestamp'''
        return self.cdata.abs_ts  # TODO A nstime_t

    @property
    def shift_offset(self):
        '''How much the abs_ts of the frame is shifted'''
        return self.cdata.shift_offset

    @property
    def rel_ts(self):
        '''Relative timestamp (yes, it can be negative)'''
        return self.cdata.rel_ts

    @property
    def del_dis_ts(self):
        '''Delta timestamp to previous displayed frame (yes, can be negative'''
        return self.cdata.del_ts_ts

    @property
    def del_cap_ts(self):
        '''Delta timestamp to previous captured frame (yes, can be negative'''
        return self.cdata.del_cap_ts


class PacketHeader(CDataObject):
    '''A wtap_pkthdr from wtap.h'''

    _struct = 'wtap_pkthdr'
    presence_flags = Attribute(doc='What stuff do we have?')
    # timestamp
    caplen = Attribute(doc='Data length in the file.')
    len = Attribute(doc='Data length on the wire.')
    pkt_encap = InstanceAttribute(EncapsulationType,
                                  doc=('The EncapsulationType of the '
                                       'current packet.'))
    interface_id = Attribute(doc='Identifier of the interface.')
    comment = StringAttribute('opt_comment', doc='Optional comment.')
    drop_count = Attribute(doc='Number of packets lost.')

    HAS_TS = mod.WTAP_HAS_TS
    HAS_CAP_LEN = mod.WTAP_HAS_CAP_LEN
    HAS_INTERFACE_ID = mod.WTAP_HAS_INTERFACE_ID
    HAS_COMMENTS = mod.WTAP_HAS_COMMENTS
    HAS_DROP_COUNT = mod.WTAP_HAS_DROP_COUNT
    HAS_PACK_FLAGS = mod.WTAP_HAS_PACK_FLAGS

    def __init__(self, cdata_obj):
        self.cdata = cdata_obj

    def is_flag_set(self, flag):
        return bool(self.presence_flags & flag)

    @property
    def timestamp(self):
        return self.cdata.ts  # TODO a wtap_nstime


# TODO garbage collection
class WTAP(object):
    '''A wtap from wtap.h'''
    FILE_TSPREC_SEC = mod.WTAP_FILE_TSPREC_SEC
    FILE_TSPREC_DSEC = mod.WTAP_FILE_TSPREC_DSEC
    FILE_TSPREC_CSEC = mod.WTAP_FILE_TSPREC_CSEC
    FILE_TSPREC_MSEC = mod.WTAP_FILE_TSPREC_MSEC
    FILE_TSPREC_USEC = mod.WTAP_FILE_TSPREC_USEC
    FILE_TSPREC_NSEC = mod.WTAP_FILE_TSPREC_NSEC
    MAX_PACKET_SIZE = mod.WTAP_MAX_PACKET_SIZE

    def __init__(self, cdata):
        self.cdata = cdata

    @classmethod
    def open_offline(cls, filename, random=False):
        '''Open a file and return a WTAP-instance. If random is True, the file
        is opened twice; the second open allows the application to do random-
        access I/O without moving the seek offset for sequential I/O, which is
        used by Wireshark to write packets as they arrive'''
        err = iface.new('int *')
        err_info = iface.new('char **')
        cdata = mod.wtap_open_offline(filename.encode(), err, err_info, random)
        if cdata == iface.NULL:
            errno = err[0]
            # If the file is exactly zero bytes, wtap_open_offline returns NULL
            # but does not set any error condition. Raise ShortRead by hand?
            if errno < 0:
                raise FileError.from_errno(errno)(err_info, False)  # TODO Fal?
            else:
                msg = os.strerror(errno)
                raise OSError(errno, msg, filename)
        return cls(cdata)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __iter__(self):
        framenum = 0
        res, data_offset = self.read()
        if res is None:
            # TODO raise a subclass of StopIteration, so we can listen for that
            # event
            raise StopIteration
        cum_bytes = iface.new('guint32*')
        elapsed_time = iface.new('nstime_t*')
        first_ts = iface.new('nstime_t*')
        prev_dis = iface.new('nstime_t*')
        prev_cap = iface.new('nstime_t*')
        while res:
            framenum += 1
            frame = Frame.new(framenum, self.packetheader.cdata, data_offset,
                              cum_bytes[0])
            # TODO iface.NULL on next line
            frame.set_before_dissect(elapsed_time, first_ts, iface.NULL, iface.NULL)
            try:
                passed = yield frame
            except GeneratorExit:
                break
            if passed:
                frame.set_after_dissect(cum_bytes, prev_dis_ts)
            res, data_offset = self.read()

    @property
    def packetheader(self):
        '''The packet header from the current packet'''
        p = mod.wtap_phdr(self.cdata)
        return PacketHeader(p) if p != iface.NULL else None

    @property
    def read_so_far(self):
        '''The approximate amount of data read sequentially so far'''
        return mod.wtap_read_so_far(self.cdata)

    @property
    def file_size(self):
        '''The file-size as reported by the OS'''
        err = iface.new('int *')
        res = mod.wtap_file_size(self.cdata, err)
        errno = err[0]
        if errno == 0:
            return res
        else:
            msg = os.strerror(errno)
            raise OSError(errno, msg)

    @property
    def is_compressed(self):
        '''True if the file is compressed (e.g. via gzip)'''
        return bool(mod.wtap_iscompressed(self.cdata))

    @property
    def snapshot_length(self):
        return mod.wtap_snapshot_length(self.cdata)

    @property
    def effective_snapshot_length(self):
        return self.snapshot_length or self.WTAP_MAX_PACKET_SIZE

    @property
    def file_type(self):
        '''The type of the file'''
        return FileType(mod.wtap_file_type(self.cdata))

    @property
    def file_encap(self):
        '''The encapsulation-type of the file'''
        return EncapsulationType(mod.wtap_file_encap(self.cdata))

    @property
    def tsprecision(self):
        '''The timestamp precision, a value like FILE_TSPREC_SEC'''
        return mod.wtap_file_tsprecision(self.cdata)

    @property
    def buf_ptr(self):
        return mod.wtap_buf_ptr(self.cdata)

    @property
    def shb_info(self):
        return mod.wtap_file_get_shb_info(self.cdata)  # TODO

    def read(self):
        err = iface.new('int *')
        err_info = iface.new('gchar **')
        data_offset = iface.new('gint64 *')
        res = mod.wtap_read(self.cdata, err, err_info, data_offset)
        if not res:
            errno = err[0]
            if errno != 0:
                raise OSError(errno, iface.string(err_info[0]))
            else:
                return None, None
        return res, data_offset[0]

    def seek_read(self, seek_off, len):
        pseudo_header = iface.new('union wtap_pseudo_header *')
        pd = iface.new('guint8 *')
        err = iface.new('int *')
        err_info = iface.new('gchar **')
        res = mod.wtap_seek_read(self.cdata, seek_off, pseudo_header, pd, len,
                                 err, err_info)
        errno = err[0]
        if errno != 0:
            raise OSError(errno, iface.string(err_info[0]))
        if not res:
            return None, None
        return pseudo_header, pd

    def clear_eof(self):
        mod.wtap_cleareof(self.cdata)

    def close(self):
        '''Close the current file'''
        mod.wtap_close(self.cdata)

    def fdclose(self):
        '''Close the file descriptor for the current file'''
        mod.wtap_fdclose(self.cdata)

    def sequential_close(self):
        '''Close the current file'''
        mod.wtap_sequential_close(self.cdata)


class FileType(object):

    def __init__(self, ft):
        if ft not in range(mod.wtap_get_num_file_types()):
            raise InvalidFileType('%i is not a valid file type' % (ft, ))
        self.ft = ft

    def __repr__(self):
        return '<FileType string="%s" short_string="%s">' % (self.string,
                                                             self.short_string)

    @classmethod
    def from_short_string(cls, short_string):
        if short_string is None:
            return cls(0)  # Zero is the unknown file-type
        ft = mod.wtap_short_string_to_file_type(short_string.encode())
        if ft == -1:
            raise InvalidFileType('File-type "%s" unknown' % (short_string, ))
        return cls(ft)

    @property
    def string(self):
        s = mod.wtap_file_type_string(self.ft)
        return iface.string(s) if s != iface.NULL else None

    @property
    def short_string(self):
        s = mod.wtap_file_type_short_string(self.ft)
        return iface.string(s) if s != iface.NULL else None

    @property
    def default_file_extension(self):
        '''The default file extension used by this file-type (e.g. pcap for
        libpcap)'''
        s = mod.wtap_default_file_extension(self.ft)
        return iface.string(s) if s != iface.NULL else None

    def get_file_extensions(self, include_compressed=True):
        '''Returns the file extensions that are used by this file type.
        If include_compressed is True, the returned values include compressed
        extensions (e.g.'pcap.gz')'''
        gslist = mod.wtap_get_file_extensions_list(self.ft, include_compressed)
        cast = lambda c: iface.string(iface.cast('gchar*', c))
        try:
            l = tuple(glib2.SinglyLinkedListIterator(gslist, cast, False))
        finally:
            mod.wtap_free_file_extensions_list(gslist)
        return l

    @property
    def file_extensions(self):
        '''A tuple of all file extensions that are used by this file type.
        Includes compressed extensions (e.g. 'pcap.gz')'''
        return self.get_file_extensions(include_compressed=True)

    @property
    def dump_can_open(self):
        ''''''  # TODO
        return bool(mod.wtap_dump_can_open(self.ft))

    def dump_can_write_encap(self, encap):
        ''''''  # TODO
        return bool(mod.wtap_dump_can_write_encap(self.ft, encap.encap))

    @property
    def dump_can_compress(self):
        ''''''  # TODO
        return bool(mod.wtap_dump_can_compress(self.ft))


def iter_file_types():
    '''Iterates over all file-types wireshark can understand'''
    # Increment from one because zero is the unknown type...
    for ft in range(1, mod.wtap_get_num_file_types()):
        yield FileType(ft)


def iter_encapsulation_types():
    '''Iterates over all encapsulation-types wireshark can understand'''
    # it should be safe that -1 (PER_PACKET) be the smallest value...
    for encap in range(-1, mod.wtap_get_num_encap_types()):
        yield EncapsulationType(encap)
