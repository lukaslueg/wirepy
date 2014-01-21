"""GLib2-related objects used by libwireshark."""

from . import cdata
from .wireshark import iface, mod


def from_gchar(cdata, free=True):
    '''Build a python-string from a gchar*'''
    s = iface.string(cdata)
    if free:
        mod.g_free(cdata)
    return s


class String(cdata.CDataObject):
    """A GString"""

    _struct = 'GString'
    string = cdata.ROStringAttribute('str')
    len = cdata.ROAttribute('len', doc='The length of the string.')
    allocated_len = cdata.ROAttribute('allocated_len',
                                      doc='Amount of allocated memory.')

    def __init__(self, string):
        buf = str(string).encode()  # TODO py2/py3k
        gstring = mod.g_string_new_len(buf, len(buf))
        if gstring == iface.NULL:
            raise MemoryError  # pragma: no cover
        self.cdata = iface.gc(gstring, self.free)

    def __len__(self):
        return self.len

    def __str__(self):
        return self.string

    @staticmethod
    def free(cdata_obj):
        """Frees the memory allocated for the GString."""
        # always free_segment
        mod.g_string_free(cdata_obj, True)


class SinglyLinkedListIterator(cdata.CDataObject):
    """A singly-linked list (GSList)."""

    _struct = 'GSList'
    next = cdata.InstanceAttribute(None, doc='The next item in the list.')

    def __init__(self, init, callable=None, gc=True):
        self.callable = callable
        if not isinstance(init, iface.CData):
            raise TypeError(type(init))
        if gc:
            self.cdata = iface.gc(cdata, mod.g_slist_free(init))
        else:
            self.cdata = init

    @staticmethod
    def free(cdata_obj):
        mod.g_slist_free(cdata_obj)

    def _cast(self, data):
        if data == iface.NULL:
            return
        if self.callable is not None:
            return self.callable(data)
        return data

    def __len__(self):
        return mod.g_slist_length(self.cdata)

    def __iter__(self):
        """Iterate of all data-items in the list."""
        yield self._cast(self.cdata.data)
        n = self.cdata.next
        while n != iface.NULL:
            yield self._cast(n.data)
            n = n.next
