'''Wireshark uses display filters for packet filtering within the GUI. The
rich syntax makes them very useful for filtering packets without manual
inspection of a packet's protocol tree. Because display filters are compiled
to bytecode and executed within wireshark's own VM, complex filters also
perform much better than inspection from within Python.

See `the official documentation <http://wiki.wireshark.org/DisplayFilters>`_
for for information about their syntax.

Example::

    # wt is a wtap.WTAP-instance, frame is a epan.Frame-instance
    filter_islocal = dfilter.DisplayFilter('ip.src==192.168.0.0/16')
    edt = epan.Dissect()
    edt.prime_dfilter(filter_islocal)
    edt.run(wt, frame)
    passed = filter_islocal.apply_edt(edt)
    if passed:
        ...

.. DisplayDocs:
'''
from .wireshark import iface, mod


class DisplayFilterError(Exception):
    '''Base-class for display-filter-related errors'''
    pass


class DisplayFilter(object):
    '''A display-filter'''
    _struct = 'dfilter_t'

    def __init__(self, init):
        '''Create a new or wrap an existing struct.

        :param init:
            A dfilter_t-object or a string

        :raises:
            :py:exc:`DisplayFilterError` in case a string was supplied and the
            new display filter failed to compile.
        '''
        if isinstance(init, iface.CData):
            self.cdata = init
        else:
            if not mod.WIREPY_EPAN_INITIALIZED:
                raise RuntimeError('EPAN must be initialized')
            dfp = iface.new('dfilter_t **dfp')
            # dfilter_compile() sets a global pointer to *char in case of an
            # error.  This is a perfectly good race conditions that we do not
            # care to avoid because Wireshark is not thread-safe anyway.
            # The string had to be regex-parsed in case we want subclasses of
            # DisplayFilterError. Meh...
            res = mod.dfilter_compile(str(init).encode(), dfp)
            if not res:
                msg = iface.string(mod.wrapped_dfilter_get_error_msg())
                raise DisplayFilterError(msg)
            self.cdata = iface.gc(dfp[0], mod.dfilter_free)

    def apply_edt(self, edt):
        '''Apply this DisplayFilter to a Dissect-instance'''
        return bool(mod.dfilter_apply_edt(self.cdata, edt.cdata))

    def apply(self, proto_tree):
        '''Apply this DisplayFilter to a ProtoTree-instance'''
        return bool(mod.dfilter_apply(self.cdata, proto_tree.cdata))

    def prime_proto_tree(self, proto_tree):
        '''Prime a ProtoTree-instance using the fields/protocols used in this
        DisplayFilter'''
        mod.dfilter_prime_proto_tree(self.cdata, proto_tree.cdata)

    @staticmethod
    def free(self, cdata):
        mod.dfilter_free(cdata)

    def dump(self):
        '''Print bytecode to stdout'''
        mod.dfilter_dump(self.cdata)
