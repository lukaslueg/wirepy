'''Helper module to make working with CFFI more convenient.

Classes that mainly wrap c-like *struct* may subclass :py:class:`CDataObject`
which carries :py:class:`MetaCDataObject` as it's metaclass. When a deriving
class is created, all class-level attributes that derive from
:py:class:`BaseAttribute` are replaced with standard python properties that
access the wrapped struct-members, automatically cast to python types, raise
Exceptions and keep references to allocated memory in order to handle garbage
collection.

.. note::
    It's not clear wether to keep this module at all, the overhead during
    runtime is probably significant. It does however provide convenience
    until design decisions quite down.
'''


import re
from wirepy import compat
from wirepy.lib.wireshark import iface, mod


def get_mod_definitions(patterns):
    defs = {}
    for pattern in patterns:
        for attr in dir(mod):
            if re.match(pattern, attr):
                if defs.get(attr, None) is not None:
                    raise ValueError('Multiple definitions for "%s"' % (attr, ))
                defs[attr] = getattr(mod, attr)
    return defs


def update_from_mod_definitions(d, patterns):
    for k, v in get_mod_definitions(patterns).items():
        if d.get(k, None) is not None:
            raise ValueError('Multiple definitions for "%s"' % (k, ))
        d[k] = v


class AttributeAccessError(AttributeError):
    '''Indicates access to an attribute that can't be accessed that way.'''


class AttributeSizeError(AttributeError):
    '''A list-like attribute was set to an incorrect size.'''


class BaseAttribute(object):
    '''An attribute on a cdata-object.

    An attribute defines methods to read, write and delete values. These
    methods end up as property()s on the final class.
    '''

    can_never_read = False
    can_never_write = False
    can_never_delete = False

    def __init__(self, structmember=None, can_read=None, can_write=None,
                 can_del=None, doc=None):
        '''
        :param structmember:
            Name of the member to access by this attribute.
            :py:class:`MetaCDataObject` will use the attribute's name in
            case **structmember** is None.
        :param can_read:
            Indicates wether this attribute should provide read access to the
            underlying member or raise an :py:exc:`AttributeAccessError`.
        :param can_write:
            Same as **can_read** for write access.
        :param can_del:
            Sam as **can_del** for deletion.
        :param doc:
            docstring to be placed on the final property.
        '''
        if can_read is None:
            can_read = not self.can_never_read
        else:
            if can_read and self.can_never_read:
                raise ValueError('This attribute-type can never read')
        if can_write is None:
            can_write = not self.can_never_write
        else:
            if can_write and self.can_never_write:
                raise ValueError('This attribute-type can never write')
        if can_del is None:
            can_del = not self.can_never_delete
        else:
            if can_del and self.can_never_delete:
                raise ValueError('This attribute-type can never delete')
        self.structmember = structmember
        self.can_read = can_read
        self.can_write = can_write
        self.can_del = can_del
        self.doc = doc
        self.attrname = None
        self.wrapped_attrname = None

    def getter(self):
        '''Generate a function that serves as a getter.'''
        raise NotImplementedError

    def getter_cant_get(self):
        '''Generate a function that indicates an access-error while reading.'''

        def get(_self):
            errmsg = 'Attribute "%s" can\'t be read from' % (self.attrname, )
            raise AttributeAccessError(errmsg)
        return get

    def setter(self):
        '''Generate a function that serves as a setter.'''
        raise NotImplementedError

    def setter_cant_set(self):
        '''Generate a function that indicates an access-error while writing.'''

        def set(_self, value):
            errmsg = 'Attribute "%s" is marked read-only' % (self.attrname, )
            raise AttributeAccessError(errmsg)
        return set

    def deleter(self):
        '''Generate a function that serves as a deleter.'''

        def delete(instance):
            # TODO ???
            self.set_backing_object(instance, self.wrapped_attrname,
                                    iface.NULL, None)
        return delete

    def deleter_cant_delete(self):
        '''Generate a function that indicates an access-error while deleting'''

        def delete(_self):
            errmsg = 'Attribute \"%s\" can\'t be deleted' % (self.attrname, )
            raise AttributeAccessError(errmsg)
        return delete

    def get_backing_object(self, instance):
        return getattr(instance.cdata, self.structmember)

    def set_backing_object(self, instance, wrapped_attrname=None,
                           backing_value=None, wrapped_value=None):
        if wrapped_attrname is not None:
            if wrapped_value is None:
                wrapped_value = backing_value
            setattr(instance, wrapped_attrname, wrapped_value)
        setattr(instance.cdata, self.structmember, backing_value)


class Attribute(BaseAttribute):
    '''An basic attribute that sets and gets the raw value.'''
    can_never_delete = True

    def getter(self):

        def get(instance):
            return self.get_backing_object(instance)
        return get

    def setter(self):

        def set(instance, value):
            self.set_backing_object(instance, backing_value=value)
        return set


class ROAttribute(Attribute):
    '''A basic attribute that can only read but never write.'''
    can_never_write = True


class BytesAttribute(BaseAttribute):

    def __init__(self, sizeattr, *args, **kwargs):
        BaseAttribute.__init__(self, *args, **kwargs)
        self.sizeattr = sizeattr

    def getter(self):

        def get(instance):
            buf = self.get_backing_object(instance)
            if buf == iface.NULL:
                return None
            else:
                bufsize = getattr(instance, self.sizeattr)
                return bytes(buf[0:bufsize])  # TODO py2/3k
        return get

    def setter(self):

        def set(instance, buf):
            if buf is None:
                cdata = iface.NULL
            else:
                cdata = iface.new('unsigned char[]', bytes(buf))
            self.set_backing_object(instance, self.wrapped_attrname, cdata)
        return set


class StringAttribute(BaseAttribute):
    '''A null-terminated string.'''

    # TODO add a size argument coming from the struct?!

    def getter(self):

        def get(instance):
            string = self.get_backing_object(instance)
            return iface.string(string) if string != iface.NULL else None
        return get

    def setter(self):

        def set(instance, string):
            if string is None:
                cdata = iface.NULL
            else:
                cdata = iface.new('char[]', string.encode())  # TODO py2/py3k
            self.set_backing_object(instance, self.wrapped_attrname, cdata)
        return set


class ROStringAttribute(StringAttribute):
    '''A zero-terminated string that can only be read but never be written.'''
    can_never_write = True


class BooleanAttribute(BaseAttribute):
    '''A boolean value.'''
    can_never_delete = True

    def getter(self):

        def get(instance):
            b = self.get_backing_object(instance)
            return bool(b)
        return get

    def setter(self):

        def set(instance, b):
            self.set_backing_object(instance, backing_value=bool(b))
        return set


class AttributeList(object):

    def __init__(self, listattr, instance):
        self.listattr = listattr
        self.instance = instance

    def _check_idx(self, idx):
        try:
            size = getattr(self.instance, self.listattr.sizeattr)
        except TypeError:
            size = self.listattr.sizeattr
            assert isinstance(size, int)
        if idx not in range(size):
            raise IndexError('Index %i, array is size %i' % (idx, size))

    def _get(self, idx):
        self._check_idx(idx)
        return self.listattr.get_backing_object(self.instance)[idx]

    def __getitem__(self, idx):
        return self._get(idx)

    def __setitem__(self, idx, value):
        self._check_idx(idx)
        cdata = getattr(self.instance, self.listattr.wrapped_attrname)
        cdata[idx] = value


class BooleanAttributeList(AttributeList):

    def __getitem__(self, idx):
        return bool(self._get(idx))


class StringAttributeList(AttributeList):

    def __getitem__(self, idx):
        string = self._get(idx)
        return iface.string(string) if string != iface.NULL else None

    def __setitem__(self, idx, string):
        self._check_idx(idx)
        if string is None:
            buf = iface.NULL
        else:
            buf = iface.new('char[]', string.encode())
        cdata, bufs = getattr(self.instance, self.listattr.wrapped_attrname)
        cdata[idx] = buf
        bufs[idx] = buf
        backing_object = getattr(getattr(self.instance,
                                         self.instance._backing_object),
                                 self.listattr.backing)
        backing_object[idx] = buf


class InstanceAttributeList(AttributeList):
    pass


class ListAttribute(BaseAttribute):
    '''A list-like attribute, such as "char \*\*" or "int\*"'''
    can_never_delete = True

    def __init__(self, sizeattr, *args, **kwargs):
        BaseAttribute.__init__(self, *args, **kwargs)
        self.sizeattr = sizeattr

    def _check_size(self, instance, collection):
        try:
            size = getattr(instance, self.sizeattr)
        except TypeError:
            size = self.sizeattr
            assert isinstance(size, int)
        if len(collection) != size:
            errmsg = 'Collection has size %i, should be %i' % (len(collection),
                                                               size)
            raise AttributeSizeError(errmsg)

    def getter(self):
        def get(instance):
            if self.get_backing_object(instance) == iface.NULL:
                return None
            else:
                return AttributeList(self, instance)
        return get


class IntListAttribute(ListAttribute):
    '''A list of integers like "int*".

       A new int[] is created and kept upon assigning to the attribute.
    '''

    def setter(self):

        def set(instance, ints):
            ints = [int(i) for i in ints]
            self._check_size(instance, ints)
            cdata_obj = iface.new('int[]', ints)
            self.set_backing_object(instance, self.wrapped_attrname,
                                    backing_value=cdata_obj)
        return set


class BooleanListAttribute(ListAttribute):

    def getter(self):

        def get(instance):
            if self.get_backing_object(instance) == iface.NULL:
                return None
            else:
                return BooleanAttributeList(self, instance)
        return get

    def setter(self):

        def set(instance, bools):
            bools = [bool(b) for b in bools]
            self._check_size(instance, bools)
            cdata = iface.new('unsigned char[]', bools)
            self.set_backing_object(instance, self.wrapped_attrname,
                                    backing_value=cdata)
        return set


class StringListAttribute(ListAttribute):

    def getter(self):

        def get(instance):
            if self.get_backing_object(instance) == iface.NULL:
                return None
            else:
                return StringAttributeList(self, instance)
        return get

    def setter(self):

        def set(instance, strings):
            bufs = []
            for string in strings:
                if string is None:
                    buf = iface.NULL
                else:
                    buf = iface.new('char[]', string.encode())
                bufs.append(buf)
            self._check_size(instance, bufs)
            cdata_obj = iface.new('char*[]', bufs)
            self.set_backing_object(instance, self.wrapped_attrname,
                                    cdata_obj, (cdata_obj, bufs))
        return set


class InstanceAttribute(BaseAttribute):

    def __init__(self, klass, null_is_none=True, keep_reference=False,
                 *args, **kwargs):
        BaseAttribute.__init__(self, *args, **kwargs)
        self.klass = klass
        self.null_is_none = null_is_none
        self.keep_reference = keep_reference

    def getter(self):

        def get(instance):
            cdata_obj = self.get_backing_object(instance)
            if self.null_is_none and cdata_obj == iface.NULL:
                return
            klass = type(instance) if self.klass is None else self.klass
            return klass(cdata_obj)
        return get

    def setter(self):

        def set(instance, value):
            try:
                cdata_obj = value.cdata
            except AttributeError:
                cdata_obj = value
            self.set_backing_object(instance, backing_value=cdata_obj)
            # TODO wrapped_attrname if self.keep_reference else None,
        return set


class InstanceListAttribute(BaseAttribute):

    def __init__(self, klass, sizeattr, null_is_none=True,
                 keep_reference=False, *args, **kwargs):
        BaseAttribute.__init__(self, *args, **kwargs)
        self.klass = klass
        self.sizeattr = sizeattr
        self.null_is_none = null_is_none
        self.keep_reference = keep_reference

    def getter(self):

        def get(instance):
            cdata_obj = self.get_backing_object(instance)
            if self.null_is_none and cdata_obj == iface.NULL:
                return
            return InstanceAttributeList(self, instance)
        return get

    def setter(self):

        def set(instance, objects):
            cdata_objs = [obj.cdata if obj is not None else iface.NULL
                          for obj in objects]
            size = getattr(instance, self.sizeattr)
            if len(cdata_objs) != size:
                errmsg = 'List has size %i, should be %i' % (len(cdata_objs),
                                                             size)
                raise AttributeSizeError(errmsg)
            t = self.klass._struct + '*[]'
            cdata_objsp = iface.new(t, cdata_objs)
            self.set_backing_object(instance, self.wrapped_attrname,
                                    cdata_objsp, (cdata_objsp, cdata_objs))
        return set


class MetaCDataObject(type):
    '''Metaclass that automatically creates accessors to the underlying
    c-level *struct*.

    A class using this metaclass should define a single "_struct" attribute
    that names the to-be-wrapped *struct*. All instances of objects deriving
    from :py:class:`BaseAttribute` are **replaced** by standard python
    properties that may keep a reference to their :py:class:`BaseAttribute`-
    instance.
    Instances of such class should have a instance-attribute named "cdata"
    that references an instance of the wrapped *struct*.
    '''

    def __new__(meta, name, bases, attrs):
        for attrname, attr in attrs.items():
            if isinstance(attr, BaseAttribute):
                if attr.structmember is None:
                    attr.structmember = attrname
                wrapped_attrname = '_' + attrname
                assert wrapped_attrname not in attrs
                attr.attrname = attrname
                attr.wrapped_attrname = wrapped_attrname
                if attr.can_read:
                    getter = attr.getter()
                else:
                    getter = attr.getter_cant_get()
                if attr.can_write:
                    setter = attr.setter()
                else:
                    setter = attr.setter_cant_set()
                if attr.can_del:
                    deleter = attr.deleter()
                else:
                    deleter = attr.deleter_cant_delete()
                prop = property(getter, setter, deleter, attr.doc)
                attrs[attrname] = prop
        try:
            patterns = attrs['_mod_defs']
        except KeyError:
            pass
        else:
            del attrs['_mod_defs']
            update_from_mod_definitions(attrs, patterns)
        return type.__new__(meta, name, bases, attrs)


@compat.add_metaclass(MetaCDataObject)
class CDataObject(object):
    '''Base class for objects wrapping *struct*'''
    _struct = None
