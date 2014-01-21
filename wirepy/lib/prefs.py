from .wireshark import iface, mod
from . import cdata


class PreferencesError(Exception):
    pass


class PrefSyntaxError(PreferencesError):
    pass


class NoSuchPreference(PreferencesError):
    pass


class PrefObsolete(PreferencesError):
    pass


class Preferences(cdata.CDataObject):

    _mod_defs = ('PREFS_', )
    file_ = cdata.ROStringAttribute('file')
    num_cols = cdata.ROAttribute()
    capture_device = cdata.ROStringAttribute()
    capture_devices_linktype = cdata.ROStringAttribute()
    capture_devices_desc = cdata.ROStringAttribute()
    capture_prom_mode = cdata.BooleanAttribute(can_write=False)

    def __init__(self, cdata):
        self.cdata = cdata

    @property
    def is_global_prefs(self):
        '''Returns True if this instance points to the global preferences'''
        return self.cdata == mod.prefs

    '''
    class FormatList(glib2.DoublyLinkedList):

        @staticmethod
        def cast_to_object(data):
            fmt_data = iface.cast('fmt_data*', data)
            return Format(fmt_data)

    @property
    def col_list(self):
        l = self.cdata.col_list
        if l != iface.NULL:
            return self.FormatList(l, backref=self)
        # TODO colum.FormatData entries
    '''

    def set_pref(self, prefstring):
        '''Given a string of the form "<pref name>:<pref spec>", parse it and
        set the preference in question'''
        prefs_set_pref_e = mod.prefs_set_pref(prefstring.encode())
        print(prefs_set_pref_e)
        if prefs_set_pref_e == self.PREFS_SET_OK:
            return
        elif prefs_set_pref_e == self.PREFS_SET_SYNTAX_ERR:
            raise PrefSyntaxError
        elif prefs_set_pref_e == self.PREFS_SET_NO_SUCH_PREF:
            raise NoSuchPreference
        elif prefs_set_pref_e == self.PREFS_SET_OBSOLETE:
            raise PrefObsolete
        else:
            raise PreferencesError('Unknown error')


def register_modules():
    mod.prefs_register_modules()


def apply_all():
    '''Call the "apply"-callback function for each module if any of its
    preferences have changed.'''
    mod.prefs_apply_all()


def copy(src):
    '''Copy a set of preferences'''
    e_prefs = iface.new('e_prefs*')
    iface.gc(mod.copy_prefs(e_prefs, src.cdata), mod.prefs_free)
    return Preferences(e_prefs)


def write(to_stdout=False):
    '''Write the global preferences to the user's preference-file; write to
    stdout if to_stdout is True.'''
    if to_stdout:
        pf_path_return = iface.NULL
    else:
        pf_path_return = iface.new('char**')
    res = mod.write_prefs(pf_path_return)
    if res == 0:
        return
    # TODO res == errno
    # TODO the filepath is leaking
    raise OSError('Failed on %s' % (iface.string(pf_path_return[0]), ))


def get_global_prefs():
    ''''''  # TODO
    return Preferences(iface.addressof(mod.prefs))


def read_prefs():
    '''Read the preferences file, make it global and return a new
    Preferences-instance'''
    gpf_open_errno = iface.new('int *')
    gpf_read_errno = iface.new('int *')
    gpf_path = iface.new('char **')
    pf_open_errno = iface.new('int *')
    pf_read_errno = iface.new('int *')
    pf_path = iface.new('char **')
    e_prefs = mod.read_prefs(gpf_open_errno, gpf_read_errno, gpf_path,
                             pf_open_errno, pf_read_errno, pf_path)
    if gpf_path[0] != iface.NULL:
        if gpf_open_errno[0] != 0:
            raise NotImplementedError  # TODO cant open global preference file
        elif gpf_read_errno[0] != 0:
            raise NotImplementedError  # TODO i/o errror reading global prefs file
        else:
            raise AssertionError
    if pf_path[0] != iface.NULL:
        if pf_open_errno[0] != 0:
            raise NotImplementedError  # TODO cant open your preference file
        elif pf_read_errno[0] != 0:
            raise NotImplementedError  # TODO i/o error reading your prefs file
        else:
            raise AssertionError
        #TODO g_free(pf_path)
        #pf_path = NULL
    assert e_prefs != iface.NULL
    return Preferences(e_prefs)


def get_column_format(col_idx):
    fmt = mod.get_column_format(col_idx)
    if fmt == -1:
        raise IndexError
    return fmt


def set_column_format(col_idx, fmt):
    mod.set_column_format(col_idx, fmt)


def get_column_title(col_idx):
    title = mod.get_column_title(col_idx)
    # These functions mask IndexErrors. Meh
    return iface.string(title) if title != iface.NULL else None


def set_column_title(col_idx, title):
    mod.set_column_title(col_idx, title.encode())


def get_column_visible(col_idx):
    return bool(mod.get_column_visible(col_idx))


def set_column_visible(col_idx, visible):
    mod.set_column_visible(col_idx, visible)


def get_column_resolved(col_idx):
    # Note: Returns True for invalid col_idx. Meh
    return mod.get_column_resolved(col_idx)


def set_column_resolved(col_idx, resolved):
    mod.set_column_resolved(col_idx, resolved)


def get_column_custom_field(col_idx):
    f = mod.get_column_custom_field(col_idx)
    return iface.string(f) if f != iface.NULL else None


def set_column_custom_field(col_idx, custom_field):
    mod.set_column_custom_field(col_idx, custom_field.encode())


def get_column_custom_occurrence(col_idx):
    return mod.get_column_custom_occurrence(col_idx)


def set_column_custom_occurrence(col_idx, custom_occurrence):
    mod.set_column_custom_occurrence(col_idx, custom_occurrence)
