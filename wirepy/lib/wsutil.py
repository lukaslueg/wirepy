from .wireshark import mod
from . import glib2


def init_process_policies():
    '''Called when the program starts, to enable security features and save
    whatever credential information we'll need later.'''
    if mod.WIREPY_INIT_PROCESS_POLICIES_CALLED:
        return
    mod.init_process_policies()
    mod.WIREPY_INIT_PROCESS_POLICIES_CALLED = 1


def started_with_special_privs():
    '''Return True if this program started with special privileges.

       :py:func:`init_process_policies` must have been called before calling
       this.
    '''
    if not mod.WIREPY_INIT_PROCESS_POLICIES_CALLED:
        raise RuntimeError('init_process_policies() must have been called')
    return bool(mod.started_with_special_privs())


def running_with_special_privs():
    '''Return True if this program is running with special privileges.

       :py:func:`init_process_policies` must have been called before calling
       this.
    '''
    if not mod.WIREPY_INIT_PROCESS_POLICIES_CALLED:
        raise RuntimeError('init_process_policies() must have been called')
    return bool(mod.running_with_special_privs())


def relinquish_special_privs_perm():
    '''Permanently relinquish special privileges.

       :py:func:`init_process_policies` must have been called before calling
       this.
    '''
    if not mod.WIREPY_INIT_PROCESS_POLICIES_CALLED:
        raise RuntimeError('init_process_policies() must have been called')
    mod.relinquish_special_privs_perm()


def get_cur_username():
    '''Get the current username or "UNKNOWN" on failure.'''
    return glib2.from_gchar(mod.get_cur_username())


def get_cur_groupname():
    '''Get the current group or "UNKNOWN" on failure.'''
    return glib2.from_gchar(mod.get_cur_groupname())
