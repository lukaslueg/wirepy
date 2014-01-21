from .wireshark import mod
from . import glib2

INIT_PROCESS_POLICIES_CALLED = False


def init_process_policies():
    '''Called when the program starts, to enable security features and save
    whatever credential information we'll need later.'''
    global INIT_PROCESS_POLICIES_CALLED
    if INIT_PROCESS_POLICIES_CALLED:
        return
    mod.init_process_policies()
    INIT_PROCESS_POLICIES_CALLED = True


def started_with_special_privs():
    '''Return True if this program started with special privileges.

       init_process_policies() must have been called before calling this.
    '''
    global INIT_PROCESS_POLICIES_CALLED
    if not INIT_PROCESS_POLICIES_CALLED:
        raise RuntimeError('init_process_policies() must have been called')
    return bool(mod.started_with_special_privs())


def running_with_special_privs():
    '''Return True if this program is running with special privileges.

       init_process_policies() must be called before calling this.
    '''
    global INIT_PROCESS_POLICIES_CALLED
    if not INIT_PROCESS_POLICIES_CALLED:
        raise RuntimeError('init_process_policies() must have been called')
    return bool(mod.running_with_special_privs())


def relinquish_special_privs_perm():
    '''Permanently relinquish special privileges. get_credential_info()
    MUST be called before calling this.'''
    mod.relinquish_special_privs_perm()


def get_cur_username():
    '''Get the current username or "UNKNOWN" on failure.'''
    return glib2.from_gchar(mod.get_cur_username())


def get_cur_groupname():
    '''Get the current group or "UNKNOWN" on failure.'''
    return glib2.from_gchar(mod.get_cur_groupname())
