"""Functions to get/set the timestamp-type behaviour of wireshark."""
from .wireshark import mod

RELATIVE = mod.TS_RELATIVE  #: Since start of capture
ABSOLUTE = mod.TS_ABSOLUTE  #: Absolute
ABSOLUTE_WITH_DATE = mod.TS_ABSOLUTE_WITH_DATE  #: Absolute with date
DELTA = mod.TS_DELTA  #: Since previously captured packet
DELTA_DIS = mod.TS_DELTA_DIS  #: Since previously displayed packet
EPOCH = mod.TS_EPOCH  #: Seconds (and fractions) since epoch
UTC = mod.TS_UTC  #: UTC time
UTC_WITH_DATE = mod.TS_UTC_WITH_DATE  #: UTC time with date

NOT_SET = mod.TS_NOT_SET  #: Special value, timestamp type not set
PREC_AUTO = mod.TS_PREC_AUTO  #: Special value, automatic precision
PREC_FIXED_SEC = mod.TS_PREC_FIXED_SEC  #: Fixed to-seconds precision
#TODO add more
SECONDS_DEFAULT = mod.TS_SECONDS_DEFAULT  #: .
SECONDS_HOUR_MIN_SEC = mod.TS_SECONDS_HOUR_MIN_SEC  #: .
SECONDS_NOT_SET = mod.TS_SECONDS_NOT_SET  #: .


class TimestampError(Exception):
    '''Base-class for all timestamp-related errors.'''
    pass


class InvalidTimestampValue(TimestampError):
    '''An invalid timestamp-type was used.'''


def get_type():
    '''Get the currently set timestamp-type.

    :returns:
        an opaque integer, e.g. :py:const:`NOT_SET`
    '''
    return mod.timestamp_get_type()


def set_type(ts_type):
    '''Set the globally used timestamp-type.

    :params ts_type:
        A timestamp-type from this module, e.g. :py:const:`RELATIVE`.
    '''
    if ts_type < 0 or ts_type > NOT_SET:
        raise InvalidTimestampValue
    mod.timestamp_set_type(ts_type)


def get_precision():
    '''Get the currently set timestamp-precision.

    :returns:
        an opaque integer, e.g. :py:const:`PREC_FIXED_SEC`
    '''
    return mod.timestamp_get_precision()


def set_precision(tsp):
    '''Set the globally used timestamp-precision.

    :param tsp:
        A timestamp-precision constant like :py:const:`PREC_FIXED_SEC`.
    '''
    # TODO check tsp against ... what?
    return mod.timestamp_set_precision(tsp)


def get_seconds_type():
    '''Get the currently set seconds-type.

    :returns:
        an opaque int, e.g. of :py:const:`SECONDS_DEFAULT`.
    '''
    return mod.timestamp_get_seconds_type()


def set_seconds_type(ts_seconds_type):
    '''Set the globally used timestamp-second-precision.

    :params ts_seconds_type:
        A timestamp-second-type, e.g. :py:const:`SECONDS_DEFAULT`.
    '''
    if ts_seconds_type < 0 or ts_seconds_type > SECONDS_NOT_SET:
        raise InvalidTimestampValue
    mod.timestamp_set_seconds_type(ts_seconds_type)


def is_initialized():
    '''Check if the globally used timestamp settings have been set.

    :returns:
        True if the timestamp-type and seconds-type are set.
    '''
    return get_type() != NOT_SET and get_seconds_type() != SECONDS_NOT_SET
