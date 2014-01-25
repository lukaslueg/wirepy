'''Stub module'''

import threading

from .cdef import iface
from .. import platform

#: The cffi-module to libwireshark, libwsutils and libwtap
mod = iface.verify('''
                   #include <glib.h>
                   #include <alloca.h>
                   #include <dlfcn.h>
                   #include <stdarg.h>

                   #include <config.h>
                   #include <wiretap/wtap.h>
                   #include <register.h>
                   #include <color.h>
                   #include <epan/epan.h>
                   #include <epan/epan_dissect.h>
                   #include <epan/timestamp.h>
                   #include <epan/column.h>
                   #include <epan/column-utils.h>
                   #include <epan/packet.h>
                   #include <epan/ipv4.h>
                   #include <epan/ipv6-utils.h>
                   #include <epan/guid-utils.h>
                   #include <epan/tvbuff.h>
                   #include <epan/nstime.h>
                   #include <epan/dfilter/drange.h>
                   #include <epan/ftypes/ftypes.h>
                   #include <epan/proto.h>
                   #include <wsutil/privileges.h>
                   #include <epan/prefs.h>

                   static const int COLUMN_FORMATS = NUM_COL_FMTS;
                   // Declare these here instead of module variables so they
                   // can be accessed without having to import the respective
                   // module
                   static int WIREPY_EPAN_INITIALIZED = 0;
                   static int WIREPY_INIT_PROCESS_POLICIES_CALLED = 0;

                   static void (*logfunc_python_callback)(char *msg, int size);
                   static void logfunc_wrapper(const char*msg, ...) {
                       char buf[2048+1];
                       va_list ap;
                       va_start(ap, msg);
                       logfunc_python_callback(buf, vsnprintf(buf, sizeof(buf), msg, ap));
                       va_end(ap);
                   }

                   static void (*failure_message)(const char *msg, int size);
                   static void open_failure_cb(const char *msg, va_list ap) {
                       char buf[2048+1];
                       failure_message(buf, vsnprintf(buf, sizeof(buf), msg, ap));
                   }

                   void wrapped_epan_init(void (*report_open_failure_fcn_p)(const char *, int, gboolean),
                                          void (*report_read_failure_fcn_p)(const char *, int),
                                          void (*report_write_failure_fcn_p)(const char *, int)) {
                       const char errmsg[] = "Failed to re-export libwireshark. Plugins will not load...";
                       // Hackish way to provide symbols to wireshark's plugins
                       // that don't link in their symbols themselves
                       if (dlopen("libwireshark.so", RTLD_NOW|RTLD_GLOBAL) == NULL)
                           failure_message(errmsg, sizeof(errmsg));
                       epan_init(register_all_protocols,
                                 register_all_protocol_handoffs,
                                 NULL, NULL,
                                 open_failure_cb,
                                 report_open_failure_fcn_p,
                                 report_read_failure_fcn_p,
                                 report_write_failure_fcn_p);
                   }

                   const char* wrapped_dfilter_get_error_msg(void) {
                       return dfilter_error_msg;
                   }

                   gboolean wrapped_proto_item_is_hidden(proto_item* item) {
                       return PROTO_ITEM_IS_HIDDEN(item);
                   }''',
                   libraries=['glib-2.0', 'wiretap', 'wsutil', 'wireshark'],
                   extra_compile_args=platform.CFLAGS,
                   extra_link_args=platform.LIBS,
                   ext_package='wirepy')


class LogFuncWrapper(object):
    logfunc_lock = threading.Lock()
    messages = []

    def __init__(self):
        self.messages = None

    def __enter__(self):
        LogFuncWrapper.logfunc_lock.acquire()
        del LogFuncWrapper.messages[:]

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self.messages = tuple(LogFuncWrapper.messages)
        finally:
            LogFuncWrapper.logfunc_lock.release()
mod.LogFuncWrapper = LogFuncWrapper


@iface.callback('void(char *msg, int size)')
def logfunc_callback(msg, size):
    logmsg = iface.string(msg, size)
    LogFuncWrapper.messages.append(logmsg)
mod.logfunc_python_callback = logfunc_callback
