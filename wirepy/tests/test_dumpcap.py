MOCK_FAIL_FAST = '--FAIL_FAST'  # Mock exit right away, no messages
MOCK_FAIL_EXIT = '--FAIL_EXIT'
MOCK_FAIL_FILTER = '--FAIL_FILTER'
MOCK_EMPTY_OUTPUT = '--EMPTY_OUTPUT'
MOCK_ILLEGAL_OUTPUT = '--ILLEGAL_OUTPUT'

if __name__ == '__main__':
    # We are here to mock dumpcap...

    import getopt
    import struct
    import sys
    import time

    def _build_message(indicator, msgbytes=b''):
        msglen = len(msgbytes)
        header = struct.pack('4B', ord(indicator), (msglen & (255 << 16)),
                             (msglen & (255 << 8)), (msglen & (255 << 0)))
        return header + msgbytes

    def _write_error_message(pipe):
        err1 = _build_message('E', b'Oh, no interfaces!\x00')
        err2 = _build_message('E', b'\x00')
        pipe.write(_build_message('E', err1 + err2))
        pipe.flush()

    def mock_capture_empty(**kwargs):
        # never give any output, as if no traffic arrives
        while True:
            time.sleep(1)

    def mock_capture_fail(pipe, **kwargs):
        _write_error_message(pipe)

    def mock_capture_filter(pipe, **kwargs):
        errmsg = _build_message('B', b'0:bad filter\x00')
        pipe.write(errmsg)
        pipe.flush()

    def mock_capture(pipe, **kwargs):
        pipe.write(_build_message('F', b'foobar\x00'))
        pipe.write(_build_message('P', b'4711\x00'))
        pipe.write(_build_message('D', b'4811\x00'))

    def mock_capture_illegal(pipe, **kwargs):
        pipe.write(_build_message('X'))
        pipe.flush()
        while True:
            time.sleep(1)

    def mock_layers_empty(pipe, **kwargs):
        pipe.write(_build_message('S'))

    def mock_layers_fail(pipe, **kwargs):
        _write_error_message(pipe)

    def mock_layers(pipe, interfaces, **kwargs):
        if 'em1' in interfaces:
            pipe.write(_build_message('S'))
            sys.stdout.write(('1\n'  # em1 can mock-rfmon...
                              '1\tEN10MB\tEthernet\n'
                              '143\tDOCSIS\tDOCSIS\n'))
        if 'lo' in interfaces:
            pipe.write(_build_message('S'))
            sys.stdout.write(('0\n'
                              '1\tEN10MB\tEthernet\n'))

    def mock_interfaces_empty(**kwargs):
        pass  # TODO No output at all - correct?

    def mock_interfaces_fail(flags, **kwargs):
        flags.remove('fail')  # dumpcap just exits with exit status 0. Meh

    def mock_interfaces_illegal(**kwargs):
        sys.stdout.write('foobar')

    def mock_interfaces(**kwargs):
        sys.stdout.write(('1. em1\t\t\t0\t\tnetwork\n'
                          '2. lo\t\tLoopback\t0\t'
                          '127.0.0.1,::1\tloopback\n'))

    def mock_stats(pipe, **kwargs):
        pipe.write(_build_message('S'))
        pipe.flush()
        sys.stdout.write(('em1\t4711\t123\n'
                          'lo\t4811\t124\n'))
        while True:
            sys.stdout.write(('em1\t0\t0\n'
                              'lo\t0\t0\n'))
            sys.stdout.flush()
            time.sleep(1)

    def mock_stats_fail(pipe, **kwargs):
        _write_error_message(pipe)

    def mock_stats_empty(pipe, **kwargs):
        pipe.write(_build_message('S'))
        pipe.flush()
        while True:
            time.sleep(1)

    def mock_stats_illegal(pipe, **kwargs):
        pipe.write(_build_message('S'))
        pipe.flush()
        sys.stdout.write('foobar')

    opts, _ = getopt.getopt(sys.argv[1:], 'Z:DLMSi:',
                            [s[2:] for s in (MOCK_FAIL_FAST, MOCK_FAIL_EXIT,
                                             MOCK_EMPTY_OUTPUT,
                                             MOCK_FAIL_FILTER,
                                             MOCK_ILLEGAL_OUTPUT)])
    interfaces = []
    command = 'capture'
    flags = set()
    pipe = None
    for o, a in opts:
        if o == MOCK_FAIL_FAST:
            sys.exit(1)
        elif o == '-M':
            pass  # machine-readable is assumed for list_interfaces()
        elif o == '-i':
            interfaces.append(a)
        elif o == '-Z':
            if a == 'none':
                pipe = sys.stderr.buffer
            else:
                raise NotImplementedError  # TODO Windows
        else:
            try:
                flags.add({MOCK_FAIL_EXIT: 'fail', MOCK_EMPTY_OUTPUT: 'empty',
                           MOCK_FAIL_FILTER: 'filter',
                           MOCK_ILLEGAL_OUTPUT: 'illegal'}[o])
            except KeyError:
                command = {'-D': 'interfaces',
                           '-L': 'layers',
                           '-S': 'stats'}[o]
    for name, mock_function in tuple(globals().items()):
        if not name.startswith('mock_'):
            continue
        comps = name[5:].split('_')
        if comps[0] == command and flags == set(comps[1:]):
            mock_function(pipe=pipe, interfaces=interfaces, flags=flags)
            break
    else:
        raise NotImplementedError((command, flags))
    sys.exit(int('fail' in flags))

    # END OF MOCK

import functools
import os
import sys
import unittest
from wirepy.lib import dumpcap


def mock_dumpcap(*extra_dumpcap_args):
    def decorator(method):
        @functools.wraps(method)
        def f(*args, **kwargs):
            dumpcap_bin = [sys.executable, os.path.abspath(__file__)]
            dumpcap_bin.extend(extra_dumpcap_args)
            dumpcap.DUMPCAP_BIN = dumpcap_bin
            dumpcap.DUMPCAP_CHECK_INTERVAL = 0.1
            return method(*args, **kwargs)
        return f
    return decorator


class TestInterfaceList(unittest.TestCase):

    @mock_dumpcap(MOCK_EMPTY_OUTPUT)
    def test_empty_list(self):
        interfaces = dumpcap.Interface.list_interfaces()
        self.assertEqual(len(interfaces), 0)

    @mock_dumpcap(MOCK_FAIL_EXIT)
    def test_list_fail(self):
        interfaces = dumpcap.Interface.list_interfaces()
        self.assertEqual(len(interfaces), 0)

    @mock_dumpcap()
    def test_list(self):
        interfaces = dumpcap.Interface.list_interfaces()
        self.assertEqual(len(interfaces), 2)
        dev = interfaces[0]
        repr(dev)
        self.assertEqual(dev.name, 'em1')
        self.assertEqual(dev.name, str(dev))
        self.assertEqual(dev.vendor_name, None)
        self.assertEqual(dev.friendly_name, None)
        self.assertEqual(dev.interface_type_string, 'WIRED')
        self.assertEqual(len(dev.addresses), 0)
        self.assertFalse(dev.loopback)
        self.assertTrue(dev.can_rfmon)
        self.assertTrue(all(isinstance(ltype, dumpcap.LinkLayerType)
                            for ltype in dev.supported_link_layer_types))
        dev = interfaces[1]
        self.assertEqual(dev.name, 'lo')
        self.assertEqual(dev.name, str(dev))
        self.assertEqual(dev.friendly_name, 'Loopback')
        self.assertEqual(dev.interface_type_string, 'WIRED')
        self.assertEqual(len(dev.addresses), 2)
        self.assertEqual(dev.addresses[0], '127.0.0.1')
        self.assertEqual(dev.addresses[1], '::1')
        self.assertTrue(dev.loopback)
        self.assertFalse(dev.can_rfmon)
        self.assertTrue(all(isinstance(ltype, dumpcap.LinkLayerType)
                            for ltype in dev.supported_link_layer_types))

    @mock_dumpcap(MOCK_FAIL_FAST)
    def test_list_fails_fast(self):
        self.assertRaises(dumpcap.ChildError,
                          dumpcap.Interface.list_interfaces)


class TestInterfaceCapabilities(unittest.TestCase):

    @mock_dumpcap()
    def test_get(self):
        rfmon, linktypes = dumpcap.Interface.get_interface_capabilities('em1')
        self.assertTrue(rfmon)
        self.assertTrue(len(linktypes), 2)
        ltype = linktypes[0]
        repr(ltype)
        self.assertEqual(ltype.dlt, 1)
        self.assertEqual(ltype.name, 'EN10MB')
        self.assertEqual(ltype.description, 'Ethernet')
        ltype = linktypes[1]
        self.assertEqual(ltype.dlt, 143)
        self.assertEqual(ltype.name, 'DOCSIS')
        self.assertEqual(ltype.description, 'DOCSIS')

    @mock_dumpcap(MOCK_FAIL_EXIT)
    def test_fail(self):
        self.assertRaises(dumpcap.ChildError,
                          dumpcap.Interface.get_interface_capabilities, 'em1')


class TestStats(unittest.TestCase):

    @mock_dumpcap()
    def test_stats(self):
        with dumpcap.LiveInterfaceStats() as stats:
            stats.clear_tick()
            stats.wait_for_tick()
        self.assertEqual(stats['em1'][0], 4711)
        self.assertEqual(stats['em1'][1], 123)
        self.assertEqual(stats['lo'][0], 4811)
        self.assertEqual(stats['lo'][1], 124)

    @mock_dumpcap(MOCK_FAIL_EXIT)
    def test_fail(self):
        self.assertRaises(dumpcap.ChildError, dumpcap.LiveInterfaceStats)

    @mock_dumpcap(MOCK_EMPTY_OUTPUT)
    def test_empty(self):
        with dumpcap.LiveInterfaceStats() as stats:
            self.assertRaises(dumpcap.NoEvents, stats.wait_for_tick,
                              timeout=1.0)

    @mock_dumpcap(MOCK_ILLEGAL_OUTPUT)
    def test_illegal(self):
        with dumpcap.LiveInterfaceStats() as stats:
            self.assertRaises(dumpcap.BrokenPipe, stats.wait_for_tick,
                              timeout=1.0)


class TestCapture(unittest.TestCase):

    @mock_dumpcap()
    def test_capture(self):
        with dumpcap.CaptureSession() as cap:
            events = iter(cap)
            event_type, event_msg = next(events)
            self.assertEqual(event_type, cap.SP_FILE)
            self.assertEqual(event_msg, 'foobar')
            event_type, event_msg = next(events)
            self.assertEqual(event_type, cap.SP_PACKET_COUNT)
            self.assertEqual(event_msg, 4711)
            event_type, event_msg = next(events)
            self.assertEqual(event_type, cap.SP_DROPS)
            self.assertEqual(event_msg, 4811)
            self.assertRaises(StopIteration, next, events)

    @mock_dumpcap(MOCK_EMPTY_OUTPUT)
    def test_empty(self):
        with dumpcap.CaptureSession() as cap:
            self.assertRaises(dumpcap.NoEvents, cap.wait_for_unhandled_event,
                              timeout=1.0)
            self.assertRaises(dumpcap.NoEvents, cap.wait_for_unhandled_event,
                              block=False)

    @mock_dumpcap(MOCK_FAIL_FILTER)
    def test_fail_filter(self):
        with dumpcap.CaptureSession() as cap:
            self.assertRaises(dumpcap.BadFilterError,
                              cap.wait_for_unhandled_event)

    @mock_dumpcap(MOCK_FAIL_FAST)
    def test_fail_fast(self):
        with dumpcap.CaptureSession() as cap:
            self.assertRaises(dumpcap.ChildError, cap.wait_for_unhandled_event)

    @mock_dumpcap(MOCK_FAIL_EXIT)
    def test_fail(self):
        with dumpcap.CaptureSession() as cap:
            self.assertRaises(dumpcap.ChildError, cap.wait_for_unhandled_event)

    @mock_dumpcap(MOCK_ILLEGAL_OUTPUT)
    def test_illegal(self):
        with dumpcap.CaptureSession() as cap:
            self.assertRaises(dumpcap.BrokenPipe, cap.wait_for_unhandled_event)
