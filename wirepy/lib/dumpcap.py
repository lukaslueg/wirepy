'''To capture network traffic from live interfaces the external ``dumpcap``-
program is used (as in ``tshark`` and ``wireshark``). This module provides
classes and functions to deal with ``dumpcap`` and get useful results from it.
'''


import io
import os
import queue
import re
import signal
import subprocess
import struct
import time
import threading


DUMPCAP_BIN = ('dumpcap', )
'''Name (and default args) of ``dumpcap`` executable'''

DUMPCAP_CHECK_INTERVAL = 1.0
'''Timeout after which ``dumpcap`` is checked for being still alive while in a
blocking call. Shorter timeouts consume more cpu-time but cause errors to
be reported more quickly.
'''

# Used to parse in Interface.list_interfaces()
INTERFACE_LIST = re.compile((r'^(\d+)\. '  # The interface number
                             r'([^\t]+)\t'  # The interface name
                             r'([^\t]*)\t'  # The vendor name
                             r'([^\t]*)\t'  # Human-friendly name
                             r'(\d+)\t'  # One of interface_type
                             r'([a-fA-F0-9\.:,]*)\t'  # Addresses
                             r'(\w+)'  # 'loopback' or 'network'
                             r'\r?\n'),
                            re.MULTILINE)

# The following definitions are not included in the distributed header files.
# These are probably not subject to frequent change, so version-dependent
# definitions will probably not be needed.

# Copied from capture_ifinfo.h
_IF_WIRED = 0
_IF_AIRPCAP = 1
_IF_PIPE = 2
_IF_STDIN = 3
_IF_BLUETOOTH = 4
_IF_WIRELESS = 5
_IF_DIALUP = 6
_IF_USB = 7
_IF_VIRTUAL = 8

# Copied from sync_pipe.h
_SP_FILE = ord('F')  # The name of the recently opened file
_SP_ERROR_MSG = ord('E')  # Error message
_SP_BAD_FILTER = ord('B')  # Error message for bad capture filter
_SP_PACKET_COUNT = ord('P')  # Packets captured since last message
_SP_DROPS = ord('D')  # Count of packets dropped in capture
_SP_SUCCESS = ord('S')  # Success indication, no extra data
_SP_QUIT = ord('Q')  # "gracefully" capture quit message (SIGUSR1)


class DumpcapError(Exception):
    '''Base-class for all exceptions'''
    pass


class NoEvents(DumpcapError):
    '''No events are available from ``dumpcap`` while waiting on a blocking
    call.
    '''
    pass


class ChildError(DumpcapError):
    '''``dumpcap`` has reported an error or died with a process exit status
    indicating failure.
    '''
    pass


class BadFilterError(ChildError):
    '''``dumpcap`` reports that the given capture filter could not be compiled.
    '''
    pass


class BrokenPipe(DumpcapError):
    '''The communication-pipe to ``dumpcap`` was closed or the receiving thread
    has died because it received an unexpected message from ``dumpcap``.
    '''
    pass


def _create_dumpcap_args(command, child_mode=True, interfaces=None,
                         capture_filter=None, snaplen=None, promiscuous=True,
                         monitor_mode=False, kernel_buffer_size=None,
                         link_layer_type=None, wifi_channel=None,
                         max_packet_count=None, autostop_duration=None,
                         autostop_filesize=None, autostop_files=None,
                         savefile=None, group_access=False,
                         ringbuffer_duration=None, ringbuffer_filesize=None,
                         ringbuffer_files=None, use_pcapng=False,
                         use_libpcap=False, max_buffered_packets=None,
                         max_buffered_bytes=None, separate_threads=False):
    args = list(DUMPCAP_BIN)
    #TODO correct argument ordering for -f, -y and such with respect to -i
    if command == 'capture':
        pass  # capturing is the default
    elif command == 'list_devices':
        args.append('-D')
    elif command == 'list_layers':
        args.append('-L')
    elif command == 'stats':
        args.append('-S')
    else:
        raise ValueError('Unknown command "%s"' % (command, ))
    if child_mode:
        # TODO Use the named pipe on windows
        args += ['-Z', 'none']
    if interfaces is not None:
        for iface in interfaces:
            args += ['-i', str(iface)]
    if capture_filter:
        args += ['-f', str(capture_filter)]
    if snaplen:
        args += ['-s', str(int(snaplen))]
    if not promiscuous:
        args.append('-p')
    if monitor_mode:
        args.append('-I')
    if kernel_buffer_size is not None:
        args += ['-B', str(int(kernel_buffer_size))]
    if link_layer_type is not None:
        args += ['-y', str(link_layer_type)]
    if wifi_channel is not None:
        args += ['-k', str(wifi_channel)]
    if max_packet_count is not None:
        args += ['-c', str(int(max_packet_count))]
    if autostop_duration is not None:
        args += ['-a', 'duration:%i' % (autostop_duration, )]
    if autostop_filesize is not None:
        args += ['-a', 'filesize:%i' % (autostop_filesize, )]
    if savefile is not None:
        args += ['-w', str(savefile)]
    if group_access:
        args.append('-g')
    if ringbuffer_duration is not None:
        args += ['-b', 'duration:%i' % (ringbuffer_duration, )]
    if ringbuffer_filesize is not None:
        args += ['-b', 'filesize:%i' % (ringbuffer_filesize, )]
    if ringbuffer_files is not None:
        args += ['-b', 'files:%i' % (ringbuffer_files, )]
    if use_pcapng:
        args.append('-n')
    if use_libpcap:
        args.append('-P')
    if max_buffered_packets is not None:
        args += ['-N', str(int(max_buffered_packets))]
    if max_buffered_bytes is not None:
        args += ['-C', str(int(max_buffered_bytes))]
    if separate_threads:
        args.append('-t')
    return args


def _open_dumpcap(*args, **kwargs):
    # TODO secure process on windows
    # bufsize=-1 due to python bug, see subprocess docs
    return subprocess.Popen(_create_dumpcap_args(*args, **kwargs),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, bufsize=-1)


def _read_messages(input):
    '''Read dumpcap-messages like SP_FILE from a file-like object.
    Messages begin with a header of four bytes, the first byte being
    an indicator and the remaining three bytes being the size of the message.

    Calling this function on a pipe to dumpcap may block the caller.
    '''
    while True:
        header = input.read(4)
        if len(header) == 0:
            # Child has exited normally
            raise StopIteration
        msgtype, s1, s2, s3 = struct.unpack('4B', header)
        msgsize = (s1 << 16) | (s2 << 8) | (s3 << 0)
        if msgsize == 0:
            yield msgtype, None
        msg = input.read(msgsize)
        yield msgtype, msg


def _parse_errormsg(errmsg):
    with io.BytesIO(errmsg) as stream:
        messages = _read_messages(stream)
        # There will be a primary and a secondary message
        _, err1 = next(messages)
        _, err2 = next(messages)
    return err1[:-1].decode() + err2[:-1].decode()


class CaptureSession(object):
    '''Use ``dumpcap`` to capture network traffic from live interfaces.

    A new subprocess is created on instantiation which starts immediately.
    ``dumpcap`` writes captured traffic to one or more files and reports it's
    activity through a set of messages. Incoming messages are received by an
    internal thread that puts *events* on a FIFO-queue were they can be
    received by calling :py:func:`wait_for_event`. One may register an
    eventhandler-function through :py:func:`register_eventhandler` that
    automatically reacts to certain event-types when
    :py:func:`wait_for_unhandled_event` is called.

    The first event after instantiation should be :py:attr:`SP_FILE`,
    indicating that ``dumpcap`` has started writing captured traffic. After
    that, multiple events of type :py:attr:`SP_PACKET_COUNT` arrive to indicate
    that a number of new packets have been written to the current file.

    For example::

        def print_packet_count(n):
            """Handle new packets as they are written to the current file."""
            # not entirely obvious example on using nonlocal...
            nonlocal fname, cap
            print('%s: %i new, %i in all files' % (fname, n, cap.packetcount))

        with CaptureSession(interfaces=('any', ),
                            autostop_duration=30) as cap:
            cap.register_eventhandler(cap.SP_PACKET_COUNT, print_packet_count)
            try:
                # Wait for the first filename
                event_type, event_msg = cap.wait_for_unhandled_event(timeout=10)
                if event_type != cap.SP_FILE:
                    # Pipe is out of sync, just exit in any case
                    raise RuntimeError
            except NoEvents:
                # Dumpcap did not start capturing for some reason.
                raise RuntimeError('Giving up on dumpcap')
            fname = event_msg
            # Now loop while dumpcap keeps sending messages
            while True:
                print('Switched to file %s' % (fname, ))
                for event_type, event_msg in cap:
                    if event_type == cap.SP_FILE:
                        # Switch files
                        fname = event_msg
                        break
                else:
                    # The event-iterator stops when dumpcap closes on its own.
                    break

    '''

    SP_FILE = _SP_FILE
    '''``dumpcap`` has recently opened a file to write newly captured packets.
    The event-message is the name of the file (a string).
    '''
    SP_ERROR_MSG = _SP_ERROR_MSG
    '''General error indicator; ``dumpcap`` has stopped. The event-message
    is an unparsed error message from ``dumpcap`` (a string).
    '''
    SP_BAD_FILTER = _SP_BAD_FILTER
    '''The supplied capture filter failed to compile; ``dumpcap`` has stopped.
    The event-message is an unparsed error message from ``dumcap`` (a string).
    '''
    SP_PACKET_COUNT = _SP_PACKET_COUNT
    '''Newly captured packets captured were written to the most recently
    given file. The event-message is the number of packets written (an int).
    '''
    SP_DROPS = _SP_DROPS
    '''Reports the count of packets dropped in capture (an int).'''
    SP_SUCCESS = _SP_SUCCESS
    '''General success indication, the event-message is None.'''
    SP_QUIT = _SP_QUIT  # "gracefully" capture quit message (SIGUSR1)

    class _CapturePipeReader(threading.Thread):

        def __init__(self, cap_session):
            threading.Thread.__init__(self)
            self.cap_session = cap_session
            self.retcode = None

        def run(self):
            try:
                pipe = self.cap_session._proc.stderr
                for msgtype, msg in _read_messages(pipe):
                    if msgtype == _SP_FILE:
                        eventmsg = self._new_file_event(msg)
                    elif msgtype == _SP_PACKET_COUNT:
                        eventmsg = self._packet_count_event(msg)
                    elif msgtype == _SP_DROPS:
                        eventmsg = self._drop_count_event(msg)
                    elif msgtype == _SP_BAD_FILTER:
                        eventmsg = self._bad_filter_event(msg)
                    elif msgtype == _SP_ERROR_MSG:
                        eventmsg = self._error_event(msg)
                    else:
                        raise NotImplementedError((msgtype, msg))
                    self.cap_session._eventqueue.put((msgtype, eventmsg))
            except Exception as exp:
                self.retcode = exp
            else:
                self.retcode = True

        def _new_file_event(self, msg):
            return msg[:-1].decode()

        def _packet_count_event(self, msg):
            packetcount = int(msg[:-1].decode())
            # Reported packetcount is added to total
            self.cap_session.packetcount += packetcount
            return packetcount

        def _drop_count_event(self, msg):
            dropcount = int(msg[:-1].decode())
            # Reported dropcount is absolute
            self.cap_session.dropcount = dropcount
            return dropcount

        def _bad_filter_event(self, msg):
            devidx, errmsg = msg[:-1].decode().split(':', 1)
            return devidx, errmsg

        def _error_event(self, msg):
            return _parse_errormsg(msg)

    def __init__(self, **extra_capture_args):
        '''Start a new packet capture using ``dumpcap``.

        :param interfaces:
            Tuple of interface-names to capture on.

        :param capture_filter:
            Packet filter to libpcap filter syntax to use while capturing.
            See `the documentation <http://wiki.wireshark.org/CaptureFilters>`_
            for more information.

        :param snaplen:
            Packet snapshot length.

        :param promiscuous:
            Capture in promiscuous-mode (True by default).

        :param monitor_mode:
            Capture in monitor-mode if available (False by default).

        :param kernel_buffer_size:
            Size of kernel buffer in MiB.

        :param link_layer_type:
            Link layer type.

        :param wifi_channel:
            Set channel on wifi interface to <freq>,[type] if possible.

        :param max_packet_count:
            Stop capturing after this number of packets.

        :param autostop_duration:
            Stop capturing after this number of seconds.

        :param autostop_filesize:
            Stop capturing after this number of KB.

        :param autostop_files:
            Stop capturing after this number of files.

        :param savefile:
            Name of file to save to (defaults to a temporary file).

        :param group_access:
            Enable group read access on the output file(s). (Defaults to
            False.)

        :param ringbuffer_duration:
            Switch to next file after this number of seconds.

        :param ringbuffer_filesize:
            Switch to next file after this number of KB.

        :param ringbuffer_files:
            Start replacing after this number of files.

        :param use_pcapng:
            Use pcapng format instead of pcap (Defaults to True).

        :param use_libpcap:
            Use libpcap format instead of pcapng (Defaults to False).

        :param max_buffered_packets:
            Maximum number of packets buffered within ``dumpcap``.

        :param max_buffered_bytes:
            Maximum number of bytes used for buffering packets within
            ``dumpcap``.

        :param separate_threads:
            Use a separate thread per interface (Defaults to False).

        The events :py:const:`SP_ERROR_MSG` and :py:const:`SP_BAD_FILTER` have
        handlers automatically registered on them to raise :py:exc:`ChildError`
        and :py:exc:`BadFilterError` in :py:func:`wait_for_unhandled_event`.
        '''
        #: The total number of packets dropped before ``dumpcap`` could
        #: receive them.
        self.packetcount = 0
        #: The total number of packets received by ``dumpcap``.
        self.dropcount = 0
        self._extra_capture_args = extra_capture_args
        self._extra_capture_args.update((('child_mode', True),
                                         ('command', 'capture')))
        self._eventqueue = queue.Queue()
        self._eventhandlers = {}
        self.register_eventhandler(self.SP_ERROR_MSG, self._error_event)
        self.register_eventhandler(self.SP_BAD_FILTER, self._bad_filter_event)
        self._proc = _open_dumpcap(**self._extra_capture_args)
        self._msgreader = self._CapturePipeReader(self)
        self._msgreader.start()

    def _error_event(self, errmsg):
        raise ChildError(errmsg)

    def _bad_filter_event(self, errmsg):
        raise BadFilterError(errmsg)

    def wait(self):
        '''Wait until ``dumpcap`` has ended on its own.'''
        self._proc.wait()

    def stop(self):
        '''Signal dumpcap to stop capturing and exit.'''
        # TODO: Windows needs terminate
        os.kill(self._proc.pid, signal.SIGINT)

    def terminate(self):
        '''Kill dumpcap.'''
        try:
            self._proc.terminate()
        except OSError:
            pass  # The child has already exited
        self._msgreader.join()

    def __enter__(self):
        '''
        :returns: the instance itself
        '''
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        '''Kill ``dumpcap`` through a call to :py:func:`terminate` and block
        until the message-pipe has stopped.
        '''
        self.terminate()

    def _check_child(self):
        retcode = self._proc.poll()
        if retcode is not None:
            # The child is dead
            if retcode != 0:
                raise ChildError('Dumpcap has died...')
            else:
                return True

    def wait_for_event(self, block=True, timeout=None):
        '''Wait for events from ``dumpcap``.

        :param block:
            If True, the call blocks until an event appears through the pipe.

        :param timeout:
            The number of seconds a call should block if **block** is True.

        :raises:
            :py:exc:`ChildError` if ``dumpcap`` has died while waiting for
            events.  :py:exc:`BrokenPipe` in case the thread receiving messages
            from ``dumpcap`` has died.  :py:exc:`NoEvents` if **block** is
            False and no event is readily available or **block** is True and
            the timeout-time has passed.

        :returns: A tuple of `(event_type, event_msg)`.
        '''
        # Wait a maximum of one second on the queue before checking the child
        queue_timeout = (DUMPCAP_CHECK_INTERVAL if timeout is None
                         else min(DUMPCAP_CHECK_INTERVAL, timeout))
        t = time.time()
        while True:
            try:
                event = self._eventqueue.get(block, queue_timeout)
            except queue.Empty:
                if not block:
                    raise NoEvents()
                # Didnt get any event for some time, maybe the child or the
                # reader have died?
                if self._check_child():
                    # Fake a success-exit-message, dumpcap doesnt do that
                    return self.SP_QUIT, 'Dumpcap has ended'
                if not self._msgreader.isAlive():
                    raise BrokenPipe(self._msgreader.retcode)
                if timeout is not None:
                    # Child and pipe are alive, maybe it's time to give up
                    timeout -= max(0, (time.time() - t))
                    if timeout <= 0:
                        raise NoEvents()
            else:
                return event

    def __iter__(self):
        '''Iterate over all events received from ``dumpcap`` until it exits
        or dies (in which case an exception is raised). The iterator uses
        :py:func:`wait_for_unhandled_event` and blocks until unhandled events
        arrive.
        '''
        while True:
            msgtype, msg = self.wait_for_unhandled_event()
            if msgtype == self.SP_QUIT:
                break
            yield msgtype, msg

    def register_eventhandler(self, event_type, func):
        '''Register a function to automatically handle an event.

        The given function is called by :py:func:`wait_for_unhandled_event`
        with the event-message being the only parameter. One event-type can
        only have one handler registered at a time.

        :param event_type:
            One of *SP_...* like :py:const:`CaptureSession.SP_FILE`

        :param func:
            A callable that will receive the event-message as it's only
            argument.
        '''
        self._eventhandlers[event_type] = func

    def wait_for_unhandled_event(self, block=True, timeout=None):
        '''Wait for events from ``dumpcap`` and pass them to their respective
        event-handler.

        Returns the next event that has no handler registered. See
        :py:func:`CaptureSession.wait_for_event` for details on the parameters
        and the return values.

        Any exceptions raised by registered event-handlers are reported to the
        caller.
        '''
        # TODO should timeout have a meaning on it's own here? Currently the
        # function may never return if timeout has a value and all events are
        # handled by their callbacks
        while True:
            event_type, event_msg = self.wait_for_event(block, timeout)
            try:
                handler = self._eventhandlers[event_type]
            except KeyError:
                return event_type, event_msg
            else:
                handler(event_msg)


class LiveInterfaceStats(object):
    '''Receive statistics on the number of packets received and dropped from
    all interfaces.

    The iterator on instances of this class provides a convenient way to
    receive statistics as they arrive without busy-waiting

    The context-manger ensures that the child-process is terminated when the
    context ends.

    Both may be used in concert to produce a generator iterator that can be
    passed around and automatically terminates ``dumpcap`` once the instance is
    garbage-collected::

        def stats():
            with LiveInterfaceStats() as s:
                for results in s:
                    yield results

        stats_iter = stats()
        next(stats_iter)  # Launch dumpcap and get statistics
        next(stats_iter)  # Get new statistics...
        ...
        del stats_iter  # or gc/stats_iter.close(), dumpcap is terminated.
    '''

    class _StatsPipeReader(threading.Thread):

        def __init__(self, inpipe):
            threading.Thread.__init__(self)
            self.stats = {}
            self.inpipe = inpipe
            self.retcode = None
            self.tickevent = threading.Event()

        def run(self):
            try:
                while True:
                    line = self.inpipe.readline().decode()
                    if line == '':
                        break
                    dev, count, dropped = line.split('\t')
                    try:
                        devstats = self.stats[dev]
                    except KeyError:
                        devstats = self.stats[dev] = [0, 0]
                    devstats[0] += int(count)
                    devstats[1] += int(dropped)
                    self.tickevent.set()
            except Exception as exp:
                self.retcode = exp
            else:
                self.retcode = True

    def __init__(self):
        '''Start capturing interface statistics.

        :raises:
            :py:exc:`ChildError` if ``dumpcap`` reported an error.
        '''
        self._proc = _open_dumpcap('stats', child_mode=True)
        indicator, errmsg = next(_read_messages(self._proc.stderr))
        if indicator == _SP_SUCCESS:
            self._statsreader = self._StatsPipeReader(self._proc.stdout)
            self._statsreader.start()
        elif indicator == _SP_ERROR_MSG:
            raise ChildError(_parse_errormsg(errmsg))
        else:
            raise NotImplementedError

    def __enter__(self):
        ''':returns: The instance itself.
        '''
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        '''Kill ``dumpcap`` through a call to :py:func:`terminate`
        '''
        self.terminate()

    def __getitem__(self, interface):
        '''Receive the current statistics for the given interface.

           :param interface: The name of the interface
           :returns: A tuple of (*packets received*, *packets dropped*)
        '''
        return tuple(self._statsreader.stats[interface])

    def __len__(self):
        ''':returns: The number of interfaces currently known.
        '''
        return len(self._statsreader.stats)

    def __iter__(self):
        '''Wait for fresh statistics by calling :py:func:`wait_for_tick` and
        yield them. The tick-event is cleared **after** yielding to the caller;
        a new call to next() will probably block but return the newest results.

        :returns:
            A tuple of (*interface_name*, (*packets received*, *packets
            dropped*)).
        '''
        while True:
            self.wait_for_tick()
            yield tuple(((iface, tuple(stats)) for iface, stats
                        in self._statsreader.stats.items()))
            self.clear_tick()

    @property
    def interfaces(self):
        '''A tuple of all currently known interface names.
        '''
        return tuple(self._statsreader.stats)

    def wait_for_tick(self, timeout=None):
        '''Block until dumpcap reports fresh statistics.

        :param timeout:
            If not None the call blocks up to that amount of seconds before
            raising NoEvents.

        :raises:
            :py:exc:`NoEvents` if no new data arrived after **timeout** has
            passed.
        '''
        tick_timeout = (DUMPCAP_CHECK_INTERVAL if timeout is None
                        else min(DUMPCAP_CHECK_INTERVAL, timeout))
        t = time.time()
        while True:
            if self._statsreader.tickevent.wait(tick_timeout):
                break
            if not self._statsreader.isAlive():
                raise BrokenPipe(self._statsreader.retcode)
            if timeout is not None:
                timeout -= max(0, (time.time() - t))
                if timeout <= 0:
                    raise NoEvents()

    def clear_tick(self):
        '''Clears the tick-event.

        Calls to :py:func:`wait_for_tick` may block again after calling this.
        '''
        self._statsreader.tickevent.clear()

    def terminate(self):
        '''Kill dumpcap.'''
        self._proc.terminate()
        self._statsreader.join()


class LinkLayerType(object):
    '''Represents a link-layer-type as reported by ``dumpcap``
    '''

    def __init__(self, dlt, name, description):
        self.dlt = dlt
        self.name = name  #: The short-name of this link-layer-type
        self.description = description  #: The human-friendly name

    def __repr__(self):
        r = '<LinkLayerType name="%s" description="%s">' % (self.name,
                                                            self.description)
        return r

    def __str__(self):
        '''Equal to :py:attr:`name`'''
        return self.name


class Interface(object):
    '''An interface or device ``dumpcap`` can use to capture packets from.
    '''

    IF_WIRED = _IF_WIRED  #: Wired device (probably Ethernet/DOCSIS)
    IF_AIRPCAP = _IF_AIRPCAP  #: The AirPcap-device
    IF_PIPE = _IF_PIPE  #: A pipe
    IF_STDIN = _IF_STDIN  #: Standard input
    IF_BLUETOOTH = _IF_BLUETOOTH  # :Bluetooth
    IF_WIRELESS = _IF_WIRELESS  #: Wireless
    IF_DIALUP = _IF_DIALUP  #: Dialup
    IF_USB = _IF_USB  #: USB
    IF_VIRTUAL = _IF_VIRTUAL  #: Virtual

    def __init__(self, name, number=None, vendor_name=None, friendly_name=None,
                 interface_type=None, addresses=None, loopback=None):
        self.name = name  #: The name of the interface.
        self._number = number  #: An opaque index number
        self.vendor_name = vendor_name
        self.friendly_name = friendly_name  # Human-friendly name
        self.interface_type = interface_type
        '''One of *IF_...* like :py:const:`Interface.IF_WIRED`
        '''
        self.addresses = addresses
        '''A list of strings representing the addresses the interface is bound
        to.
        '''
        self.loopback = loopback  #: True if the interface is a loopback

    @staticmethod
    def get_interface_capabilities(interface, monitor_mode=False):
        '''Query link-layer-types an interface supports.

        :param interface:
            The name of the interface to query.

        :param monitor_mode:
            True if the interface shall be put into monitor-mode before
            querying available link-layer-types.

        :returns:
            A tuple with two members, the first indicating wether the interface
            supports monitor-mode, the second being a list of
            :py:class:`LinkLayerType`.
        '''
        # One could specify more than one interface to dumpcap and dumpcap
        # answers
        proc = _open_dumpcap('list_layers', interfaces=(interface, ),
                             monitor_mode=monitor_mode)
        outs, errs = proc.communicate()
        indicator, errmsg = next(_read_messages(io.BytesIO(errs)))
        if indicator == _SP_SUCCESS:
            lines = re.compile(r'\r?\n').split(outs.decode())
            can_rfmon = lines[0] == '1'

            def _scan():
                for line in lines[1:-1]:
                    dlt, name, description = line.split('\t')
                    dlt = int(dlt)
                    yield LinkLayerType(dlt, name, description)
            return can_rfmon, list(_scan())
        elif indicator == _SP_ERROR_MSG:
            raise ChildError(_parse_errormsg(errmsg))
        else:
            raise NotImplementedError

    @property
    def interface_type_string(self):
        try:
            return {self.IF_WIRED: 'WIRED', self.IF_AIRPCAP: 'AIRPCAP',
                    self.IF_PIPE: 'PIPE', self.IF_STDIN: 'STDIN',
                    self.IF_BLUETOOTH: 'BLUETOOTH',
                    self.IF_WIRELESS: 'WIRELESS', self.IF_DIALUP: 'DIALUP',
                    self.IF_USB: 'USB',
                    self.IF_VIRTUAL: 'VIRTUAL'}[self.interface_type]
        except KeyError:
            return 'UNKNOWN'

    @property
    def capabilities(self):
        '''The capabilities of this interface.

        See :py:func:`get_interface_capabilities` for details.
        '''
        # TODO memoize this
        return self.get_interface_capabilities(self.name)

    @property
    def can_rfmon(self):
        '''True if this interface supports monitor-mode.'''
        return self.capabilities[0]

    @property
    def supported_link_layer_types(self):
        '''A list of supported link-layer-types.'''
        return self.capabilities[1]

    def __repr__(self):
        r = '<Interface "%s" of type "%s"' % (self.name,
                                              self.interface_type_string)
        r += ', loopback>' if self.loopback else '>'
        return r

    def __str__(self):
        '''Equal to :py:attr:`name`'''
        return self.name

    @classmethod
    def list_interfaces(cls):
        '''Report the interfaces dumpcap knows about.

        :raises: :py:exc:`ChildError` if ``dumpcap`` returns an error.

        :returns: A list of :py:class:`Interface`-instances.
        '''
        dumpcap_args = list(DUMPCAP_BIN) + ['-M', '-D']
        try:
            buf = subprocess.check_output(dumpcap_args)
        except subprocess.CalledProcessError as exp:
            raise ChildError(exp)
        buf = buf.decode()
        interfaces = []
        for (number, name, vendor_name, friendly_name, interface_type,
             addresses, loopback) in INTERFACE_LIST.findall(buf):
            number = int(number)
            interface_type = int(interface_type)
            addresses = addresses.split(',') if addresses else []
            loopback = loopback == 'loopback'
            interfaces.append(cls(name, number, vendor_name or None,
                                  friendly_name or None, interface_type,
                                  addresses, loopback))
        return interfaces
