'''Capture network traffic and generate event-reports about it's content.

Events are reported to Cube (http://square.github.io/cube/), which stores them
in it's database for later analysis.

This example requires a running Cube daemon on localhost; note that naively
executing it will flood your mongodb instance with useless events. Also see
https://github.com/tsileo/cube-client for one extra dependency.

The main process starts ``dumpcap`` in order to write captured traffic to a
series of temporary files. Sub-processes handled by the multiprocessing module
take care of dissection and reporting. Note that this allows us to use multiple
CPUs for dissection at the expense of not having a single - readily available -
global state e.g. for stream reconstruction.

We report every single captured packet as an event to Cube: This is madness.
A more reality-bound tool would examine the protocol-tree itself or use a
series of DisplayFilter-instances to look for conditions worthy of reporting.

You may be interested in Cube and Cubism (http://square.github.io/cubism/) in
case you want to take this example more seriously for yourself.
Cube generates a report about the captured HTTP-traffic (bytes per second) in
a series of ten second intervals using a request like
http//.../metric?expression=sum(packet(length).eq(protocol, "HTTP"))&step=1e4
'''
import os
import multiprocessing
import tempfile
import cube
from wirepy.lib import column, dumpcap, epan, wtap, prefs

# Some required setup
epan.epan_init()
prefs.read_prefs()
epan.init_dissection()

# Use columns to quickly get some general information without having
# to dive into the protocol-tree
CINFO = column.ColumnInfo([column.Format(column.Type.PACKET_LENGTH),
                           column.Format(column.Type.PROTOCOL),
                           column.Format(column.Type.ABS_DATE_TIME)])


def _dissect_file(fname):
    '''Dissect a savefile and report events about information found within to
    Cube.

    This function is executed as a subprocess.
    '''
    print('Starting to dissect file %s' % (fname, ))
    try:
        c = cube.Cube()
        with wtap.WTAP.open_offline(fname) as wt:
            for frame in wt:
                edt = epan.Dissect()
                edt.prime_cinfo(CINFO)
                edt.run(wt, frame, CINFO)
                edt.fill_in_columns()
                # We could dive into edt.tree, the protocol-tree, but are
                # only interested in the column-info readily provided
                length = int(epan.iface.string(CINFO._col_datap[0]))
                proto = epan.iface.string(CINFO._col_datap[1])
                timestamp = epan.iface.string(CINFO._col_datap[2])
                # The event-timestamp is the time the packet was logged,
                # ctime is the time the packet was captured
                c.put('packet', {'protocol': proto, 'length': length,
                                 'ctime': timestamp})
        print('Successfully dissected file %s' % (fname, ))
    except Exception as exp:
        print('Failed with file %s\n\%s' % (fname, exp))
        raise
    finally:
        os.unlink(fname)


def _report_packet_drops(drop_count):
    print('Dropped %i packets' % (drop_count, ))


def _report_packet_count(packet_count):
    print('Captured %i packets' % (packet_count, ))


def _dump_to_tempfiles(process_pool):
    '''Capture traffic to tempfiles and submit new filenames to the queue'''
    # A random prefix for all tempfiles
    temp_prefix = tempfile.NamedTemporaryFile().name
    # Capture on all interfaces, use a ringbuffer, exclude localhost to prevent
    # an endless loop around the event collector
    cap_args = dict(interfaces=('any', ), savefile=temp_prefix,
                    ringbuffer_filesize=1 * 1024,  # one megabyte per file
                    capture_filter='host not 127.0.0.1')
    with dumpcap.CaptureSession(**cap_args) as cap:
        # Register some event handlers so we dont have to deal with those
        # events in the loop below (if we are interested at all...)
        cap.register_eventhandler(cap.SP_PACKET_COUNT, _report_packet_count)
        cap.register_eventhandler(cap.SP_DROPS, _report_packet_drops)
        # Deal with the first file-event outside the loop, so we can break
        # away in case dumpcap never sees any traffic due to some unknown
        # error condition...
        try:
            event_type, event_msg = cap.wait_for_event(timeout=10)
            # SP_FILE should always be the first event
            if event_type != cap.SP_FILE:
                raise RuntimeError('Unexpected event from dumpcap')
        except dumpcap.NoEvents:
            errmsg = ('Dumpcap did not start receiving packets for some time.'
                      ' Giving up.')
            raise RuntimeError(errmsg)
        fname = event_msg
        print('Started writing packets to %s' % (fname, ))
        # Now wait for dumpcap to finish writing to the current file
        for event_type, event_msg in iter(cap):
            if event_type == cap.SP_FILE:
                print('Switched writing to %s' % (event_msg, ))
                # Now that dumpcap has switched files, it is time to
                # dissect the previously completed file
                process_pool.apply_async(_dissect_file, (fname, ))
                fname = event_msg


def dump_dissect_and_report():
    '''Dump network traffic and report events to Cube'''
    # Create one subprocess per cpu but restart for every dissection
    pool = multiprocessing.Pool(maxtasksperchild=1)
    print('Starting to capture')
    _dump_to_tempfiles(pool)  # Start submitting work
    print('Stopped capturing, stopping dissection')
    pool.close()
    print('Waiting for dissectors')
    pool.join()
    print('All done')


if __name__ == '__main__':
    dump_dissect_and_report()
