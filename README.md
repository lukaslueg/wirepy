wirepy
======

A foreign function interface to use Wireshark within Python

Documentation at http://wirepy.readthedocs.org/


Example:
```python
'''Capture traffic from all interfaces for 30 seconds and look for HTTP traffic.

Note the use of column.Type.CUSTOM in conjunction with field "http.user_agent".
The dictionary created in _show() will contain a string like
"Mozilla/5.0 (X11; Linux x86_64; rv:26.0) Gecko/20100101 Firefox/26.0" when a
HTTP request is made on the network. We get to this without ever having to really
look at any of the packets by ourselves.
'''

import pprint
from wirepy.lib import column, dfilter, dumpcap, epan, wtap, prefs

# Some required setup
epan.epan_init()
prefs.read_prefs()
epan.init_dissection()

# Some general information we are interested in for every packet
CINFO = column.ColumnInfo([column.Format(column.Type.NUMBER,
                                         title='Packet number'),
                           column.Format(column.Type.INFO, title='Info'),
                           column.Format(column.Type.PACKET_LENGTH,
                                         title='Length'),
                           column.Format(column.Type.EXPERT, title='Expert'),
                           column.Format(column.Type.PROTOCOL,
                                         title='The protocol'),
                           column.Format(column.Type.ABS_TIME,
                                         title='The time'),
                           column.Format(column.Type.UNRES_DST,
                                         title='Destination'),
                           column.Format(column.Type.CUSTOM,
                                         title='The user agent',
                                         custom_field='http.user_agent')])

# We will only be interested in http traffic
FILTER_HTTP = dfilter.DisplayFilter('http')


def _display_tree_fi(node, lvl=0):
    '''Display FieldInfo representations'''
    fi = node.field_info
    if fi is not None:
        # Skip text fields
        if fi.hfinfo.abbrev == 'text':
            return
        print((' ' * lvl) + fi.hfinfo.abbrev + ": " + fi.rep)
    # Depth-first into the protocol-tree
    if node.first_child is not None:
        _display_tree_fi(node.first_child, lvl + 1)
    if node.next is not None:
        _display_tree_fi(node.next, lvl)


def _show(wt, frame):
    '''Dissect a single frame using the wtap's current state'''
    edt = epan.Dissect()
    edt.prime_dfilter(FILTER_HTTP)
    edt.prime_cinfo(CINFO)
    edt.run(wt, frame, CINFO)
    if not FILTER_HTTP.apply_edt(edt):
        # No http traffic in the packet, throw it away
        return
    edt.fill_in_columns()
    _display_tree_fi(edt.tree)
    pprint.pprint(dict(((CINFO.titles[i],
                        epan.iface.string(CINFO._col_datap[i]))
                        for i in range(len(CINFO)))))


def _iter():
    with dumpcap.CaptureSession(interfaces=('any', ),
                                autostop_duration=30) as cap:
        try:
            event_type, event_msg = cap.wait_for_event(timeout=10)
            if event_type != cap.SP_FILE:
                # pipe out of sync
                raise RuntimeError('Unexpected event from dumpcap')
        except dumpcap.NoEvents:
            # Child did not start capturing...
            errmsg = ('Dumpcap did not start receiving packets for some time.'
                      ' Giving up.')
            raise RuntimeError(errmsg)
        # Received the first file dumpcap is writing to. Since we didnt request
        # a ringbuffer, dumpcap will write to only one file for the entire
        # session.
        fname = event_msg
        while True:
            with wtap.WTAP.open_offline(fname) as wt:
                frameiter = iter(wt)
                # Started to read from the current savefile. Now wait for
                # dumpcap to report about written packets.
                for event_type, event_msg in iter(cap):
                    if event_type == cap.SP_PACKET_COUNT:
                        # Dissect as many packets as have been written
                        for i in range(event_msg):
                            wt.clear_eof()
                            try:
                                frame = next(frameiter)
                            except StopIteration:
                                errmsg = ('Dumpcap reported new packets, but'
                                          ' the capture-file does not have'
                                          ' them.')
                                raise RuntimeError(errmsg)
                            yield wt, frame
                    elif event_type == cap.SP_FILE:
                        # A new savefile has been created, stop reading from
                        # the current file.
                        fname = event_msg
                        break
                else:
                    # The iterator on cap reaches this point if there are
                    # no more events from dumpcap - capturing has stopped,
                    # quit the loop
                    break


def read():
    for wt, frame in _iter():
        _show(wt, frame)


if __name__ == '__main__':
    read()
```
