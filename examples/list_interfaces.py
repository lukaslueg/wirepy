'''List interfaces available to dumpcap to stdout'''
from wirepy.lib import dumpcap

for idx, iface in enumerate(dumpcap.Interface.list_interfaces()):
    print('%i: %s\t%s%s' % (idx, iface.name, iface.interface_type_string,
                            ('', '\tloopback')[iface.loopback]))
    print('\tDoes %ssupport monitor mode' % ('not ', '')[iface.can_rfmon])
    print('\tSupports %s' % (', '.join((ltype.name for ltype in
                                        iface.supported_link_layer_types))))
    print()
