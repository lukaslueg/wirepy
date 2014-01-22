'''Print all known protocols to stdout, just like ``tshark -G protocols``'''
import wirepy.lib.epan

wirepy.lib.epan.epan_init()

for proto in wirepy.lib.epan.iter_protocols():
    print('%s\t%s\t%s' % (proto.name, proto.short_name, proto.filter_name))
