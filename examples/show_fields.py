'''Print known fields to stdout, somewhat like ``tshark -G fields``'''
import wirepy.lib.epan

wirepy.lib.epan.epan_init()

for field in wirepy.lib.epan.iter_fields():
    print('%s\t%s\t%s' % (field.name, field.abbrev, field.blurb))
