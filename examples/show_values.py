'''Show known field-values, somewhat like ``tshark -G values``'''
from wirepy.lib import epan

epan.epan_init()

for field in epan.iter_fields():
    print(repr(field))
    for value in field:
        print(' ' + repr(value))
