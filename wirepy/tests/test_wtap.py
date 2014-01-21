import os
import unittest
import tempfile
from wirepy.lib import wtap


class TestFunctions(unittest.TestCase):

    def test_iter_ftypes(self):
        for ftype in wtap.iter_file_types():
            self.assertTrue(isinstance(ftype, wtap.FileType))
            self.assertTrue(isinstance(repr(ftype), str))

    def test_iter_etypes(self):
        for encap in wtap.iter_encapsulation_types():
            self.assertTrue(isinstance(encap, wtap.EncapsulationType))
            self.assertTrue(isinstance(repr(encap), str))


class TestFileType(unittest.TestCase):

    def test_unknown(self):
        ft = wtap.FileType.from_short_string(None)
        self.assertEqual(ft.string, None)
        self.assertEqual(ft.short_string, None)
        self.assertEqual(ft.ft, 0)

    def test_new(self):
        ftype = wtap.FileType.from_short_string('pcap')
        self.assertTrue(isinstance(ftype, wtap.FileType))
        self.assertEqual(ftype.short_string, 'pcap')
        self.assertTrue(isinstance(ftype.string, str))
        self.assertEqual(ftype.default_file_extension, 'pcap')
        self.assertTrue(ftype.dump_can_open or True)
        self.assertTrue(ftype.dump_can_compress or True)

    def test_invalid(self):
        self.assertRaises(wtap.InvalidFileType, wtap.FileType, -1)
        self.assertRaises(wtap.InvalidFileType,
                          wtap.FileType.from_short_string, '_B0RK_')

    def test_file_extension(self):
        ftype = wtap.FileType.from_short_string('libpcap')
        extensions = ftype.file_extensions
        self.assertTrue(all((isinstance(e, str) for e in extensions)))
        self.assertGreater(len(extensions), 0)
        self.assertTrue('cap' in extensions)


class TestEncapsulationType(unittest.TestCase):

    def test_new(self):
        encap = wtap.EncapsulationType.from_short_string('ether')
        self.assertTrue(isinstance(encap, wtap.EncapsulationType))
        self.assertEqual(encap.short_string, 'ether')
        self.assertTrue(isinstance(encap.string, str))

    def test_invalid(self):
        self.assertRaises(wtap.InvalidEncapsulationType,
                          wtap.EncapsulationType, -2)
        self.assertRaises(wtap.InvalidEncapsulationType,
                          wtap.EncapsulationType.from_short_string, '_B0RK_')


class TestWTAP(unittest.TestCase):
    testpath = os.path.dirname(os.path.abspath(__file__))
    testfile = os.path.join(testpath, 'sample_files/http.cap.gz')

    def test_open_not_existing_file(self):
        self.assertRaises(OSError, wtap.WTAP.open_offline, '_B0RK_')

    def test_open_truncated_file(self):
        with tempfile.NamedTemporaryFile() as tfile:
            tfile.write('_B0RK_'.encode())
            tfile.flush()
            self.assertRaises(wtap.UnknownFormat, wtap.WTAP.open_offline,
                              tfile.name)

    def test_open_offline(self):
        with wtap.WTAP.open_offline(self.testfile) as w:
            self.assertTrue(isinstance(w, wtap.WTAP))
            self.assertTrue(w.is_compressed)
            self.assertEqual(w.file_type.short_string, 'pcap')
            self.assertEqual(w.file_encap.short_string, 'ether')
            self.assertEqual(w.tsprecision, w.FILE_TSPREC_USEC)
            self.assertGreater(w.read_so_far, 0)
            self.assertGreater(w.file_size, 0)

    def test_iter(self):
        with wtap.WTAP.open_offline(self.testfile) as w:
            frame = next(iter(w))
            self.assertTrue(isinstance(frame, wtap.Frame))
            self.assertTrue(isinstance(frame.link_type,
                                       wtap.EncapsulationType))

    def test_read(self):
        with wtap.WTAP.open_offline(self.testfile) as w:
            res, data_offset = w.read()
            header = w.packetheader
            self.assertTrue(isinstance(header, wtap.PacketHeader))
            self.assertTrue(header.is_flag_set(header.HAS_TS))
            self.assertTrue(header.is_flag_set(header.HAS_CAP_LEN))
            self.assertGreater(header.caplen, 0)
            self.assertGreater(header.len, 0)
