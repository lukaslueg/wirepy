import unittest
from wirepy.lib import column, epan

epan.epan_init()


class TestType(unittest.TestCase):

    def test_init(self):
        col = column.Type(column.Type.ABS_TIME)
        self.assertTrue(isinstance(col, column.Type))
        self.assertTrue(isinstance(col.format_desc, str))
        self.assertTrue(isinstance(col.format_string, str))

    def test_from_string(self):
        col = column.Type.from_string('%At')
        self.assertTrue(isinstance(col, column.Type))

    def test_iter(self):
        for col in column.Type.iter_column_formats():
            self.assertTrue(isinstance(col, column.Type))
            repr(col)

    def test_invalid_col(self):
        self.assertRaises(column.InvalidColumnType, column.Type, -1)
        self.assertRaises(column.InvalidColumnType, column.Type.from_string,
                          '_B0RK_')


class TestFormat(unittest.TestCase):

    def test_init(self):
        f = column.Format(title='The time', type_=column.Type.ABS_TIME,
                          custom_field='eth.src', custom_occurrence=1,
                          visible=True, resolved=True)
        self.assertEqual(f.title, 'The time')
        self.assertEqual(f.type_, column.Type.ABS_TIME)
        self.assertEqual(f.custom_field, 'eth.src')
        self.assertEqual(f.custom_occurrence, 1)
        self.assertEqual(f.visible, True)
        self.assertEqual(f.resolved, True)


class TestColumn(unittest.TestCase):

    def test_init(self):
        fmts = [column.Format(column.Type.ABS_TIME, title='The time'),
                column.Format(column.Type.UNRES_DST, title='Destination'),
                column.Format(column.Type.CUSTOM, title='Foobar',
                              custom_field='eth.src')]
        info = column.ColumnInfo(fmts)
        del fmts
        self.assertEqual(info.fmts[0], column.Type.ABS_TIME)
        self.assertEqual(info.fmts[1], column.Type.UNRES_DST)
        self.assertEqual(info.titles[0], 'The time')
        self.assertEqual(info.titles[1], 'Destination')
        self.assertEqual(info.custom_fields[2], 'eth.src')
        self.assertTrue(info.have_custom_cols)
