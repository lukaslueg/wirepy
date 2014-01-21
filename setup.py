import re
import setuptools
import sys
from setuptools.command.test import test as TestCommand

import wirepy.lib.wireshark
import wirepy.platform

#TODO Not really used right now


def pip_to_requirements():
    pattern = re.compile('(.*)([>=]=[.0-9]*).*')
    with open('requirements.txt') as f:
        for line in f:
            m = pattern.match(line)
            if m:
                yield '%s (%s)' % m.groups()
            else:
                yield line.strip()

with open('README', 'r') as f:
    description = f.read()


class Tox(TestCommand):

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import tox
        errno = tox.cmdline(self.test_args)
        sys.exit(errno)


setuptools.setup(name=wirepy.platform.__package_name__,
                 version=wirepy.platform.__package_name__,
                 description='A tool to do stuff',
                 long_description=description,
                 author='Myself',
                 author_email='myself@myself.com',
                 url='http://goatse.cx',
                 zip_safe=False,  # for cffi
                 requires=list(pip_to_requirements()),
                 setup_requires=['cffi>=0.6'],
                 tests_require=['tox', 'nose'],
                 packages=['wirepy', 'wirepy.lib', 'wirepy.tests'],
                 ext_package='wirepy',
                 ext_modules=[wirepy.lib.wireshark.iface.verifier.get_extension()],
                 cmdclass={'test': Tox})
