# Copyright (c) 2012-2013 by Posquit0.
# All rights reserved.
try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup

from sys import version_info
import subprocess

PACKAGE_NAME = 'Expluit0'
VERSION = "0.4.2"

# Custom build steps
subprocess.call([
    "make", "-C", "expluit0/utils"
])

extra = dict()

if version_info >= (3,):
    extra['use_2to3'] = True

setup(
    name=PACKAGE_NAME,
    version=VERSION,
    author="Byungjin Park",
    author_email="posquit0.bj@gmail.com",
    maintainer="Byungjin Park",
    maintainer_email="posquit0.bj@gmail.com",
    url="https://github.com/posquit0/Expluit0",
    download_url="https://github.com/posquit0/Expluit0/zipball/{}".format(VERSION),
    description="The Exploit Framework for Your CTF",
    long_description=open('README.rst').read(),
    license="MIT",
    packages=find_packages(
        exclude=['tests', 'ez_setup', 'docs'],
    ),
    include_package_data=True,
    zip_safe=True,
    package_data={
        '': [
            '*.rst',
            '*.txt',
        ],
        'expluit0': [
            'stub/linux/x86/*.s',
            'stub/linux/x64/*.s',
            'stub/freebsd/x86/*.s',
            'stub/freebsd/x64/*.s',
            'utils/*.c',
        ]
    },
    install_requires=[
    ],
    keywords=[
        'exploit', 'ctf', 'framework',
        'posquit0', 'system', 'shellcode',
        'expluit0', 'expluito', 'shell',
    ],
    platforms=[
        'Linux', 'Unix', 'Mac OS-X'
    ],
    ext_modules=[
    ],
    **extra
)
