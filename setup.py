from setuptools import setup, find_packages
import sys.version_info

VERSION = "0.4.1"

extra = dict()

if sys.version_info >= (3,):
    extra['use_2to3'] = True

setup(
    name="Expluit0",
    version=VERSION,
    author="Byungjin Park",
    author_email="posquit0.bj@gmail.com",
    url="https://github.com/posquit0/Expluit0",
    download_url="https://github.com/posquit0/Expluit0/zipball/{}".format(VERSION),
    description="The Exploit Framework for Your CTF",
    long_description=open('README.rst').read(),
    license="BSD",
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
        ]
    },
    install_requires=[
    ],
    keywords=[
        'exploit', 'ctf', 'framework',
        'posquit0', 'system', 'shellcode',
        'expluit0', 'expluito', 'shell',
    ],
    **extra
)
