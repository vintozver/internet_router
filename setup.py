#!/usr/bin/env python

from setuptools import setup

setup(
    name='internet_router',
    version='1.0',
    description='IPv4/IPv6 internet router for a small home network with a minimum of configuration required',
    author='Vitaly Greck',
    author_email='vintozver@ya.ru',
    url='https://www.python.org/sigs/distutils-sig/',
    packages=['internet_router'],
    install_requires=[
        'pyroute2',
    ],
    entry_points={
        'console_scripts': [
            'internet_router=internet_router.run:main',
            'internet_router_dhcp_script=internet_router.run:dhcp_script',
        ],
    },
)
