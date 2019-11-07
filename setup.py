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
        'pyroute2', 'jinja2', 'python-iptables'
    ],
    entry_points={
        'console_scripts': [
            'internet_router=internet_router.run:service',
            'internet_router_dhclient4_script=internet_router.script:dhclient4',
            'internet_router_dhclient6_script=internet_router.script:dhclient6',
            'internet_router_pppd_script=internet_router.script:pppd',
        ],
    },
)
