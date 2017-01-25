#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name='pyfw',
    version='0.1.4',
    description='Python Firewall',
    author='Petr Messner',
    author_email='petr.messner@gmail.com',
    classifiers=[
        'Programming Language :: Python :: 3.4',
    ],
    packages=find_packages(exclude=['doc', 'tests*']),
    install_requires=[
        'pyyaml',
    ],
    entry_points={
        'console_scripts': [
            'pyfw=pyfw:pyfw_main'
        ],
    })
