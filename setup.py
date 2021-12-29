#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


long_description = (
    open('README.md').read()
)

version = '1.0.3'


setup(
    name='django-encrypted-field',
    description=(
        'This is a Django Model Field class that can be '
        'encrypted using ChaCha20 poly 1305, and other algorithms.'
    ),
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/patowc/django-encrypted-field',
    license='MIT',
    author='Román Ramírez',
    author_email='rramirez@rootedcon.com',
    packages=find_packages(),
    version=version,
    install_requires=[
        'Django>=4.0',
        'pycryptodomex>=3.12.0'
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Framework :: Django',
    ],
    zip_safe=False,
)
