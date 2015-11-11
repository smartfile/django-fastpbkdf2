#!/usr/bin/env python
from setuptools import setup

description = 'Django password hasher using a fast PBKDF2 implementation written in C (fastpbkdf2)'
try:
   import pypandoc
   long_description = pypandoc.convert('README.md', 'rst')
except (IOError, ImportError):
   long_description = ''

setup (
    name='django-fastpbkdf2',
    version = '0.0.1',
    description=description,
    long_description=long_description,
    author='SmartFile',
    author_email='tech@smartfile.com',
    maintainer='Travis Cunningham',
    maintainer_email='tcunningham@smartfile.com',
    url='http://github.com/smartfile/django-fastpbkdf2',
    license='BSD',
    packages=['django_fastpbkdf2'],
    install_requires=['fastpbkdf2'],
)
