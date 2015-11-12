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
    install_requires=['fastpbkdf2', 'Django>=1.4.2'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Framework :: Django',
    ],
    zip_safe=False,
    tests_require=['Django>=1.4.2'],
    test_suite='runtests.runtests',
)
