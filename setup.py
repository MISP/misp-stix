#!/usr/bin/env python
# -*- coding: utf-8 -*-
from os import path
from setuptools import setup
import misp_stix_converter

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), 'r') as f:
    long_description = f.read()

setup(
    name='misp_stix_converter',
    version=misp_stix_converter.__version__,
    author='Christian Studer',
    author_email='christian.studer@circl.lu',
    maintainer='Christian Studer',
    url='https://github.com/chrisr3d/misp-stix-converter',
    project_urls={
        'Documentation': 'https://github.com/chrisr3d/misp-stix-converter/documentation',
        'Source': 'https://github.com/chrisr3d/misp-stix-converter',
        'Tracker': 'https://github.com/chrisr3d/misp-stix-converter/issues'
    },
    description='Python scripts to convert MISP into STIX or STIX into MISP',
    long_description=long_description,
    long_description_content_type='text/markdown',
    python_requires='>=3.6',
    packages=['misp_stix_converter'],
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security',
        'Topic :: Internet',
    ],
    install_requires=['pymisp', 'stix']
)
