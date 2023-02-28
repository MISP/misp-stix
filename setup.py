#!/usr/bin/env python
# -*- coding: utf-8 -*-
from os import path
from setuptools import setup
import misp_stix_converter

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), 'r') as f:
    long_description = f.read()

setup(
    name='misp-stix',
    version=misp_stix_converter.__version__,
    author='Christian Studer',
    author_email='christian.studer@circl.lu',
    maintainer='Christian Studer',
    url='https://github.com/MISP/misp-stix',
    project_urls={
        'Documentation': 'https://github.com/MISP/misp-stix/documentation',
        'Source': 'https://github.com/MISP/misp-stix',
        'Tracker': 'https://github.com/MISP/misp-stix/issues'
    },
    description='Python scripts to convert MISP into STIX or STIX into MISP',
    long_description=long_description,
    long_description_content_type='text/markdown',
    python_requires='>=3.8',
    packages=['misp_stix_converter'],
    entry_points={"console_scripts": ["misp_stix_converter = misp_stix_converter:main"]},
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: Internet',
    ],
    install_requires=['pymisp', 'stix', 'misp-lib-stix2'],
    tests_require=['pytest', 'flake8'],
    include_package_data=True,
    package_data={'misp_stix_converter': ['data/cti', 'data/misp-galaxy']}
)
