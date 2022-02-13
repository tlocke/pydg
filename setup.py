#!/usr/bin/env python

from setuptools import setup

import versioneer

long_description = """

Pydg
----
Pydg is a pure-Python EdgeDB client. It is tested on Python versions 3.6+, on
CPython and PyPy, and EdgeDB versions 1.0+. Pydg is distributed under the
MIT Licence.
"""

cmdclass = dict(versioneer.get_cmdclass())
version = versioneer.get_version()

setup(
    name="pydg",
    version=version,
    cmdclass=cmdclass,
    description="EdgeDB client library",
    long_description=long_description,
    author="The Contributors",
    url="https://github.com/tlocke/pg8000",
    license="MIT",
    python_requires=">=3.6",
    install_requires=["scramp>=1.4.1"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: Implementation",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: Jython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Operating System :: OS Independent",
        "Topic :: Database :: Front-Ends",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="EdgeDb client driver",
    packages=("pydg",),
)
