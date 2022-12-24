"""Setup Script"""

from __future__ import absolute_import
from setuptools import setup


VERSION = '1.0.0'

setup(
    name='pyxamstore',
    version=VERSION,
    description='Xamarin AssemblyStore Explorer (pyxamstore)',

    download_url='https://github.com/jakev/pyxamstore',

    author='Jake Valletta',
    author_email='javallet@gmail.com',

    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7'],

    keywords='android device security mobile reverse-engineering Xamarin AssemblyStore',

    packages=["pyxamstore"],

    install_requires=open("requirements.txt", "rb").read().decode("utf-8").split("\n"),

    entry_points={
        'console_scripts': [
            'pyxamstore = pyxamstore.explorer:main',
        ],
    },
)
