from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='syncrypto',
    version='0.0.1',
    description='Sync folders in encrypted way',
    long_description=long_description,
    url='https://github.com/liangqing/syncrypto',
    author='liangqing',
    author_email='liangqing226@gmail.com',
    license='http://www.apache.org/licenses/LICENSE-2.0',
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Communications :: File Sharing',
    ],
    packages=find_packages(),
    install_requires=['pycrypto'],
    package_data={
        'syncrypto': ['README.rst', 'LICENSE'],
    },
    entry_points={
        'console_scripts': [
            'syncrypto = syncrypto.__main__:main',
        ],
    },
)
