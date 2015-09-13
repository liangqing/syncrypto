from setuptools import setup, find_packages
from codecs import open
from os import path
import syncrypto

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='syncrypto',
    version=syncrypto.__version__,
    description=syncrypto.__doc__,
    long_description=long_description,
    url='https://github.com/liangqing/syncrypto',
    author=syncrypto.__author__,
    author_email='liangqing226@gmail.com',
    license='http://www.apache.org/licenses/LICENSE-2.0',
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Communications :: File Sharing',
    ],
    packages=find_packages(),
    install_requires=['cryptography', 'lockfile'],
    package_data={
        'syncrypto': ['README.rst', 'LICENSE'],
    },
    entry_points={
        'console_scripts': [
            'syncrypto = syncrypto.__main__:main',
        ],
    },
)
