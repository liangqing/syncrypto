Synchronize a folder with its encrypted content
===============================================

.. image:: https://img.shields.io/pypi/v/syncrypto.svg
    :target: https://pypi.python.org/pypi/syncrypto/
    :alt: Latest Version

.. image:: https://travis-ci.org/liangqing/syncrypto.svg?branch=master
    :target: https://travis-ci.org/liangqing/syncrypto

.. image:: https://codecov.io/github/liangqing/syncrypto/coverage.svg?branch=master
    :target: https://codecov.io/github/liangqing/syncrypto?branch=master

Introduction
============
You can use ``syncrypto`` to encrypt a folder to another folder which contains the
corresponding encrypted content.

The most common scenario is\:

.. code-block::

                         syncrypto                         syncrypto
  plaintext folder A  <-------------> encrypted folder B <-----------> plaintext folder C

The files in encrypted folder B are encrypted, so you can store it in any unsafe
environment, such as cloud service(Dropbox/OneDrive), USB storage or any other
storage that you can not control.

Each plaintext file has a corresponding encrypted file in the encrypted folder,
so if you modify one file in plaintext folder, there will be only one file
modified in the encrypted folder. This make sure the synchronization only changes
the necessary content in encrypted folder, and is very useful for file based
cloud storage service to synchronizing minimal contents.

The synchronization is bidirectional, every time you synchronize two folders
(one is plaintext folder, another is encrypted folder) with ``syncrypto``,
you will get the same result in the two folders eventually.

Installation
============

``syncrypto`` supports both python 2 and python 3, and is tested_ in:

.. _tested: https://travis-ci.org/liangqing/syncrypto

* python 2.6
* python 2.7
* python 3.3
* python 3.4

you can install it only by:

.. code-block:: bash

    pip install syncrypto


Usage
=====

Synchronization
---------------

.. code-block:: bash

    syncrypto [encrypted folder] [plaintext folder]

it will prompt you to input a password, if the encrypted folder is empty, 
the input password will be set to the encrypted folder, or it will be used
to verify the password you set before.

Notice that the first argument is encrypted folder, and the second one is
plaintext folder


Add rule for Synchronization
----------------------------

If you want ignore files while synchronizing, you can add rule to do that,
such as\:

.. code-block:: bash

    syncrypto --rule "ignore: name match *.swp"

the command above ignores files which name matches \*.swp

You can add rules multiple times\:

.. code-block:: bash

    syncrypto --rule "include: name eq README.md" --rule "ignore: name match *.md"

the command above ignores files matching "\*.md" but includes files named "README.md".

The rules are ordered, it means that the rules in front have higher priority than
later, if a rule matches, the matching process will returned immediately.

You can add rules in a file looks like\:

.. code-block::

    include: name eq README.md

    # ignore all markdown files, this is a comment
    ignore: name match *.md

and use the rules by "--rule-file" option:

.. code-block:: bash

    syncrypto --rule-file [rule file path]

the default rule file path is "[plaintext folder]/.syncrypto/rules", so you can
add rules in "[plaintext folder]/.syncrypto/rules", and don't need specify the
"--rule-file" option explicitly.

If you give some rules in command line, and write some rules in rule file at
the same time, the rules in command line will have higher priority than rules
in file.


Change the password
-------------------

.. code-block:: bash

    syncrypto --change-password [encrypted folder]

change the password of the encrypted folder


Show the help
-------------

.. code-block:: bash

    syncrypto -h


License
=======

Apache License 2.0
