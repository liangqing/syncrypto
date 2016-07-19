Two-way synchronization between a folder and its ciphertext
===========================================================

.. image:: https://img.shields.io/pypi/v/syncrypto.svg
    :target: https://pypi.python.org/pypi/syncrypto/
    :alt: Latest Version

.. image:: https://travis-ci.org/liangqing/syncrypto.svg?branch=master
    :target: https://travis-ci.org/liangqing/syncrypto
    :alt: Build And Test Status

.. image:: https://codecov.io/github/liangqing/syncrypto/coverage.svg?branch=master
    :target: https://codecov.io/github/liangqing/syncrypto?branch=master
    :alt: Code Coverage

.. image:: https://landscape.io/github/liangqing/syncrypto/master/landscape.svg?style=flat
   :target: https://landscape.io/github/liangqing/syncrypto/master
   :alt: Code Health

Introduction
============
You can use ``syncrypto`` to encrypt a folder to another folder which contains the
corresponding encrypted content.

The most common scenario is\:

.. code-block:: text

                         syncrypto                         syncrypto
  plaintext folder A  <-------------> encrypted folder B <-----------> plaintext folder C
    in machine X                       in cloud storage                 in machine Y

The files in encrypted folder B are encrypted, so you can store it in any unsafe
environment, such as cloud service(Dropbox/OneDrive), USB storage or any other
storage that you can not control.

Each plaintext file has a corresponding encrypted file in the encrypted folder,
so if you modify one file in plaintext folder, there will be only one file
modified in the encrypted folder after synchronization. This make sure the
synchronization only changes the necessary content in encrypted folder, and is
very useful for file based cloud storage service to synchronizing minimal contents.

**The synchronization is two-way**, files not only syncing from plain text folder to
encrypted folder, but also syncing from encrypted folder to plain text folder.
``syncrypto`` will choose the newest file.

If conflict happens, ``syncrypto`` will rename the plaintext file(add 'conflict'
word in it), and sync the encrypted file.

``syncrypto`` never delete files, if files or folders should be deleted or over
written by the syncing algorithm, ``syncrypto`` just move the files or folders
to the trash, the trash in encrypted folder located at _syncrypto/trash,
at .syncrypto/trash in plaintext folder. Files in encrypted folder's trash are
also encrypted. You can delete any files in trash in any time if you make sure
the files in it are useless.


Installation
============

Support Platform
----------------

``syncrypto`` supports both python 2 and python 3, and is tested_ in\:

.. _tested: https://travis-ci.org/liangqing/syncrypto

* python 2.6
* python 2.7
* python 3.3
* python 3.4
* python 3.5

And support Linux, OS X, Windows operating systems

Install Dependencies
--------------------

**If you are using windows, just jump to next**

Because ``syncrypto`` rely on cryptography_ , so need to install some
dependencies before install ``syncrypto``\:

.. _cryptography: https://github.com/pyca/cryptography

For Debian and Ubuntu, the following command will ensure that the required
dependencies are installed\:

.. code-block::

    sudo apt-get install build-essential libssl-dev libffi-dev python-dev


For Fedora and RHEL-derivatives, the following command will ensure that the
required dependencies are installed\:

.. code-block::

    sudo yum install gcc libffi-devel python-devel openssl-devel

For OS X, run\:

.. code-block::

    xcode-select --install


Install And Update By pip
-------------------------

After installing all dependencies, you can install ``syncrypto`` by pip_ \:

.. _pip: https://pip.pypa.io/en/latest/installing.html

.. code-block::

    pip install syncrypto

or update by\:

.. code-block::

    pip install -U syncrypto

Usage
=====

Synchronization
---------------

.. code-block::

    syncrypto [encrypted folder] [plaintext folder]

It will prompt you to input a password, if the encrypted folder is empty,
the input password will be set to the encrypted folder, or it will be used
to verify the password you set before (take it easy, ``syncrypto`` never store
plaintext password)

If you don't want input password in interactive mode, you can use --password-file
option\:

.. code-block::

    syncrypto [encrypted folder] [plaintext folder] --password-file [password file path]

The password file contains the password in it.

Notice that the first argument is encrypted folder, and the second one is
plaintext folder.


Add rule for Synchronization
----------------------------

Sometimes, it is unnecessary to encrypt and sync some files
(for example, some temporary files),
if you want ignore these files, you can add rule\:

.. code-block::

    syncrypto [encrypted folder] [plaintext folder] --rule 'ignore: name match *.swp'

the command above ignores files which name matches \*.swp

You can add rules multiple times\:

.. code-block::

    syncrypto [encrypted folder] [plaintext folder] --rule 'include: name eq README.md' --rule 'ignore: name match *.md'

the command above ignores files matching "\*.md" but includes files named "README.md".

The rules are ordered, it means that the rules in front have higher priority than
later, if a rule matches, the matching process will returned immediately.

You can add rules in a file looks like\:

.. code-block::

    include: name eq README.md

    # ignore all markdown files, this is a comment
    ignore: name match *.md

and use the rules by "--rule-file" option\:

.. code-block::

    syncrypto [encrypted folder] [plaintext folder] --rule-file [rule file path]

the default rule file path is "[plaintext folder]/.syncrypto/rules", so you can
add rules in "[plaintext folder]/.syncrypto/rules", and don't need specify the
"--rule-file" option explicitly.

If you give some rules in command line, and write some rules in rule file at
the same time, the rules in command line will have higher priority than rules
in file.

The format of a rule\:

.. code-block::

    [action]: [file attribute] [operand] [value]

``action`` can be ``include``, ``exclude``, ``ignore``

``include`` means the file matching the rule will syncing, ``exclude`` means the
file matching the rule will not syncing.

``ignore`` equals ``exclude``.

``syncrypto`` supports a lot of file attributes while matching rules, the complete
list is\:

* ``name``, the name of the file, include file extension.
* ``path``, the relative path from the root of the plaintext folder.
* ``size``, the size of the file
* ``ctime``, the change time of the file, (in windows, it is creation time)
* ``mtime``, the modification time of the file

operands\:

* ``eq``, ``==``
* ``gt``, ``>``
* ``lt``, ``<``
* ``gte``, ``>=``
* ``lte``, ``<=``
* ``ne``, ``!=``, ``<>``
* ``match``, match by glob, for example, "\*.md" matches all files end with "md"
* ``regexp``, perform a regular expression match

The unit of value in ``size`` rules are "byte" by default, you can also use
"K", "M" "G", for example specify the value "2K" means 2048 bytes

The format of value in ``ctime``, ``mtime`` is "%Y-%m-%d %H:%M:%S"

Encrypt a file
--------------

.. code-block::

    syncrypto --encrypt-file [plaintext file path]

This command will encrypt the plaintext file to its parent folder with the filename
add a "encrypted" word

You can also specify the target encrypted file by --out-file option, such as\:

.. code-block::

    syncrypto --encrypt-file [plaintext file path] --out-file [encrypted file path]

Decrypt a file
--------------

.. code-block::

    syncrypto --decrypt-file [encrypted file path]

This command will decrypt the encrypted file to **current working directory**

You can also specify the target plaintext file by --out-file option, such as\:

.. code-block::

    syncrypto --decrypt-file [encrypted file path] --out-file [plaintext file path]


Change the password
-------------------

.. code-block::

    syncrypto --change-password [encrypted folder]

Change the password of the encrypted folder, this will re-encrypt all files within
the encrypted folder


Show the help
-------------

.. code-block::

    syncrypto -h


License
=======

Apache License, Version 2.0
