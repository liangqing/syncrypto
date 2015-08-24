Synchronize plaintext folder with its encrypted content
=======================================================

Introduction
------------
You can use "syncrypto" to encrypt a folder to another folder which contains the
corresponding encrypted content of the files within former.

The most common scenario is\:

.. code::

                         syncrypto                         syncrypto
  plaintext folder A  <-------------> encrypted folder B <-----------> plaintext folder C

The files in encrypted folder B are encrypted, so you can store it in any unsafe
environment, such as Cloud service(Dropbox/OneDrive), USB storage or any other
storage that you can not controlled.

Each plaintext file has a corresponding encrypted file in the encrypted folder,
so if you modify one file in plaintext folder, there will be only one file be
modified in the encrypted folder. This make sure the synchronization changes the
minimal files in encrypted folder.

The synchronization is bidirectional, every time you synchronize two folders
(one is plaintext folder, another is encrypted folder) with "syncrypto",
you will get the same result in the two folders finally.

Installation
------------

.. code:: bash

    pip install syncrypto


Usage
-----

1) Synchronization

.. code-block:: bash

    syncrypto [encrypted folder] [plaintext folder]

it will prompt you to input a password, if the encrypted folder is empty, 
the input password will be set to the encrypted folder, or it will be used
to verify the password you set before.



2) Change the password

.. code-block:: bash

    syncrypto --change-password [encrypted folder]

change the password of the encrypted folder

3) Add rule for Synchronization

If you want ignore files while synchronizing, you can add rule to do that,
such as\:

.. code-block:: bash

    syncrypto --rule "ignore: name match *.swp"

the command above ignores files which name matches *.swp

You can add rules multiple times\:

.. code-block:: bash

    syncrypto --rule "include: name eq README.md" --rule "ignore: name match *.md"

the command above ignores files matching "*.md" but include "README.md",
the rules are ordered, it means that the rules in front have high priority than
later.

4) Show the help

.. code-block:: bash

    syncrypto -h


License
-------

Apache License
