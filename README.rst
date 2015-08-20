Sync folders in encrypted way
=============================

Introduction
------------

"syncrypto" synchronizes plaintext files within a folder to another folder which contains encrypted contents of the files.

Each plaintext file has a correspondent encrypted file in the encrypted folder.

The synchronization is bidirectional, every time you synchronize two folders(one is plaintext folder, another is encrypted folder) with "syncrypto", you will get the same result in the two folders finally.

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
the input password will be set to the encrypted folder, or it will be used to verify the password you set before.



2) Change the password

.. code-block:: bash

    syncrypto --change-password [encrypted folder]

change the password of the encrypted folder
