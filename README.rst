Sync folders in encrypted way
=============================

Introduction
------------

`syncrypto` synchronizes plaintext files within a folder to another folder which contains encrypted contents of the files.

Each plaintext file has a correspondence encrypted file in the encrypted folder.

The synchronization is bidirectional, every time you synchronize two folders(one is plaintext folder, another is encrypted folder) with `syncrypto`, you will get the same result in the two folders finally.

Installation
------------

.. code:: bash

    pip install syncrypto


Usage
-----

1) Synchronization

.. code-block:: bash

    syncrypto [encrypted folder] [plaintext folder]

this command will prompt you to input a password, if the encrypted folder is empty, the inputted password will set to the folder, or it will used to verify the password.



2) Change the password

.. code-block:: bash

    syncrypto --change-password [encrypted folder]

this command will change the password of the encrypted folder