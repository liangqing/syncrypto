#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2015 Qing Liang (https://github.com/liangqing)
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

from __future__ import print_function
from __future__ import unicode_literals
from io import open
import unittest
import os
import os.path
import shutil
from tempfile import mkdtemp
from syncrypto import FileTree, Crypto, Syncrypto, InvalidFolder
from filecmp import dircmp
from syncrypto.crypto import DecryptError
from util import clear_folder, prepare_filetree

try:
    from cStringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO


class SyncTestCase(unittest.TestCase):

    def setUp(self):
        self.crypto = Crypto('password')
        self.plain_folder = mkdtemp()
        self.plain_folder_check = mkdtemp()
        self.encrypted_folder = mkdtemp()
        prepare_filetree(self.plain_folder, '''
            sync_file_modify:hello world
            sync_file_delete:delete
            sync/file/modify:hello world
            empty_dir_delete/
            not_empty_dir/dir2/dir3/file
            dir2/file2
        ''')
        self.plain_tree = self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.plain_tree_check = FileTree()
        self.encrypted_tree = FileTree()
        self.snapshot_tree = FileTree()

    def tearDown(self):
        shutil.rmtree(self.plain_folder)
        shutil.rmtree(self.plain_folder_check)
        shutil.rmtree(self.encrypted_folder)

    def isPass(self):
        sync = Syncrypto(self.crypto, self.encrypted_folder, self.plain_folder,
                         self.encrypted_tree, self.plain_tree)
        sync2 = Syncrypto(self.crypto, self.encrypted_folder,
                          self.plain_folder_check,
                          self.encrypted_tree, self.plain_tree_check)
        sync.sync_folder()
        sync2.sync_folder()
        directory_cmp = dircmp(self.plain_folder, self.plain_folder_check)
        self.assertEqual(len(directory_cmp.left_only), 0)
        self.assertEqual(len(directory_cmp.right_only), 0)
        self.assertEqual(len(directory_cmp.diff_files), 0)

    def test_init(self):
        self.isPass()

    def pass_invalid_encrypted_folder(self):
        invalid_folder = self.encrypted_folder+os.path.sep+"invalid_folder"
        with open(invalid_folder, 'wb') as f:
            f.write(b'Test')
        Syncrypto(self.crypto, invalid_folder, self.plain_folder)
        os.remove(invalid_folder)

    def pass_invalid_plaintext_folder(self):
        invalid_folder = self.plain_folder+os.path.sep+"invalid_folder"
        with open(invalid_folder, 'wb') as f:
            f.write(b'Test')
        Syncrypto(self.crypto, self.encrypted_folder, invalid_folder)
        os.remove(invalid_folder)

    def test_false_directory(self):
        self.assertRaises(InvalidFolder, self.pass_invalid_encrypted_folder)
        self.assertRaises(InvalidFolder, self.pass_invalid_plaintext_folder)

    def test_add_file(self):
        path = self.plain_folder + os.path.sep + "add_file"
        fp = open(path, "wb")
        fp.write(b"hello world")
        fp.close()
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.isPass()

    def test_add_file_and_modify(self):
        path = self.plain_folder + os.path.sep + "add_file_and_modify"
        fp = open(path, "wb")
        fp.write(b"hello world")
        fp.close()
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.isPass()

        path = self.plain_folder + os.path.sep + "add_file_and_modify"
        fp = open(path, "wb")
        fp.write(b"hello world again")
        fp.close()
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.plain_tree.get("add_file_and_modify").mtime += 1
        self.isPass()

    def test_modify_file(self):
        path = self.plain_tree.get("sync_file_modify").fs_path(
            self.plain_folder)
        fp = open(path, "wb")
        fp.write(b"hello world again")
        fp.close()
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.plain_tree.get("sync_file_modify").mtime += 1
        self.isPass()

    def test_modify_file_in_folder(self):
        path = self.plain_tree.get("sync/file/modify").fs_path(
            self.plain_folder)
        fp = open(path, "wb")
        fp.write(b"hello world again")
        fp.close()
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.plain_tree.get("sync/file/modify").mtime += 1
        self.isPass()

    def test_delete_file(self):
        path = self.plain_tree.get("sync_file_delete").fs_path(
            self.plain_folder)
        os.remove(path)
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.isPass()

    def test_delete_empty_folder(self):
        path = self.plain_tree.get("empty_dir_delete").fs_path(
            self.plain_folder)
        shutil.rmtree(path)
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.isPass()

    def test_delete_non_empty_folder(self):
        path = self.plain_tree.get("not_empty_dir").fs_path(self.plain_folder)
        shutil.rmtree(path)
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.isPass()

    def test_change_password(self):
        sync = Syncrypto(self.crypto, self.encrypted_folder, self.plain_folder,
                         self.encrypted_tree, self.plain_tree,
                         self.snapshot_tree)
        sync.sync_folder()
        oldpass = self.crypto.password
        newpass = "new password"
        sync.change_password(newpass)
        self.crypto.password = oldpass
        self.assertRaises(DecryptError, sync._load_encrypted_tree)
        self.crypto.password = newpass.encode("ascii")
        sync.sync_folder()


if __name__ == '__main__':
    unittest.main()
