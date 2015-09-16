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
import sys
import os
import os.path
import shutil
from tempfile import mkdtemp, mkstemp
from filecmp import cmp as file_cmp
from syncrypto import cli as syncrypto_cli_raw
from time import time
from subprocess import Popen, PIPE
import pexpect
from util import clear_folder, prepare_filetree, tree_cmp

try:
    from cStringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO


FS_ENCODING = sys.getfilesystemencoding()
py3 = sys.version_info[0] == 3
py2 = sys.version_info[0] == 2
py2_6 = (sys.version_info[0] == 2 and sys.version_info[1] == 6)
is_win = (os.name == "nt")


def syncrypto_cli(args):
    if py3:
        return syncrypto_cli_raw(args)
    args = [arg.encode(FS_ENCODING) for arg in args]
    return syncrypto_cli_raw(args)


class CliTestCase(unittest.TestCase):

    def setUp(self):
        self.plain_folder = mkdtemp()
        self.plain_folder_check = mkdtemp()
        self.encrypted_folder = mkdtemp()
        fd, self.password_file = mkstemp()
        os.write(fd, b"password test")
        os.close(fd)

    def tearDown(self):
        shutil.rmtree(self.plain_folder)
        shutil.rmtree(self.plain_folder_check)
        shutil.rmtree(self.encrypted_folder)
        os.remove(self.password_file)

    def tree_cmp(self, folder1, folder2):
        return tree_cmp(folder1, folder2, ignores=[".syncrypto"])

    def check_result(self):
        cmp_result = self.tree_cmp(self.plain_folder, self.plain_folder_check)
        self.assertEqual(cmp_result.left_only, [])
        self.assertEqual(cmp_result.right_only, [])
        self.assertEqual(cmp_result.diff_files, [])

    def cli(self, args):
        self.assertEqual(syncrypto_cli(args), 0)

    def pipe(self, args):
        os.chdir(os.path.dirname(os.path.dirname(__file__)))
        if py2_6:
            args = ["python", "-m", "syncrypto"] + args
        else:
            args = ["python", "-m", "syncrypto.__main__"] + args
        return Popen(args, stdout=PIPE, stdin=PIPE, stderr=PIPE)

    def pexpect(self, args):
        os.chdir(os.path.dirname(os.path.dirname(__file__)))
        args = ["python", "-m", "syncrypto"] + args
        return pexpect.spawn(" ".join(args))

    def check_result_after_sync(self):
        self.cli(["--password-file", self.password_file, self.encrypted_folder,
                  self.plain_folder])
        self.cli(["--password-file", self.password_file, self.encrypted_folder,
                  self.plain_folder_check])
        self.check_result()

    def check_result_after_sync_from_check_folder(self):
        self.cli(["--password-file", self.password_file, self.encrypted_folder,
                  self.plain_folder_check])
        self.cli(["--password-file", self.password_file, self.encrypted_folder,
                  self.plain_folder])
        self.check_result()

    def clear_folders(self):
        clear_folder(self.plain_folder)
        clear_folder(self.plain_folder_check)
        clear_folder(self.encrypted_folder)

    def norm_path(self, folder, pathname):
        return folder+os.path.sep+pathname.replace("/", os.path.sep)

    def modify_file(self, folder, pathname, content):
        path = self.norm_path(folder, pathname)
        fd = open(path, 'wb')
        fd.write(content.encode("utf-8"))
        fd.close()
        os.utime(path, (time(), time()+1))

    def add_file(self, folder, pathname, content):
        path = self.norm_path(folder, pathname)
        fd = open(path, 'wb')
        fd.write(content.encode("utf-8"))
        fd.close()

    def add_folder(self, folder, pathname):
        os.makedirs(self.norm_path(folder, pathname))

    def delete_file(self, folder, pathname):
        os.remove(self.norm_path(folder, pathname))

    def delete_folder(self, folder, pathname):
        shutil.rmtree(self.norm_path(folder, pathname))

    def rename(self, folder, pathname, pathname2):
        os.rename(self.norm_path(folder, pathname),
                  self.norm_path(folder, pathname2))

    def test_invalid_password(self):
        self.cli(["--password-file", self.password_file, self.encrypted_folder,
                  self.plain_folder])
        fd, path = mkstemp()
        os.write(fd, b"wrong password")
        os.close(fd)
        self.assertEqual(syncrypto_cli(["--password-file", path,
                                        self.encrypted_folder,
                                        self.plain_folder]), 3)

    def test_interactive_input_password(self):
        if is_win:
            return
        self.cli(["--password-file", self.password_file, self.encrypted_folder,
                  self.plain_folder])
        child = self.pexpect([self.encrypted_folder, self.plain_folder])
        child.expect("password:")
        child.sendline("password test")
        child.expect(pexpect.EOF)
        child.close()
        self.assertEqual(child.exitstatus, 0)

    def test_interactive_invalid_password(self):
        if is_win:
            return
        self.cli(["--password-file", self.password_file, self.encrypted_folder,
                  self.plain_folder])
        child = self.pexpect([self.encrypted_folder, self.plain_folder])
        child.expect("password:")
        child.sendline("wrong password")
        child.expect(pexpect.EOF)
        child.close()
        self.assertEqual(child.exitstatus, 3)

    def test_basic_sync(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            simple_file: hello world
            file/in/sub/folder: hello world
            empty_dir/
        ''')
        self.check_result_after_sync()

    def test_basic_sync_multiple_times(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            simple_file: hello world
            file/in/sub/folder: hello world
            empty_dir/
        ''')
        self.check_result_after_sync()
        self.check_result_after_sync()
        self.check_result_after_sync_from_check_folder()
        self.check_result_after_sync()
        self.check_result_after_sync_from_check_folder()
        self.check_result_after_sync_from_check_folder()
        self.check_result_after_sync()

    def test_modify_file(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            keep_same: same file
            will_modify: modify the file please
            file/in/sub/folder/will_modify: modify the file please!
            empty_dir/
        ''')
        self.check_result_after_sync()
        self.modify_file(self.plain_folder, "will_modify", "it is modified")
        self.modify_file(self.plain_folder, "file/in/sub/folder/will_modify",
                         "it is modified")
        self.check_result_after_sync()

    def test_modify_file_in_check_folder(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            keep_same: same file
            will_modify: modify the file please
            file/in/sub/folder/will_modify: modify the file please!
            empty_dir/
        ''')
        self.check_result_after_sync()
        self.modify_file(self.plain_folder_check,
                         "will_modify", "it is modified")
        self.modify_file(self.plain_folder_check,
                         "file/in/sub/folder/will_modify", "it is modified")
        self.check_result_after_sync_from_check_folder()

    def test_rename_file(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            keep_same: same file
            will_rename: rename
            will_rename2: rename
            file/in/sub/folder/will_rename: rename
            empty_dir/
        ''')
        self.check_result_after_sync()
        self.rename(self.plain_folder, "will_rename", "renamed")
        self.rename(self.plain_folder, "file/in/sub/folder/will_rename",
                    "renamed2")
        self.rename(self.plain_folder, "will_rename2",
                    "file/in/sub/folder/renamed2")
        self.check_result_after_sync()

    def test_rename_file_in_check_folder(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            keep_same: same file
            will_rename: rename
            will_rename2: rename
            file/in/sub/folder/will_rename: rename
            empty_dir/
        ''')
        self.check_result_after_sync()
        self.rename(self.plain_folder_check, "will_rename", "renamed")
        self.rename(self.plain_folder_check, "file/in/sub/folder/will_rename",
                    "renamed2")
        self.rename(self.plain_folder_check, "will_rename2",
                    "file/in/sub/folder/renamed2")
        self.check_result_after_sync_from_check_folder()

    def test_add_file(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            simple_file: simple file
            file/in/sub/folder/simple_file: file in the folder!
            empty_dir/
        ''')
        self.check_result_after_sync()
        self.add_file(self.plain_folder, "add_file", "add file")
        self.add_file(self.plain_folder, "file/in/sub/folder/add_file",
                      "add file!")
        self.check_result_after_sync()

    def test_add_file_in_check_folder(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            simple_file: simple file
            file/in/sub/folder/simple_file: file in the folder!
            empty_dir/
        ''')
        self.check_result_after_sync()
        self.add_file(self.plain_folder_check, "add_file", "add file")
        self.add_file(self.plain_folder_check, "file/in/sub/folder/add_file",
                      "add file!")
        self.check_result_after_sync_from_check_folder()

    def test_add_folder(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            simple_file: simple file
            file/in/sub/folder/simple_file: file in the folder!
            empty_dir/
        ''')
        self.check_result_after_sync()
        self.add_folder(self.plain_folder, "empty_dir/add_folder")
        self.add_folder(self.plain_folder, "folder/with/file")
        self.add_file(self.plain_folder, "folder/with/file/test", "test\ntest!")
        self.check_result_after_sync()

    def test_add_folder_in_check_folder(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            simple_file: simple file
            file/in/sub/folder/simple_file: file in the folder!
            empty_dir/
        ''')
        self.check_result_after_sync()
        self.add_folder(self.plain_folder_check, "empty_dir/add_folder")
        self.add_folder(self.plain_folder_check, "folder/with/file")
        self.add_file(self.plain_folder_check, "folder/with/file/test",
                      "test\ntest!")
        self.check_result_after_sync_from_check_folder()

    def test_delete_file(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            delete_me: delete me!
            file/in/sub/folder/delete_me: oh, please delete me!
        ''')
        self.check_result_after_sync()
        self.delete_file(self.plain_folder, "delete_me")
        self.delete_file(self.plain_folder, "file/in/sub/folder/delete_me")
        self.check_result_after_sync()

    def test_delete_file_in_check_folder(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            delete_me: delete me!
            file/in/sub/folder/delete_me: oh, please delete me!
        ''')
        self.check_result_after_sync()
        self.delete_file(self.plain_folder_check, "delete_me")
        self.delete_file(self.plain_folder_check,
                         "file/in/sub/folder/delete_me")
        self.check_result_after_sync_from_check_folder()

    def test_delete_folder(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            file_reserve: test
            folder/reserve: lol
            empty_folder1/
            empty_folder2/in/sub/folder/
            non_empty_folder1/file: test 1
            non_empty_folder2/in/sub/folder/file: test 2
        ''')
        self.check_result_after_sync()
        self.delete_folder(self.plain_folder, "empty_folder1")
        self.delete_folder(self.plain_folder, "empty_folder2/in/sub/folder/")
        self.delete_folder(self.plain_folder, "non_empty_folder1")
        self.delete_folder(self.plain_folder, "non_empty_folder2/in/sub/folder")
        self.check_result_after_sync()

    def test_delete_folder_in_check_folder(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            file_reserve: test
            folder/reserve: LOL
            empty_folder1/
            empty_folder2/in/sub/folder/
            non_empty_folder1/file: test 1
            non_empty_folder2/in/sub/folder/file: test 2
        ''')
        self.check_result_after_sync()
        self.delete_folder(self.plain_folder_check, "empty_folder1")
        self.delete_folder(self.plain_folder_check,
                           "empty_folder2/in/sub/folder/")
        self.delete_folder(self.plain_folder_check, "non_empty_folder1")
        self.delete_folder(self.plain_folder_check,
                           "non_empty_folder2/in/sub/folder")
        self.check_result_after_sync_from_check_folder()

    def test_rule_set(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            filename_sync: 1
            filename_not_sync: 2
            filename_not_sync_encrypted: 3
        ''')
        self.cli(["--password-file", self.password_file,
                  "--rule",
                  "exclude: name match *_not_sync",
                  self.encrypted_folder, self.plain_folder])
        self.cli(["--password-file", self.password_file,
                  "--rule",
                  "exclude: name match *_encrypted",
                  self.encrypted_folder, self.plain_folder_check])
        cmp_result = self.tree_cmp(self.plain_folder, self.plain_folder_check)
        self.assertEqual(sorted(cmp_result.left_only),
                         ["filename_not_sync", "filename_not_sync_encrypted"])
        self.assertEqual(len(cmp_result.right_only), 0)
        self.assertEqual(len(cmp_result.diff_files), 0)

    def test_rule_file(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            filename_sync: 1
            filename_not_sync: 2
            filename_not_sync_encrypted: 3
        ''')
        dot_folder = os.path.join(self.plain_folder, ".syncrypto")
        dot_folder_check = os.path.join(self.plain_folder_check, ".syncrypto")
        if not os.path.exists(dot_folder):
            os.mkdir(dot_folder)
        if not os.path.exists(dot_folder_check):
            os.mkdir(dot_folder_check)
        with open(os.path.join(dot_folder, "rules"), 'wb') as f:
            f.write(b'exclude: name match *_not_sync')
        with open(os.path.join(dot_folder_check, "rules"), 'wb') as f:
            f.write(b'exclude: name match *_encrypted')
        self.cli(["--password-file", self.password_file,
                  self.encrypted_folder, self.plain_folder])
        self.cli(["--password-file", self.password_file,
                  self.encrypted_folder, self.plain_folder_check])
        cmp_result = self.tree_cmp(self.plain_folder, self.plain_folder_check)
        self.assertEqual(sorted(cmp_result.left_only),
                         ["filename_not_sync", "filename_not_sync_encrypted"])
        self.assertEqual(len(cmp_result.right_only), 0)
        self.assertEqual(len(cmp_result.diff_files), 0)

    def test_encrypted_file_name(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            normal: hello
            normal_folder/file: hello
            211: 1
            117/hello: 2
        ''')
        self.check_result_after_sync()

    def test_conflict_starting(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            files.txt: text file
            folder/no_extension: no extension file
            folder/no_conflict1:1
        ''')
        prepare_filetree(self.plain_folder_check, '''
            files.txt: different text file!
            folder/no_extension: no extension file!
            folder/no_conflict2: 2
        ''')
        self.cli(["--password-file", self.password_file, self.encrypted_folder,
                  self.plain_folder])
        self.cli(["--password-file", self.password_file, self.encrypted_folder,
                  self.plain_folder_check])
        cmp_result = self.tree_cmp(self.plain_folder, self.plain_folder_check)
        self.assertEqual(cmp_result.left_only, [])
        self.assertEqual(sorted(cmp_result.right_only),
                         ["files.conflict.txt",
                          "folder/no_conflict2",
                          "folder/no_extension.conflict"])
        self.assertEqual(cmp_result.diff_files, [])
        self.assertEqual(open(os.path.join(self.plain_folder_check,
                                           "files.conflict.txt")).read(),
                         "different text file!")
        self.assertEqual(open(
            os.path.join(self.plain_folder_check,
                         "folder/no_extension.conflict")).read(),
                         "no extension file!")

    def test_conflict_after_syncing(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            files.txt: text file
            folder/no_extension: no extension file
            folder/no_conflict1:1
        ''')
        self.check_result_after_sync()
        self.modify_file(self.plain_folder, "files.txt", "modified")
        self.modify_file(self.plain_folder_check, "files.txt", "modified 2")
        self.cli(["--password-file", self.password_file, self.encrypted_folder,
                  self.plain_folder])
        self.cli(["--password-file", self.password_file, self.encrypted_folder,
                  self.plain_folder_check])
        cmp_result = self.tree_cmp(self.plain_folder, self.plain_folder_check)
        self.assertEqual(cmp_result.left_only, [])
        self.assertEqual(sorted(cmp_result.right_only),
                         ["files.conflict.txt"])

    def test_encrypt_file_no_out_file(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            test_simple_file: hello
            ext.txt: with extension
        ''')
        self.cli(["--password-file", self.password_file, "--encrypt-file",
                  os.path.join(self.plain_folder, "test_simple_file")])
        self.assertTrue(os.path.exists(
            os.path.join(self.plain_folder, "test_simple_file.encrypted")))
        self.cli([
            "--password-file", self.password_file,
            "--decrypt-file",
            os.path.join(self.plain_folder, "test_simple_file.encrypted"),
            "--out-file",
            os.path.join(self.plain_folder, "test_simple_file_decrypted")
                  ])
        self.assertTrue(
            file_cmp(
                os.path.join(self.plain_folder, "test_simple_file_decrypted"),
                os.path.join(self.plain_folder, "test_simple_file"), False))

        self.cli(["--password-file", self.password_file, "--encrypt-file",
                  os.path.join(self.plain_folder, "ext.txt")])
        self.assertTrue(os.path.exists(
            os.path.join(self.plain_folder, "ext.encrypted.txt")))
        self.cli([
            "--password-file", self.password_file,
            "--decrypt-file",
            os.path.join(self.plain_folder, "ext.encrypted.txt"),
            "--out-file",
            os.path.join(self.plain_folder, "ext.decrypted.txt")
                  ])
        self.assertTrue(
            file_cmp(
                os.path.join(self.plain_folder, "ext.decrypted.txt"),
                os.path.join(self.plain_folder, "ext.txt"), False))

    def test_encrypt_file_given_out_file(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            test_simple_file: hello
        ''')
        self.cli(["--password-file", self.password_file, "--encrypt-file",
                  os.path.join(self.plain_folder, "test_simple_file")])
        self.assertTrue(os.path.exists(
            os.path.join(self.plain_folder, "test_simple_file.encrypted")))
        self.cli([
            "--password-file", self.password_file,
            "--decrypt-file",
            os.path.join(self.plain_folder, "test_simple_file.encrypted"),
            "--out-file",
            os.path.join(self.plain_folder, "test_simple_file_decrypted")
                  ])
        self.assertTrue(
            file_cmp(
                os.path.join(self.plain_folder, "test_simple_file_decrypted"),
                os.path.join(self.plain_folder, "test_simple_file"), False))

    def test_decrypt_file_no_out_file(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            test_simple_file: hello
        ''')
        self.cli(["--password-file", self.password_file, self.encrypted_folder,
                  self.plain_folder])
        encrypted_path = None
        for name in os.listdir(self.encrypted_folder):
            if name.startswith(".") or name.startswith('_'):
                continue
            encrypted_path = name
        self.assertFalse(encrypted_path is None)
        origin = os.getcwd()
        os.chdir(self.plain_folder_check)
        self.cli(["--password-file", self.password_file, "--decrypt-file",
                  os.path.join(self.encrypted_folder, encrypted_path)])
        self.assertTrue(os.path.exists("test_simple_file"))
        with open("test_simple_file") as f:
            self.assertEqual(f.read(), "hello")
        os.chdir(origin)

    def test_decrypt_file_given_out_file(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            test_simple_file: hello
        ''')
        self.cli(["--password-file", self.password_file, self.encrypted_folder,
                  self.plain_folder])
        encrypted_path = None
        for name in os.listdir(self.encrypted_folder):
            if name.startswith(".") or name.startswith('_'):
                continue
            encrypted_path = name
        self.assertFalse(encrypted_path is None)
        plain_path = os.path.join(self.plain_folder_check, "decrypted_file")
        self.cli(["--password-file", self.password_file, "--decrypt-file",
                  os.path.join(self.encrypted_folder, encrypted_path),
                  '--out-file', plain_path])
        origin = os.getcwd()
        os.chdir(self.plain_folder_check)
        self.assertTrue(os.path.exists("decrypted_file"))
        with open("decrypted_file") as f:
            self.assertEqual(f.read(), "hello")
        os.chdir(origin)

    def test_pass_wrong_arguments(self):
        self.clear_folders()
        prepare_filetree(self.plain_folder, '''
            test_simple_file: hello
        ''')
        self.check_result_after_sync()
        self.assertNotEqual(syncrypto_cli(["--password-file",
                                           self.password_file,
                                           self.plain_folder,
                                           self.encrypted_folder]), 0)

    def test_not_ascii_arguments(self):
        plain_folder = mkdtemp("中文")
        plain_folder_check = mkdtemp("中文")
        encrypted_folder = mkdtemp("中文")
        prepare_filetree(plain_folder, '''
            文件: 你好
        ''')
        self.cli(["--password-file", self.password_file,
                  encrypted_folder,
                  plain_folder])
        self.cli(["--password-file", self.password_file,
                  encrypted_folder,
                  plain_folder_check])
        cmp_result = self.tree_cmp(plain_folder, plain_folder_check)
        self.assertEqual(cmp_result.left_only, [])
        self.assertEqual(cmp_result.right_only, [])
        self.assertEqual(cmp_result.diff_files, [])


if __name__ == '__main__':
    unittest.main()
