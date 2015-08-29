#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from Crypto import Random
import os
import os.path
import shutil
from subprocess import call
from tempfile import mkstemp, mkdtemp
from syncrypto import File, FileRule, FileRuleSet, FileTree, Crypto, Syncrypto
from syncrypto import cmd as syncrypto_cmd
from time import time, strftime, localtime
from cStringIO import StringIO 
from filecmp import dircmp


def format_datetime(t):
    return strftime("%Y-%m-%d %H:%M:%S", localtime(t))


def clear_folder(folder):
    for name in os.listdir(folder):
        if name == '.' or name == '..':
            continue
        path = folder+os.path.sep+name
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)


def prepare_filetree(root, tree_string):
    lines = tree_string.split("\n")
    for line in lines:
        line = line.strip()
        if line == '' or line[0] == '#':
            continue
        pos = line.find(':')
        content = ''
        if pos >= 0:
            content = line[pos+1:]
            line = line[:pos]
        pathname = line.strip().replace("/", os.path.sep)
        path = root + os.path.sep + pathname
        if pathname.endswith(os.path.sep) and not os.path.exists(path):
            os.makedirs(path)
            continue
        directory = os.path.dirname(path)
        if not os.path.exists(directory):
            os.makedirs(directory)
        fp = open(path, 'w')
        fp.write(content)
        fp.close()


class FileTestCase(unittest.TestCase):

    def setUp(self):
        file_fp, file_path = mkstemp()
        self.file_path = file_path
        stat = os.stat(self.file_path)
        self.file_attrs = {
            'pathname': os.path.basename(self.file_path),
            'size': stat.st_size,
            'ctime': int(time()),
            'mtime': stat.st_mtime,
            'mode': stat.st_mode,
        }
        self.file_object = File(**self.file_attrs)

    def tearDown(self):
        os.remove(self.file_path)

    def test_property(self):
        stat = os.stat(self.file_path)
        self.assertEqual(self.file_object.isdir, False)
        self.assertEqual(self.file_object.digest, None)
        self.assertEqual(self.file_object.size, stat.st_size)
        self.assertEqual(self.file_object.ctime, stat.st_ctime)
        self.assertEqual(self.file_object.mtime, stat.st_mtime)
        self.assertEqual(self.file_object.mode, stat.st_mode)
        self.assertEqual(self.file_object.pathname,
                         os.path.basename(self.file_path))

    def test_to_dict(self):
        d = self.file_object.to_dict()
        for k, v in self.file_attrs.iteritems():
            self.assertEqual(d[k], v)

    def test_from_file(self):
        stat = os.stat(self.file_path)
        d = {
            'pathname': os.path.basename(self.file_path),
            'fs_pathname': os.path.basename(self.file_path),
            'size': stat.st_size,
            'ctime': stat.st_ctime,
            'mtime': stat.st_mtime,
            'mode': stat.st_mode,
            'digest': None,
            'isdir': False,
            'salt': None
        }
        file_object = File.from_file(self.file_path, d['pathname'])
        self.assertEqual(d, file_object.to_dict())

    def test_from_dict(self):
        stat = os.stat(self.file_path)
        d = {
            'pathname': os.path.basename(self.file_path),
            'fs_pathname': os.path.basename(self.file_path),
            'size': stat.st_size,
            'ctime': int(time()),
            'mtime': stat.st_mtime,
            'mode': stat.st_mode,
            'digest': None,
            'isdir': False,
            'salt': None
        }
        file_object = File(**d)
        self.assertEqual(d, file_object.to_dict())


class FileRuleTestCase(unittest.TestCase):

    def setUp(self):
        file_fp, file_path = mkstemp()
        self.file_path = file_path
        self.file_entry = File.from_file(self.file_path, os.path.basename(
            self.file_path))

    def tearDown(self):
        os.remove(self.file_path)

    def test_eq(self):
        f1 = FileRule('name', 'eq', os.path.basename(self.file_path), 'include')
        f2 = FileRule('name', 'eq', "...", 'include')
        self.assertEqual(f1.test(self.file_entry), "include")
        self.assertEqual(f2.test(self.file_entry), None)

    def test_ne(self):
        f1 = FileRule('name', 'ne', os.path.basename(self.file_path), 'exclude')
        f2 = FileRule('name', 'ne', "...", 'exclude')
        self.assertEqual(f2.test(self.file_entry), "exclude")
        self.assertEqual(f1.test(self.file_entry), None)

    def test_lt(self):
        f1 = FileRule('size', 'lt', 10, 'include')
        f2 = FileRule('size', 'lt', 0, 'include')
        self.assertEqual(f1.test(self.file_entry), 'include')
        self.assertEqual(f2.test(self.file_entry), None)

    def test_gt(self):
        f1 = FileRule('mtime', 'gt',
                      format_datetime(time()-3600), 'exclude')
        f2 = FileRule('mtime', 'gt',
                      format_datetime(time()+3600), 'exclude')
        self.assertEqual(f1.test(self.file_entry), 'exclude')
        self.assertEqual(f2.test(self.file_entry), None)

    def test_lte(self):
        f1 = FileRule('ctime', 'lte',
                      format_datetime(self.file_entry.ctime), 'include')
        f2 = FileRule('ctime', 'lte',
                      format_datetime(time()-3600), 'include')
        f3 = FileRule('ctime', 'eq',
                      format_datetime(self.file_entry.ctime), 'include')
        self.assertEqual(f1.test(self.file_entry), 'include')
        self.assertEqual(f2.test(self.file_entry), None)
        self.assertEqual(f3.test(self.file_entry), 'include')

    def test_match(self):
        f1 = FileRule('name', 'match', "*", 'include')
        f2 = FileRule('name', 'match', "", 'include')
        f3 = FileRule('name', 'match',
                      os.path.basename(self.file_entry.pathname), 'include')
        self.assertEqual(f1.test(self.file_entry), 'include')
        self.assertEqual(f2.test(self.file_entry), None)
        self.assertEqual(f3.test(self.file_entry), 'include')

        file_entry = self.file_entry.clone()
        file_entry.pathname = "t.test"
        f = FileRule("name", "match", "*.test", "include")
        self.assertEqual(f.test(file_entry), "include")
        file_entry.pathname = "test"
        self.assertEqual(f.test(file_entry), None)


class FileRuleSetTestCase(unittest.TestCase):

    def setUp(self):
        file_fp, file_path = mkstemp()
        self.file_path = file_path
        self.file_entry = File.from_file(self.file_path, os.path.basename(
            self.file_path))

    def tearDown(self):
        os.remove(self.file_path)

    def testBasic(self):
        rule_set = FileRuleSet()
        rule_set.add("size", ">", 1024, "include")
        rule_set.add("path", "eq", self.file_entry.pathname, "exclude")
        self.assertEqual(rule_set.test(self.file_entry), "exclude")

    def testBasicParse(self):
        rule_set = FileRuleSet()
        rule_set.add_rule_by_string("size > 1024", "include")
        rule_set.add_rule_by_string("path = "+self.file_entry.pathname,
                                    "exclude")
        self.assertEqual(rule_set.test(self.file_entry), "exclude")

    def testBasicParseWithQuotes(self):
        rule_set = FileRuleSet()
        rule_set.add_rule_by_string("size > '1024'", "include")
        rule_set.add_rule_by_string("path = \""+self.file_entry.pathname+"\"",
                                    "exclude")
        self.assertEqual(rule_set.test(self.file_entry), "exclude")

    def testParseWithNoAction(self):
        f = FileRuleSet.parse("include: size > 1024")
        self.assertEqual(f.action, "include")
        self.assertEqual(f.attr, "size")
        self.assertEqual(f.op, "gt")
        self.assertEqual(f.value, 1024)

    def testParseWithAction(self):
        f = FileRuleSet.parse("size > 1024", "exclude")
        self.assertEqual(f.action, "exclude")
        self.assertEqual(f.attr, "size")
        self.assertEqual(f.op, "gt")
        self.assertEqual(f.value, 1024)

    def testDefaultAction(self):
        rule_set = FileRuleSet()
        rule_set.add_rule_by_string("exclude: size > 1024000")
        self.assertEqual(rule_set.test(self.file_entry), rule_set.default_action)
        rule_set = FileRuleSet(default_action="hahaha")
        rule_set.add_rule_by_string("exclude: size > 1024000")
        self.assertEqual(rule_set.test(self.file_entry), "hahaha")

    def testMatchPattern(self):
        f = FileRuleSet.parse("exclude: name match *_not_sync")
        self.assertEqual(f.action, "exclude")
        self.assertEqual(f.attr, "name")
        self.assertEqual(f.op, "match")
        self.assertEqual(f.value, "*_not_sync")


class FileTreeTestCase(unittest.TestCase):

    def setUp(self):
        self.directory_path = mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.directory_path)

    def test_walk_tree(self):
        prepare_filetree(self.directory_path, '''
a
b/
c/d/e/f
1/2
        ''')
        filetree = FileTree.from_fs(self.directory_path)
        self.assertEqual(filetree.get('a').isdir, False)
        self.assertEqual(filetree.get('b').isdir, True)
        self.assertEqual(filetree.get('c').isdir, True)
        self.assertEqual(filetree.get('c/d').isdir, True)
        self.assertEqual(filetree.get('c/d/e').isdir, True)
        self.assertEqual(filetree.get('c/d/e/f').isdir, False)
        self.assertEqual(filetree.get('1').isdir, True)
        self.assertEqual(filetree.get('1/2').isdir, False)
        self.assertEqual(len(filetree.files()), 3)
        self.assertEqual(len(filetree.folders()), 5)


class CryptoTestCase(unittest.TestCase):

    def setUp(self):
        file_fp, file_path = mkstemp()
        self.password = 'password'
        self.crypto = Crypto(self.password)
        self.file_path = file_path
        self.file_entry = File.from_file(file_path, os.path.basename(file_path))

    def tearDown(self):
        os.remove(self.file_path)
        
    def testEncrypt(self):
        in_fd = StringIO()
        middle_fd = StringIO()
        out_fd = StringIO()
        in_fd.write(Random.new().read(1024))
        in_fd.seek(0)
        self.crypto.encrypt_fd(in_fd, middle_fd, self.file_entry)
        middle_fd.seek(0)
        self.crypto.decrypt_fd(middle_fd, out_fd)
        self.assertEqual(in_fd.getvalue(), out_fd.getvalue())

    def testRepeatEncrypt(self):
        in_fd = StringIO()
        out_fd1 = StringIO()
        out_fd2 = StringIO()
        in_fd.write(Random.new().read(1024))
        in_fd.seek(0)
        self.crypto.encrypt_fd(in_fd, out_fd1, self.file_entry)
        in_fd.seek(0)
        self.crypto.encrypt_fd(in_fd, out_fd2, self.file_entry)
        self.assertEqual(out_fd1.getvalue(), out_fd2.getvalue())

    def testCompress(self):
        in_fd = StringIO()
        middle_fd = StringIO()
        out_fd = StringIO()
        in_fd.write(Random.new().read(1024))
        in_fd.seek(0)
        self.crypto.encrypt_fd(in_fd, middle_fd, self.file_entry,
                               Crypto.COMPRESS)
        middle_fd.seek(0)
        self.crypto.decrypt_fd(middle_fd, out_fd)
        self.assertEqual(in_fd.getvalue(), out_fd.getvalue())


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
                         self.encrypted_tree, self.plain_tree,
                         self.snapshot_tree)
        sync2 = Syncrypto(self.crypto, self.encrypted_folder,
                          self.plain_folder_check,
                          self.encrypted_tree, self.plain_tree_check,
                          self.snapshot_tree)
        sync.sync_folder()
        sync2.sync_folder()
        dcmp = dircmp(self.plain_folder, self.plain_folder_check)
        self.assertEqual(len(dcmp.left_only), 0)
        self.assertEqual(len(dcmp.right_only), 0)
        self.assertEqual(len(dcmp.diff_files), 0)

    def testInit(self):
        self.isPass()

    def testAddFile(self):
        path = self.plain_folder + os.path.sep + "add_file"
        fp = open(path, "wb")
        fp.write("hello world")
        fp.close()
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.isPass()

    def testAddFileAndModify(self):
        path = self.plain_folder + os.path.sep + "add_file_and_modify"
        fp = open(path, "wb")
        fp.write("hello world")
        fp.close()
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.isPass()

        path = self.plain_folder + os.path.sep + "add_file_and_modify"
        fp = open(path, "wb")
        fp.write("hello world again")
        fp.close()
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.plain_tree.get("add_file_and_modify").mtime += 1
        self.isPass()

    def testModifyFile(self):
        path = self.plain_tree.get("sync_file_modify").fs_path(
            self.plain_folder)
        fp = open(path, "wb")
        fp.write("hello world again")
        fp.close()
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.plain_tree.get("sync_file_modify").mtime += 1
        self.isPass()

    def testModifyFileInFolder(self):
        path = self.plain_tree.get("sync/file/modify").fs_path(
            self.plain_folder)
        fp = open(path, "wb")
        fp.write("hello world again")
        fp.close()
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.plain_tree.get("sync/file/modify").mtime += 1
        self.isPass()

    def testDeleteFile(self):
        path = self.plain_tree.get("sync_file_delete").fs_path(
            self.plain_folder)
        os.remove(path)
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.isPass()

    def testDeleteEmptyFolder(self):
        path = self.plain_tree.get("empty_dir_delete").fs_path(
            self.plain_folder)
        shutil.rmtree(path)
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.isPass()

    def testDeleteNonEmptyFolder(self):
        path = self.plain_tree.get("not_empty_dir").fs_path(self.plain_folder)
        shutil.rmtree(path)
        self.plain_tree = FileTree.from_fs(self.plain_folder)
        self.isPass()


class CmdTestCase(unittest.TestCase):

    def setUp(self):
        self.plain_folder = mkdtemp()
        self.plain_folder_check = mkdtemp()
        self.encrypted_folder = mkdtemp()
        self.password = "password_test"

    def tearDown(self):
        shutil.rmtree(self.plain_folder)
        shutil.rmtree(self.plain_folder_check)
        shutil.rmtree(self.encrypted_folder)

    def checkResult(self):
        dcmp = dircmp(self.plain_folder, self.plain_folder_check)
        self.assertEqual(len(dcmp.left_only), 0)
        self.assertEqual(len(dcmp.right_only), 0)
        self.assertEqual(len(dcmp.diff_files), 0)

    def checkResultAfterSync(self):
        syncrypto_cmd(["--password", self.password, self.encrypted_folder,
                       self.plain_folder])
        syncrypto_cmd(["--password", self.password, self.encrypted_folder,
                       self.plain_folder_check])

    def clearFolders(self):
        clear_folder(self.plain_folder)
        clear_folder(self.plain_folder_check)
        clear_folder(self.encrypted_folder)

    def modifyFile(self, folder, pathname, content):
        fd = open(folder+os.path.sep+pathname, 'wb')
        fd.write(content)
        fd.close()

    def addFile(self, folder, pathname, content):
        fd = open(folder+os.path.sep+pathname, 'wb')
        fd.write(content)
        fd.close()

    def addFolder(self, folder, pathname):
        os.makedirs(folder+os.path.sep+pathname)

    def deleteFile(self, folder, pathname):
        os.remove(folder+os.path.sep+pathname)

    def deleteFolder(self, folder, pathname):
        shutil.rmtree(folder+os.path.sep+pathname)

    def rename(self, folder, pathname, pathname2):
        os.rename(folder+os.path.sep+pathname, folder+os.path.sep+pathname2)

    def testBasicSync(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
simple_file: hello world
file/in/sub/folder: hello world
empty_dir/
        ''')
        self.checkResultAfterSync()

    def testBasicSyncMultipleTimes(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
simple_file: hello world
file/in/sub/folder: hello world
empty_dir/
        ''')
        self.checkResultAfterSync()
        self.checkResultAfterSync()
        self.checkResultAfterSync()

    def testModifyFile(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
keep_same: same file
will_modify: modify the file please
file/in/sub/folder/will_modify: modify the file please!
empty_dir/
        ''')
        self.checkResultAfterSync()
        self.modifyFile(self.plain_folder, "will_modify", "it is modified")
        self.modifyFile(self.plain_folder, "file/in/sub/folder/will_modify",
                        "it is modified")
        self.checkResultAfterSync()

    def testModifyFileInCheckFolder(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
keep_same: same file
will_modify: modify the file please
file/in/sub/folder/will_modify: modify the file please!
empty_dir/
        ''')
        self.checkResultAfterSync()
        self.modifyFile(self.plain_folder_check,
                        "will_modify", "it is modified")
        self.modifyFile(self.plain_folder_check,
                        "file/in/sub/folder/will_modify", "it is modified")
        self.checkResultAfterSync()

    def testRenameFile(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
keep_same: same file
will_rename: rename
will_rename2: rename
file/in/sub/folder/will_rename: rename
empty_dir/
        ''')
        self.checkResultAfterSync()
        self.rename(self.plain_folder, "will_rename", "renamed")
        self.rename(self.plain_folder, "file/in/sub/folder/will_rename",
                    "renamed2")
        self.rename(self.plain_folder, "will_rename2",
                    "file/in/sub/folder/renamed2")
        self.checkResultAfterSync()

    def testRenameFileInCheckFolder(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
keep_same: same file
will_rename: rename
will_rename2: rename
file/in/sub/folder/will_rename: rename
empty_dir/
        ''')
        self.checkResultAfterSync()
        self.rename(self.plain_folder_check, "will_rename", "renamed")
        self.rename(self.plain_folder_check, "file/in/sub/folder/will_rename",
                    "renamed2")
        self.rename(self.plain_folder_check, "will_rename2",
                    "file/in/sub/folder/renamed2")
        self.checkResultAfterSync()

    def testAddFile(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
simple_file: simple file
file/in/sub/folder/simple_file: file in the folder!
empty_dir/
        ''')
        self.checkResultAfterSync()
        self.addFile(self.plain_folder, "add_file", "add file")
        self.addFile(self.plain_folder, "file/in/sub/folder/add_file",
                     "add file!")
        self.checkResultAfterSync()

    def testAddFileInCheckFolder(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
simple_file: simple file
file/in/sub/folder/simple_file: file in the folder!
empty_dir/
        ''')
        self.checkResultAfterSync()
        self.addFile(self.plain_folder_check, "add_file", "add file")
        self.addFile(self.plain_folder_check, "file/in/sub/folder/add_file",
                     "add file!")
        self.checkResultAfterSync()

    def testAddFolder(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
simple_file: simple file
file/in/sub/folder/simple_file: file in the folder!
empty_dir/
        ''')
        self.checkResultAfterSync()
        self.addFolder(self.plain_folder, "empty_dir/add_folder")
        self.addFolder(self.plain_folder, "folder/with/file")
        self.addFile(self.plain_folder, "folder/with/file/test", "test\ntest!")
        self.checkResultAfterSync()

    def testAddFolderInCheckFolder(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
simple_file: simple file
file/in/sub/folder/simple_file: file in the folder!
empty_dir/
        ''')
        self.checkResultAfterSync()
        self.addFolder(self.plain_folder_check, "empty_dir/add_folder")
        self.addFolder(self.plain_folder_check, "folder/with/file")
        self.addFile(self.plain_folder_check, "folder/with/file/test",
                     "test\ntest!")
        self.checkResultAfterSync()

    def testDeleteFile(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
delete_me: delete me!
file/in/sub/folder/delete_me: oh, please delete me!
        ''')
        self.checkResultAfterSync()
        call(["find", self.encrypted_folder])
        self.deleteFile(self.plain_folder, "delete_me")
        self.deleteFile(self.plain_folder, "file/in/sub/folder/delete_me")
        self.checkResultAfterSync()
        print "=="
        call(["find", self.encrypted_folder])

    def testDeleteFileInCheckFolder(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
delete_me: delete me!
file/in/sub/folder/delete_me: oh, please delete me!
        ''')
        self.checkResultAfterSync()
        self.deleteFile(self.plain_folder_check, "delete_me")
        self.deleteFile(self.plain_folder_check, "file/in/sub/folder/delete_me")
        self.checkResultAfterSync()

    def testDeleteFolder(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
file_reserve: test
folder/reserve: lol
empty_folder1/
empty_folder2/in/sub/folder/
non_empty_folder1/file: test 1
non_empty_folder2/in/sub/folder/file: test 2
        ''')
        self.checkResultAfterSync()
        self.deleteFolder(self.plain_folder, "empty_folder1")
        self.deleteFolder(self.plain_folder, "empty_folder2/in/sub/folder/")
        self.deleteFolder(self.plain_folder, "non_empty_folder1")
        self.deleteFolder(self.plain_folder, "non_empty_folder2/in/sub/folder")
        self.checkResultAfterSync()

    def testDeleteFolderInCheckFolder(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
file_reserve: test
folder/reserve: LOL
empty_folder1/
empty_folder2/in/sub/folder/
non_empty_folder1/file: test 1
non_empty_folder2/in/sub/folder/file: test 2
        ''')
        self.checkResultAfterSync()
        self.deleteFolder(self.plain_folder_check, "empty_folder1")
        self.deleteFolder(self.plain_folder_check,
                          "empty_folder2/in/sub/folder/")
        self.deleteFolder(self.plain_folder_check, "non_empty_folder1")
        self.deleteFolder(self.plain_folder_check,
                          "non_empty_folder2/in/sub/folder")
        self.checkResultAfterSync()

    def testRuleSet(self):
        self.clearFolders()
        prepare_filetree(self.plain_folder, '''
filename_sync: 1
filename_not_sync: 2
        ''')
        syncrypto_cmd(["--password", self.password,
                       "--rule", "exclude: name match *_not_sync",
                       self.encrypted_folder, self.plain_folder])
        syncrypto_cmd(["--password", self.password,
                       self.encrypted_folder, self.plain_folder_check])
        dcmp = dircmp(self.plain_folder, self.plain_folder_check)
        self.assertEqual(dcmp.left_only, ["filename_not_sync"])
        self.assertEqual(len(dcmp.right_only), 0)
        self.assertEqual(len(dcmp.diff_files), 0)


#     def testChangePassword(self):
#         self.clearFolders()
#         prepare_filetree(self.plain_folder, '''
# file_reserve: test
# folder/reserve: LOL
# empty_folder1/
# empty_folder2/in/sub/folder/
# non_empty_folder1/file: test 1
# non_empty_folder2/in/sub/folder/file: test 2
#         ''')
#         syncrypto_cmd(["--password", self.password,
#                        "--change-password", self.encrypted_folder])

if __name__ == '__main__':
    unittest.main()
