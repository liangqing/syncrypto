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
import unittest
import os
import os.path
import shutil
from tempfile import mkstemp, mkdtemp
from syncrypto import FileEntry, FileTree
from time import time
from util import prepare_filetree
from syncrypto.util import file_hexlify_digest, file_digest, hexlify, is_windows


try:
    from cStringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO


class FileEntryTestCase(unittest.TestCase):

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
        self.file_object = FileEntry(**self.file_attrs)
        os.close(file_fp)

    def tearDown(self):
        os.remove(self.file_path)

    def test_property(self):
        stat = os.stat(self.file_path)
        self.assertEqual(self.file_object.isdir, False)
        self.assertEqual(self.file_object.digest, None)
        self.assertEqual(self.file_object.size, stat.st_size)
        self.assertEqual(self.file_object.ctime, int(stat.st_ctime))
        self.assertEqual(self.file_object.mtime, stat.st_mtime)
        self.assertEqual(self.file_object.mode, stat.st_mode)
        self.assertEqual(self.file_object.pathname,
                         os.path.basename(self.file_path))

    def test_to_dict(self):
        d = self.file_object.to_dict()
        for k in self.file_attrs:
            self.assertEqual(d[k], self.file_attrs[k])

    def test_from_file(self):
        stat = os.stat(self.file_path)
        d = {
            'pathname': os.path.basename(self.file_path),
            'fs_pathname': os.path.basename(self.file_path),
            'size': stat.st_size,
            'ctime': stat.st_ctime,
            'mtime': stat.st_mtime,
            'mode': stat.st_mode,
            'digest': file_hexlify_digest(self.file_path),
            'isdir': False,
            'salt': None
        }
        if is_windows:
            d['mode'] = None
        file_object = FileEntry.from_file(self.file_path, d['pathname'])
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
            'digest': file_digest(self.file_path),
            'isdir': False,
            'salt': None
        }
        file_object = FileEntry(**d)
        d['digest'] = hexlify(d['digest'])
        self.assertEqual(d, file_object.to_dict())


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


if __name__ == '__main__':
    unittest.main()
