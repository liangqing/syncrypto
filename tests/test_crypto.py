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
from __future__ import absolute_import
from __future__ import unicode_literals
from io import open
import unittest
import os
import os.path
from tempfile import mkstemp
from syncrypto import FileEntry, Crypto

try:
    from cStringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO


class CryptoTestCase(unittest.TestCase):

    def setUp(self):
        file_fp, file_path = mkstemp()
        self.password = 'password'
        self.crypto = Crypto(self.password)
        self.file_path = file_path
        self.file_entry = FileEntry.from_file(file_path,
                                              os.path.basename(file_path))
        os.close(file_fp)

    def tearDown(self):
        os.remove(self.file_path)

    def test_basic_encrypt(self):
        in_fd = BytesIO()
        middle_fd = BytesIO()
        out_fd = BytesIO()
        in_fd.write(b"hello")
        in_fd.seek(0)
        self.crypto.encrypt_fd(in_fd, middle_fd, self.file_entry)
        middle_fd.seek(0)
        self.crypto.decrypt_fd(middle_fd, out_fd)
        self.assertEqual(in_fd.getvalue(), out_fd.getvalue())

    def test_file_api(self):
        fd1, file_path1 = mkstemp()
        fd2, file_path2 = mkstemp()
        fd3, file_path3 = mkstemp()
        os.write(fd1, b'hello world')
        os.close(fd1)
        os.close(fd2)
        os.close(fd3)
        self.crypto.encrypt_file(file_path1, file_path2, self.file_entry)
        self.crypto.decrypt_file(file_path2, file_path3)
        self.assertEqual(open(file_path3, 'rb').read(), b'hello world')
        os.remove(file_path1)
        os.remove(file_path2)
        os.remove(file_path3)

    def test_large_encrypt(self):
        in_fd = BytesIO()
        middle_fd = BytesIO()
        out_fd = BytesIO()
        in_fd.write(os.urandom(1024*1024))
        in_fd.seek(0)
        self.crypto.encrypt_fd(in_fd, middle_fd, self.file_entry)
        middle_fd.seek(0)
        self.crypto.decrypt_fd(middle_fd, out_fd)
        self.assertEqual(in_fd.getvalue(), out_fd.getvalue())

    def test_encrypt_twice(self):
        in_fd = BytesIO()
        out_fd1 = BytesIO()
        out_fd2 = BytesIO()
        in_fd.write(b"hello")
        in_fd.seek(0)
        self.crypto.encrypt_fd(in_fd, out_fd1, self.file_entry)
        in_fd.seek(0)
        self.crypto.encrypt_fd(in_fd, out_fd2, self.file_entry)
        self.assertEqual(out_fd1.getvalue(), out_fd2.getvalue())

    def test_repeat_encrypt(self):
        in_fd = BytesIO()
        out_fd1 = BytesIO()
        out_fd2 = BytesIO()
        in_fd.write(os.urandom(1024))
        in_fd.seek(0)
        self.crypto.encrypt_fd(in_fd, out_fd1, self.file_entry)
        in_fd.seek(0)
        self.crypto.encrypt_fd(in_fd, out_fd2, self.file_entry)
        self.assertEqual(out_fd1.getvalue(), out_fd2.getvalue())

    def test_compress(self):
        in_fd = BytesIO()
        middle_fd = BytesIO()
        out_fd = BytesIO()
        in_fd.write(os.urandom(1024))
        in_fd.seek(0)
        self.crypto.encrypt_fd(in_fd, middle_fd, self.file_entry,
                               Crypto.COMPRESS)
        middle_fd.seek(0)
        self.crypto.decrypt_fd(middle_fd, out_fd)
        self.assertEqual(in_fd.getvalue(), out_fd.getvalue())

if __name__ == '__main__':
    unittest.main()
