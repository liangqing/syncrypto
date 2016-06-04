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

from __future__ import unicode_literals
import sys
import os
import hashlib
import binascii
from getpass import getpass as builtin_getpass

py3 = sys.version_info[0] == 3
py2 = sys.version_info[0] == 2
py2_6 = (py2 and sys.version_info[1] == 6)
is_windows = os.name == "nt"
fs_encoding = sys.getfilesystemencoding()

if py3:

    def unicode_text(s, encoding="utf-8"):
        if isinstance(s, str):
            return s
        elif isinstance(s, bytes):
            return str(s, encoding)
        else:
            return str(s)


    def printable_text(s, encoding="utf-8"):
        return unicode_text(s, encoding)


    def command_text(s):
        return unicode_text(s, fs_encoding)

    def command_encoded(s):
        return s

else:

    def unicode_text(s, encoding="utf-8"):
        if isinstance(s, unicode):
            return s
        if not isinstance(s, str) or not isinstance(s, bytes):
            s = s.__str__()
        if isinstance(s, unicode):
            return s
        return unicode(s, encoding=encoding)

    def printable_text(s, encoding="utf-8"):
        if isinstance(s, str):
            return s
        s = unicode_text(s)
        return s.encode(encoding)


    def command_text(s):
        return unicode_text(s, fs_encoding)

    def command_encoded(s):
        return s.encode(fs_encoding)


def file_digest(path, buffer_size=10240):
    md5_obj = hashlib.md5()
    with open(path, 'rb') as f:
        while True:
            data = f.read(buffer_size)
            if len(data) <= 0:
                break
            md5_obj.update(data)
    return md5_obj.digest()


def string_digest(string, encoding="utf-8"):
    md5_obj = hashlib.md5()
    md5_obj.update(string.encode(encoding))
    return hexlify(md5_obj.digest())


def hexlify(data):
    return unicode_text(binascii.hexlify(data))


def file_hexlify_digest(path):
    return hexlify(file_digest(path))


def getpass(text="password:"):
    if is_windows and py2:
        text = text.encode("utf8")
    return builtin_getpass(text)
