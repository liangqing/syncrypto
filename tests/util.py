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
import os
import os.path
import shutil
from time import strftime, localtime

try:
    from cStringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO


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


def print_folder(folder):
    for root, dirs, files in os.walk(folder):
        for d in dirs:
            print(root + "/" + d)
        for f in files:
            print(root + "/" + f)


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
        fp = open(path, 'wb')
        fp.write(content.encode("utf-8"))
        fp.close()

