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
from filecmp import cmp as file_cmp
from tempfile import mkdtemp
from time import strftime, localtime
from fnmatch import fnmatch

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
            content = line[pos+1:].strip()
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


class TreeCmpResult:

    def __init__(self):
        self.left_only = []
        self.right_only = []
        self.diff_files = []

    def __str__(self):
        return "left_only: %s\n right_only: %s\n diff_files: %s" % \
               (self.left_only, self.right_only, self.diff_files)


def tree_cmp(left, right, pathname="", ignores=None):
    is_dir_left = left is not None and os.path.isdir(left)
    is_dir_right = right is not None and os.path.isdir(right)
    exists_left = left is not None and os.path.exists(left)
    exists_right = right is not None and os.path.exists(right)
    cmp_result = TreeCmpResult()
    if is_dir_left and is_dir_right:
        sub_files = list(set(os.listdir(left)+os.listdir(right)))
        for sub_file in sub_files:
            if sub_file == "." or sub_file == "..":
                continue
            ignore = False
            if ignores is not None:
                for pattern in ignores:
                    if fnmatch(sub_file, pattern):
                        ignore = True
                        break
            if ignore:
                continue
            if pathname == "":
                sub_pathname = sub_file
            else:
                sub_pathname = pathname+"/"+sub_file
            sub_cmp = \
                tree_cmp(os.path.join(left, sub_file),
                         os.path.join(right, sub_file),
                         sub_pathname)
            cmp_result.left_only += sub_cmp.left_only
            cmp_result.right_only += sub_cmp.right_only
            cmp_result.diff_files += sub_cmp.diff_files
    elif is_dir_left:
        if not exists_right:
            cmp_result.left_only.append(pathname)
        else:
            cmp_result.diff_files.append(pathname)
        sub_files = os.listdir(left)
        for sub_file in sub_files:
            if sub_file == "." or sub_file == "..":
                continue
            ignore = False
            if ignores is not None:
                for pattern in ignores:
                    if fnmatch(sub_file, pattern):
                        ignore = True
                        break
            if ignore:
                continue
            if pathname == "":
                sub_pathname = sub_file
            else:
                sub_pathname = pathname+"/"+sub_file
            sub_cmp = \
                tree_cmp(os.path.join(left, sub_file),
                         None,
                         sub_pathname)
            cmp_result.left_only += sub_cmp.left_only
    elif is_dir_right:
        if not exists_left:
            cmp_result.right_only.append(pathname)
        else:
            cmp_result.diff_files.append(pathname)
        sub_files = os.listdir(right)
        for sub_file in sub_files:
            if sub_file == "." or sub_file == "..":
                continue
            if pathname == "":
                sub_pathname = sub_file
            else:
                sub_pathname = pathname+"/"+sub_file
            sub_cmp = \
                tree_cmp(None, os.path.join(right, sub_file),
                         sub_pathname)
            cmp_result.right_only += sub_cmp.right_only
    elif exists_left and exists_right:
        if not file_cmp(left, right, False):
            cmp_result.diff_files.append(pathname)
    elif exists_left:
        cmp_result.left_only.append(pathname)
    elif exists_right:
        cmp_result.right_only.append(pathname)
    return cmp_result

if __name__ == "__main__":
    folder1 = mkdtemp()
    folder2 = mkdtemp()
    prepare_filetree(folder1, """
    a/b/c:1
    x/y:2
    x/z:11
    w:3
    .haha
                     """)
    prepare_filetree(folder2, """
    x/z:22
    a/b/c/d:2
                     """)
    # cmp2 = dircmp(os.path.join(folder1, "a", "b"),
    #               os.path.join(folder2, "a", "b"))
    cmp = tree_cmp(folder1, folder2, ignores=[".*"])
    print(cmp)
    shutil.rmtree(folder1)
    shutil.rmtree(folder2)
