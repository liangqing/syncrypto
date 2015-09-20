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
import binascii
import os
import os.path
import re
from datetime import datetime
import time
from fnmatch import fnmatch
from .util import unicode_text, file_digest


class InvalidRuleString(Exception):
    pass


class InvalidRegularExpression(Exception):
    pass


class FileEntry(object):

    def __init__(self, pathname, size, ctime, mtime, mode, digest=None,
                 isdir=False, fs_pathname=None, salt=None):
        self.pathname = pathname
        self.isdir = isdir
        self.size = size
        self.ctime = ctime
        self.mtime = mtime
        self.mode = mode
        self.digest = digest
        self.fs_pathname = fs_pathname
        self.salt = salt

    def __str__(self):
        t = datetime.fromtimestamp(self.mtime)
        if self.isdir:
            return " ".join(['directory', self.pathname, ':',
                             unicode_text(t), self.fs_pathname])
        else:
            return " ".join(['file', self.pathname, ':',
                             unicode_text(t), self.fs_pathname])

    def name(self):
        return (self.split())[1]

    def split(self):
        pos = self.pathname.rfind('/')
        if pos < 0:
            return '', self.pathname
        return self.pathname[:pos], self.pathname[pos+1:]

    def fs_path(self, root):
        if os.path.sep != '/':
            return root + os.path.sep + self.fs_pathname.replace('/',
                                                                 os.path.sep)
        return root + os.path.sep + self.fs_pathname

    def to_dict(self):
        d = {}
        for k in FileEntry.properties():
            v = getattr(self, k)
            if v is not None and (k == 'digest' or k == 'salt'):
                d[k] = binascii.hexlify(v).decode('utf-8')
            else:
                d[k] = v
        return d

    def clone(self):
        return FileEntry(self.pathname, self.size, self.ctime, self.mtime,
                         self.mode, self.digest, self.isdir, self.fs_pathname)

    def copy_attr_from(self, target):
        self.isdir = target.isdir
        self.size = target.size
        self.ctime = target.ctime
        self.mtime = target.mtime
        if target.mode is not None:
            self.mode = target.mode
        self.salt = target.salt
        self.digest = target.digest

    @classmethod
    def from_dict(cls, d):
        if 'digest' in d and d['digest'] is not None:
            d['digest'] = binascii.unhexlify(d['digest'])
        if 'salt' in d and d['salt'] is not None:
            d['salt'] = binascii.unhexlify(d['salt'])
        return cls(**d)

    @classmethod
    def from_file(cls, path, pathname):
        stat = os.stat(path)
        mode = stat.st_mode
        if os.name == 'nt':
            mode = None
        size = stat.st_size
        isdir = os.path.isdir(path)
        digest = None
        if not isdir and size <= 10240:
            digest = file_digest(path)
        return cls(pathname, size, stat.st_ctime, stat.st_mtime,
                   mode, isdir=isdir,
                   fs_pathname=pathname, digest=digest)

    @staticmethod
    def properties():
        return ["pathname", "isdir", "size", "ctime",
                "mtime", "mode", "digest", "fs_pathname", "salt"]


class FileRule(object):

    _OP_MAP = {
        ">": "gt",
        "<": "lt",
        ">=": "gte",
        "<=": "lte",
        "=": "eq",
        "==": "eq",
        "!=": "ne",
        "<>": "ne"
    }

    _SUPPORTED_ATTRIBUTES = [
        "path", "name", "size", "ctime", "mtime"
    ]

    def __init__(self, attr, op, value, action):
        if op in FileRule._OP_MAP:
            op = FileRule._OP_MAP[op]
        if op not in ['eq', 'ne', 'lt', 'lte', 'gt', 'gte', 'match', 'regexp']:
            raise ValueError("Unsupported file filter op: "+op)
        if attr != 'name' and attr not in self._SUPPORTED_ATTRIBUTES:
            raise ValueError("Unsupported file filter attribute: "+attr)
        self.attr = attr
        if attr == 'size':
            value = unicode_text(value).lower()
            unit = value[-1]
            if unit == 'g':
                self.value = int(value[:-1]) << 30
            elif unit == 'm':
                self.value = int(value[:-1]) << 20
            elif unit == 'k':
                self.value = int(value[:-1]) << 10
            else:
                self.value = int(value)
        elif attr == 'ctime' or attr == 'mtime':
            self.value = time.mktime(datetime.strptime(
                value, "%Y-%m-%d %H:%M:%S").timetuple())
        elif op == 'regexp':
            if value[0] != '^':
                value = '^'+value
            if value[-1] != '$':
                value += '$'
            try:
                self.value = re.compile(value)
            except re.error:
                self.value = None
            if self.value is None:
                raise InvalidRegularExpression(
                    "Regular expression '"+value+"' not correct")
        else:
            self.value = value

        self.op = op
        self.action = action

    def test(self, file_entry):
        if file_entry is None:
            return None
        attr = self.attr
        if attr == 'name' or attr == 'path':
            attr = 'pathname'
        value = getattr(file_entry, attr)
        if self.attr == 'name':
            value = os.path.basename(value)
        method = getattr(self, self.op)
        if method(value, self.value):
            return self.action
        return None

    @staticmethod
    def eq(a, b):
        return a == b

    @staticmethod
    def ne(a, b):
        return a != b

    @staticmethod
    def lt(a, b):
        return a < b

    @staticmethod
    def gt(a, b):
        return a > b

    @staticmethod
    def lte(a, b):
        return a <= b

    @staticmethod
    def gte(a, b):
        return a >= b

    @staticmethod
    def match(value, pattern):
        return fnmatch(value, pattern)

    @staticmethod
    def regexp(value, regexp):
        return regexp.match(value) is not None

    def to_dict(self):
        value = self.value
        return {
            'attr': self.attr,
            'value': value,
            'op': self.op
        }

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


class FileRuleSet(object):

    _RULE_STRING_REGEXP = re.compile(
        r"\s*(\w+)\s+(\S+)\s+(\".+\"|'.+'|.+)\s*")

    _RULE_STRING_REGEXP_WITH_ACTION = re.compile(
        r"\s*(include|exclude|ignore)\s*:\s*(\w+)\s+(\S+)\s+(\".+\"|'.+'|.+)\s*"
    )

    def __init__(self, default_action="include"):
        self._rules = []
        self.default_action = default_action

    def add(self, attr, op, value, action):
        self._rules.append(FileRule(attr, op, value, action))

    def add_rule(self, rule):
        self._rules.append(rule)

    def add_rule_by_string(self, rule_string, action=None):
        self._rules.append(self.parse(rule_string, action))

    def test(self, file_entry):
        for rule in self._rules:
            action = rule.test(file_entry)
            if action is not None:
                return action
        return self.default_action

    @classmethod
    def parse(cls, rule_string, action=None):
        if action is None:
            match = cls._RULE_STRING_REGEXP_WITH_ACTION.match(rule_string)
        else:
            match = cls._RULE_STRING_REGEXP.match(rule_string)
        if match is None:
            raise InvalidRuleString()
        if action is None:
            return FileRule(match.group(2).strip(),
                            match.group(3).strip(), match.group(4).strip('"\''),
                            match.group(1).strip())
        return FileRule(match.group(1).strip(),
                        match.group(2).strip(), match.group(3).strip('"\''),
                        action)


class FileTree(object):

    def __init__(self, table=None):
        self._table = table
        if self._table is None:
            self._table = {}

    def pathnames(self):
        return list(self._table)

    def files(self):
        files = []
        for pathname in self._table:
            f = self._table[pathname]
            if not f.isdir:
                files.append(f)
        return files

    def folders(self):
        folders = []
        for pathname in self._table:
            f = self._table[pathname]
            if f.isdir:
                folders.append(f)
        return folders 

    def get(self, pathname):
        if pathname in self._table:
            return self._table[pathname]
        return None

    def set(self, pathname, file_entry):
        self._table[pathname] = file_entry

    def remove(self, pathname):
        if pathname in self._table:
            del self._table[pathname]

    def has(self, pathname):
        return pathname in self._table

    def has_fs_pathname(self, fs_pathname):
        for f in self._table.values():
            if f.fs_pathname == fs_pathname:
                return True
        return False

    def walk_tree(self, path, rule_set, pathname=''):
        isfile = os.path.isfile(path)
        isdir = os.path.isdir(path)
        if (isfile or isdir) and pathname != '':
            file_entry = FileEntry.from_file(path, pathname)
            if rule_set is None:
                self._table[pathname] = file_entry
            else:
                action = rule_set.test(file_entry)
                if action == "include":
                    self._table[pathname] = file_entry
                else:
                    return
        if not isdir:
            return
        for name in os.listdir(path):
            if name == '.' or name == '..' \
                    or name == '.syncrypto' or name == '_syncrypto':
                continue
            sub_pathname = pathname+'/'+name
            if pathname == '':
                sub_pathname = name
            self.walk_tree(path+os.path.sep+name, rule_set, sub_pathname)

    def __str__(self):
        table = self._table
        s = ""
        for key in table:
            item = table[key]
            s += unicode_text(item)+"\n"
        return s

    def to_dict(self):
        table = {}
        for pathname in self._table:
            f = self._table[pathname]
            if f is not None:
                table[pathname] = f.to_dict()
        return {
            'table': table,
        }

    @classmethod
    def from_fs(cls, root, table=None, rule_set=None):
        filetree = cls(table)
        filetree.walk_tree(root, rule_set)
        return filetree

    @classmethod
    def from_dict(cls, d):
        table = {}
        if 'table' in d:
            t = d['table']
            for pathname in t:
                f = t[pathname]
                table[pathname] = FileEntry.from_dict(f)
        return cls(table)
