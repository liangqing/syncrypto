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
import unittest
import os
import os.path
from tempfile import mkstemp
from syncrypto import FileEntry, FileRule, FileRuleSet, InvalidRegularExpression
from util import format_datetime

from time import time

try:
    from cStringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO


class FileRuleTestCase(unittest.TestCase):

    def setUp(self):
        file_fp, file_path = mkstemp()
        self.file_path = file_path
        self.file_entry = FileEntry.from_file(self.file_path, os.path.basename(
            self.file_path))
        os.close(file_fp)

    def tearDown(self):
        os.remove(self.file_path)

    def test_eq(self):

        for op in ['eq', '=', '==']:
            f1 = FileRule('name', op, os.path.basename(self.file_path),
                          'include')
            f2 = FileRule('name', op, "...", 'include')
            self.assertEqual(f1.test(self.file_entry), "include")
            self.assertEqual(f2.test(self.file_entry), None)

    def test_ne(self):
        for op in ['ne', '!=', '<>']:
            f1 = FileRule('name', op, os.path.basename(self.file_path),
                          'exclude')
            f2 = FileRule('name', op, "...", 'exclude')
            self.assertEqual(f2.test(self.file_entry), "exclude")
            self.assertEqual(f1.test(self.file_entry), None)

    def test_lt(self):
        for op in ['lt', '<']:
            f1 = FileRule('size', op, 10, 'include')
            f2 = FileRule('size', op, 0, 'include')
            self.assertEqual(f1.test(self.file_entry), 'include')
            self.assertEqual(f2.test(self.file_entry), None)

    def test_gt(self):
        for op in ['gt', '>']:
            f1 = FileRule('mtime', op,
                          format_datetime(time()-3600), 'exclude')
            f2 = FileRule('mtime', op,
                          format_datetime(time()+3600), 'exclude')
            self.assertEqual(f1.test(self.file_entry), 'exclude')
            self.assertEqual(f2.test(self.file_entry), None)

    def test_gte(self):
        for op in ['gte', '>=']:
            f1 = FileRule('mtime', op,
                          format_datetime(time()-3600), 'exclude')
            f2 = FileRule('mtime', op,
                          format_datetime(time()+3600), 'exclude')
            self.assertEqual(f1.test(self.file_entry), 'exclude')
            self.assertEqual(f2.test(self.file_entry), None)

    def test_lte(self):
        self.file_entry.ctime = int(self.file_entry.ctime)
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

    def test_size(self):
        self.file_entry.size = 2
        for unit in ["k", "M", "G"]:

            f = FileRule('size', '>', "1"+unit, 'include')
            self.assertEqual(f.test(self.file_entry), None)
            f = FileRule('size', '<', "1"+unit, 'include')
            self.assertEqual(f.test(self.file_entry), 'include')

            self.file_entry.size <<= 10

            f = FileRule('size', '>', "1"+unit, 'include')
            self.assertEqual(f.test(self.file_entry), 'include')
            f = FileRule('size', '<', "1"+unit, 'include')
            self.assertEqual(f.test(self.file_entry), None)
            f = FileRule('size', 'eq', "2"+unit, 'include')
            self.assertEqual(f.test(self.file_entry), 'include')

        # no unit
        self.file_entry.size = 99
        f = FileRule('size', '>', 100, 'include')
        self.assertEqual(f.test(self.file_entry), None)
        f = FileRule('size', '<', 100, 'include')
        self.assertEqual(f.test(self.file_entry), 'include')

    def regexp_invalid(self):
        f = FileRule('name', 'regexp', "*.txt", 'include')

    def test_regexp(self):
        self.file_entry.pathname = "test_file.txt"
        f = FileRule('name', 'regexp', "test.*", 'include')
        self.assertEqual(f.test(self.file_entry), 'include')
        f = FileRule('name', 'regexp', "test*", 'include')
        self.assertEqual(f.test(self.file_entry), None)
        self.assertRaises(InvalidRegularExpression, self.regexp_invalid)


class FileRuleSetTestCase(unittest.TestCase):

    def setUp(self):
        file_fp, file_path = mkstemp()
        self.file_path = file_path
        self.file_entry = FileEntry.from_file(self.file_path, os.path.basename(
            self.file_path))
        os.close(file_fp)

    def tearDown(self):
        os.remove(self.file_path)

    def test_basic(self):
        rule_set = FileRuleSet()
        rule_set.add("size", ">", 1024, "include")
        rule_set.add("path", "eq", self.file_entry.pathname, "exclude")
        self.assertEqual(rule_set.test(self.file_entry), "exclude")

    def test_basic_parse(self):
        rule_set = FileRuleSet()
        rule_set.add_rule_by_string("size > 1024", "include")
        rule_set.add_rule_by_string("path = "+self.file_entry.pathname,
                                    "exclude")
        self.assertEqual(rule_set.test(self.file_entry), "exclude")

    def test_basic_parse_with_quotes(self):
        rule_set = FileRuleSet()
        rule_set.add_rule_by_string("size > '1024'", "include")
        rule_set.add_rule_by_string("path = \""+self.file_entry.pathname+"\"",
                                    "exclude")
        self.assertEqual(rule_set.test(self.file_entry), "exclude")

    def test_parse_with_no_action(self):
        f = FileRuleSet.parse("include: size > 1024")
        self.assertEqual(f.action, "include")
        self.assertEqual(f.attr, "size")
        self.assertEqual(f.op, "gt")
        self.assertEqual(f.value, 1024)

    def test_parse_with_action(self):
        f = FileRuleSet.parse("size > 1024", "exclude")
        self.assertEqual(f.action, "exclude")
        self.assertEqual(f.attr, "size")
        self.assertEqual(f.op, "gt")
        self.assertEqual(f.value, 1024)

    def test_default_action(self):
        rule_set = FileRuleSet()
        rule_set.add_rule_by_string("exclude: size > 1024000")
        self.assertEqual(rule_set.test(self.file_entry),
                         rule_set.default_action)
        rule_set = FileRuleSet(default_action="laf")
        rule_set.add_rule_by_string("exclude: size > 1024000")
        self.assertEqual(rule_set.test(self.file_entry), "laf")

    def test_match_pattern(self):
        f = FileRuleSet.parse("exclude: name match *_not_sync")
        self.assertEqual(f.action, "exclude")
        self.assertEqual(f.attr, "name")
        self.assertEqual(f.op, "match")
        self.assertEqual(f.value, "*_not_sync")


if __name__ == '__main__':
    unittest.main()
