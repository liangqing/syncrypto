#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals
from io import open
import os
import sys
import os.path
import shutil
import hashlib
import json
from datetime import datetime
from time import sleep
from getpass import getpass
from stat import *
from .crypto import Crypto, UnrecognizedContent
from .filetree import FileTree, FileRuleSet
try:
    from cStringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO


class GenerateEncryptedFilePathError(Exception):
    pass


class ChangeTheSamePassword(Exception):
    pass


class InvalidFolder(Exception):
    pass


class Syncrypto:

    def __init__(self, crypto, encrypted_folder, plain_folder=None,
                 encrypted_tree=None, plain_tree=None, snapshot_tree=None,
                 rule_set=None, rule_file=None, debug=False):

        self.crypto = crypto
        self.encrypted_folder = encrypted_folder
        self.plain_folder = plain_folder
        self.encrypted_tree = encrypted_tree
        self.plain_tree = plain_tree
        self.snapshot_tree = snapshot_tree
        self.rule_set = rule_set
        self._debug = debug

        if not os.path.isdir(self.encrypted_folder):
            if os.path.exists(self.encrypted_folder):
                raise InvalidFolder("encrypted folder path is not correct: " +
                                    self.encrypted_folder)
            else:
                os.makedirs(self.encrypted_folder)

        if plain_folder is not None:
            if not os.path.isdir(self.plain_folder):
                if os.path.exists(self.plain_folder):
                    raise InvalidFolder("plaintext folder path is not correct: "
                                        + self.plain_folder)
                else:
                    os.makedirs(self.plain_folder)
            if self.rule_set is None:
                self.rule_set = FileRuleSet()

            if rule_file is None:
                rule_file = self._rule_path()

            if os.path.exists(rule_file):
                with open(rule_file, 'rb') as f:
                    for line in f:
                        line = line.strip()
                        if line == "" or line[0] == '#':
                            continue
                        self.rule_set.add_rule_by_string(line.decode("ascii"))

            if self.snapshot_tree is None:
                self._load_snapshot_tree()

            if self.plain_tree is None:
                self._load_plain_tree()

        if self.encrypted_tree is None:
            self._load_encrypted_tree()

    def debug(self, message):
        if self._debug:
            print("[DEBUG]", message)

    @staticmethod
    def info(message):
        print(message)

    def _generate_encrypted_path(self, encrypted_file):
        dirname, name = encrypted_file.split()
        md5 = hashlib.md5(name.encode("utf-8")).hexdigest()
        i = 2
        while True:
            if dirname == '':
                fs_pathname = md5[:i]
            else:
                parent = self.encrypted_tree.get(dirname)
                fs_pathname = parent.fs_pathname + '/' + md5[:i]
            if not self.encrypted_tree.has_fs_pathname(fs_pathname):
                encrypted_file.fs_pathname = fs_pathname
                return
            i += 1
        raise GenerateEncryptedFilePathError()

    def _encrypt_file(self, pathname):
        plain_file = self.plain_tree.get(pathname)
        plain_path = plain_file.fs_path(self.plain_folder)
        encrypted_file = self.encrypted_tree.get(pathname)
        if encrypted_file is None:
            encrypted_file = plain_file.clone()
            self._generate_encrypted_path(encrypted_file)
        encrypted_path = encrypted_file.fs_path(self.encrypted_folder)
        mtime = plain_file.mtime
        if plain_file.isdir:
            if not os.path.exists(encrypted_path):
                os.makedirs(encrypted_path)
            os.chmod(encrypted_path, plain_file.mode | S_IWUSR | S_IRUSR)
            os.utime(encrypted_path, (mtime, mtime))
            encrypted_file.copy_attr_from(plain_file)
            return encrypted_file
        if os.path.isdir(encrypted_path):
            shutil.rmtree(encrypted_path)
        directory = os.path.dirname(encrypted_path)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        plain_fd = open(plain_path, 'rb')
        encrypted_fd = open(encrypted_path, 'wb')
        self.crypto.encrypt_fd(plain_fd, encrypted_fd, plain_file)
        encrypted_file.copy_attr_from(plain_file)
        os.chmod(encrypted_path, plain_file.mode)
        os.utime(encrypted_path, (mtime, mtime))
        plain_fd.close()
        encrypted_fd.close()
        return encrypted_file

    def _decrypt_file(self, pathname):
        encrypted_file = self.encrypted_tree.get(pathname)
        encrypted_path = encrypted_file.fs_path(self.encrypted_folder)
        plain_file = self.plain_tree.get(pathname)
        if plain_file is None:
            plain_file = encrypted_file.clone()
            plain_file.fs_pathname = plain_file.pathname
        plain_path = plain_file.fs_path(self.plain_folder)
        mtime = encrypted_file.mtime
        if encrypted_file.isdir:
            if not os.path.exists(plain_path):
                os.makedirs(plain_path)
            os.chmod(plain_path, encrypted_file.mode | S_IWUSR | S_IRUSR)
            os.utime(plain_path, (mtime, mtime))
            plain_file.copy_attr_from(encrypted_file)
            return plain_file
        if os.path.isdir(plain_path):
            shutil.rmtree(plain_path)
        directory = os.path.dirname(plain_path)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        plain_fd = open(plain_path, 'wb')
        encrypted_fd = open(encrypted_path, 'rb')
        self.crypto.decrypt_fd(encrypted_fd, plain_fd)
        plain_file.copy_attr_from(encrypted_file)
        plain_fd.close()
        encrypted_fd.close()
        os.chmod(plain_path, encrypted_file.mode)
        os.utime(plain_path, (mtime, mtime))
        return plain_file

    def _is_ignore(self, plain_file, encrypted_file):
        return (self.rule_set.test(plain_file) != 'include' and
                self.rule_set.test(encrypted_file) != 'include')

    def _compare_file(self, encrypted_file, plain_file, snapshot_file):
        if self._is_ignore(plain_file, encrypted_file):
            return "exclude"
        if plain_file is not None and encrypted_file is not None:
            if plain_file.mtime > encrypted_file.mtime:
                return "encrypt"
            elif plain_file.mtime < encrypted_file.mtime:
                return "decrypt"
        elif plain_file is not None:
            # encrypted_tree.is_new or \
            if snapshot_file is None or snapshot_file.mtime < plain_file.mtime:
                return "encrypt"
            else:
                return "remove plain"
        elif encrypted_file is not None:
            if snapshot_file is not None and snapshot_file.mtime >= \
                    encrypted_file.mtime:
                return "remove encrypted"
            else:
                return "decrypt"
        return None

    def _encrypted_trash_path(self):
        i = 0
        suffix = ''
        while True:
            path = os.path.join(self.encrypted_folder, '_syncrypto', 'trash',
                                datetime.now().isoformat()+suffix)
            if not os.path.exists(path):
                self._ensure_dir(path)
                return path
            i += 1
            suffix = "."+str(i)

    def _encrypted_tree_path(self):
        path = os.path.join(self.encrypted_folder, '_syncrypto', 'filetree')
        self._ensure_dir(path)
        return path

    def _rule_path(self):
        return self._plain_folder_path("rules")

    def _snapshot_tree_path(self):
        md5 = hashlib.md5(self.encrypted_folder.encode("utf-8")).hexdigest()
        return self._plain_folder_path(md5+'.filetree')

    def _plain_folder_path(self, sub_file):
        filename = ".syncrypto"
        path = os.path.join(self.plain_folder, filename, sub_file)
        self._ensure_dir(path)
        return path

    def _save_trees(self):
        fp = open(self._encrypted_tree_path(), "wb")
        self.crypto.encrypt_fd(
            BytesIO(json.dumps(self.encrypted_tree.to_dict()).encode("utf-8")),
            fp, None, Crypto.COMPRESS)
        fp.close()
        fp = open(self._snapshot_tree_path(), 'wb')
        self.crypto.compress_fd(
            BytesIO(json.dumps(self.snapshot_tree.to_dict()).encode("utf-8")),
            fp)
        fp.close()

    def _load_encrypted_tree(self):
        encrypted_tree_path = self._encrypted_tree_path()
        if not os.path.exists(encrypted_tree_path):
            self.encrypted_tree = FileTree()
        else:
            fp = open(encrypted_tree_path, "rb")
            try:
                tree_fd = BytesIO()
                self.crypto.decrypt_fd(fp, tree_fd)
                tree_fd.seek(0)
                self.encrypted_tree = FileTree.from_dict(
                    json.loads(tree_fd.getvalue().decode("utf-8")))
            except UnrecognizedContent:
                self.encrypted_tree = FileTree()
            finally:
                fp.close()

    def _load_plain_tree(self):
        self.plain_tree = FileTree.from_fs(self.plain_folder,
                                           rule_set=self.rule_set)

    def _load_snapshot_tree(self):
        snapshot_tree_path = self._snapshot_tree_path()
        if not os.path.exists(snapshot_tree_path):
            self.snapshot_tree = FileTree()
        else:
            fp = open(snapshot_tree_path, "rb")
            try:
                tree_fd = BytesIO()
                self.crypto.decompress_fd(fp, tree_fd)
                tree_fd.seek(0)
                self.snapshot_tree = FileTree.from_dict(
                    json.loads(tree_fd.getvalue().decode("utf-8")))
            except UnrecognizedContent:
                self.snapshot_tree = FileTree()
            finally:
                fp.close()

    @staticmethod
    def _ensure_dir(path):
        target_dir = os.path.dirname(path)
        if not os.path.isdir(target_dir):
            os.makedirs(target_dir)

    def _delete_file(self, pathname, target):
        tree, root = None, None
        if target == "encrypted folder":
            tree = self.encrypted_tree
            root = self.encrypted_folder
        elif target == "plaintext folder":
            tree = self.plain_tree
            root = self.plain_folder
        file_entry = tree.get(pathname)
        fs_path = file_entry.fs_path(root)
        if os.path.isdir(fs_path):
            shutil.rmtree(fs_path)
            self.info("Delete folder %s in %s." % (file_entry.fs_pathname,
                                                   target))
        elif os.path.exists(fs_path):
            os.remove(fs_path)
            self.info("Delete file %s in %s." % (file_entry.fs_pathname,
                                                 target))
        tree.remove(pathname)

    @staticmethod
    def _revise_folder(tree, root):
        for entry in tree.folders():
            fs_path = entry.fs_path(root)
            os.utime(fs_path, (entry.mtime, entry.mtime))

    def sync_folder(self):
        if self.plain_folder is None:
            raise Exception("please specify the plaintext folder to sync files")

        results = []
        pathnames = list(set(self.plain_tree.pathnames() +
                             self.encrypted_tree.pathnames()))
        pathnames.sort()
        encrypted_remove_list = []
        plain_remove_list = []
        self.info(("Start synchronizing between encrypted folder %s "
                   "and plaintext folder %s") % (
            self.encrypted_folder, self.plain_folder
        ))
        self.debug("encrypted_tree:")
        self.debug(self.encrypted_tree)
        self.debug("plain_tree:")
        self.debug(self.plain_tree)
        self.debug("snapshot_tree:")
        self.debug(self.snapshot_tree)

        for pathname in pathnames:
            encrypted_file = self.encrypted_tree.get(pathname)
            plain_file = self.plain_tree.get(pathname)
            action = self._compare_file(encrypted_file, plain_file,
                                        self.snapshot_tree.get(pathname))
            self.debug("%s: %s, %s" % (action, encrypted_file, plain_file))
            if action == "remove encrypted":
                encrypted_remove_list.append(pathname)
            elif action == "remove plain":
                plain_remove_list.append(pathname)
            elif action == "encrypt":
                encrypted_file = self._encrypt_file(pathname)
                self.encrypted_tree.set(pathname, encrypted_file)
                self.info("Encrypt %s to %s." %
                          (plain_file.fs_pathname, encrypted_file.fs_pathname))
            elif action == "decrypt":
                plain_file = self._decrypt_file(pathname)
                self.plain_tree.set(pathname, plain_file)
                self.info("Decrypt %s to %s." %
                          (encrypted_file.fs_pathname, plain_file.fs_pathname))
            results.append((action, pathname))

        for pathname in encrypted_remove_list:
            self._delete_file(pathname, "encrypted folder")
        for pathname in plain_remove_list:
            self._delete_file(pathname, "plaintext folder")

        self._revise_folder(self.encrypted_tree, self.encrypted_folder)
        self._revise_folder(self.plain_tree, self.plain_folder)

        self.debug("encrypted_tree:")
        self.debug(self.encrypted_tree)
        self.debug("plain_tree:")
        self.debug(self.plain_tree)
        self.snapshot_tree = self.encrypted_tree
        self._save_trees()
        self.info(("Finish synchronizing between encrypted folder %s "
                   "and plaintext folder %s") % (
            self.encrypted_folder, self.plain_folder
        ))
        return results

    def change_password(self, newpass):
        oldpass = self.crypto.password
        if oldpass == newpass:
            raise ChangeTheSamePassword()
        for file_entry in self.encrypted_tree.files():
            fs_path = file_entry.fs_path(self.encrypted_folder)

            self.crypto.password = oldpass
            fp = open(fs_path, 'rb')
            string = BytesIO()
            self.crypto.decrypt_fd(fp, string)
            fp.close()

            self.crypto.password = newpass
            fp = open(fs_path, 'wb')
            self.crypto.encrypt_fd(string, fp)
            fp.close()
        self.crypto.password = newpass

    def clear_encrypted_folder(self):
        encrypted_tree = FileTree.from_fs(self.encrypted_folder)
        for file_entry in encrypted_tree:
            fs_pathname = file_entry.pathname.replace(os.path.sep, "/")
            fs_path = file_entry.fs_path(self.encrypted_folder)
            if not self.encrypted_tree.has_fs_pathname(fs_pathname):
                if os.path.isdir(fs_path) and len(os.listdir(fs_path)) <= 0:
                    os.rmdir(fs_path)
                else:
                    path = self._encrypted_trash_path()
                    os.rename(fs_path, path)
                    parent = os.path.dirname(fs_path)
                    if len(os.listdir(parent)) <= 0:
                        os.rmdir(parent)


def main(args=sys.argv[1:]):

    from .cli import parser

    args = parser.parse_args(args=args)

    password = args.password

    rule_set = FileRuleSet()

    if args.rule is not None:
        for rule_string in args.rule:
            rule_set.add_rule_by_string(rule_string)

    if not password:
        password = getpass(b'Please input the password:')

    crypto = Crypto(password)

    syncrypto = Syncrypto(crypto, args.encrypted_folder, args.plaintext_folder,
                          rule_set=rule_set, rule_file=args.rule_file,
                          debug=args.debug)

    if args.change_password:
        newpass1 = None
        while True:
            newpass1 = getpass(b'Please input the new password:')
            newpass2 = getpass(b'Please re input the new password:')
            if len(newpass1) < 6:
                print("new password is too short")
            elif newpass1 != newpass2:
                print("two inputs are not match")
            else:
                break
        syncrypto.change_password(newpass1)
        return 0
    elif args.clear_encrypted_folder:
        syncrypto.clear_encrypted_folder()
        return 0
    elif args.print_encrypted_tree:
        print(syncrypto.encrypted_tree)
        return 0
    elif args.plaintext_folder:
        if args.interval:
            while True:
                syncrypto.sync_folder()
                sleep(args.interval)
        else:
            syncrypto.sync_folder()
        return 0
    return 1
