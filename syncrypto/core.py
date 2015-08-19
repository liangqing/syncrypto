#!/usr/bin/env python
# -*- coding: utf-8 -*- 

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
from crypto import Crypto, UnrecognizedContent
from filetree import FileTree
from cStringIO import StringIO


class GenerateEncryptedFilePathError(Exception):
    pass


class ChangeTheSamePassword(Exception):
    pass


class Syncrypto:

    def __init__(self, crypto, encrypted_folder, plain_folder=None,
                 encrypted_tree=None, plain_tree=None, snapshot_tree=None,
                 rule_set=None):

        self.crypto = crypto
        self.encrypted_folder = encrypted_folder
        self.plain_folder = plain_folder
        self.encrypted_tree = encrypted_tree
        self.plain_tree = plain_tree
        self.snapshot_tree = snapshot_tree
        self.rule_set = rule_set

        if not os.path.isdir(self.encrypted_folder):
            raise Exception("encrypted folder path is not directory: " +
                            self.encrypted_folder)

        if plain_folder is not None:
            if not os.path.isdir(self.plain_folder):
                raise Exception("plain folder path is not directory: " +
                                self.plain_folder)
            if self.snapshot_tree is None:
                self._load_snapshot_tree()

            if self.plain_tree is None:
                self._load_plain_tree()

        if self.encrypted_tree is None:
            self._load_encrypted_tree()

    def _generate_encrypted_path(self, encrypted_file):
        dirname, name = encrypted_file.split()
        md5 = hashlib.md5(name).hexdigest()
        i = 2
        while True:
            if dirname == '':
                fs_pathname = md5[:i]
            else:
                fs_pathname = dirname + '/' + md5[:i]
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
            self.encrypted_tree.put(pathname, encrypted_file)
        encrypted_path = encrypted_file.fs_path(self.encrypted_folder)
        mtime = plain_file.mtime
        if os.path.isdir(plain_path):
            if not os.path.exists(encrypted_path):
                os.makedirs(encrypted_path)
            os.chmod(encrypted_path, plain_file.mode | S_IWUSR | S_IRUSR)
            os.utime(encrypted_path, (mtime, mtime))
            return
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

    def _decrypt_file(self, pathname):
        encrypted_file = self.encrypted_tree.get(pathname)
        encrypted_path = encrypted_file.fs_path(self.encrypted_folder)
        plain_file = self.plain_tree.get(pathname)
        if plain_file is None:
            plain_file = encrypted_file.clone()
            plain_file.fs_pathname = plain_file.pathname
            self.plain_tree.put(pathname, plain_file)
        plain_path = plain_file.fs_path(self.plain_folder)
        mtime = encrypted_file.mtime
        if os.path.isdir(encrypted_path):
            if not os.path.exists(plain_path):
                os.makedirs(plain_path)
            os.chmod(plain_path, encrypted_file.mode | S_IWUSR | S_IRUSR)
            os.utime(plain_path, (mtime, mtime))
            return
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

    def _sync_file(self, pathname):
        plain_file = self.plain_tree.get(pathname)
        encrypted_file = self.encrypted_tree.get(pathname)
        snapshot_file = self.snapshot_tree.get(pathname)
        if plain_file is not None and encrypted_file is not None:
            if plain_file.mtime > encrypted_file.mtime:
                self._encrypt_file(pathname)
                return "decrypted", plain_file
            elif plain_file.mtime < encrypted_file.mtime:
                self._decrypt_file(pathname)
                return "encrypted", encrypted_file
        elif plain_file is not None:
            # encrypted_tree.is_new or \
            if snapshot_file is None or snapshot_file.mtime < plain_file.mtime:
                self._encrypt_file(pathname)
                return "encrypted", plain_file
            else:
                fs_path = plain_file.fs_path(self.plain_folder)
                if os.path.isdir(fs_path):
                    shutil.rmtree(fs_path)
                    return "remove plain directory", None
                elif os.path.exists(fs_path):
                    os.remove(fs_path)
                    return "remove plain file", None
        elif encrypted_file is not None:
            if snapshot_file is not None and snapshot_file.mtime >= \
                    encrypted_file.mtime:
                fs_path = encrypted_file.fs_path(self.encrypted_folder)
                if os.path.isdir(fs_path):
                    shutil.rmtree(fs_path)
                    return "remove encrypted directory", None
                elif os.path.exists(fs_path):
                    os.remove(fs_path)
                    return "remove encrypted file", None
            else:
                self._decrypt_file(pathname)
                return "decrypted", encrypted_file
        return None, None

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

    def _snapshot_tree_path(self):
        md5 = hashlib.md5(self.encrypted_folder).hexdigest()
        filename = ".syncrypto"
        if os.name == 'nt':
            filename = "_syncrypto"
        path = os.path.join(self.plain_folder, filename, md5+'.filetree')
        self._ensure_dir(path)
        return path

    def _save_trees(self):
        fp = open(self._encrypted_tree_path(), "wb")
        self.crypto.encrypt_fd(
            StringIO(json.dumps(self.encrypted_tree.to_dict())),
            fp, None, Crypto.COMPRESS)
        fp.close()
        fp = open(self._snapshot_tree_path(), 'wb')
        self.crypto.compress_fd(
            StringIO(json.dumps(self.snapshot_tree.to_dict())), fp)
        fp.close()

    def _load_encrypted_tree(self):
        encrypted_tree_path = self._encrypted_tree_path()
        if not os.path.exists(encrypted_tree_path):
            self.encrypted_tree = FileTree()
        else:
            fp = open(encrypted_tree_path, "rb")
            try:
                tree_fd = StringIO()
                self.crypto.decrypt_fd(fp, tree_fd)
                tree_fd.seek(0)
                self.encrypted_tree = FileTree.from_dict(json.load(tree_fd))
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
                tree_fd = StringIO()
                self.crypto.decompress_fd(fp, tree_fd)
                tree_fd.seek(0)
                self.snapshot_tree = FileTree.from_dict(json.load(tree_fd))
            except UnrecognizedContent:
                self.snapshot_tree = FileTree()
            finally:
                fp.close()

    @staticmethod
    def _ensure_dir(path):
        target_dir = os.path.dirname(path)
        if not os.path.isdir(target_dir):
            os.makedirs(target_dir)

    def sync_folder(self):
        if self.plain_folder is None:
            raise Exception("please specify the plaintext folder to sync files")
        pathnames = set(self.plain_tree.pathnames() + self.encrypted_tree.
                        pathnames())
        new_snapshot_tree = FileTree()
        results = []
        for pathname in pathnames:
            action, file_entry = self._sync_file(pathname)
            new_snapshot_tree.set(pathname, file_entry)
            results.append((action, file_entry))
        self.snapshot_tree = new_snapshot_tree
        self._save_trees()
        return results

    def change_password(self, newpass):
        oldpass = self.crypto.password
        if oldpass == newpass:
            raise ChangeTheSamePassword()
        for file_entry in self.encrypted_tree.files():
            fs_path = file_entry.fs_path(self.encrypted_folder)

            self.crypto.password = oldpass
            fp = open(fs_path, 'rb')
            string = StringIO()
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

    from cli import parser

    args = parser.parse_args(args=args)

    password = args.password

    if not password:
        password = getpass('please input the password:')

    crypto = Crypto(password)

    syncrypto = Syncrypto(crypto, args.encrypted_folder, args.plaintext_folder)

    if args.change_password:
        newpass1 = None
        while True:
            newpass1 = getpass('please input the new password:')
            newpass2 = getpass('please re input the new password:')
            if len(newpass1) < 6:
                print "new password is too short"
            elif newpass1 != newpass2:
                print "two inputs are not match"
            else:
                break
        syncrypto.change_password(newpass1)
        return 0
    elif args.clear_encrypted_folder:
        syncrypto.clear_encrypted_folder()
        return 0
    elif args.print_encrypted_tree:
        print syncrypto.encrypted_tree
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

