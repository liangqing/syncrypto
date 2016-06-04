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
import sys
import os.path
import shutil
import json
from datetime import datetime
from time import sleep, time
from lockfile.mkdirlockfile import MkdirLockFile as LockFile
from random import randint
from stat import S_IWUSR, S_IRUSR
from .crypto import Crypto, DecryptError
from .filetree import FileTree, FileRuleSet, FileEntry
from .util import printable_text, string_digest, getpass

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


DEFAULT_RULES = b"""ignore: name eq .Trashes
ignore: name eq .fseventsd
ignore: name eq Thumb.db
ignore: name eq node_modules
ignore: name eq .sass-cache
ignore: name eq .idea
ignore: name eq .git
ignore: name eq .svn
ignore: name eq .hg
ignore: name eq .cvs
ignore: name match *.pyc
ignore: name match *.class
ignore: name match .*TemporaryItems
ignore: name match .*DS_Store
ignore: name match *.swp
ignore: name match *.swo"""


class Syncrypto(object):

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
        self._encrypted_folder_is_new = False
        self._trash_name = self._generate_trash_name()
        self._snapshot_trash_name = None
        self._snapshot_tree_name = string_digest(self.encrypted_folder)
        self._encrypted_filetree_entry = None

        if not os.path.isdir(self.encrypted_folder):
            if os.path.exists(self.encrypted_folder):
                raise InvalidFolder("Encrypted folder path is not correct: " +
                                    self.encrypted_folder)
            else:
                os.makedirs(self.encrypted_folder)

        if os.path.exists(os.path.join(self.encrypted_folder, ".syncrypto")):
            raise InvalidFolder("Encrypted folder can not has .syncrypto folder"
                                " within it, do you pass the wrong arguments?")

        if plain_folder is not None:
            if not os.path.isdir(self.plain_folder):
                if os.path.exists(self.plain_folder):
                    raise InvalidFolder(
                        "Plaintext folder path is not correct: " +
                        self.plain_folder)
                else:
                    os.makedirs(self.plain_folder)

            if os.path.exists(
                    os.path.join(self.plain_folder, "_syncrypto")):
                raise InvalidFolder(
                    "Plaintext folder can not has _syncrypto folder within it"
                    ", do you pass the wrong arguments?")

            if self.rule_set is None:
                self.rule_set = FileRuleSet()

            if rule_file is None:
                rule_file = self._plain_rule_path()
                if not os.path.exists(rule_file):
                    with open(rule_file, "wb") as f:
                        f.write(DEFAULT_RULES)

            if os.path.exists(rule_file):
                with open(rule_file, 'rb') as f:
                    for line in f:
                        line = line.strip()
                        if line == b"" or line[0] == b'#':
                            continue
                        self.rule_set.add_rule_by_string(line.decode("ascii"))

    def debug(self, message):
        if self._debug:
            print("[DEBUG]", printable_text(message))

    @staticmethod
    def info(message):
        print(printable_text(message))

    @staticmethod
    def error(message):
        print(printable_text(message), file=sys.stderr)

    @staticmethod
    def _generate_trash_name():
        return datetime.now().isoformat().replace(':', '_')

    def _generate_encrypted_path(self, encrypted_file):
        dirname, name = encrypted_file.split()
        digest = string_digest(name)
        i = 2
        while True:
            if dirname == '':
                fs_pathname = digest[:i]
            else:
                parent = self.encrypted_tree.get(dirname)
                if parent is None:
                    self.error("Can not find file entry for %s" %
                               dirname)
                    raise GenerateEncryptedFilePathError()
                fs_pathname = parent.fs_pathname + '/' + digest[:i]
            if not self.encrypted_tree.has_fs_pathname(fs_pathname):
                encrypted_file.fs_pathname = fs_pathname
                return
            i += 1
        raise GenerateEncryptedFilePathError()

    def _encrypt_file(self, pathname):
        plain_file = self.plain_tree.get(pathname)
        plain_path = plain_file.fs_path(self.plain_folder)
        encrypted_file = self.encrypted_tree.get(pathname)
        if not os.path.exists(plain_path):
            self.error("%s not exists!" % plain_path)
            return encrypted_file
        if encrypted_file is None:
            encrypted_file = plain_file.clone()
            if pathname.startswith(".syncrypto/"):
                encrypted_file.fs_pathname = '_'+plain_file.fs_pathname[1:]
            else:
                try:
                    self._generate_encrypted_path(encrypted_file)
                except GenerateEncryptedFilePathError:
                    return None
        encrypted_path = encrypted_file.fs_path(self.encrypted_folder)
        mtime = plain_file.mtime
        if plain_file.isdir:
            if not os.path.exists(encrypted_path):
                os.makedirs(encrypted_path)
            encrypted_file.copy_attr_from(plain_file)
            return encrypted_file
        if os.path.exists(encrypted_path):
            self._move_to_encrypted_trash(encrypted_file)
        directory = os.path.dirname(encrypted_path)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        plain_fd = open(plain_path, 'rb')
        encrypted_fd = open(encrypted_path, 'wb')
        self.crypto.encrypt_fd(plain_fd, encrypted_fd, plain_file)
        encrypted_file.copy_attr_from(plain_file)
        if plain_file.mode is not None:
            os.chmod(encrypted_path, plain_file.mode)
        os.utime(encrypted_path, (mtime, mtime))
        plain_fd.close()
        encrypted_fd.close()
        return encrypted_file

    def _decrypt_file(self, pathname):
        encrypted_file = self.encrypted_tree.get(pathname)
        encrypted_path = encrypted_file.fs_path(self.encrypted_folder)
        plain_file = self.plain_tree.get(pathname)
        if not os.path.exists(encrypted_path):
            self.error("%s not exists!" % encrypted_path)
            return plain_file
        if plain_file is None:
            plain_file = encrypted_file.clone()
            plain_file.fs_pathname = plain_file.pathname
        plain_path = plain_file.fs_path(self.plain_folder)
        mtime = encrypted_file.mtime
        if encrypted_file.isdir:
            if not os.path.exists(plain_path):
                os.makedirs(plain_path)
            if encrypted_file.mode is not None:
                os.chmod(plain_path, encrypted_file.mode | S_IWUSR | S_IRUSR)
            os.utime(plain_path, (mtime, mtime))
            plain_file.copy_attr_from(encrypted_file)
            return plain_file
        if os.path.exists(plain_path):
            self._move_to_plain_trash(plain_file)
        directory = os.path.dirname(plain_path)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        plain_fd = open(plain_path, 'wb')
        encrypted_fd = open(encrypted_path, 'rb')
        self.crypto.decrypt_fd(encrypted_fd, plain_fd)
        plain_file.copy_attr_from(encrypted_file)
        plain_fd.close()
        encrypted_fd.close()
        if encrypted_file.mode is not None:
            os.chmod(plain_path, encrypted_file.mode)
        os.utime(plain_path, (mtime, mtime))
        return plain_file

    @staticmethod
    def _conflict_path(path):
        dirname = os.path.dirname(path)
        filename = os.path.basename(path)
        dot_pos = filename.rfind(".")
        if dot_pos > 0:
            name = filename[:dot_pos]
            ext = filename[dot_pos:]
        else:
            name = filename
            ext = ""
        name += ".conflict"
        conflict_path = os.path.join(dirname, name+ext)
        i = 1
        if os.path.exists(conflict_path):
            conflict_path = \
                os.path.join(dirname, name+"."+str(i)+ext)
            i += 1
        return conflict_path

    def _is_ignore(self, plain_file, encrypted_file):
        return (self.rule_set.test(plain_file) != 'include' or
                self.rule_set.test(encrypted_file) != 'include')

    @staticmethod
    def _is_equal(file_entry, file_entry_compare):
        if file_entry is None or file_entry_compare is None:
            return False
        if file_entry.isdir and file_entry_compare.isdir:
            return True
        if file_entry.digest is not None \
                and file_entry_compare.digest is not None:
            return file_entry.digest == file_entry_compare.digest
        return \
            file_entry.size == file_entry_compare.size and \
            int(file_entry.mtime) == int(file_entry_compare.mtime)

    def _compare_file(self, encrypted_file, plain_file, snapshot_file):
        if self._is_ignore(plain_file, encrypted_file):
            return "ignore"
        if self._encrypted_folder_is_new:
            return "encrypt"
        if self._is_equal(plain_file, encrypted_file):
            return 'same'
        plain_file_changed = not self._is_equal(plain_file, snapshot_file)
        encrypted_file_changed = not self._is_equal(encrypted_file,
                                                    snapshot_file)
        if plain_file is not None and encrypted_file is not None:
            if plain_file_changed and not encrypted_file_changed:
                return "encrypt"
            elif encrypted_file_changed and not plain_file_changed:
                return "decrypt"
            elif not encrypted_file_changed and not plain_file_changed:
                return "same"
            else:
                return 'conflict'
        elif plain_file is not None:
            if plain_file_changed:
                return "encrypt"
            else:
                return "remove plain"
        elif encrypted_file is not None:
            if encrypted_file_changed:
                return "decrypt"
            else:
                return "remove encrypted"
        return None

    def _move_to_encrypted_trash(self, file_entry):
        trash_path = self._trash_path_in_encrypted_folder(file_entry)
        if os.path.exists(trash_path):
            if os.path.isdir(trash_path):
                shutil.rmtree(trash_path)
            else:
                os.remove(trash_path)
        shutil.move(file_entry.fs_path(self.encrypted_folder), trash_path)

    def _move_to_plain_trash(self, file_entry):
        trash_path = self._trash_path_in_plain_folder(file_entry)
        if os.path.exists(trash_path):
            if os.path.isdir(trash_path):
                shutil.rmtree(trash_path)
            else:
                os.remove(trash_path)
        shutil.move(file_entry.fs_path(self.plain_folder), trash_path)

    def _trash_path_in_encrypted_folder(self, file_entry):
        path = file_entry.fs_path(
            os.path.join(self.encrypted_folder, '_syncrypto', 'trash',
                         self._trash_name))
        self._ensure_dir(path)
        return path

    def _trash_path_in_plain_folder(self, file_entry):
        path = file_entry.fs_path(
            os.path.join(self.plain_folder, '.syncrypto', 'trash',
                         self._trash_name))
        self._ensure_dir(path)
        return path

    def _plain_rule_path(self):
        return self._plain_folder_path("rules")

    def _encrypted_rule_path(self):
        return self._plain_folder_path("rules")

    def _encrypted_tree_path(self):
        return self._encrypted_folder_path("filetree")

    def _snapshot_tree_path(self):
        return self._plain_folder_path(self._snapshot_tree_name+'.filetree')

    def _plain_folder_path(self, sub_file):
        filename = ".syncrypto"
        path = os.path.join(self.plain_folder, filename, sub_file)
        self._ensure_dir(path)
        return path

    def _encrypted_folder_path(self, sub_file):
        filename = "_syncrypto"
        path = os.path.join(self.encrypted_folder, filename, sub_file)
        self._ensure_dir(path)
        return path

    def _save_trees(self):
        self._save_encrypted_tree()
        self._save_snapshot_tree()

    def _save_encrypted_tree(self):
        fp = open(self._encrypted_tree_path(), "wb")
        tree_dict = self.encrypted_tree.to_dict()
        tree_dict["snapshot_tree_name"] = self._snapshot_tree_name
        self.crypto.encrypt_fd(BytesIO(json.dumps(tree_dict).encode("utf-8")),
                               fp, self._encrypted_filetree_entry,
                               Crypto.COMPRESS)
        fp.close()

    def _load_encrypted_tree(self):
        encrypted_tree_path = self._encrypted_tree_path()
        if not os.path.exists(encrypted_tree_path):
            self.encrypted_tree = FileTree()
            self._encrypted_folder_is_new = True
            snapshot_tree_path = \
                os.path.join(self.plain_folder, ".syncrypto",
                             self._snapshot_tree_name+".filetree")
            if not os.path.exists(snapshot_tree_path):
                self._snapshot_tree_name = string_digest(
                    os.path.abspath(self.encrypted_folder)+str(time()))
        else:
            fp = open(encrypted_tree_path, "rb")
            try:
                tree_fd = BytesIO()
                self._encrypted_filetree_entry = \
                    self.crypto.decrypt_fd(fp, tree_fd)
                tree_fd.seek(0)
                tree_dict = json.loads(tree_fd.getvalue().decode("utf-8"))
                if "snapshot_tree_name" in tree_dict:
                    self._snapshot_tree_name = tree_dict["snapshot_tree_name"]
                self.encrypted_tree = FileTree.from_dict(tree_dict)
            finally:
                fp.close()

    def _save_snapshot_tree(self):
        fp = open(self._snapshot_tree_path(), 'wb')
        snapshot_tree_dict = self.snapshot_tree.to_dict()
        snapshot_tree_dict["trash_name"] = self._trash_name
        self.crypto.compress_fd(
            BytesIO(json.dumps(snapshot_tree_dict).encode("utf-8")), fp)
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
                snapshot_tree_dict = \
                    json.loads(tree_fd.getvalue().decode("utf-8"))
                if "trash_name" in snapshot_tree_dict:
                    self._snapshot_trash_name = snapshot_tree_dict["trash_name"]
                self.snapshot_tree = FileTree.from_dict(snapshot_tree_dict)
            finally:
                fp.close()

    @staticmethod
    def _ensure_dir(path):
        target_dir = os.path.dirname(path)
        if not os.path.isdir(target_dir):
            os.makedirs(target_dir)

    def _delete_file(self, pathname, is_in_encrypted_folder):
        tree, root, target = None, None, None
        if is_in_encrypted_folder:
            tree = self.encrypted_tree
            root = self.encrypted_folder
            target = "encrypted folder"
        else:
            tree = self.plain_tree
            root = self.plain_folder
            target = "plaintext folder"
        file_entry = tree.get(pathname)
        fs_path = file_entry.fs_path(root)
        if os.path.isdir(fs_path):
            if is_in_encrypted_folder:
                self._move_to_encrypted_trash(file_entry)
            else:
                self._move_to_plain_trash(file_entry)
            self.info("Delete folder %s in %s" % (file_entry.pathname,
                                                  target))
        elif os.path.exists(fs_path):
            if is_in_encrypted_folder:
                self._move_to_encrypted_trash(file_entry)
            else:
                self._move_to_plain_trash(file_entry)
            self.info("Delete file %s in %s" % (file_entry.pathname,
                                                target))
        tree.remove(pathname)

    @staticmethod
    def _revise_folder(tree, root):
        for entry in tree.folders():
            fs_path = entry.fs_path(root)
            os.utime(fs_path, (entry.mtime, entry.mtime))

    def _do_sync_folder(self):

        if self.plain_folder is None:
            raise Exception("please specify the plaintext folder to sync files")

        pathnames = list(set(self.plain_tree.pathnames() +
                             self.encrypted_tree.pathnames()))
        pathnames.sort()
        encrypted_remove_list = []
        plain_remove_list = []
        self.info(("Start synchronizing between encrypted folder '%s' "
                   "and plaintext folder '%s'") % (
            self.encrypted_folder, self.plain_folder
        ))
        self.debug("encrypted_tree:")
        self.debug(self.encrypted_tree)
        self.debug("plain_tree:")
        self.debug(self.plain_tree)
        self.debug("snapshot_tree:")
        self.debug(self.snapshot_tree)
        if os.path.exists(self._plain_rule_path()) \
                or os.path.exists(self._encrypted_rule_path()):
            pathnames.append(".syncrypto/rules")
            self.plain_tree.set(".syncrypto/rules",
                                FileEntry.from_file(self._plain_rule_path(),
                                                    ".syncrypto/rules"))
        ignore_prefix = None
        for pathname in pathnames:
            if ignore_prefix is not None \
                    and pathname.startswith(ignore_prefix):
                self.plain_tree.remove(pathname)
                self.encrypted_tree.remove(pathname)
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
                if encrypted_file is None:
                    continue
                self.encrypted_tree.set(pathname, encrypted_file)
                if not encrypted_file.isdir:
                    self.info("Encrypt %s to %s" %
                              (plain_file.fs_pathname,
                               encrypted_file.fs_pathname))
            elif action == "decrypt":
                plain_file = self._decrypt_file(pathname)
                if plain_file is None:
                    continue
                self.plain_tree.set(pathname, plain_file)
                if not plain_file.isdir:
                    self.info("Decrypt %s to %s" %
                              (encrypted_file.fs_pathname,
                               plain_file.fs_pathname))
            elif action == "same":
                if not encrypted_file.isdir:
                    self.debug("%s is not changed " % plain_file.fs_pathname)
            elif action == 'conflict':
                if plain_file.isdir and encrypted_file.isdir:
                    continue
                plain_path = plain_file.fs_path(self.plain_folder)
                shutil.move(plain_path, self._conflict_path(plain_path))
                if plain_file.isdir:
                    ignore_prefix = pathname
                plain_file = self._decrypt_file(pathname)
                self.plain_tree.set(pathname, plain_file)
                self.info("%s has conflict!" % plain_file.fs_pathname)
            elif action == 'ignore':
                if encrypted_file is not None:
                    encrypted_remove_list.append(pathname)
                if (plain_file is not None and plain_file.isdir) \
                        or \
                        (encrypted_file is not None and encrypted_file.isdir):
                    ignore_prefix = pathname+'/'

        for pathname in encrypted_remove_list:
            self._delete_file(pathname, True)
        for pathname in plain_remove_list:
            self._delete_file(pathname, False)

        self._revise_folder(self.plain_tree, self.plain_folder)

        self.debug("encrypted_tree:")
        self.debug(self.encrypted_tree)
        self.debug("plain_tree:")
        self.debug(self.plain_tree)
        self.snapshot_tree = self.encrypted_tree
        self._save_trees()
        self.info(("Finish synchronizing between encrypted folder '%s' "
                   "and plaintext folder '%s'") % (
            self.encrypted_folder, self.plain_folder
        ))
        self._trash_name = self._generate_trash_name()

    def sync_folder(self, reload_tree=True):
        encrypted_folder_lock = LockFile(self.encrypted_folder)
        if encrypted_folder_lock.is_locked():
            self.info("Acquiring the lock of encrypted folder...")
        else:
            self.debug("Encrypted folder is not locked")
        with encrypted_folder_lock:
            self.debug("Acquired the encrypted folder's lock")
            plain_folder_lock = LockFile(self.plain_folder)
            if plain_folder_lock.is_locked():
                self.info("Acquiring the lock of plaintext folder...")
            else:
                self.debug("Plaintext folder is not locked")
            with plain_folder_lock:
                self.debug("Acquired the plaintext folder's lock")
                if reload_tree:
                    self._load_encrypted_tree()
                    self._load_plain_tree()
                    self._load_snapshot_tree()
                if self.snapshot_tree is None:
                    self._load_snapshot_tree()
                self._do_sync_folder()

    def change_password(self, newpass):
        if self.encrypted_tree is None:
            self._load_encrypted_tree()
        newpass = newpass.encode('utf-8')
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

            string.seek(0)
            self.crypto.password = newpass
            fp = open(fs_path, 'wb')
            self.crypto.encrypt_fd(string, fp, file_entry)
            fp.close()
        self.crypto.password = newpass
        self._save_encrypted_tree()


def _generate_tmp_path(folder=None):
    if folder is None:
        folder = os.getcwd()
    while True:
        path = os.path.join(folder,
                            "%d_%d" % (int(time()), randint(1000, 9999)))
        if not os.path.exists(path):
            return path


def cli_decrypt_file(crypto, encrypted_path, plain_path=None):
    if not os.path.isfile(encrypted_path):
        print(printable_text(encrypted_path+" is not a file"))
        return 1
    if plain_path is not None:
        file_entry = crypto.decrypt_file(encrypted_path, plain_path)
    else:
        tmp_path = _generate_tmp_path()
        file_entry = crypto.decrypt_file(encrypted_path, tmp_path)
        plain_path = file_entry.name()
        os.rename(tmp_path, plain_path)
    if file_entry.mode is not None:
        os.chmod(plain_path, file_entry.mode)
    os.utime(plain_path, (file_entry.mtime, file_entry.mtime))
    return 0


def cli_encrypt_file(crypto, plain_path, encrypted_path=None):
    if not os.path.isfile(plain_path):
        print(printable_text(plain_path+" is not a file"))
        return 1
    filename = os.path.basename(plain_path)
    pos = filename.rfind('.')
    if pos > 0:
        name = filename[:pos]
        ext = filename[pos:]
    else:
        name = filename
        ext = ''
    file_entry = FileEntry.from_file(plain_path, filename)
    if encrypted_path is not None:
        crypto.encrypt_file(plain_path, encrypted_path, file_entry)
    else:
        encrypted_path = os.path.join(os.path.dirname(plain_path),
                                      name+'.encrypted'+ext)
        crypto.encrypt_file(plain_path, encrypted_path, file_entry)
    return 0


def main(args=sys.argv[1:]):

    from .cli import parser

    args = parser.parse_args(args=args)

    if args.version:
        from .package_info import __version__
        print(__version__)
        return 1

    password = None

    if args.password_file is not None and os.path.exists(args.password_file):
        with open(args.password_file) as f:
            password = f.read().strip("\n")

    rule_set = FileRuleSet()

    if args.rule is not None:
        for rule_string in args.rule:
            rule_set.add_rule_by_string(rule_string)

    if password is None:
        password = getpass('Please input the password:')

    crypto = Crypto(password)

    try:

        if args.decrypt_file is not None:
            return cli_decrypt_file(crypto, args.decrypt_file, args.out_file)

        if args.encrypt_file is not None:
            return cli_encrypt_file(crypto, args.encrypt_file, args.out_file)

        if args.encrypted_folder is None:
            parser.print_help()
            return 1

        syncrypto = Syncrypto(crypto,
                              args.encrypted_folder,
                              args.plaintext_folder,
                              rule_set=rule_set,
                              rule_file=args.rule_file,
                              debug=args.debug)
        if args.change_password:
            newpass1 = None
            while True:
                newpass1 = getpass('Please input the new password:')
                newpass2 = getpass('Please re input the new password:')
                if len(newpass1) < 6:
                    print("new password is too short")
                elif newpass1 != newpass2:
                    print("two inputs are not match")
                else:
                    break
            syncrypto.change_password(newpass1)
        elif args.print_encrypted_tree:
            print(printable_text(syncrypto.encrypted_tree))
        elif args.plaintext_folder is not None:
            if args.interval:
                while True:
                    syncrypto.sync_folder()
                    sleep(args.interval)
            else:
                syncrypto.sync_folder()
        return 0
    except DecryptError:
        print("Your password is not correct")
        return 3
    except InvalidFolder as e:
        print(e.args[0])
        return 4
