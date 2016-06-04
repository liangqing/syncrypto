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
from __future__ import division
from io import open
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import zlib
import hashlib
from struct import pack, unpack
from time import time
from io import BytesIO
from .filetree import FileEntry


class InvalidKey(Exception):
    pass


class DecryptError(Exception):
    pass


class VersionNotCompatible(Exception):
    pass


class Crypto(object):

    VERSION = 0x1

    COMPRESS = 0x1

    BUFFER_SIZE = 1024 * 16

    def __init__(self, password, key_size=32):

        self.password = password.encode("utf-8")
        self.key_size = key_size
        self.block_size = 16

    def encrypt_file(self, plain_path, encrypted_path, plain_file_entry):
        with open(plain_path, 'rb') as plain_fd:
            with open(encrypted_path, 'wb') as encrypted_fd:
                self.encrypt_fd(plain_fd, encrypted_fd, plain_file_entry)

    def decrypt_file(self, encrypted_path, plain_path):
        with open(encrypted_path, 'rb') as encrypted_fd:
            with open(plain_path, 'wb') as plain_fd:
                return self.decrypt_fd(encrypted_fd, plain_fd)

    @staticmethod
    def compress_fd(in_fd, out_fd):
        compress_obj = zlib.compressobj()
        while True:
            data = in_fd.read(Crypto.BUFFER_SIZE)
            if len(data) > 0:
                out_fd.write(compress_obj.compress(data))
            else:
                break
        out_fd.write(compress_obj.flush())

    @staticmethod
    def decompress_fd(in_fd, out_fd):
        decompress_obj = zlib.decompressobj()
        while True:
            data = in_fd.read(Crypto.BUFFER_SIZE)
            if len(data) > 0:
                out_fd.write(decompress_obj.decompress(data))
            else:
                break
        out_fd.write(decompress_obj.flush())

    def gen_key_and_iv(self, salt):
        d = d_i = b''
        while len(d) < self.key_size + self.block_size:
            d_i = hashlib.md5(d_i + self.password + salt).digest()
            d += d_i
        return d[:self.key_size], d[self.key_size:self.key_size+self.block_size]

    @staticmethod
    def _build_footer(file_entry):
        return file_entry.digest + \
               pack(b'!Q', file_entry.size) + \
               pack(b'!I', int(file_entry.mtime)) + \
               pack(b'!i', file_entry.mode or 0)

    @staticmethod
    def _unpack_footer(pathname, footer):
        (size, mtime, mode) = unpack(b'!QIi', footer[16:32])
        if mode == 0:
            mode = None
        return FileEntry(pathname, size, None, mtime, mode,
                         footer[:16], False)

    def encrypt_fd(self, in_fd, out_fd, file_entry, flags=0):
        """
            +-----------------------------------------------------+
            | Version(1) | Flags(1) | Pathname size(2) | Salt(12) |
            +-----------------------------------------------------+
            |                  Encrypted Pathname                 |
            +-----------------------------------------------------+
            |                  Encrypted Content                  |
            |                        ...                          |
            +-----------------------------------------------------+
            |              Encrypted Content Digest(16)           |
            +-----------------------------------------------------+
            |         size(8)*        |   mtime(4)   |   mode(4)  |
            +-----------------------------------------------------+
            |              Encrypted Entire Digest(16)            |
            +-----------------------------------------------------+

            * size, mtime, mode are also encrypted
        """
        bs = self.block_size
        if file_entry is None:
            file_entry = FileEntry('file_entry.tmp', 0, time(), time(), 0)
        if file_entry.salt is None:
            file_entry.salt = os.urandom(bs - 4)
        key, iv = self.gen_key_and_iv(file_entry.salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        pathname = file_entry.pathname.encode("utf-8")[:2**16]
        pathname_size = len(pathname)
        pathname_padding = b''
        if pathname_size % bs != 0:
            padding_length = (bs - pathname_size % bs)
            pathname_padding = padding_length * b'\0'

        flags &= 0xFF
        out_fd.write(pack(b'BB', self.VERSION, flags))
        out_fd.write(pack(b'!H', pathname_size))
        out_fd.write(file_entry.salt)
        out_fd.write(encryptor.update(pathname+pathname_padding))
        compress_obj = None
        if flags & Crypto.COMPRESS:
            compress_obj = zlib.compressobj()

        finished = False
        md5 = hashlib.md5()
        rest = b''
        end = False
        while not finished:
            if compress_obj is not None:
                buf = BytesIO()
                buf.write(rest)
                compress_size = len(rest)
                while compress_size < self.BUFFER_SIZE:
                    in_data = in_fd.read(self.BUFFER_SIZE)
                    if len(in_data) == 0:
                        end = True
                        try:
                            buf.write(compress_obj.flush())
                        except Exception:
                            pass
                        break
                    md5.update(in_data)
                    compress_data = compress_obj.compress(in_data)
                    compress_size += len(compress_data)
                    buf.write(compress_data)
                data = buf.getvalue()
                data_size = len(data)
                if end:
                    chunk = data
                elif data_size < self.BUFFER_SIZE:
                    rest_size = data_size % bs
                    chunk = data[:-rest_size]
                    rest = data[-rest_size:]
                else:
                    chunk = data[:self.BUFFER_SIZE]
                    rest = data[self.BUFFER_SIZE:]
            else:
                chunk = in_fd.read(self.BUFFER_SIZE)
                md5.update(chunk)
            if len(chunk) == 0 or len(chunk) % bs != 0:
                padding_length = (bs - len(chunk) % bs) or bs
                chunk += padding_length * pack(b'B', padding_length)
                finished = True
            out_fd.write(encryptor.update(chunk))

        file_entry.digest = md5.digest()
        footer = self._build_footer(file_entry)
        md5.update(footer)
        entire_digest = md5.digest()
        out_fd.write(encryptor.update(footer))
        out_fd.write(encryptor.update(entire_digest))
        out_fd.write(encryptor.finalize())
        return file_entry

    def decrypt_fd(self, in_fd, out_fd):
        (version, flags, salt, pathname, decryptor) = \
            self.extract_header(in_fd)
        md5 = hashlib.md5()
        next_chunk = ''
        finished = False
        file_entry = None
        decompress_obj = None
        if flags & self.COMPRESS:
            decompress_obj = zlib.decompressobj()
        footer_size = 48
        entire_digest = None
        entire_digest_check = None
        content_digest_check = None
        footer = None
        while not finished:
            chunk, next_chunk = next_chunk, in_fd.read(self.BUFFER_SIZE)
            if not chunk:
                continue
            plaintext = decryptor.update(chunk)
            if len(next_chunk) < self.BUFFER_SIZE:
                plaintext += decryptor.update(next_chunk)
                plaintext += decryptor.finalize()
                entire_digest = plaintext[-16:]
                footer = plaintext[-footer_size:-16]
                file_entry = self._unpack_footer(pathname, footer)
                padding_length = 0
                if len(plaintext) > footer_size:
                    padding_length = \
                        bytearray(plaintext[-footer_size-1:-footer_size])[0]
                plaintext = plaintext[:-padding_length-footer_size]
                finished = True
            if decompress_obj is not None:
                decompress_error = False
                try:
                    plaintext = decompress_obj.decompress(plaintext)
                except zlib.error:
                    decompress_error = True
                if decompress_error:
                    raise DecryptError()
            md5.update(plaintext)
            out_fd.write(plaintext)
            if finished:
                if decompress_obj is not None:
                    rest = decompress_obj.flush()
                    md5.update(rest)
                    out_fd.write(rest)
                content_digest_check = md5.digest()
                md5.update(footer)
                entire_digest_check = md5.digest()

        if file_entry is None or entire_digest is None \
                or entire_digest_check is None or content_digest_check is None:
            raise DecryptError()

        file_entry.salt = salt
        if file_entry.digest != content_digest_check or entire_digest != \
                entire_digest_check:
            raise DecryptError()

        return file_entry

    def extract_header(self, in_fd):
        bs = self.block_size
        line = in_fd.read(bs)
        if len(line) < bs:
            raise DecryptError(
                "header line size is not correct, expect %d, got %d" %
                (bs, len(line)))
        ints = bytearray(line[:2])
        version = ints[0]
        if version > self.VERSION:
            raise VersionNotCompatible("Unrecognized version: (%d)" % version)
        flags = ints[1]
        (pathname_size,) = unpack(b'!H', line[2:4])
        salt = line[4:]
        key, iv = self.gen_key_and_iv(salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        pathname_block_size = pathname_size
        if pathname_size % bs != 0:
            pathname_block_size = int((pathname_size/bs+1) * bs)
        pathname_data = in_fd.read(pathname_block_size)
        if len(pathname_data) < pathname_block_size:
            raise DecryptError(
                "pathname length is not correct, expect %d, got %d" %
                (pathname_block_size, len(pathname_data)))
        pathname_data = decryptor.update(pathname_data)[:pathname_size]
        try:
            pathname = pathname_data.decode("utf-8")
        except UnicodeDecodeError:
            raise DecryptError()

        return version, flags, salt, pathname, decryptor

    def extract_entry(self, in_fd):
        (version, flags, salt, pathname, decryptor) = \
            self.extract_header(in_fd)
