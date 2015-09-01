#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from cStringIO import StringIO 
import zlib
import hashlib
from struct import pack, unpack
from filetree import FileEntry
from time import time


def _hex(data):
    return data.encode('hex')


class InvalidKey(Exception):
    pass


class DigestMissMatch(Exception):
    pass


class UnrecognizedContent(Exception):
    pass


class VersionNotCompatible(Exception):
    pass


class Crypto:

    VERSION = 0x1

    COMPRESS = 0x1

    BUFFER_SIZE = 1024

    def __init__(self, password, key_size=32):

        self.password = password
        self.key_size = key_size
        self.block_size = 16

    def encrypt_file(self, plain_path, encrypted_path, plain_file):
        plain_fd = open(plain_path, 'rb')
        encrypted_fd = open(encrypted_path, 'wb')
        self.encrypt_fd(plain_fd, encrypted_fd, plain_file)
        plain_fd.close()
        encrypted_fd.close()

    def decrypt_file(self, encrypted_path, plain_path):
        plain_fd = open(plain_path, 'wb')
        encrypted_fd = open(encrypted_path, 'rb')
        file_entry = self.decrypt_fd(encrypted_fd, plain_fd)
        plain_fd.close()
        encrypted_fd.close()
        return file_entry

    @staticmethod
    def compress_fd(in_fd, out_fd):
        out_fd.write(zlib.compress(in_fd.read()))

    @staticmethod
    def decompress_fd(in_fd, out_fd):
        out_fd.write(zlib.decompress(in_fd.read()))

    def gen_key_and_iv(self, salt):
        d = d_i = ''
        while len(d) < self.key_size + self.block_size:
            d_i = hashlib.md5(d_i + self.password + salt).digest()
            d += d_i
        return d[:self.key_size], d[self.key_size:self.key_size+self.block_size]

    def _header_size(self, file_entry):
        bs = self.block_size
        pathname = file_entry.pathname
        pathname_size = len(pathname)
        max_pathname = 2 ** 16 - 36
        if pathname_size > max_pathname:
            pathname = pathname[-max_pathname:]
            pathname_size = max_pathname
        header_size = pathname_size + 36
        header_padding = ''
        if header_size % bs != 0:
            padding_length = (bs - header_size % bs)
            header_padding = padding_length * chr(0)
        return header_size, header_padding, pathname

    @staticmethod
    def _build_footer(file_entry):
        return file_entry.digest + \
               pack('!Q', file_entry.size) + \
               pack('!I', int(file_entry.ctime)) + \
               pack('!I', int(file_entry.mtime)) + \
               pack('!i', file_entry.mode) + (12 * chr(0))

    @staticmethod
    def _unpack_footer(pathname, footer):
        (size, ctime, mtime, mode) = unpack('!QIIi', footer[16:36])
        return FileEntry(pathname, size, ctime, mtime, mode,
                         footer[:16], False)

    def encrypt_fd(self, in_fd, out_fd, file_entry, flags=0):
        """
            +-----------------------------------------------------+
            | Version(1) | Flags(1) | Pathname size(2) | Salt(12) |
            +-----------------------------------------------------+
            |                   Encrypted Pathname                |
            +-----------------------------------------------------+
            |                   Encrypted Content                 |
            |                         ...                         |
            +-----------------------------------------------------+
            |                   Encrypted Digest(16)              |
            +-----------------------------------------------------+
            |         size(8)*        |   ctime(4)   |   mtime(4) |
            +-----------------------------------------------------+
            |     mode(4)   |            padding(12)              |
            +-----------------------------------------------------+

            * size, ctime, mtime, mode are also encrypted
        """
        bs = self.block_size
        if file_entry is None:
            file_entry = FileEntry('.tmp', 0, time(), time(), 0)
        if file_entry.salt is None:
            file_entry.salt = os.urandom(bs - 4)
        key, iv = self.gen_key_and_iv(file_entry.salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        pathname = file_entry.pathname[:2**16]
        pathname_size = len(pathname)
        pathname_padding = ''
        if pathname_size % bs != 0:
            padding_length = (bs - pathname_size % bs)
            pathname_padding = padding_length * chr(0)

        flags &= 0xFF
        out_fd.write(chr(self.VERSION))
        out_fd.write(chr(flags))
        out_fd.write(pack('!H', pathname_size))
        out_fd.write(file_entry.salt)
        out_fd.write(encryptor.update(pathname+pathname_padding))

        if flags & Crypto.COMPRESS:
            buf = StringIO()
            self.compress_fd(in_fd, buf)
            in_fd = buf
            in_fd.seek(0)

        finished = False
        md5 = hashlib.md5()
        while not finished:
            chunk = in_fd.read(Crypto.BUFFER_SIZE * bs)
            md5.update(chunk)
            if len(chunk) == 0 or len(chunk) % bs != 0:
                padding_length = (bs - len(chunk) % bs) or bs
                chunk += padding_length * chr(padding_length)
                finished = True
            out_fd.write(encryptor.update(chunk))

        file_entry.digest = md5.digest()
        out_fd.write(encryptor.update(self._build_footer(file_entry)))
        out_fd.write(encryptor.finalize())
        return file_entry

    def decrypt_fd(self, in_fd, out_fd):
        bs = self.block_size
        line = in_fd.read(bs)
        if len(line) < bs:
            raise UnrecognizedContent(
                "header line size is not correct, expect %d, got %d" %
                (bs, len(line)))
        version = ord(line[0])
        if version > self.VERSION:
            raise VersionNotCompatible("Unrecognized version: (%d)" % version)
        flags = ord(line[1])
        (pathname_size,) = unpack('!H', line[2:4])
        salt = line[4:]
        key, iv = self.gen_key_and_iv(salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        pathname_block_size = pathname_size
        if pathname_size % bs != 0:
            pathname_block_size = (pathname_size/bs+1) * bs
        pathname_data = in_fd.read(pathname_block_size)
        if len(pathname_data) < pathname_block_size:
            raise UnrecognizedContent(
                "pathname length is not correct, expect %d, got %d" %
                (pathname_block_size, len(pathname_data)))
        pathname = decryptor.update(pathname_data)[:pathname_size]
        str_io = StringIO()
        md5 = hashlib.md5()
        next_chunk = ''
        finished = False
        file_entry = None
        while not finished:
            chunk, next_chunk = next_chunk, in_fd.read(self.BUFFER_SIZE * bs)
            if chunk:
                plaintext = decryptor.update(chunk)
                if len(next_chunk) == 0:
                    plaintext += decryptor.finalize()
                    file_entry = self._unpack_footer(pathname, plaintext[-48:])
                    padding_length = ord(plaintext[-49])
                    plaintext = plaintext[:-padding_length-48]
                    finished = True
                str_io.write(plaintext)
                md5.update(plaintext)
        if flags & self.COMPRESS:
            buf = StringIO()
            str_io.seek(0)
            self.decompress_fd(str_io, buf)
            str_io.close()
            str_io = buf
            str_io.seek(0)

        file_entry.salt = salt
        if file_entry.digest != md5.digest()[:bs]:
            raise DigestMissMatch()

        out_fd.write(str_io.getvalue())
        str_io.close()
        return file_entry
