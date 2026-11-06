#!/usr/bin/env python3
"""Refuse a DEB whose data or control archive has any non-root owner."""

import argparse
import lzma
import os
from pathlib import Path
import re
import resource
import signal
import sys
import tarfile


class InvalidDeb(ValueError):
    pass


def deadline_expired(_signal, _frame):
    raise InvalidDeb('verification deadline exceeded')


class Section:
    def __init__(self, stream, offset, size):
        self.stream = stream
        self.offset = offset
        self.size = size
        self.position = 0

    def read(self, count=-1):
        if count < 0:
            count = self.size - self.position
        count = min(count, self.size - self.position)
        self.stream.seek(self.offset + self.position)
        data = self.stream.read(count)
        self.position += len(data)
        return data

    def seek(self, offset, whence=os.SEEK_SET):
        base = (0, self.position, self.size)[whence]
        position = base + offset
        if not 0 <= position <= self.size:
            raise InvalidDeb('archive section seek out of bounds')
        self.position = position
        return position

    def tell(self):
        return self.position

    def readable(self):
        return True

    def seekable(self):
        return True


class BoundedReader:
    """Bound all decoded tar bytes, including hidden PAX/GNU metadata."""

    def __init__(self, stream, limit):
        self.stream = stream
        self.remaining = limit
        self.limit = limit

    def read(self, count=-1):
        if count < 0:
            count = self.remaining + 1
        if count > self.remaining:
            count = self.remaining + 1
        data = self.stream.read(count)
        self.remaining -= len(data)
        if self.remaining < 0:
            raise InvalidDeb(f'decoded tar stream exceeds {self.limit // (1024 * 1024)} MiB')
        return data


class LimitedXzReader:
    """Decode xz in small chunks with a bounded decoder dictionary."""

    def __init__(self, section):
        self.section = section
        self.decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ,
                                             memlimit=64 * 1024 * 1024)

    def read(self, count=-1):
        if count < 0:
            count = 64 * 1024
        output = bytearray()
        while len(output) < count and not self.decoder.eof:
            if self.decoder.needs_input:
                compressed = self.section.read(64 * 1024)
                if not compressed:
                    raise InvalidDeb('truncated xz stream')
            else:
                compressed = b''
            output.extend(self.decoder.decompress(compressed,
                          max_length=min(count - len(output), 64 * 1024)))
        if self.decoder.eof and (self.decoder.unused_data or self.section.read(1)):
            raise InvalidDeb('trailing or concatenated xz stream')
        return bytes(output)


def sections(stream):
    if stream.read(8) != b'!<arch>\n':
        raise InvalidDeb('invalid ar magic')
    result = {}
    while header := stream.read(60):
        if len(header) != 60 or header[58:] != b'`\n':
            raise InvalidDeb('invalid ar header')
        name = header[:16].strip().decode('ascii', 'strict').rstrip('/')
        size_text = header[48:58].strip()
        if not re.fullmatch(rb'[0-9]+', size_text):
            raise InvalidDeb('invalid ar size')
        size = int(size_text)
        offset = stream.tell()
        if name in result or name not in ('debian-binary', 'control.tar.xz', 'data.tar.xz'):
            raise InvalidDeb('unexpected or duplicate ar member')
        result[name] = (offset, size)
        stream.seek(offset + size + size % 2)
    if set(result) != {'debian-binary', 'control.tar.xz', 'data.tar.xz'}:
        raise InvalidDeb('missing required ar member')
    return result


def verify(path):
    if not path.is_file() or path.stat().st_size > 512 * 1024 * 1024:
        raise InvalidDeb('missing or oversized DEB')
    with path.open('rb') as stream:
        members = sections(stream)
        offset, size = members['debian-binary']
        if size != 4 or Section(stream, offset, size).read() != b'2.0\n':
            raise InvalidDeb('unsupported DEB format')
        for archive in ('control.tar.xz', 'data.tar.xz'):
            offset, size = members[archive]
            count = 0
            expanded = 0
            decoded = LimitedXzReader(Section(stream, offset, size))
            # Current signed-candidate DEBs expand below 32 MiB per archive.
            # Keep a bounded margin while refusing giant PAX/GNU metadata.
            bounded = BoundedReader(decoded, 128 * 1024 * 1024)
            with tarfile.open(fileobj=bounded, mode='r|') as tar:
                for entry in tar:
                    count += 1
                    if count > 10000:
                        raise InvalidDeb(f'{archive}: too many members')
                    expanded += entry.size
                    if expanded > 1024 * 1024 * 1024:
                        raise InvalidDeb(f'{archive}: expanded members exceed 1 GiB')
                    if entry.uid != 0 or entry.gid != 0:
                        raise InvalidDeb(f'{archive}: non-root owner: {entry.name}')
                    if entry.isdir() and entry.mode & 0o022:
                        raise InvalidDeb(f'{archive}: writable directory: {entry.name}')
            while bounded.read(64 * 1024):
                pass
            if count == 0:
                raise InvalidDeb(f'{archive}: empty archive')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('deb', type=Path)
    args = parser.parse_args()
    # tarfile materializes an entire PAX/GNU metadata record before yielding
    # it. Bound process memory as well as decoded bytes for hostile archives.
    if sys.platform == 'linux':
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        ceiling = 512 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS,
                           (min(soft, ceiling) if soft >= 0 else ceiling,
                            min(hard, ceiling) if hard >= 0 else ceiling))
    signal.signal(signal.SIGALRM, deadline_expired)
    signal.alarm(30)
    try:
        verify(args.deb)
    except (InvalidDeb, OSError, UnicodeError, tarfile.TarError, ValueError,
            lzma.LZMAError, MemoryError) as error:
        print(f'DEB ownership REFUSED: {error}', file=sys.stderr)
        return 1
    finally:
        signal.alarm(0)
    print('PASS: DEB control and data archives are root:root')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
