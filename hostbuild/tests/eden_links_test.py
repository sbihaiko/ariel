#!/usr/bin/env python3
"""Acceptance for the eden_links payload, driven through its own process.

The payload is compiled for the host and run against a fake console tree:
/mnt/usb0..usb7, /data/prosperoeden. Every assertion is what the owner or Eden
can see afterwards - the answer line on stdout, and the bytes of Eden's
settings file - never the program's internals.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, '..', '..', 'bundles', 'eden_links', 'eden_links.c')

failures = []

SAMPLE = {
    "version": 1,
    "audio": {"volume": 100},
    "library": {"last_game": "Zelda.nsp", "recent": ["Zelda.nsp"]},
}


def check(name, actual, expected):
    if actual != expected:
        failures.append('%s: expected %r, got %r' % (name, expected, actual))


class Tree:
    """A fake console root; EDEN_LINKS_ROOT points the payload at it."""

    def __init__(self, binary, settings=None):
        self.binary = binary
        self.root = tempfile.mkdtemp(prefix='eden-links-')
        self.folder = os.path.join(self.root, 'data', 'prosperoeden')
        os.makedirs(os.path.join(self.folder, 'config'))
        for i in range(8):
            os.makedirs(os.path.join(self.root, 'mnt', 'usb%d' % i))
        self.config = os.path.join(self.folder, 'config', 'prosperoeden.json')
        if settings is not None:
            with open(self.config, 'w') as f:
                f.write(settings)
        self.log = os.path.join(self.folder, 'eden-links.log')

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def mkdir(self, relative, *entries):
        path = os.path.join(self.root, relative)
        os.makedirs(path, exist_ok=True)
        for entry in entries:
            with open(os.path.join(path, entry), 'w') as f:
                f.write('x')
        return path

    def run(self):
        result = subprocess.run(
            [self.binary], capture_output=True, text=True, timeout=30,
            env=dict(os.environ, EDEN_LINKS_ROOT=self.root))
        check('exit code', result.returncode, 0)
        return result.stdout.strip()

    def settings(self):
        with open(self.config) as f:
            return json.load(f)

    def raw(self):
        with open(self.config) as f:
            return f.read()


def banner():
    return json.dumps(SAMPLE, indent=2)


def case_set_absent(binary):
    t = Tree(binary, banner())
    try:
        t.mkdir('mnt/usb0/eden/roms', '.ariel-eden')
        check('absent: answer', t.run(), 'eden-link set /mnt/usb0/eden')
        got = t.settings()
        want = dict(SAMPLE)
        want['game_files'] = '/mnt/usb0/eden'
        check('absent: settings', got, want)
        check('absent: second run', t.run(), 'eden-link unchanged /mnt/usb0/eden')
        with open(t.log) as f:
            check('absent: log lines', len(f.read().splitlines()), 2)
    finally:
        t.cleanup()


def case_replace(binary):
    old = json.dumps(dict(SAMPLE, game_files='/data/prosperoeden/roms'), indent=2)
    t = Tree(binary, old)
    try:
        t.mkdir('mnt/usb3/eden/roms', 'Zelda.nsp')
        check('replace: answer', t.run(), 'eden-link set /mnt/usb3/eden')
        want = dict(SAMPLE)
        want['game_files'] = '/mnt/usb3/eden'
        check('replace: settings', t.settings(), want)
        check('replace: only the value moved',
              t.raw().replace('/mnt/usb3/eden', '/data/prosperoeden/roms'), old)
    finally:
        t.cleanup()


def case_nested_title(binary):
    t = Tree(binary, banner())
    try:
        # The library on the console holds one directory per title, and the
        # .nsp lives inside that directory, not beside it.
        t.mkdir('mnt/usb0/eden/roms/Zelda Breath of the Wild',
                'Zelda Breath of the Wild [01007EF00011E000][v0].nsp')
        check('nested: answer', t.run(), 'eden-link set /mnt/usb0/eden')
    finally:
        t.cleanup()


def case_flat_layout(binary):
    t = Tree(binary, banner())
    try:
        t.mkdir('mnt/usb2/roms', 'Game.nsp')
        check('flat: answer', t.run(), 'eden-link set /mnt/usb2')
    finally:
        t.cleanup()


def case_lowest_mount_wins(binary):
    t = Tree(binary, banner())
    try:
        t.mkdir('mnt/usb0/roms', 'Game.nsp')
        t.mkdir('mnt/usb1/eden/roms', 'Game.nsp')
        check('lowest: answer', t.run(), 'eden-link set /mnt/usb0')
    finally:
        t.cleanup()


def case_no_library(binary):
    t = Tree(binary, banner())
    try:
        t.mkdir('mnt/usb0')  # an empty mount is not a library
        check('none: answer', t.run(), 'eden-link no_usb_library')
        check('none: settings untouched', t.raw(), banner())
    finally:
        t.cleanup()


def case_missing_settings(binary):
    t = Tree(binary, None)
    try:
        t.mkdir('mnt/usb0/eden/roms', '.ariel-eden')
        result = subprocess.run(
            [t.binary], capture_output=True, text=True, timeout=30,
            env=dict(os.environ, EDEN_LINKS_ROOT=t.root))
        check('missing: exit code', result.returncode, 1)
        check('missing: answer', result.stdout.strip(),
              'eden-link failed settings /mnt/usb0/eden')
    finally:
        t.cleanup()


def main():
    tempdir = tempfile.mkdtemp(prefix='eden-links-build-')
    binary = os.path.join(tempdir, 'eden_links')
    try:
        built = subprocess.run(
            ['cc', '-Wall', '-Wextra', '-Werror', '-std=c11',
             '-D_POSIX_C_SOURCE=200809L', '-DARIEL_HOST_BUILD=1',
             '-o', binary, SOURCE],
            capture_output=True, text=True)
        if built.returncode != 0:
            print(built.stderr)
            return 1
        for case in (case_set_absent, case_replace, case_nested_title,
                     case_flat_layout, case_lowest_mount_wins, case_no_library,
                     case_missing_settings):
            case(binary)
    finally:
        shutil.rmtree(tempdir, ignore_errors=True)

    if failures:
        for failure in failures:
            print('FAIL ' + failure)
        return 1
    print('eden_links: ok')
    return 0


if __name__ == '__main__':
    sys.exit(main())
