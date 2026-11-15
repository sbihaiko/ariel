#!/usr/bin/env python3
"""Acceptance for the retro_links payload, driven through its own process.

The payload is compiled for the host and run against a fake console tree:
/mnt/usb0..usb7, /data/homebrew/PPSA99169<version>. Every assertion is what the
owner, RetroArch or ES-DE can see afterwards - the answer line on stdout, the
bytes of the four kinds of file, and the log - never the program's internals.
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, '..', '..', 'bundles', 'retro_links', 'retro_links.c')
APP = 'PPSA99169-4.0.0-beta-4.zip-app'

failures = []

CFG = '''# seed configuration
video_driver = "vulkan"
content_directory = "/mnt/usb0/retroarch"
rgui_browser_directory = "/mnt/usb0/retroarch"
system_directory = "/mnt/usb0/retroarch/bios"
libretro_directory = "/app0/cores"
'''

SETTINGS = '''<?xml version="1.0"?>
<settings>
<string name="MediaDirectory" value="/app0/library" />
<string name="ROMDirectory" value="/mnt/usb0/retroarch" />
</settings>
'''

SYSTEMS = '''<?xml version="1.0"?>
<systemList>
\t<system>
\t\t<name>nes</name>
\t\t<path>/mnt/usb0/retroarch/nes</path>
\t\t<extension>.nes</extension>
\t</system>
\t<system>
\t\t<name>arcade</name>
\t\t<path>/mnt/usb0/arcade</path>
\t\t<extension>.zip</extension>
\t</system>
\t<system>
\t\t<name>snes</name>
\t\t<path>/mnt/usb0/retroarch/snes</path>
\t\t<extension>.sfc</extension>
\t</system>
</systemList>
'''

# The label with a space and a parenthesis is the shape the romset really has.
PLAYLIST = '''{
  "version": "1.5",
  "default_core_path": "",
  "items": [
    {
      "path": "/mnt/usb0/retroarch/nes/Metroid.nes",
      "label": "Metroid",
      "core_name": "DETECT"
    },
    {
      "path": "/mnt/usb0/retroarch/atari2600/Pitfall (1982).bin",
      "label": "Pitfall"
    }
  ]
}
'''


def check(name, actual, expected):
    if actual != expected:
        failures.append('%s: expected %r, got %r' % (name, expected, actual))


class Tree:
    """A fake console root; RETRO_LINKS_ROOT points the payload at it."""

    def __init__(self, binary, app=APP):
        self.binary = binary
        self.root = tempfile.mkdtemp(prefix='retro-links-')
        for i in range(8):
            os.makedirs(os.path.join(self.root, 'mnt', 'usb%d' % i))
        self.app = os.path.join(self.root, 'data', 'homebrew', app)
        self.make_app('config/retroarch.cfg', CFG)
        self.make_app('es-de/ES-DE/settings/es_settings.xml', SETTINGS)
        self.make_app('es-de/ES-DE/custom_systems/es_systems.xml', SYSTEMS)
        self.make_app('playlists/Atari - 2600.lpl', PLAYLIST)

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def path(self, relative):
        return os.path.join(self.root, relative)

    def make(self, relative, text):
        path = self.path(relative)
        self.write(path, text)
        return path

    def make_app(self, relative, text):
        path = self.app_file(relative)
        self.write(path, text)
        return path

    @staticmethod
    def write(path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(text)

    def app_file(self, relative):
        return os.path.join(self.app, relative)

    def read_app(self, relative):
        with open(self.app_file(relative)) as f:
            return f.read()

    def library(self, usb, *folders, marker=True):
        base = 'mnt/usb%d/retroarch' % usb
        for folder in folders:
            self.make(base + '/' + folder + '/.keep', '')
        if marker:
            self.make(base + '/.ariel-retroarch', '')
        return self.path(base)

    def run(self):
        result = subprocess.run(
            [self.binary], capture_output=True, text=True, timeout=30,
            env=dict(os.environ, RETRO_LINKS_ROOT=self.root))
        check('exit code', result.returncode, 0)
        return result.stdout.strip()

    def log(self):
        with open(os.path.join(self.app, 'retro-links.log')) as f:
            return f.read().splitlines()


def full_library(tree, usb=2):
    """A library holding every file the sample files name, on one mount."""
    tree.library(usb, 'nes', 'atari2600', 'arcade', 'snes', 'bios')
    tree.make('mnt/usb%d/retroarch/nes/Metroid.nes' % usb, 'x')
    tree.make('mnt/usb%d/retroarch/atari2600/Pitfall (1982).bin' % usb, 'x')


def case_set(binary):
    t = Tree(binary)
    try:
        full_library(t)
        check('set: answer', t.run(),
              'retro-link set /mnt/usb2/retroarch paths=9')
        check('set: config', t.read_app('config/retroarch.cfg'), CFG.replace(
            '/mnt/usb0/retroarch', '/mnt/usb2/retroarch'))
        check('set: settings', t.read_app('es-de/ES-DE/settings/es_settings.xml'),
              SETTINGS.replace('/mnt/usb0/retroarch', '/mnt/usb2/retroarch'))
        # The arcade system names <drive>/arcade, outside retroarch/, so it is
        # repaired to the folder of that name under the found root.
        want = (SYSTEMS
                .replace('/mnt/usb0/retroarch', '/mnt/usb2/retroarch')
                .replace('/mnt/usb0/arcade', '/mnt/usb2/retroarch/arcade'))
        check('set: systems', t.read_app(
            'es-de/ES-DE/custom_systems/es_systems.xml'), want)
        check('set: playlist', t.read_app('playlists/Atari - 2600.lpl'),
              PLAYLIST.replace('/mnt/usb0/retroarch', '/mnt/usb2/retroarch'))
        check('set: log', t.log(), ['retro-link set /mnt/usb2/retroarch paths=9'])
        check('set: second run', t.run(), 'retro-link unchanged /mnt/usb2/retroarch')
        check('set: log after the second run', t.log(),
              ['retro-link set /mnt/usb2/retroarch paths=9',
               'retro-link unchanged /mnt/usb2/retroarch'])
    finally:
        t.cleanup()


def case_already_correct(binary):
    t = Tree(binary)
    try:
        full_library(t)
        for relative in ('config/retroarch.cfg',
                         'es-de/ES-DE/settings/es_settings.xml',
                         'es-de/ES-DE/custom_systems/es_systems.xml',
                         'playlists/Atari - 2600.lpl'):
            t.make_app(relative, t.read_app(relative)
                   .replace('/mnt/usb0/retroarch', '/mnt/usb2/retroarch')
                   .replace('/mnt/usb0/arcade', '/mnt/usb2/retroarch/arcade'))
        before = {r: t.read_app(r) for r in ('config/retroarch.cfg',
                                             'es-de/ES-DE/settings/es_settings.xml',
                                             'es-de/ES-DE/custom_systems/es_systems.xml',
                                             'playlists/Atari - 2600.lpl')}
        check('correct: answer', t.run(), 'retro-link unchanged /mnt/usb2/retroarch')
        for relative, text in before.items():
            check('correct: %s untouched' % relative, t.read_app(relative), text)
    finally:
        t.cleanup()


def case_no_library(binary):
    t = Tree(binary)
    try:
        t.make('mnt/usb0/retroarch/README', '')
        check('none: answer', t.run(), 'retro-link no_usb_library')
        check('none: config untouched', t.read_app('config/retroarch.cfg'), CFG)
        check('none: no log', os.path.exists(os.path.join(t.app, 'retro-links.log')),
              False)
    finally:
        t.cleanup()


def case_no_app(binary):
    t = Tree(binary)
    try:
        full_library(t)
        shutil.rmtree(t.app)
        check('no app: answer', t.run(), 'retro-link no_app')
    finally:
        t.cleanup()


def case_missing_file_left_alone(binary):
    t = Tree(binary)
    try:
        t.library(2, 'nes', 'atari2600', 'arcade', 'snes', 'bios')
        t.make('mnt/usb2/retroarch/nes/Metroid.nes', 'x')
        t.make('mnt/usb2/retroarch/atari2600/Pitfall (1982).bin', 'x')
        t.make_app('playlists/Atari - 2600.lpl',
               PLAYLIST.replace('/mnt/usb0/retroarch/nes/Metroid.nes',
                                '/mnt/usb0/retroarch/nes/NotThere.nes'))
        t.run()
        check('missing: entry kept', t.read_app('playlists/Atari - 2600.lpl'),
              PLAYLIST.replace('/mnt/usb0/retroarch/nes/Metroid.nes',
                               '/mnt/usb0/retroarch/nes/NotThere.nes')
              .replace('/mnt/usb0/retroarch', '/mnt/usb2/retroarch')
              .replace('/mnt/usb2/retroarch/nes/NotThere.nes',
                       '/mnt/usb0/retroarch/nes/NotThere.nes'))
    finally:
        t.cleanup()


def case_content_fallback(binary):
    t = Tree(binary)
    try:
        t.library(3, 'arcade', 'nes', marker=False)
        check('fallback: answer', t.run(),
              'retro-link set /mnt/usb3/retroarch paths=5')
    finally:
        t.cleanup()


def case_lowest_mount_wins(binary):
    t = Tree(binary)
    try:
        t.library(1, 'arcade', 'nes')
        t.library(4, 'arcade', 'nes')
        check('lowest: answer', t.run(),
              'retro-link set /mnt/usb1/retroarch paths=5')
    finally:
        t.cleanup()


def case_lowest_app_name_wins(binary):
    t = Tree(binary, app='PPSA99169-9.9.9.zip-app')
    try:
        full_library(t)
        older = os.path.join(t.root, 'data', 'homebrew', 'PPSA99169-1.0.0.zip-app')
        os.makedirs(os.path.join(older, 'es-de', 'ES-DE', 'settings'))
        shutil.copy(os.path.join(t.app, 'es-de', 'ES-DE', 'settings',
                                 'es_settings.xml'),
                    os.path.join(older, 'es-de', 'ES-DE', 'settings',
                                 'es_settings.xml'))
        t.run()
        check('app name: newest folder untouched',
              open(os.path.join(t.app, 'config', 'retroarch.cfg')).read(), CFG)
        check('app name: lowest folder repaired',
              open(os.path.join(older, 'es-de', 'ES-DE', 'settings',
                                'es_settings.xml')).read(),
              SETTINGS.replace('/mnt/usb0/retroarch', '/mnt/usb2/retroarch'))
    finally:
        t.cleanup()


def main():
    tempdir = tempfile.mkdtemp(prefix='retro-links-build-')
    binary = os.path.join(tempdir, 'retro_links')
    try:
        built = subprocess.run(
            ['cc', '-Wall', '-Wextra', '-Werror', '-std=c11',
             '-D_POSIX_C_SOURCE=200809L', '-DARIEL_HOST_BUILD=1',
             '-o', binary, SOURCE],
            capture_output=True, text=True)
        if built.returncode != 0:
            print(built.stderr)
            return 1
        for case in (case_set, case_already_correct, case_no_library,
                     case_no_app, case_missing_file_left_alone,
                     case_content_fallback, case_lowest_mount_wins,
                     case_lowest_app_name_wins):
            case(binary)
    finally:
        shutil.rmtree(tempdir, ignore_errors=True)

    if failures:
        for failure in failures:
            print('FAIL ' + failure)
        return 1
    print('retro_links: ok')
    return 0


if __name__ == '__main__':
    sys.exit(main())
