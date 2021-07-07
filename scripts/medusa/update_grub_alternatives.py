#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2021 Roderik Ploszek
"""Add kgdbwait entries to the grub menu.

Sections denoted by ### symbols have to be present in the /etc/grub.d/10_linux
file

"""


def insert_into_section(name: str, what: str, where: str) -> str:
    """Find section in file and insert text.

    :param name: Name of the section
    :param what: Text to insert
    :param where: Text where to search the section and insert into
    :return: Modified text
    """
    start = f'### {name} section ###\n'
    end = f'### end {name} section ###'

    start_i = where.index(start) + len(start)
    end_i = where.index(end)
    return where[:start_i] + what + where[end_i:]


with open('/etc/grub.d/10_linux') as f:
    c = f.read()

c = insert_into_section('medusa simple', r'''    linux_entry "${OS} (kgdbwait)" "${version}" simple \
    "${GRUB_CMDLINE_LINUX} kgdboc=ttyS0,115200 kgdbwait"
''', c)
c = insert_into_section('medusa advanced', r'''  linux_entry "${OS} (kgdbwait)" "${version}" advanced \
              "${GRUB_CMDLINE_LINUX} kgdboc=ttyS0,115200 kgdbwait"
''', c)

with open('/etc/grub.d/10_linux', 'w') as f:
    f.write(c)
