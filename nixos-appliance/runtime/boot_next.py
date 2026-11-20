"""Keep the installed Nest off its install media.

A virtual machine (Proxmox) puts the CD first in the boot order again at every
start. With the Nest ISO still attached the server then starts the installer,
which waits for a claim before it starts the installed Nest. UEFI BootNext
names the entry for the next start only and wins over the boot order, so the
running Nest names the entry it started from. A person who wants the ISO
picks it in the firmware's boot menu.
"""
import os
from pathlib import Path
import struct

EFIVARS = Path('/sys/firmware/efi/efivars')
GLOBAL = '8be4df61-93ca-11d2-aa0d-00e098032b8c'
# Non-volatile, boot service and runtime access: what firmware expects of BootNext.
ATTRIBUTES = 7


def start_from_this_disk_next_time(efivars=EFIVARS):
    """Best effort: a server that refuses the variable starts as before."""
    try:
        current = (efivars / ('BootCurrent-' + GLOBAL)).read_bytes()
        if len(current) != 6:
            return False
        wanted = struct.pack('<I', ATTRIBUTES) + current[4:]
        target = efivars / ('BootNext-' + GLOBAL)
        try:
            if target.read_bytes() == wanted:
                return True
        except FileNotFoundError:
            pass
        # efivarfs takes a variable in one write.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        try:
            os.write(fd, wanted)
        finally:
            os.close(fd)
        return True
    except OSError as error:
        print('the next start follows the firmware boot order: ' + str(error), flush=True)
        return False
