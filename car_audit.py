#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
car_audit.py - offline USB tamper-evidence and ride auditing for kids' rental cars
==================================================================================

Runs 100% locally (Python 3.8+, standard library only). No cloud, no network.

    python car_audit.py            # interactive menu
    sudo python3 car_audit.py      # Linux/macOS: root is needed for raw disk reads
    (Windows: run the terminal "as Administrator" for raw volume reads)

READ THIS FIRST - WHAT A USB STICK CAN AND CANNOT RECORD
-------------------------------------------------------
A USB flash drive is passive storage. It has no clock, no battery and no CPU we
can program. It cannot run a "background script" when the car powers it up,
and no file we place on it can make the car's MP3 board execute anything. The
ONLY way a power-on can leave a trace on the drive is if the MP3 board itself
WRITES something to the drive (a resume/bookmark file, a settings file, a
FAT metadata update). Many cheap boards mount the stick read-only and write
nothing at all; most of them run the "FatFs" library, which never touches the
FAT "dirty" flags, and none of them has a real-time clock, so whatever they do
write tends to carry a fixed fake date (e.g. 2000-01-01 or 1980-01-01).

So this tool does NOT invent numbers. It collects real file-system evidence,
says how strong each piece is, and only counts rides it can actually see.
Before trusting it for payroll, run the CALIBRATION TEST (menu option 2 asks
for it): initialize a drive, drive the car exactly N times (pulling the stick
out at least once), then audit and type N. If the audit cannot see your N rides,
this car's MP3 board leaves no trace and you need hardware that records power
(see "Better hardware options" in the About screen).

WHAT IT CAN DETECT RELIABLY
---------------------------
* The drive was plugged into a phone or another computer (Windows, macOS,
  Linux and Android all leave their own hidden folders/files on FAT32).
* The drive was yanked from a computer/phone mid-write, or repaired by
  Windows CHKDSK (FOUND.000 folders) - from the FAT dirty flags, the FSInfo
  free-cluster counter, orphaned ("lost") clusters and FAT copy mismatches.
* Files were added, changed or deleted (even deleted entries stay readable
  in the directory as 0xE5 records until the slot is reused).
* Our own registry (.car_sys/) was edited, replaced, truncated or deleted -
  it is encrypted and authenticated with a key derived from the owner's PIN,
  and the ledger is a hash chain.

FAT32 FORENSICS USED (see the Fat32Volume class for byte-level details)
-----------------------------------------------------------------------
1. Volume Boot Record byte 0x41 ("BS_Reserved1"): Windows NT and Linux set
   bit 0 when a writable mount starts and clear it on a clean unmount.
   Bit 1 = "disk errors, surface scan wanted".
2. FAT[1] entry (the second 32-bit entry of the FAT): bit 27 is the
   "ClnShutBit" (1 = clean shutdown, 0 = volume was in use when power went),
   bit 26 is the "HrdErrBit" (0 = an I/O error happened).
3. FSInfo sector: "free cluster count" and "next free" hints. Drivers update
   them lazily at sync/unmount; a value that disagrees with the real FAT
   means the last writer never finished (power cut / yank).
4. Orphaned clusters: clusters marked allocated in the FAT that no directory
   entry points to - the typical scar of a file write cut off by power loss.
5. FAT #1 vs FAT #2 mismatch: drivers write both copies; a cut between the
   two writes leaves them different.
6. Directory entries: creation time (10 ms), modification time (2 s) and
   last-access DATE (no time) for every file, including deleted entries.
   Changes since the previous audit are clustered into "power-on sessions"
   using the owner's ride duration as the gap.

Limitations stated plainly: flags (1)-(2) are single bits, so they prove "at
least one unclean removal since the last clean eject", never "how many".
Always use "Safely Remove / Eject" on your own PC so the flags reset.
"""

import array
import datetime
import getpass
import hashlib
import hmac
import html
import json
import os
import platform
import re
import secrets
import struct
import subprocess
import sys

VERSION = "1.0"

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
SYS_DIR = ".car_sys"
META_FILE = "metadata.bin"
LEDGER_FILE = "ride_log.dat"
OUR_FILES = {META_FILE, LEDGER_FILE}

META_MAGIC = b"CARSYS01"
REC_MAGIC = b"CR"
PBKDF2_ITERATIONS = 200_000

REPORT_DIR = os.path.join(os.path.expanduser("~"), "car_audit_reports")

# Audio and playlist files are "content", never evidence of a ride. They are
# tracked only to say "songs were added/removed".
MUSIC_EXT = {
    ".mp3", ".wav", ".wma", ".flac", ".aac", ".m4a", ".ogg", ".ape", ".amr",
    ".mid", ".midi", ".mp2", ".m3u", ".pls", ".lrc",
}

# Names that operating systems create on their own when a FAT drive is
# mounted. Their appearance means the stick was inside that kind of device.
# (key = lower-case name of a top-level entry, value = who creates it)
HOST_ARTIFACTS = {
    "system volume information": "Windows PC",
    "$recycle.bin": "Windows PC",
    "recycler": "Windows PC (old)",
    "recycled": "Windows PC (old)",
    "desktop.ini": "Windows PC",
    "thumbs.db": "Windows PC",
    "autorun.inf": "Windows PC / malware",
    ".trashes": "Mac",
    ".spotlight-v100": "Mac",
    ".fseventsd": "Mac",
    ".ds_store": "Mac",
    ".temporaryitems": "Mac",
    ".metadata_never_index": "Mac",
    "lost.dir": "Android phone",
    "android": "Android phone",
    ".thumbnails": "Android phone / Linux",
    "dcim": "Phone / camera",
}
HOST_ARTIFACT_PREFIXES = {
    "._": "Mac (AppleDouble file)",
    ".trash-": "Linux PC",
    "found.": "Windows CHKDSK repair (unclean removal)",
}
CHKDSK_PATTERN = re.compile(r"^(found\.\d{3}|file\d{4}\.chk|fsck\d{4}\.rec)$", re.I)


class AuditError(Exception):
    """Something the user must fix (wrong path, not FAT32, wrong PIN...)."""


class TamperError(AuditError):
    """Authenticated data failed verification."""


# ==========================================================================
# 1. CRYPTO (stdlib only)
# ==========================================================================
# Python's standard library has no AES, so the registry uses an
# encrypt-then-MAC construction built from primitives that ARE in hashlib/hmac:
#   * keys:        PBKDF2-HMAC-SHA256(owner PIN, random salt, 200k rounds)
#   * encryption:  SHA-256 in counter mode as a keystream (XOR)
#   * integrity:   HMAC-SHA256 over header + nonce + ciphertext
# This hides earnings/settings from employees and makes any edit detectable.
# It is a pragmatic stdlib design, not a certified cipher suite.

class Crypto:
    def __init__(self, pin, salt, iterations=PBKDF2_ITERATIONS):
        km = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, iterations, dklen=64)
        self.enc_key, self.mac_key = km[:32], km[32:]

    def _keystream(self, nonce, n):
        out = bytearray()
        counter = 0
        while len(out) < n:
            out += hashlib.sha256(self.enc_key + nonce + counter.to_bytes(8, "big")).digest()
            counter += 1
        return bytes(out[:n])

    def _xor(self, data, nonce):
        if not data:
            return b""
        ks = self._keystream(nonce, len(data))
        return (int.from_bytes(data, "big") ^ int.from_bytes(ks, "big")).to_bytes(len(data), "big")

    def seal(self, plaintext, aad=b""):
        nonce = secrets.token_bytes(16)
        ct = self._xor(plaintext, nonce)
        tag = hmac.new(self.mac_key, aad + nonce + ct, hashlib.sha256).digest()
        return nonce + ct + tag

    def open(self, blob, aad=b""):
        if len(blob) < 48:
            raise TamperError("sealed blob too short")
        nonce, ct, tag = blob[:16], blob[16:-32], blob[-32:]
        good = hmac.new(self.mac_key, aad + nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, good):
            raise TamperError("authentication failed (wrong PIN or file was modified)")
        return self._xor(ct, nonce)


# ==========================================================================
# 2. RAW DEVICE ACCESS
# ==========================================================================
# Raw paths per OS:
#   Windows : \\.\E:          (volume handle, needs Administrator)
#   Linux   : /dev/sdb1       (from /proc/mounts, needs root)
#   macOS   : /dev/rdisk4s1   (from `mount`, needs root)
#   any     : a disk image file made with dd / Win32DiskImager (no rights needed)
# Windows raw handles only accept reads that start on a sector boundary and
# are a whole number of sectors long, so every read below is aligned to 512.

class RawDevice:
    ALIGN = 512

    def __init__(self, path):
        self.path = path
        try:
            self.f = open(path, "rb", buffering=0)
        except PermissionError:
            raise AuditError(
                "Permission denied reading %s. Run as Administrator (Windows) "
                "or with sudo (Linux/macOS)." % path)
        except OSError as e:
            raise AuditError("Cannot open raw device %s: %s" % (path, e))

    def read(self, offset, length):
        start = offset - (offset % self.ALIGN)
        end = offset + length
        end_aligned = -(-end // self.ALIGN) * self.ALIGN
        self.f.seek(start)
        buf = bytearray()
        remaining = end_aligned - start
        while remaining > 0:
            chunk = self.f.read(min(remaining, 1 << 20))
            if not chunk:
                break
            buf += chunk
            remaining -= len(chunk)
        data = bytes(buf[offset - start: offset - start + length])
        if len(data) != length:
            raise AuditError("Short read at offset %d on %s" % (offset, self.path))
        return data

    def close(self):
        try:
            self.f.close()
        except OSError:
            pass


def _unescape_mount(s):
    # /proc/mounts encodes spaces etc. as octal escapes, e.g. "\040"
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def resolve_raw_device(mount_path):
    """Map a mounted folder/drive letter to its raw device.

    Returns (raw_path or None, note). The note says whether flag readings can
    be trusted given how the audit PC mounted the drive.
    """
    system = platform.system()
    if system == "Windows":
        drive = os.path.splitdrive(os.path.abspath(mount_path))[0]
        if len(drive) == 2 and drive[1] == ":":
            return "\\\\.\\" + drive, "windows"
        return None, "could not find a drive letter"
    if system == "Linux":
        target = os.path.realpath(mount_path)
        found = None
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    dev, mnt, fstype, opts = parts[:4]
                    if os.path.realpath(_unescape_mount(mnt)) == target:
                        found = (dev, fstype, opts.split(","))
        except OSError:
            pass
        if found and found[0].startswith("/dev/"):
            return found[0], ("linux-ro" if "ro" in found[2] else "linux-rw")
        return None, "not found in /proc/mounts"
    if system == "Darwin":
        try:
            out = subprocess.run(["mount"], capture_output=True, text=True).stdout
        except OSError:
            out = ""
        target = os.path.realpath(mount_path)
        for line in out.splitlines():
            m = re.match(r"^(/dev/\S+) on (.+) \((.+)\)$", line)
            if m and os.path.realpath(m.group(2)) == target:
                return m.group(1).replace("/dev/disk", "/dev/rdisk"), "mac"
        return None, "not found in `mount` output"
    return None, "unsupported OS for auto-detection"


# ==========================================================================
# 3. FAT32 PARSER
# ==========================================================================
def fat_datetime(date_val, time_val=0, tenth=0):
    """Decode FAT packed date/time. Local time, 2-second resolution.

    date: bits 15-9 year-1980, 8-5 month, 4-0 day
    time: bits 15-11 hour, 10-5 minute, 4-0 seconds/2
    tenth: 0-199 extra 10 ms units (creation time only)
    """
    if date_val == 0:
        return None
    year = 1980 + (date_val >> 9)
    month = (date_val >> 5) & 0x0F
    day = date_val & 0x1F
    hour = time_val >> 11
    minute = (time_val >> 5) & 0x3F
    sec = (time_val & 0x1F) * 2 + tenth // 100
    try:
        return datetime.datetime(year, month, day, hour, minute, min(sec, 59),
                                 (tenth % 100) * 10000)
    except ValueError:
        return None


def iso(dt):
    return dt.isoformat(timespec="seconds") if dt else None


def from_iso(s):
    return datetime.datetime.fromisoformat(s) if s else None


class Fat32Volume:
    """Read-only FAT32 parser working on a RawDevice.

    Layout of a FAT32 volume:
      sector 0              Volume Boot Record (BPB = BIOS Parameter Block)
      sector BPB_FSInfo     FSInfo (free-cluster hints)
      sector BPB_BkBootSec  backup boot sector (usually 6)
      reserved area end     FAT #1, FAT #2 (each FATSz32 sectors)
      after the FATs        data region, cluster 2 is the first cluster
    """

    EOC = 0x0FFFFFF8   # >= this means end-of-chain
    BAD = 0x0FFFFFF7

    def __init__(self, dev):
        self.dev = dev
        bs = dev.read(0, 512)
        if bs[510:512] != b"\x55\xAA":
            raise AuditError("No boot signature (0x55AA): not a FAT volume, or "
                             "you selected the whole disk instead of the partition.")
        if bs[3:11] == b"EXFAT   ":
            raise AuditError("This drive is exFAT. Reformat it as FAT32 (most MP3 "
                             "boards need FAT32 anyway).")
        if bs[3:11] == b"NTFS    ":
            raise AuditError("This drive is NTFS. Reformat it as FAT32.")
        (self.bps, self.spc, self.rsvd, self.nfats, root_ent, tot16, _media,
         fatsz16, _spt, _heads, _hidden, tot32) = struct.unpack_from("<HBHBHHBHHHII", bs, 11)
        if self.bps not in (512, 1024, 2048, 4096) or self.spc == 0 or self.spc & (self.spc - 1):
            raise AuditError("Corrupt BPB (bytes/sector=%d, sectors/cluster=%d)" % (self.bps, self.spc))
        if fatsz16 != 0 or root_ent != 0:
            raise AuditError("This is FAT12/FAT16, not FAT32. Reformat as FAT32.")
        (self.fatsz, self.ext_flags, _fsver, self.root_clus, self.fsinfo_sec,
         self.bkboot_sec) = struct.unpack_from("<IHHIHH", bs, 36)
        self.total_sectors = tot32 or tot16
        self.state_byte = bs[0x41]          # BS_Reserved1 - dirty flags
        self.vol_id = struct.unpack_from("<I", bs, 67)[0]
        self.label = bs[71:82].decode("ascii", "replace").strip()
        self.cluster_bytes = self.bps * self.spc
        self.fat_offset = self.rsvd * self.bps
        self.data_offset = (self.rsvd + self.nfats * self.fatsz) * self.bps
        self.cluster_count = (self.total_sectors - self.rsvd - self.nfats * self.fatsz) // self.spc
        self.max_cluster = self.cluster_count + 1
        # ExtFlags bit 7 = mirroring disabled, bits 0-3 = the one active FAT
        self.active_fat = (self.ext_flags & 0x0F) if (self.ext_flags & 0x80) else 0
        self._fat_cache = {}

    # ---- FAT tables -------------------------------------------------------
    def fat_bytes(self, index):
        if index not in self._fat_cache:
            # Only the entries for real clusters are meaningful; the rest of
            # the last FAT sector is slack.
            n = min(self.fatsz * self.bps, (self.max_cluster + 1) * 4)
            self._fat_cache[index] = self.dev.read(self.fat_offset + index * self.fatsz * self.bps, n)
        return self._fat_cache[index]

    def fat_array(self, index=None):
        raw = self.fat_bytes(self.active_fat if index is None else index)
        code = "I" if array.array("I").itemsize == 4 else "L"
        arr = array.array(code)
        arr.frombytes(raw[: len(raw) - len(raw) % 4])
        if sys.byteorder == "big":
            arr.byteswap()
        return arr

    # ---- Low-level power-state flags ------------------------------------
    def read_flags(self):
        """Return every unclean-shutdown indicator stored in the volume."""
        fat = self.fat_array()
        fat1 = fat[1] if len(fat) > 1 else 0x0FFFFFFF
        flags = {
            # VBR byte 0x41: bit0 = volume dirty (mounted, not cleanly unmounted)
            "boot_dirty": bool(self.state_byte & 0x01),
            # bit1 = errors were seen, a surface scan is wanted
            "boot_errors": bool(self.state_byte & 0x02),
            # FAT[1] bit 27: 1 = clean shutdown. Cleared => power lost while in use
            "fat_clean_shutdown": bool(fat1 & 0x08000000),
            # FAT[1] bit 26: 1 = no hard I/O error
            "fat_no_hard_error": bool(fat1 & 0x04000000),
            "fat1_raw": "0x%08X" % fat1,
        }
        # Backup boot sector should match the primary one; some drivers only
        # update one of them, so we report it but do not alarm on it alone.
        try:
            bk = self.dev.read(self.bkboot_sec * self.bps, 512) if self.bkboot_sec else None
            flags["backup_boot_dirty"] = bool(bk[0x41] & 0x01) if bk and bk[510:512] == b"\x55\xAA" else None
        except AuditError:
            flags["backup_boot_dirty"] = None
        # FSInfo sector: lead sig "RRaA", struct sig "rrAa", trail 0xAA550000
        fsi = self.dev.read(self.fsinfo_sec * self.bps, 512) if self.fsinfo_sec else b""
        if len(fsi) == 512 and fsi[0:4] == b"RRaA" and fsi[484:488] == b"rrAa":
            free_hint, next_hint = struct.unpack_from("<II", fsi, 488)
            flags["fsinfo_free"] = None if free_hint == 0xFFFFFFFF else free_hint
            flags["fsinfo_next"] = None if next_hint == 0xFFFFFFFF else next_hint
        else:
            flags["fsinfo_free"] = flags["fsinfo_next"] = None
        flags["actual_free"] = sum(1 for c in range(2, min(len(fat), self.max_cluster + 1))
                                   if (fat[c] & 0x0FFFFFFF) == 0)
        flags["fsinfo_stale"] = (flags["fsinfo_free"] is not None
                                 and flags["fsinfo_free"] != flags["actual_free"])
        # FAT copy mismatch: entries that differ between FAT #1 and FAT #2.
        flags["fat_mirror_diffs"] = 0
        if self.nfats >= 2 and not (self.ext_flags & 0x80):
            a, b = self.fat_bytes(0), self.fat_bytes(1)
            if a != b:
                fa, fb = self.fat_array(0), self.fat_array(1)
                # entry 1 holds the flags themselves and legitimately differs
                flags["fat_mirror_diffs"] = sum(1 for i in range(2, min(len(fa), len(fb)))
                                                if (fa[i] ^ fb[i]) & 0x0FFFFFFF)
        flags["fat_sha256"] = hashlib.sha256(self.fat_bytes(self.active_fat)).hexdigest()
        return flags

    # ---- Clusters & directories ------------------------------------------
    def chain(self, start, fat, limit=None):
        """Yield the clusters of a chain, defending against loops/corruption."""
        seen = set()
        c = start
        limit = limit or self.cluster_count
        while 2 <= c <= self.max_cluster and c not in seen and len(seen) < limit:
            seen.add(c)
            yield c
            if c >= len(fat):
                return
            c = fat[c] & 0x0FFFFFFF
            if c >= self.EOC or c == self.BAD or c == 0:
                return

    def read_cluster(self, c):
        return self.dev.read(self.data_offset + (c - 2) * self.cluster_bytes, self.cluster_bytes)

    @staticmethod
    def _lfn_checksum(short11):
        s = 0
        for b in short11:
            s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
        return s

    def walk(self):
        """Walk the whole tree from the root cluster.

        Returns (entries, reached_bitmap). Each entry is a dict with name,
        path, attributes, timestamps, size, first cluster and a 'deleted'
        flag. reached_bitmap marks every cluster owned by a live entry.
        """
        fat = self.fat_array()
        reached = bytearray(self.max_cluster + 1)
        entries = []
        visited_dirs = set()
        stack = [(self.root_clus, "")]
        for c in self.chain(self.root_clus, fat):
            reached[c] = 1
        while stack:
            dir_clus, dir_path = stack.pop()
            if dir_clus in visited_dirs:
                continue
            visited_dirs.add(dir_clus)
            lfn_parts, lfn_sum = {}, None
            for c in self.chain(dir_clus, fat, limit=4096):
                data = self.read_cluster(c)
                for off in range(0, len(data), 32):
                    e = data[off: off + 32]
                    first = e[0]
                    if first == 0x00:          # end of directory
                        break
                    attr = e[11]
                    if attr == 0x0F:           # long-file-name fragment
                        if first == 0xE5:
                            continue
                        order = first & 0x1F
                        if first & 0x40:
                            lfn_parts, lfn_sum = {}, e[13]
                        lfn_parts[order] = e[1:11] + e[14:26] + e[28:32]
                        continue
                    deleted = first == 0xE5
                    short = bytes([0xE5 if first == 0x05 else first]) + e[1:11]
                    long_name = None
                    if lfn_parts and not deleted and lfn_sum == self._lfn_checksum(short):
                        raw = b"".join(lfn_parts[k] for k in sorted(lfn_parts))
                        long_name = raw.decode("utf-16-le", "replace").split("\x00")[0]
                    lfn_parts, lfn_sum = {}, None
                    if attr & 0x08:            # volume label
                        continue
                    base = short[:8].decode("cp437", "replace").rstrip()
                    ext = short[8:11].decode("cp437", "replace").rstrip()
                    if e[12] & 0x08:
                        base = base.lower()
                    if e[12] & 0x10:
                        ext = ext.lower()
                    if deleted:
                        base = "?" + base[1:]   # first char is lost on delete
                    name = long_name or (base + ("." + ext if ext else ""))
                    if name in (".", ".."):
                        continue
                    (crt_tenth, crt_time, crt_date, acc_date, clus_hi, wrt_time,
                     wrt_date, clus_lo, size) = struct.unpack_from("<BHHHHHHHI", e, 13)
                    first_clus = (clus_hi << 16) | clus_lo
                    is_dir = bool(attr & 0x10)
                    path = dir_path + "/" + name
                    entries.append({
                        "path": path, "name": name, "dir": is_dir, "attr": attr,
                        "size": size, "clus": first_clus, "deleted": deleted,
                        "ctime": fat_datetime(crt_date, crt_time, crt_tenth),
                        "mtime": fat_datetime(wrt_date, wrt_time),
                        "adate": fat_datetime(acc_date),
                    })
                    if not deleted and 2 <= first_clus <= self.max_cluster:
                        for cc in self.chain(first_clus, fat):
                            reached[cc] = 1
                        if is_dir:
                            stack.append((first_clus, path))
                else:
                    continue
                break   # hit the 0x00 end marker
        return entries, reached

    def orphan_clusters(self, reached):
        """Clusters allocated in the FAT that no live directory entry owns."""
        fat = self.fat_array()
        n = 0
        for c in range(2, min(len(fat), self.max_cluster + 1)):
            v = fat[c] & 0x0FFFFFFF
            if v != 0 and v != self.BAD and not reached[c]:
                n += 1
        return n


# ==========================================================================
# 4. SNAPSHOTS - a fingerprint of the drive taken at init and after each audit
# ==========================================================================
def classify(path):
    """-> 'ours' | 'music' | 'host:<who>' | 'chkdsk' | 'other'"""
    parts = [p for p in path.split("/") if p]
    if not parts:
        return "other"
    top = parts[0].lower()
    leaf = parts[-1].lower()
    if top == SYS_DIR:
        return "ours"
    if CHKDSK_PATTERN.match(top) or CHKDSK_PATTERN.match(leaf):
        return "chkdsk"
    if top in HOST_ARTIFACTS:
        return "host:" + HOST_ARTIFACTS[top]
    for prefix, who in HOST_ARTIFACT_PREFIXES.items():
        if leaf.startswith(prefix) or top.startswith(prefix):
            return "host:" + who
    if leaf == ".ds_store":
        return "host:Mac"
    if os.path.splitext(leaf)[1] in MUSIC_EXT:
        return "music"
    return "other"


def entry_key(e):
    if e["deleted"]:
        # Deleted entries have no unique name; identify them by their remains.
        return "DEL|%s|%s|%s|%d" % (e["path"].rsplit("/", 1)[0], e["name"][1:].lower(),
                                    iso(e["ctime"]), e["clus"])
    return e["path"].lower()


def raw_snapshot(vol):
    flags = vol.read_flags()
    entries, reached = vol.walk()
    snap = {"mode": "raw", "taken_at": iso(datetime.datetime.now()), "flags": flags,
            "orphans": vol.orphan_clusters(reached), "files": {}, "music": {}}
    for e in entries:
        cls = classify(e["path"])
        if cls == "ours":
            continue
        k = entry_key(e)
        if cls == "music" and not e["deleted"]:
            snap["music"][k] = e["size"]
            continue
        snap["files"][k] = {"p": e["path"], "d": e["dir"], "s": e["size"], "x": e["deleted"],
                            "c": iso(e["ctime"]), "m": iso(e["mtime"]), "a": iso(e["adate"]),
                            "k": cls}
    return snap, entries


def file_snapshot(mount):
    """Fallback when raw access is impossible: os.stat() only.

    Loses deleted entries, dirty flags, orphans and FAT mirrors, and OS
    caches/timezone conversion make times less exact.
    """
    snap = {"mode": "files", "taken_at": iso(datetime.datetime.now()), "flags": None,
            "orphans": None, "files": {}, "music": {}}
    for root, dirs, files in os.walk(mount):
        for name in dirs + files:
            full = os.path.join(root, name)
            rel = "/" + os.path.relpath(full, mount).replace(os.sep, "/")
            cls = classify(rel)
            if cls == "ours":
                continue
            try:
                st = os.stat(full)
            except OSError:
                continue
            if cls == "music" and name in files:
                snap["music"][rel.lower()] = st.st_size
                continue
            birth = getattr(st, "st_birthtime", None)
            if birth is None and platform.system() == "Windows":
                birth = st.st_ctime    # on Windows st_ctime is creation time
            ts = datetime.datetime.fromtimestamp
            snap["files"][rel.lower()] = {
                "p": rel, "d": name in dirs, "s": st.st_size, "x": False,
                "c": iso(ts(birth)) if birth else None, "m": iso(ts(st.st_mtime)),
                "a": iso(ts(st.st_atime).replace(hour=0, minute=0, second=0, microsecond=0)),
                "k": cls}
    return snap


# ==========================================================================
# 5. REGISTRY ON THE DRIVE (.car_sys/metadata.bin + .car_sys/ride_log.dat)
# ==========================================================================
def sys_path(mount, name=None):
    p = os.path.join(mount, SYS_DIR)
    return os.path.join(p, name) if name else p


def hide_path(path):
    """Mark as hidden+system on Windows (the dot prefix hides it elsewhere)."""
    if platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x02 | 0x04)
        except Exception:
            pass


def write_durable(path, data):
    """Write via a temp file + fsync + rename so a yank cannot half-write it."""
    tmp = path + ".tmp"
    if platform.system() == "Windows" and os.path.exists(path):
        # Hidden/system files cannot be replaced on Windows until unhidden.
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x80)
        except Exception:
            pass
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    hide_path(path)


def save_metadata(mount, salt, crypto, meta):
    header = META_MAGIC + salt + struct.pack(">I", PBKDF2_ITERATIONS)
    blob = crypto.seal(json.dumps(meta, separators=(",", ":")).encode(), aad=header)
    write_durable(sys_path(mount, META_FILE), header + blob)


def load_metadata(mount, pin):
    path = sys_path(mount, META_FILE)
    if not os.path.isfile(path):
        raise AuditError("No %s/%s on this drive - initialize it first." % (SYS_DIR, META_FILE))
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:8] != META_MAGIC or len(raw) < 28 + 48:
        raise TamperError("metadata.bin header is damaged or replaced")
    salt = raw[8:24]
    iterations = struct.unpack(">I", raw[24:28])[0]
    if not 10_000 <= iterations <= 10_000_000:
        raise TamperError("metadata.bin header is damaged")
    crypto = Crypto(pin, salt, iterations)
    meta = json.loads(crypto.open(raw[28:], aad=raw[:28]).decode())
    return meta, salt, crypto


def read_ledger(mount, crypto):
    """Decrypt and verify the hash chain. Returns (records, problems)."""
    path = sys_path(mount, LEDGER_FILE)
    records, problems = [], []
    if not os.path.isfile(path):
        return records, ["ride_log.dat is missing"]
    with open(path, "rb") as f:
        data = f.read()
    pos, prev_tag = 0, "GENESIS"
    while pos < len(data):
        if data[pos:pos + 2] != REC_MAGIC or pos + 6 > len(data):
            problems.append("ledger is corrupt at byte %d" % pos)
            break
        n = struct.unpack(">I", data[pos + 2:pos + 6])[0]
        blob = data[pos + 6: pos + 6 + n]
        if len(blob) != n:
            problems.append("ledger is truncated at byte %d" % pos)
            break
        try:
            rec = json.loads(crypto.open(blob, aad=REC_MAGIC).decode())
        except (TamperError, ValueError):
            problems.append("ledger record #%d failed authentication" % (len(records) + 1))
            break
        if rec.get("seq") != len(records) + 1 or rec.get("prev") != prev_tag:
            problems.append("ledger chain broken at record #%d (records removed or reordered)"
                            % (len(records) + 1))
        records.append(rec)
        prev_tag = blob[-32:].hex()
        pos += 6 + n
    return records, problems


def append_ledger(mount, crypto, records, rtype, data):
    prev = "GENESIS"
    path = sys_path(mount, LEDGER_FILE)
    if records and os.path.isfile(path):
        # tag of the last record = last 32 bytes of the file
        with open(path, "rb") as f:
            f.seek(-32, os.SEEK_END)
            prev = f.read(32).hex()
    rec = {"seq": len(records) + 1, "prev": prev, "time": iso(datetime.datetime.now()),
           "type": rtype, "data": data}
    blob = crypto.seal(json.dumps(rec, separators=(",", ":")).encode(), aad=REC_MAGIC)
    with open(path, "ab") as f:
        f.write(REC_MAGIC + struct.pack(">I", len(blob)) + blob)
        f.flush()
        os.fsync(f.fileno())
    hide_path(path)
    records.append(rec)
    return blob[-32:].hex()


# ==========================================================================
# 6. EVIDENCE ANALYSIS - compare "now" against the last trusted snapshot
# ==========================================================================
def analyse(base, now, settings, since, raw_note):
    """Produce the audit findings dict from two snapshots."""
    gap = datetime.timedelta(minutes=max(1, settings["ride_minutes"]))
    upper = datetime.datetime.now() + datetime.timedelta(days=1)
    timed, date_only, bad_clock = [], [], []
    tamper, notes = [], []
    foreign = {}

    def add_time(label, ts_iso, precise=True):
        ts = from_iso(ts_iso)
        if ts is None:
            return
        if ts < since - datetime.timedelta(minutes=5) or ts > upper:
            # Boards with no real-time clock stamp a fixed fake date
            bad_clock.append((label, ts))
        elif precise:
            timed.append((ts, label))
        else:
            date_only.append((ts.date(), label))

    bf, nf = base["files"], now["files"]
    for k, cur in nf.items():
        old = bf.get(k)
        kind = cur["k"]
        if kind.startswith("host:"):
            if old is None:
                foreign.setdefault(kind[5:], []).append(cur)
            elif cur["m"] != old["m"] or cur["s"] != old["s"]:
                notes.append("%s changed (%s) - normal if this PC wrote it, "
                             "suspicious otherwise" % (cur["p"], kind[5:]))
            continue
        if kind == "chkdsk":
            if old is None:
                tamper.append(("Windows CHKDSK recovered lost data into %s - the drive "
                               "was repaired after an unclean removal" % cur["p"], "high"))
            continue
        if cur["x"]:
            if old is None:
                add_time("deleted entry " + cur["p"], cur["m"])
            continue
        if old is None:
            add_time("new " + cur["p"], cur["c"])
            if cur["m"] != cur["c"]:
                add_time("write " + cur["p"], cur["m"])
        else:
            if cur["m"] != old["m"] or cur["s"] != old["s"]:
                add_time("write " + cur["p"], cur["m"])
            if cur["a"] and cur["a"] != old["a"]:
                add_time("read " + cur["p"], cur["a"], precise=False)
    for k, old in bf.items():
        if k not in nf and not old["x"] and old["k"] == "other":
            notes.append("%s was removed" % old["p"])

    for who, items in foreign.items():
        when = sorted(filter(None, (from_iso(i["c"]) for i in items)))
        tamper.append(("Drive was plugged into a %s (created %s%s)" % (
            who, ", ".join(sorted({i["p"] for i in items})[:4]),
            "; first seen %s" % iso(when[0]) if when else ""), "high"))

    # ---- low-level unclean-shutdown indicators ---------------------------
    yanks = []
    fl, bfl = now.get("flags"), base.get("flags")
    if fl:
        if fl["boot_dirty"]:
            if raw_note == "linux-rw":
                notes.append("Boot-sector dirty bit is set, but Linux sets it itself while "
                             "the drive is mounted read-write, so it is ignored here.")
            else:
                yanks.append(("Boot sector 'volume dirty' bit is SET: the last writable "
                              "mount was not cleanly ejected", "medium"))
        if not fl["fat_clean_shutdown"]:
            yanks.append(("FAT[1] clean-shutdown bit is CLEARED (%s): power was lost or the "
                          "drive was pulled while a host had it open for writing" % fl["fat1_raw"],
                          "high"))
        if fl["boot_errors"] or not fl["fat_no_hard_error"]:
            yanks.append(("A host recorded disk I/O errors on this drive", "medium"))
        if fl["fsinfo_stale"] and not (bfl and bfl.get("fsinfo_stale")):
            yanks.append(("FSInfo free-cluster counter (%s) disagrees with the real FAT (%s): "
                          "the last writer never finished its sync" % (fl["fsinfo_free"], fl["actual_free"]),
                          "medium"))
        if bfl and fl["fat_mirror_diffs"] > bfl.get("fat_mirror_diffs", 0):
            yanks.append(("FAT #1 and FAT #2 now differ in %d entries: a write was cut between "
                          "the two copies" % fl["fat_mirror_diffs"], "high"))
        if bfl and fl["fat_sha256"] != bfl.get("fat_sha256") and not timed and not bad_clock \
                and not foreign and not date_only:
            notes.append("The allocation table changed although no file timestamps did.")
    if now.get("orphans") is not None and base.get("orphans") is not None \
            and now["orphans"] > base["orphans"]:
        yanks.append(("%d orphaned clusters appeared (allocated but owned by no file): a "
                      "file write was cut off by power loss" % (now["orphans"] - base["orphans"]),
                      "high"))

    # ---- music is content, not evidence ------------------------------------
    added = len(set(now["music"]) - set(base["music"]))
    removed = len(set(base["music"]) - set(now["music"]))

    # ---- cluster timed events into power-on sessions -------------------------
    timed.sort()
    sessions = []
    for ts, label in timed:
        if sessions and ts - sessions[-1]["end"] <= gap:
            sessions[-1]["end"] = ts
            sessions[-1]["events"].append(label)
        else:
            sessions.append({"start": ts, "end": ts, "events": [label]})
    timed_days = {s["start"].date() for s in sessions}
    extra_days = sorted({d for d, _ in date_only} - timed_days)

    if sessions:
        rides = len(sessions) + len(extra_days)
        confidence = "MEDIUM - counts only power-ons where the MP3 board wrote to the drive"
    elif extra_days:
        rides = len(extra_days)
        confidence = "LOW - only last-access dates moved; at least one ride on each of these days"
    elif bad_clock:
        rides = None
        confidence = ("NOT COUNTABLE - the board wrote %d time(s) but stamps a fake date "
                      "(no clock), so separate rides cannot be told apart" % len(bad_clock))
    else:
        rides = 0
        confidence = ("NO EVIDENCE - nothing on the drive changed. Either the car was not "
                      "used, or this MP3 board never writes to the drive (run the calibration test)")

    return {
        "sessions": [{"start": iso(s["start"]), "end": iso(s["end"]), "events": s["events"]}
                     for s in sessions],
        "extra_days": [d.isoformat() for d in extra_days],
        "bad_clock": [(l, iso(t)) for l, t in bad_clock],
        "rides": rides, "confidence": confidence,
        "revenue": None if rides is None else rides * settings["price"],
        "yanks": yanks, "tamper": tamper, "notes": notes,
        "music_added": added, "music_removed": removed, "music_total": len(now["music"]),
        "flags": fl, "orphans": now.get("orphans"),
    }


# ==========================================================================
# 7. REPORTS (plain text + HTML, saved on the PC, never on the drive)
# ==========================================================================
def money(x, cur):
    return "%s %s" % (cur, "{:,.2f}".format(x)) if x is not None else "n/a"


def build_text_report(meta, res, period, calib):
    s = meta["settings"]
    lines = [
        "CAR AUDIT REPORT - %s" % meta["car_name"],
        "=" * 60,
        "Drive ID          : %s" % meta["car_id"],
        "Period            : %s  ->  %s" % period,
        "Evidence source   : %s" % res["source"],
        "Price per ride    : %s   Ride length: %d min" % (money(s["price"], s["currency"]), s["ride_minutes"]),
        "",
        "TOTAL ESTIMATED RIDES   : %s" % ("not countable" if res["rides"] is None else res["rides"]),
        "TAMPER / YANK EVENTS    : %d (at least)" % (len(res["yanks"]) + len(res["tamper"])),
        "CALCULATED REVENUE      : %s" % money(res["revenue"], s["currency"]),
        "Confidence              : %s" % res["confidence"],
        "",
    ]
    if calib is not None:
        seen = res["rides"] or 0
        if res["rides"] is None:
            lines += ["CALIBRATION: you drove %d ride(s); the board wrote %d time(s), all with a "
                      "fake date." % (calib, len(res["bad_clock"])),
                      "  -> " + ("One write per ride, but undated: rides could be counted only if "
                                 "you audit after every ride." if len(res["bad_clock"]) == calib else
                                 "Fewer writes than rides: this board cannot be used to count rides."),
                      ""]
            calib = None
    if calib is not None:
        lines += ["CALIBRATION: you drove %d ride(s); the drive shows %s." % (calib, seen),
                  "  -> " + ("This board leaves usable traces." if seen == calib else
                             "Partial traces only - treat ride counts as a minimum." if seen else
                             "This MP3 board leaves NO trace. Ride counting is not possible with "
                             "this board; only tamper detection works. See About -> hardware."), ""]
    lines.append("Unclean removal / power-cut evidence:")
    lines += ["  [%s] %s" % (c, t) for t, c in res["yanks"]] or ["  none"]
    lines.append("Tamper evidence:")
    lines += ["  [%s] %s" % (c, t) for t, c in res["tamper"]] or ["  none"]
    lines.append("Power-on sessions:")
    for i, sess in enumerate(res["sessions"], 1):
        lines.append("  %3d. %s - %s  (%d event%s)" % (i, sess["start"], sess["end"][11:],
                     len(sess["events"]), "" if len(sess["events"]) == 1 else "s"))
    for d in res["extra_days"]:
        lines.append("   +   %s  (date-only evidence)" % d)
    if not res["sessions"] and not res["extra_days"]:
        lines.append("  none")
    if res["bad_clock"]:
        lines.append("Writes with an impossible date (board has no clock): %d" % len(res["bad_clock"]))
    lines.append("Music files: %d on drive, %d added, %d removed (ignored for counting)"
                 % (res["music_total"], res["music_added"], res["music_removed"]))
    if res["notes"]:
        lines.append("Notes:")
        lines += ["  - " + n for n in res["notes"]]
    if res["flags"]:
        f = res["flags"]
        lines += ["Raw FAT32 state: boot_dirty=%s fat_clean=%s fat1=%s fsinfo_free=%s actual_free=%s "
                  "fat_mirror_diffs=%s orphans=%s" % (f["boot_dirty"], f["fat_clean_shutdown"],
                  f["fat1_raw"], f["fsinfo_free"], f["actual_free"], f["fat_mirror_diffs"], res["orphans"])]
    return "\n".join(lines) + "\n"


def build_html_report(meta, res, period, text):
    s = meta["settings"]
    e = html.escape
    tamper_n = len(res["yanks"]) + len(res["tamper"])
    rows = "".join("<tr><td>%s</td><td>%s</td><td>%d</td></tr>" % (e(x["start"]), e(x["end"][11:]),
                   len(x["events"])) for x in res["sessions"]) or "<tr><td colspan=3>none</td></tr>"
    ev = "".join("<li><b>%s</b> %s</li>" % (e(c), e(t)) for t, c in res["yanks"] + res["tamper"]) \
        or "<li>none</li>"
    return """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Car Audit</title>
<style>
:root{--bg:#fff;--fg:#1b1f24;--mut:#5b6470;--card:#f3f5f7;--bad:#b42318;--ok:#067647}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--fg:#e8eaed;--mut:#9aa3ad;--card:#1d2126;--bad:#f97066;--ok:#47cd89}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:auto;padding:16px}
.k{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.k div{background:var(--card);border-radius:10px;padding:14px}.k b{display:block;font-size:28px}
.m{color:var(--mut)}.bad{color:var(--bad)}table{border-collapse:collapse;width:100%%}
td,th{padding:6px;border-bottom:1px solid var(--card);text-align:left}pre{white-space:pre-wrap;font-size:12px}
</style></head><body>
<h1>%s</h1><p class="m">Drive %s &middot; %s &rarr; %s &middot; source: %s</p>
<div class="k"><div>Total estimated rides<b>%s</b></div>
<div>Tamper / yank events<b class="%s">%d</b></div>
<div>Calculated revenue<b>%s</b></div></div>
<p><b>Confidence:</b> %s</p>
<h2>Evidence</h2><ul>%s</ul>
<h2>Power-on sessions</h2><table><tr><th>Start</th><th>End</th><th>Events</th></tr>%s</table>
<details><summary>Full text report</summary><pre>%s</pre></details>
</body></html>""" % (e(meta["car_name"]), e(meta["car_id"]), e(period[0]), e(period[1]), e(res["source"]),
                     "not countable" if res["rides"] is None else res["rides"],
                     "bad" if tamper_n else "", tamper_n,
                     e(money(res["revenue"], s["currency"])), e(res["confidence"]), ev, rows, e(text))


def save_reports(meta, text, html_doc):
    os.makedirs(REPORT_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", meta["car_name"]) or "car"
    base = os.path.join(REPORT_DIR, "%s_%s" % (safe, stamp))
    with open(base + ".txt", "w", encoding="utf-8") as f:
        f.write(text)
    with open(base + ".html", "w", encoding="utf-8") as f:
        f.write(html_doc)
    return base + ".txt", base + ".html"


# ==========================================================================
# 8. CLI
# ==========================================================================
def ask(prompt, default=None, cast=str, check=None):
    while True:
        suffix = " [%s]" % default if default is not None else ""
        raw = input("%s%s: " % (prompt, suffix)).strip()
        if not raw and default is not None:
            raw = str(default)
        try:
            val = cast(raw)
            if check and not check(val):
                raise ValueError
            return val
        except (ValueError, TypeError):
            print("  Invalid value, try again.")


def ask_yes(prompt, default=False):
    raw = input("%s [%s]: " % (prompt, "Y/n" if default else "y/N")).strip().lower()
    return default if not raw else raw.startswith("y")


def ask_pin(confirm=False):
    while True:
        pin = getpass.getpass("Owner PIN (min 6 chars): ")
        if len(pin) < 6:
            print("  Too short.")
            continue
        if confirm and getpass.getpass("Repeat PIN: ") != pin:
            print("  PINs do not match.")
            continue
        return pin


def pick_drive():
    """Ask for the mount point and (optionally) override the raw device."""
    hint = "E:\\" if platform.system() == "Windows" else "/media/<you>/<USB> or /Volumes/<USB>"
    mount = ask("USB drive folder/letter (e.g. %s)" % hint, check=lambda p: os.path.isdir(p))
    raw, note = resolve_raw_device(mount)
    print("  Raw device: %s" % (raw or "not detected (%s)" % note))
    override = input("  Press Enter to accept, or type a raw device / disk-image path: ").strip()
    if override:
        raw, note = override, "manual"
    return mount, raw, note


def open_volume(raw):
    """Return (RawDevice, Fat32Volume) or (None, None) with a warning."""
    if not raw:
        return None, None
    dev = RawDevice(raw)
    try:
        return dev, Fat32Volume(dev)
    except AuditError:
        dev.close()
        raise


def take_snapshot(mount, raw):
    try:
        dev, vol = open_volume(raw)
    except AuditError as e:
        print("  ! Raw FAT32 access unavailable: %s" % e)
        print("  ! Falling back to file timestamps only (no dirty flags, no deleted entries).")
        dev = vol = None
    if vol is None:
        return file_snapshot(mount), None
    try:
        snap, _ = raw_snapshot(vol)
        return snap, vol
    finally:
        dev.close()


def cmd_initialize():
    print("\n=== INITIALIZE DRIVE ===")
    print("This prepares a FAT32 USB drive in place. Existing songs are kept.")
    mount, raw, note = pick_drive()
    if raw:
        dev, vol = open_volume(raw)     # refuses exFAT/NTFS/FAT16 with a clear message
        print("  FAT32 volume '%s', serial %08X, %d clusters of %d KB"
              % (vol.label, vol.vol_id, vol.cluster_count, vol.cluster_bytes // 1024))
        if vol.cluster_count < 65525:
            print("  ! Fewer than 65525 clusters: some devices will treat this as FAT16.")
        dev.close()
    if os.path.exists(sys_path(mount, META_FILE)):
        if not ask_yes("  This drive is already initialized. Wipe its history and start over?"):
            return
    car_name = ask("Car name / number", "Car-1")
    currency = ask("Currency", "KES")
    price = ask("Price per ride", 100.0, float, lambda v: v >= 0)
    minutes = ask("Ride duration in minutes", 10, int, lambda v: 1 <= v <= 240)
    pin = ask_pin(confirm=True)

    os.makedirs(sys_path(mount), exist_ok=True)
    hide_path(sys_path(mount))
    for name in (META_FILE, LEDGER_FILE):
        if os.path.exists(sys_path(mount, name)):
            os.remove(sys_path(mount, name))
    salt = secrets.token_bytes(16)
    crypto = Crypto(pin, salt)
    now = datetime.datetime.now()
    meta = {
        "version": VERSION, "car_id": secrets.token_hex(6).upper(), "car_name": car_name,
        "created": iso(now), "audit_host": platform.system(),
        "settings": {"price": price, "ride_minutes": minutes, "currency": currency},
        "ledger_count": 0, "last_tag": None,
    }
    records = []
    tag = append_ledger(mount, crypto, records, "INIT", {"car": car_name, "host": platform.node()})
    meta["ledger_count"], meta["last_tag"] = len(records), tag
    # Baseline AFTER our files are written; .car_sys is excluded from it.
    snap, _ = take_snapshot(mount, raw)
    meta["baseline"] = snap
    meta["last_audit"] = iso(now)
    save_metadata(mount, salt, crypto, meta)
    print("\n  Done. Drive ID %s. Baseline: %d entries, %d music files (%s mode)."
          % (meta["car_id"], len(snap["files"]), len(snap["music"]), snap["mode"]))
    print("  IMPORTANT: use 'Safely Remove / Eject' now so the FAT dirty flags are cleared.")
    print("  Then run the calibration test: drive the car a known number of times and audit.")


def cmd_audit():
    print("\n=== AUDIT DRIVE ===")
    mount, raw, note = pick_drive()
    # Read the raw state FIRST, before this program writes anything.
    now_snap, vol = take_snapshot(mount, raw)
    pin = ask_pin()
    tamper_pre = []
    try:
        meta, salt, crypto = load_metadata(mount, pin)
    except TamperError as e:
        raise AuditError("Registry check failed: %s. If the PIN is right, the registry was "
                         "edited or replaced - treat this drive as tampered." % e)
    records, problems = read_ledger(mount, crypto)
    if len(records) != meta.get("ledger_count") or (records and meta.get("last_tag") is None):
        problems.append("ledger has %d records but the registry expects %d (records deleted or "
                        "an old copy restored)" % (len(records), meta.get("ledger_count", 0)))
    tamper_pre += [(p, "high") for p in problems]
    extra = sorted(set(os.listdir(sys_path(mount))) - OUR_FILES)
    if extra:
        tamper_pre.append(("unexpected files inside %s: %s" % (SYS_DIR, ", ".join(extra)), "medium"))

    base = meta["baseline"]
    if base["mode"] != now_snap["mode"]:
        print("  ! Baseline was taken in '%s' mode, now '%s' mode: comparison is weaker."
              % (base["mode"], now_snap["mode"]))
    since = from_iso(meta["last_audit"])
    res = analyse(base, now_snap, meta["settings"], since, note)
    res["tamper"] = tamper_pre + res["tamper"]
    res["source"] = "raw FAT32 (%s)" % raw if now_snap["mode"] == "raw" else "file timestamps only"

    calib = None
    if ask_yes("Calibration test? (do you know the exact number of rides since the last audit)"):
        calib = ask("Actual number of rides", 0, int, lambda v: v >= 0)

    period = (meta["last_audit"], iso(datetime.datetime.now()))
    text = build_text_report(meta, res, period, calib)
    txt_path, html_path = save_reports(meta, text, build_html_report(meta, res, period, text))
    print("\n" + text)
    print("Reports saved:\n  %s\n  %s" % (txt_path, html_path))

    if not ask_yes("Close this audit period (record it in the ledger and reset the baseline)?", True):
        print("  Not recorded. The next audit will cover the same period again.")
        return
    tag = append_ledger(mount, crypto, records, "AUDIT", {
        "from": period[0], "to": period[1], "rides": res["rides"], "revenue": res["revenue"],
        "tamper": len(res["yanks"]) + len(res["tamper"]), "calibration": calib,
        "settings": meta["settings"]})
    meta["ledger_count"], meta["last_tag"] = len(records), tag
    meta["baseline"], _ = take_snapshot(mount, raw)
    meta["last_audit"] = period[1]
    save_metadata(mount, salt, crypto, meta)
    print("  Audit recorded (ledger entry #%d). Eject the drive safely before unplugging." % len(records))


def cmd_settings():
    print("\n=== PRICE / RIDE SETTINGS ===")
    mount = ask("USB drive folder/letter", check=lambda p: os.path.isdir(p))
    meta, salt, crypto = load_metadata(mount, ask_pin())
    records, problems = read_ledger(mount, crypto)
    if problems:
        raise AuditError("Ledger problems found (%s). Run an audit first." % "; ".join(problems))
    s = meta["settings"]
    s["currency"] = ask("Currency", s["currency"])
    s["price"] = ask("Price per ride", s["price"], float, lambda v: v >= 0)
    s["ride_minutes"] = ask("Ride duration in minutes", s["ride_minutes"], int, lambda v: 1 <= v <= 240)
    meta["last_tag"] = append_ledger(mount, crypto, records, "SETTINGS", dict(s))
    meta["ledger_count"] = len(records)
    save_metadata(mount, salt, crypto, meta)
    print("  Saved.")


def cmd_history():
    print("\n=== LEDGER HISTORY ===")
    mount = ask("USB drive folder/letter", check=lambda p: os.path.isdir(p))
    meta, _, crypto = load_metadata(mount, ask_pin())
    records, problems = read_ledger(mount, crypto)
    cur = meta["settings"]["currency"]
    total = 0.0
    for r in records:
        d = r["data"]
        if r["type"] == "AUDIT":
            total += d.get("revenue") or 0
            print("  #%-3d %s AUDIT  %s -> %s  rides=%s  revenue=%s  tamper=%s" % (
                r["seq"], r["time"], d["from"][:16], d["to"][:16],
                "n/a" if d["rides"] is None else d["rides"], money(d["revenue"], cur), d["tamper"]))
        else:
            print("  #%-3d %s %s %s" % (r["seq"], r["time"], r["type"], json.dumps(d)))
    print("  Lifetime audited revenue: %s" % money(total, cur))
    for p in problems:
        print("  ! " + p)


def cmd_inspect():
    print("\n=== RAW FAT32 INSPECTION (read-only, no PIN) ===")
    raw = input("Raw device or disk image (blank = pick by drive folder): ").strip()
    if not raw:
        _, raw, _ = pick_drive()
    dev, vol = open_volume(raw)
    try:
        flags = vol.read_flags()
        entries, reached = vol.walk()
        print("  Label %-11s serial %08X  clusters %d x %d B  FATs %d (active %d)" % (
            vol.label, vol.vol_id, vol.cluster_count, vol.cluster_bytes, vol.nfats, vol.active_fat))
        for k, v in flags.items():
            print("  %-20s %s" % (k, v))
        print("  %-20s %d" % ("orphan_clusters", vol.orphan_clusters(reached)))
        live = [e for e in entries if not e["deleted"]]
        print("  Entries: %d live, %d deleted" % (len(live), len(entries) - len(live)))
        for e in sorted(entries, key=lambda x: x["path"].lower())[:200]:
            print("   %s %-48s c=%s m=%s a=%s" % ("DEL" if e["deleted"] else ("DIR" if e["dir"] else "   "),
                  e["path"][:48], iso(e["ctime"]), iso(e["mtime"]), e["adate"].date() if e["adate"] else None))
    finally:
        dev.close()


ABOUT = """
HOW TO USE
  1. Initialize: plug the stick into your PC, choose option 1, set PIN/price/ride length.
     Always "Safely Remove / Eject" afterwards.
  2. Calibrate once per car: drive exactly N rides, yank the stick once while the car
     is on, then audit (option 2) and answer the calibration question with N.
  3. Audit whenever you like. Reports are saved in: %s

WHAT THE NUMBERS MEAN
  Rides     = distinct power-on sessions in which the MP3 board wrote to the drive,
              grouped by your ride duration. A ride that writes nothing is invisible.
  Tamper    = foreign computer/phone mounts, CHKDSK repairs, registry/ledger edits.
  Yank      = unclean-removal scars (dirty flags, orphaned clusters, FAT mismatch,
              stale FSInfo). These prove "at least one", they cannot count each yank.

WHY THERE IS NO "AUTO-RUN" FILE ON THE DRIVE
  A USB stick cannot execute code, and MP3 boards never run files from it. Nothing
  placed on the drive can force the board to write. That is why calibration matters.

BETTER HARDWARE OPTIONS (if calibration shows the board leaves no trace)
  * A sealed 12V/24V hour meter or impulse counter wired to the car's ignition
    (very cheap, counts every power-on, cannot be bypassed by pulling the USB).
  * A small microcontroller logger (e.g. ESP32 or ATmega + RTC + its own SD card)
    powered from the ignition line that writes a timestamped line per power-on.
    This script's ledger/report format could then read that log file instead.
"""


def main():
    print("Kids' Car Rental Auditor v%s - offline, standard-library Python" % VERSION)
    actions = {"1": cmd_initialize, "2": cmd_audit, "3": cmd_settings,
               "4": cmd_history, "5": cmd_inspect, "6": lambda: print(ABOUT % REPORT_DIR)}
    while True:
        print("\n  1) Initialize a USB drive\n  2) Run audit\n  3) Change price / ride duration"
              "\n  4) View ledger history\n  5) Inspect raw FAT32 state\n  6) About / limitations"
              "\n  0) Exit")
        choice = input("Choose: ").strip()
        if choice == "0":
            return
        fn = actions.get(choice)
        if not fn:
            continue
        try:
            fn()
        except AuditError as e:
            print("\n  ERROR: %s" % e)
        except KeyboardInterrupt:
            print("\n  Cancelled.")
        except OSError as e:
            print("\n  Drive I/O error: %s (was the drive removed?)" % e)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print()
