#!/usr/bin/env python3
"""
NTFS Volume Information Parser
Parses $Volume and boot sector to extract volume-level metadata.

Critical for forensic analysis - provides volume creation time,
serial number, and other volume-level timestamps.

Author: Cyber Chakshu SIEM Team
"""

import struct
import os
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class VolumeInformation:
    """Volume Information from $Volume"""

    volume_flags: int
    version: int
    minor_version: int
    volume_creation_time: Optional[datetime]
    volume_modification_time: Optional[datetime]
    volume_serial_number: Optional[str]
    sectors_per_cluster: int
    bytes_per_sector: int
    total_sectors: int
    free_sectors: int
    cluster_count: int
    free_clusters: int


@dataclass
class BootSector:
    """NTFS Boot Sector"""

    jump_instruction: bytes
    oem_id: bytes
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    fats: int
    root_entries: int
    small_sectors: int
    media_descriptor: int
    sectors_per_fat: int
    sectors_per_track: int
    heads: int
    hidden_sectors: int
    large_sectors: int
    total_sectors_64: int
    mft_location: int
    mft_mirror_location: int
    clusters_per_mft_record: int
    clusters_per_index_buffer: int
    volume_serial_number: str
    checksum: int
    bootstrap: bytes
    signature: str


class VolumeInfoParser:
    """Parser for NTFS Volume information"""

    NTFS_SIGNATURE = b"NTFS    "

    def __init__(self, volume_data: bytes = None, boot_sector_data: bytes = None):
        self.volume_data = volume_data or b""
        self.boot_sector_data = boot_sector_data or b""
        self.volume_info: Optional[VolumeInformation] = None
        self.boot_sector: Optional[BootSector] = None
        self._parse()

    def _read_timestamp(self, offset: int, data: bytes) -> Optional[datetime]:
        """Read 8-byte NTFS timestamp"""
        if offset + 8 > len(data):
            return None
        try:
            value = struct.unpack("<Q", data[offset : offset + 8])[0]
            if value == 0:
                return None
            return datetime(1601, 1, 1) + timedelta(microseconds=value // 10)
        except:
            return None

    def _parse_volume(self) -> Optional[VolumeInformation]:
        """Parse $Volume attribute"""
        if len(self.volume_data) < 100:
            return None

        try:
            volume_flags = struct.unpack("<I", self.volume_data[0:4])[0]
            version = struct.unpack("<H", self.volume_data[4:6])[0]
            minor_version = struct.unpack("<H", self.volume_data[6:8])[0]

            volume_creation = self._read_timestamp(8, self.volume_data)
            volume_modification = self._read_timestamp(16, self.volume_data)

            return VolumeInformation(
                volume_flags=volume_flags,
                version=version,
                minor_version=minor_version,
                volume_creation_time=volume_creation,
                volume_modification_time=volume_modification,
                volume_serial_number=None,
                sectors_per_cluster=0,
                bytes_per_sector=512,
                total_sectors=0,
                free_sectors=0,
                cluster_count=0,
                free_clusters=0,
            )
        except:
            return None

    def _parse_boot_sector(self) -> Optional[BootSector]:
        """Parse NTFS Boot Sector"""
        if len(self.boot_sector_data) < 80:
            return None

        try:
            jump_instruction = self.boot_sector_data[0:3]
            oem_id = self.boot_sector_data[3:11]

            if oem_id != self.NTFS_SIGNATURE:
                return None

            bytes_per_sector = struct.unpack("<H", self.boot_sector_data[11:13])[0]
            sectors_per_cluster = self.boot_sector_data[13]
            reserved_sectors = struct.unpack("<H", self.boot_sector_data[14:16])[0]
            fats = self.boot_sector_data[16]
            root_entries = struct.unpack("<H", self.boot_sector_data[17:19])[0]
            small_sectors = struct.unpack("<H", self.boot_sector_data[19:21])[0]
            media_descriptor = self.boot_sector_data[21]
            sectors_per_fat = struct.unpack("<H", self.boot_sector_data[22:24])[0]
            sectors_per_track = struct.unpack("<H", self.boot_sector_data[24:26])[0]
            heads = struct.unpack("<H", self.boot_sector_data[26:28])[0]
            hidden_sectors = struct.unpack("<I", self.boot_sector_data[28:32])[0]
            large_sectors = struct.unpack("<I", self.boot_sector_data[32:36])[0]

            total_sectors_64 = struct.unpack("<Q", self.boot_sector_data[40:48])[0]
            mft_location = struct.unpack("<Q", self.boot_sector_data[48:56])[0]
            mft_mirror_location = struct.unpack("<Q", self.boot_sector_data[56:64])[0]
            clusters_per_mft_record = struct.unpack("<Q", self.boot_sector_data[64:72])[
                0
            ]
            clusters_per_index_buffer = struct.unpack(
                "<Q", self.boot_sector_data[72:80]
            )[0]

            volume_serial_bytes = self.boot_sector_data[80:88]
            volume_serial_number = f"{volume_serial_bytes[3]:02X}{volume_serial_bytes[2]:02X}-{volume_serial_bytes[1]:02X}{volume_serial_bytes[0]:02X}"

            checksum = struct.unpack("<I", self.boot_sector_data[88:92])[0]
            bootstrap = self.boot_sector_data[92:512]

            total_sectors = total_sectors_64
            sectors_per_cluster_val = sectors_per_cluster
            cluster_count = (
                total_sectors // sectors_per_cluster_val
                if sectors_per_cluster_val > 0
                else 0
            )
            bytes_per_cluster = bytes_per_sector * sectors_per_cluster_val

            return BootSector(
                jump_instruction=jump_instruction,
                oem_id=oem_id,
                bytes_per_sector=bytes_per_sector,
                sectors_per_cluster=sectors_per_cluster,
                reserved_sectors=reserved_sectors,
                fats=fats,
                root_entries=root_entries,
                small_sectors=small_sectors,
                media_descriptor=media_descriptor,
                sectors_per_fat=sectors_per_fat,
                sectors_per_track=sectors_per_track,
                heads=heads,
                hidden_sectors=hidden_sectors,
                large_sectors=large_sectors,
                total_sectors_64=total_sectors_64,
                mft_location=mft_location,
                mft_mirror_location=mft_mirror_location,
                clusters_per_mft_record=clusters_per_mft_record,
                clusters_per_index_buffer=clusters_per_index_buffer,
                volume_serial_number=volume_serial_number,
                checksum=checksum,
                bootstrap=bootstrap,
                signature="Valid" if checksum != 0 else "Invalid",
            )
        except:
            return None

    def _parse(self):
        """Parse both volume and boot sector"""
        self.volume_info = self._parse_volume()
        self.boot_sector = self._parse_boot_sector()

    def get_volume_info(self) -> Optional[VolumeInformation]:
        """Get volume information"""
        return self.volume_info

    def get_boot_sector(self) -> Optional[BootSector]:
        """Get boot sector information"""
        return self.boot_sector

    def get_volume_creation_time(self) -> Optional[datetime]:
        """Get volume creation time"""
        if self.boot_sector:
            return None
        if self.volume_info and self.volume_info.volume_creation_time:
            return self.volume_info.volume_creation_time
        return None

    def get_volume_serial(self) -> Optional[str]:
        """Get volume serial number"""
        if self.boot_sector:
            return self.boot_sector.volume_serial_number
        return None

    def calculate_partition_size(self) -> int:
        """Calculate partition size in bytes"""
        if self.boot_sector:
            return self.boot_sector.total_sectors_64 * self.boot_sector.bytes_per_sector
        return 0

    def get_mft_location(self) -> Optional[int]:
        """Get MFT cluster location"""
        if self.boot_sector:
            return (
                self.boot_sector.mft_location
                * self.boot_sector.sectors_per_cluster
                * self.boot_sector.bytes_per_sector
            )
        return None

    def export_to_dict(self) -> Dict[str, Any]:
        """Export volume info to dictionary"""
        result = {
            "boot_sector": None,
            "volume_info": None,
        }

        if self.boot_sector:
            bs = self.boot_sector
            result["boot_sector"] = {
                "oem_id": bs.oem_id.decode("ascii", errors="ignore"),
                "bytes_per_sector": bs.bytes_per_sector,
                "sectors_per_cluster": bs.sectors_per_cluster,
                "total_sectors": bs.total_sectors_64,
                "volume_size_bytes": bs.total_sectors_64 * bs.bytes_per_sector,
                "volume_size_gb": round(
                    bs.total_sectors_64 * bs.bytes_per_sector / (1024**3), 2
                ),
                "mft_location": bs.mft_location,
                "mft_mirror_location": bs.mft_mirror_location,
                "clusters_per_mft_record": bs.clusters_per_mft_record,
                "clusters_per_index_buffer": bs.clusters_per_index_buffer,
                "volume_serial_number": bs.volume_serial_number,
                "signature": bs.signature,
            }

        if self.volume_info:
            vi = self.volume_info
            result["volume_info"] = {
                "volume_flags": vi.volume_flags,
                "version": vi.version,
                "minor_version": vi.minor_version,
                "volume_creation_time": vi.volume_creation_time.isoformat()
                if vi.volume_creation_time
                else None,
                "volume_modification_time": vi.volume_modification_time.isoformat()
                if vi.volume_modification_time
                else None,
            }

        return result


def parse_volume_from_image(
    image_path: str, partition_offset: int = 0, image_type: str = "raw"
) -> VolumeInfoParser:
    """Parse volume info from a disk image using icat (The Sleuth Kit)"""
    import subprocess

    cmd = ["icat"]
    if image_type == "ewf":
        cmd.extend(["-i", "ewf"])
    cmd.extend(["-o", str(partition_offset)])
    cmd.append(image_path)
    cmd.append("$Volume")

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=60)
        volume_data = result.stdout if result.returncode == 0 else b""
    except:
        volume_data = b""

    boot_offset = partition_offset * 512
    cmd = ["dd", f"if={image_path}", "bs=512", "count=1", f"skip={partition_offset}"]

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=30)
        boot_data = result.stdout if result.returncode == 0 else b""
    except:
        boot_data = b""

    return VolumeInfoParser(volume_data=volume_data, boot_sector_data=boot_data)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python volume_parser.py <volume_binary_file> [boot_sector_file]")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        volume_data = f.read()

    boot_data = b""
    if len(sys.argv) > 2:
        with open(sys.argv[2], "rb") as f:
            boot_data = f.read()

    parser = VolumeInfoParser(volume_data=volume_data, boot_sector_data=boot_data)

    print("Volume Information Analysis")
    print("=" * 60)

    if parser.boot_sector:
        bs = parser.boot_sector
        print(f"OEM ID: {bs.oem_id.decode()}")
        print(
            f"Volume Size: {bs.total_sectors_64 * bs.bytes_per_sector:,} bytes ({round(bs.total_sectors_64 * bs.bytes_per_sector / (1024**3), 2)} GB)"
        )
        print(f"Volume Serial: {bs.volume_serial_number}")
        print(f"Bytes Per Sector: {bs.bytes_per_sector}")
        print(f"Sectors Per Cluster: {bs.sectors_per_cluster}")
        print(f"MFT Location: Cluster {bs.mft_location}")
        print(f"Clusters Per MFT Record: {bs.clusters_per_mft_record}")
    else:
        print("Could not parse boot sector")

    if parser.volume_info:
        vi = parser.volume_info
        print(f"\nVolume Creation Time: {vi.volume_creation_time}")
        print(f"Volume Modification Time: {vi.volume_modification_time}")
        print(f"Volume Flags: 0x{vi.volume_flags:08X}")
    else:
        print("\nCould not parse $Volume")
