#!/usr/bin/env python3
"""
NTFS USN Journal Parser
Parses raw USN Journal ($UsnJrnl:$J) to extract file change records.

The USN Journal logs file-level changes (create, delete, rename, modify).
Critical for detecting timestomping - USN records the ACTUAL time of file creation.

Author: Cyber Chakshu SIEM Team
"""

import struct
import os
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


USN_REASON_FLAGS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x00400000: "TRANSACTED_CHANGE",
    0x80000000: "CLOSE",
}


@dataclass
class USNRecord:
    """USN Record structure"""

    record_length: int
    major_version: int
    minor_version: int
    file_reference_number: int
    parent_file_reference_number: int
    usn: int
    timestamp: datetime
    reason: int
    source_info: int
    security_id: int
    file_attributes: int
    file_name_length: int
    file_name_offset: int
    file_name: str

    @property
    def reasons_str(self) -> List[str]:
        """Get human-readable reason flags"""
        reasons = []
        for flag, name in USN_REASON_FLAGS.items():
            if self.reason & flag:
                reasons.append(name)
        return reasons if reasons else ["NONE"]

    @property
    def file_ref_str(self) -> str:
        """Format file reference number"""
        return f"0x{self.file_reference_number:016X}"

    @property
    def parent_ref_str(self) -> str:
        """Format parent file reference number"""
        return f"0x{self.parent_file_reference_number:016X}"


@dataclass
class USNJournalHeader:
    """USN Journal Header"""

    journal_size: int
    allocation_size: int
    free_size: int
    lowest_valid_usn: int
    max_usn: int
    next_usn: int
    record_count: int = 0


class USNJournalParser:
    """Parser for raw NTFS USN Journal"""

    USN_JOURNAL_MAGIC = 0x00000000

    def __init__(self, usn_data: bytes):
        self.data = usn_data
        self.header: Optional[USNJournalHeader] = None
        self.records: List[USNRecord] = []
        self._parse()

    def _read_timestamp(self, offset: int) -> datetime:
        """Read 8-byte NTFS timestamp (100-nanosecond intervals since 1601-01-01)"""
        try:
            value = struct.unpack("<Q", self.data[offset : offset + 8])[0]
            if value == 0:
                return datetime(1601, 1, 1)
            return datetime(1601, 1, 1) + timedelta(microseconds=value // 10)
        except:
            return datetime(1601, 1, 1)

    def _parse_header(self, offset: int = 0) -> Optional[USNJournalHeader]:
        """Parse USN Journal header"""
        if len(self.data) < 80:
            return None

        try:
            journal_size = struct.unpack("<Q", self.data[0:8])[0]
            allocation_size = struct.unpack("<Q", self.data[8:16])[0]
            free_size = struct.unpack("<Q", self.data[16:24])[0]
            lowest_valid_usn = struct.unpack("<Q", self.data[24:32])[0]
            max_usn = struct.unpack("<Q", self.data[32:40])[0]
            next_usn = struct.unpack("<Q", self.data[40:48])[0]

            self.header = USNJournalHeader(
                journal_size=journal_size,
                allocation_size=allocation_size,
                free_size=free_size,
                lowest_valid_usn=lowest_valid_usn,
                max_usn=max_usn,
                next_usn=next_usn,
            )
            return self.header
        except:
            return None

    def _parse_record(self, offset: int) -> Optional[USNRecord]:
        """Parse a single USN record"""
        if offset + 64 > len(self.data):
            return None

        try:
            record_length = struct.unpack("<I", self.data[offset : offset + 4])[0]
            if record_length == 0 or record_length > 65536:
                return None

            if offset + record_length > len(self.data):
                return None

            major_version = struct.unpack("<H", self.data[offset + 4 : offset + 6])[0]
            minor_version = struct.unpack("<H", self.data[offset + 6 : offset + 8])[0]

            if major_version != 2:
                return None

            file_reference_number = struct.unpack(
                "<Q", self.data[offset + 8 : offset + 16]
            )[0]
            parent_file_reference_number = struct.unpack(
                "<Q", self.data[offset + 16 : offset + 24]
            )[0]
            usn = struct.unpack("<Q", self.data[offset + 24 : offset + 32])[0]

            timestamp = self._read_timestamp(offset + 32)

            reason = struct.unpack("<I", self.data[offset + 40 : offset + 44])[0]
            source_info = struct.unpack("<I", self.data[offset + 44 : offset + 48])[0]
            security_id = struct.unpack("<I", self.data[offset + 48 : offset + 52])[0]
            file_attributes = struct.unpack("<I", self.data[offset + 52 : offset + 56])[
                0
            ]
            file_name_length = struct.unpack(
                "<H", self.data[offset + 58 : offset + 60]
            )[0]
            file_name_offset = struct.unpack(
                "<H", self.data[offset + 60 : offset + 62]
            )[0]

            name_offset = offset + file_name_offset
            if name_offset + file_name_length <= len(self.data):
                file_name = self.data[
                    name_offset : name_offset + file_name_length
                ].decode("utf-16-le", errors="ignore")
            else:
                file_name = ""

            return USNRecord(
                record_length=record_length,
                major_version=major_version,
                minor_version=minor_version,
                file_reference_number=file_reference_number,
                parent_file_reference_number=parent_file_reference_number,
                usn=usn,
                timestamp=timestamp,
                reason=reason,
                source_info=source_info,
                security_id=security_id,
                file_attributes=file_attributes,
                file_name_length=file_name_length,
                file_name_offset=file_name_offset,
                file_name=file_name,
            )
        except:
            return None

    def _parse(self):
        """Parse all USN records"""
        self.header = self._parse_header()

        if not self.header:
            return

        offset = 64
        record_count = 0

        while offset < len(self.data) and offset < 1024 * 1024:
            record = self._parse_record(offset)
            if record:
                self.records.append(record)
                offset += record.record_length
                record_count += 1
            else:
                break

        if self.header:
            self.header.record_count = record_count

    def get_records(self) -> List[USNRecord]:
        """Get all parsed USN records"""
        return self.records

    def get_file_create_events(self) -> List[USNRecord]:
        """Get all FILE_CREATE events"""
        return [r for r in self.records if r.reason & 0x00000100]

    def get_file_delete_events(self) -> List[USNRecord]:
        """Get all FILE_DELETE events"""
        return [r for r in self.records if r.reason & 0x00000200]

    def get_rename_events(self) -> List[USNRecord]:
        """Get all rename events"""
        return [r for r in self.records if r.reason & (0x00001000 | 0x00002000)]

    def get_records_for_file(self, file_ref: int) -> List[USNRecord]:
        """Get all USN records for a specific file reference number"""
        return [r for r in self.records if r.file_reference_number == file_ref]

    def get_first_create_time(self, file_ref: int) -> Optional[datetime]:
        """Get first creation time for a file from USN journal"""
        file_records = self.get_records_for_file(file_ref)
        create_records = [r for r in file_records if r.reason & 0x00000100]

        if create_records:
            return min(r.timestamp for r in create_records)
        return None

    def detect_timestomp(
        self, si_created: datetime, fn_created: datetime, file_ref: int
    ) -> Dict[str, Any]:
        """Detect timestomping by comparing SI/FN with USN journal"""
        usn_create_time = self.get_first_create_time(file_ref)

        result = {
            "usn_create_time": usn_create_time.isoformat() if usn_create_time else None,
            "si_created": si_created.isoformat() if si_created else None,
            "fn_created": fn_created.isoformat() if fn_created else None,
            "is_suspicious": False,
            "reason": "",
            "severity": "LOW",
        }

        if not usn_create_time:
            result["reason"] = (
                "No USN FILE_CREATE record found - journal may have been cleared"
            )
            result["severity"] = "HIGH"
            result["is_suspicious"] = True
            return result

        if si_created and fn_created:
            usn_vs_si_diff = abs((usn_create_time - si_created).total_seconds())
            usn_vs_fn_diff = abs((usn_create_time - fn_created).total_seconds())

            if usn_vs_si_diff > 86400:
                result["is_suspicious"] = True
                result["reason"] = (
                    f"SI created time differs from USN by {usn_vs_si_diff / 86400:.1f} days"
                )
                result["severity"] = "HIGH"
            elif usn_vs_fn_diff > 86400:
                result["is_suspicious"] = True
                result["reason"] = (
                    f"FN created time differs from USN by {usn_vs_fn_diff / 86400:.1f} days"
                )
                result["severity"] = "HIGH"
            elif si_created < usn_create_time:
                result["is_suspicious"] = True
                result["reason"] = (
                    "SI created time is BEFORE USN journal creation event"
                )
                result["severity"] = "CRITICAL"
            else:
                result["reason"] = "All timestamps consistent with USN journal"

        return result

    def export_to_dict(self) -> Dict[str, Any]:
        """Export parsed USN data to dictionary"""
        return {
            "header": {
                "journal_size": self.header.journal_size if self.header else 0,
                "allocation_size": self.header.allocation_size if self.header else 0,
                "free_size": self.header.free_size if self.header else 0,
                "lowest_valid_usn": self.header.lowest_valid_usn if self.header else 0,
                "max_usn": self.header.max_usn if self.header else 0,
                "next_usn": self.header.next_usn if self.header else 0,
                "record_count": self.header.record_count if self.header else 0,
            },
            "total_records": len(self.records),
            "create_events": len(self.get_file_create_events()),
            "delete_events": len(self.get_file_delete_events()),
            "rename_events": len(self.get_rename_events()),
            "records": [
                {
                    "file_reference": r.file_ref_str,
                    "parent_reference": r.parent_ref_str,
                    "usn": r.usn,
                    "timestamp": r.timestamp.isoformat(),
                    "reasons": r.reasons_str,
                    "file_name": r.file_name,
                }
                for r in self.records[:1000]
            ],
        }


def parse_usn_from_image(
    image_path: str, partition_offset: int = 0, image_type: str = "raw"
) -> USNJournalParser:
    """Parse USN Journal from a disk image using icat (The Sleuth Kit)"""
    import subprocess

    cmd = ["icat"]
    if image_type == "ewf":
        cmd.extend(["-i", "ewf"])
    cmd.extend(["-o", str(partition_offset)])
    cmd.append(image_path)
    cmd.append("$UsnJrnl:$J")

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=120)
        if result.returncode == 0 and result.stdout:
            return USNJournalParser(result.stdout)
    except Exception as e:
        print(f"Error extracting USN Journal: {e}")

    return USNJournalParser(b"")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python usn_parser.py <usn_journal_binary_file>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    parser = USNJournalParser(data)

    print(f"USN Journal Analysis")
    print("=" * 60)
    if parser.header:
        print(f"Journal Size: {parser.header.journal_size:,} bytes")
        print(f"Allocation Size: {parser.header.allocation_size:,} bytes")
        print(f"Free Size: {parser.header.free_size:,} bytes")
        print(f"Total Records: {len(parser.records):,}")
        print(f"File Create Events: {len(parser.get_file_create_events()):,}")
        print(f"File Delete Events: {len(parser.get_file_delete_events()):,}")
        print(f"Rename Events: {len(parser.get_rename_events()):,}")
    else:
        print("Could not parse USN journal header")
