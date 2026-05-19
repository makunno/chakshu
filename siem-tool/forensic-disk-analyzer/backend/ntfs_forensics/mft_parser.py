#!/usr/bin/env python3
"""
NTFS MFT Parser
Parses raw Master File Table to extract $SI and $FN timestamps separately.

The key forensic insight: $SI and $FN store timestamps independently.
Attackers often modify $SI but forget $FN (or vice versa).

Author: Cyber Chakshu SIEM Team
"""

import struct
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


class AttributeType(Enum):
    """NTFS Attribute Type IDs"""

    STANDARD_INFORMATION = 0x10
    ATTRIBUTE_LIST = 0x20
    FILE_NAME = 0x30
    OBJECT_ID = 0x40
    SECURITY_DESCRIPTOR = 0x50
    VOLUME_NAME = 0x60
    VOLUME_INFORMATION = 0x70
    DATA = 0x80
    INDEX_ROOT = 0x90
    INDEX_ALLOCATION = 0xA0
    BITMAP = 0xB0
    REPARSE_POINT = 0xC0
    EA_INFORMATION = 0xE0
    EA = 0xF0
    LOGGED_UTILITY_STREAM = 0x100


@dataclass
class NTFSTime:
    """Windows NTFS timestamp (100-nanosecond intervals since 1601-01-01)"""

    value: int

    def to_datetime(self) -> Optional[datetime]:
        """Convert NTFS timestamp to Python datetime"""
        if self.value == 0:
            return None
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=self.value // 10)
        except (ValueError, OSError):
            return None

    def to_iso_string(self) -> Optional[str]:
        """Convert to ISO format string"""
        dt = self.to_datetime()
        return dt.isoformat() if dt else None

    def __str__(self):
        return self.to_iso_string() or "None"


@dataclass
class SIAttribute:
    """$Standard_Information ($SI) Attribute"""

    created: NTFSTime
    modified: NTFSTime
    mft_modified: NTFSTime
    accessed: NTFSTime
    flags: int
    owner_id: int
    security_id: int

    @property
    def created_str(self) -> str:
        return self.created.to_iso_string() or "None"

    @property
    def modified_str(self) -> str:
        return self.modified.to_iso_string() or "None"

    @property
    def accessed_str(self) -> str:
        return self.accessed.to_iso_string() or "None"

    @property
    def mft_modified_str(self) -> str:
        return self.mft_modified.to_iso_string() or "None"


@dataclass
class FNAttribute:
    """$File_Name ($FN) Attribute"""

    parent_directory_ref: int
    created: NTFSTime
    modified: NTFSTime
    mft_modified: NTFSTime
    accessed: NTFSTime
    allocated_size: int
    real_size: int
    flags: int
    filename: str
    namespace: int

    @property
    def created_str(self) -> str:
        return self.created.to_iso_string() or "None"

    @property
    def modified_str(self) -> str:
        return self.modified.to_iso_string() or "None"

    @property
    def accessed_str(self) -> str:
        return self.accessed.to_iso_string() or "None"

    @property
    def mft_modified_str(self) -> str:
        return self.mft_modified.to_iso_string() or "None"


@dataclass
class MFTRecord:
    """MFT Record structure"""

    record_number: int
    sequence_number: int
    is_in_use: bool
    is_directory: bool
    allocated_size: int
    real_size: int
    base_record_ref: int
    attributes: List[Tuple[AttributeType, bytes]] = field(default_factory=list)

    si_attribute: Optional[SIAttribute] = None
    fn_attributes: List[FNAttribute] = field(default_factory=list)
    filename_primary: str = ""

    def has_suspicious_timestamps(self) -> bool:
        """Check if any timestamps are in the future or suspicious"""
        if not self.si_attribute:
            return False

        now = datetime.now()
        year_threshold = now.year + 1

        for ts in [
            self.si_attribute.created,
            self.si_attribute.modified,
            self.si_attribute.accessed,
            self.si_attribute.mft_modified,
        ]:
            dt = ts.to_datetime()
            if dt and dt.year > year_threshold:
                return True

        return False


class MFTParser:
    """Parser for raw NTFS Master File Table"""

    MFT_RECORD_SIZE = 1024
    FILE_RECORD_MAGIC = b"FILE"

    def __init__(self, mft_data: bytes):
        self.data = mft_data
        self.records: List[MFTRecord] = []
        self._parse()

    def _readNTFSTime(self, offset: int) -> NTFSTime:
        """Read 8-byte NTFS timestamp"""
        value = struct.unpack("<Q", self.data[offset : offset + 8])[0]
        return NTFSTime(value)

    def _parse_record(self, offset: int) -> Optional[MFTRecord]:
        """Parse a single MFT record"""
        if offset + self.MFT_RECORD_SIZE > len(self.data):
            return None

        magic = self.data[offset : offset + 4]
        if magic != self.FILE_RECORD_MAGIC:
            return None

        flags = struct.unpack("<H", self.data[offset + 22 : offset + 24])[0]
        allocated_size = struct.unpack("<I", self.data[offset + 24 : offset + 28])[0]
        real_size = struct.unpack("<I", self.data[offset + 28 : offset + 32])[0]
        base_record_ref = struct.unpack("<Q", self.data[offset + 32 : offset + 40])[0]
        sequence_number = struct.unpack("<H", self.data[offset + 16 : offset + 18])[0]

        is_in_use = (flags & 0x0001) != 0
        is_directory = (flags & 0x0002) != 0
        record_number = struct.unpack("<I", self.data[offset + 44 : offset + 48])[0]

        record = MFTRecord(
            record_number=record_number,
            sequence_number=sequence_number,
            is_in_use=is_in_use,
            is_directory=is_directory,
            allocated_size=allocated_size,
            real_size=real_size,
            base_record_ref=base_record_ref,
        )

        self._parse_attributes(record, offset + 56)

        return record

    def _parse_attributes(self, record: MFTRecord, start_offset: int):
        """Parse attributes within an MFT record"""
        offset = start_offset

        while offset < len(self.data) and offset < start_offset + record.real_size - 48:
            attr_type = struct.unpack("<I", self.data[offset : offset + 4])[0]

            if attr_type == 0xFFFFFFFF:
                break

            attr_length = struct.unpack("<I", self.data[offset + 4 : offset + 8])[0]
            non_resident = self.data[offset + 8]
            name_length = self.data[offset + 9]
            name_offset = struct.unpack("<H", self.data[offset + 10 : offset + 12])[0]

            if attr_length <= 0:
                break

            if attr_type == AttributeType.STANDARD_INFORMATION.value:
                si = self._parse_si_attribute(self.data, offset)
                if si:
                    record.si_attribute = si

            elif attr_type == AttributeType.FILE_NAME.value:
                fn = self._parse_fn_attribute(self.data, offset)
                if fn:
                    record.fn_attributes.append(fn)
                    if not record.filename_primary and fn.namespace == 3:
                        record.filename_primary = fn.filename

            record.attributes.append(
                (AttributeType(attr_type), self.data[offset : offset + attr_length])
            )
            offset += attr_length

    def _parse_si_attribute(self, data: bytes, offset: int) -> Optional[SIAttribute]:
        """Parse $Standard_Information attribute"""
        try:
            non_resident = data[offset + 8]

            if non_resident == 0:
                content_offset = struct.unpack("<H", data[offset + 20 : offset + 22])[0]
                content_start = offset + content_offset

                return SIAttribute(
                    created=self._readNTFSTime(content_start + 16),
                    modified=self._readNTFSTime(content_start + 24),
                    mft_modified=self._readNTFSTime(content_start + 32),
                    accessed=self._readNTFSTime(content_start + 40),
                    flags=struct.unpack(
                        "<I", data[content_start + 48 : content_start + 52]
                    )[0],
                    owner_id=struct.unpack(
                        "<I", data[content_start + 56 : content_start + 60]
                    )[0],
                    security_id=struct.unpack(
                        "<I", data[content_start + 60 : content_start + 64]
                    )[0],
                )
        except Exception:
            pass
        return None

    def _parse_fn_attribute(self, data: bytes, offset: int) -> Optional[FNAttribute]:
        """Parse $File_Name attribute"""
        try:
            non_resident = data[offset + 8]

            if non_resident == 0:
                content_offset = struct.unpack("<H", data[offset + 20 : offset + 22])[0]
                content_start = offset + content_offset

                name_length = data[content_start + 64]
                name_start = content_start + 66

                filename_bytes = data[name_start : name_start + name_length * 2]
                filename = filename_bytes.decode("utf-16-le", errors="ignore")

                return FNAttribute(
                    parent_directory_ref=struct.unpack(
                        "<Q", data[content_start : content_start + 8]
                    )[0],
                    created=self._readNTFSTime(content_start + 8),
                    modified=self._readNTFSTime(content_start + 16),
                    mft_modified=self._readNTFSTime(content_start + 24),
                    accessed=self._readNTFSTime(content_start + 32),
                    allocated_size=struct.unpack(
                        "<I", data[content_start + 36 : content_start + 40]
                    )[0],
                    real_size=struct.unpack(
                        "<I", data[content_start + 40 : content_start + 44]
                    )[0],
                    flags=struct.unpack(
                        "<I", data[content_start + 44 : content_start + 48]
                    )[0],
                    filename=filename,
                    namespace=data[content_start + 64],
                )
        except Exception:
            pass
        return None

    def _parse(self):
        """Parse all MFT records"""
        offset = 0
        while offset < len(self.data):
            record = self._parse_record(offset)
            if record:
                if record.is_in_use and record.filename_primary:
                    self.records.append(record)
            offset += self.MFT_RECORD_SIZE

    def get_file_records(self) -> List[MFTRecord]:
        """Get all parsed file records"""
        return self.records

    def compare_si_fn(self) -> List[Dict[str, Any]]:
        """Compare $SI and $FN timestamps to detect timestomping"""
        anomalies = []

        for record in self.records:
            if not record.si_attribute or not record.fn_attributes:
                continue

            si = record.si_attribute
            fn = record.fn_attributes[0]

            si_created = si.created.to_datetime()
            fn_created = fn.created.to_datetime()
            si_modified = si.modified.to_datetime()
            fn_modified = fn.modified.to_datetime()

            if si_created and fn_created:
                diff_created = abs((si_created - fn_created).total_seconds())
                if diff_created > 1:
                    anomalies.append(
                        {
                            "file": record.filename_primary,
                            "record_number": record.record_number,
                            "anomaly_type": "CREATED_MISMATCH",
                            "si_created": si.created_str,
                            "fn_created": fn.created_str,
                            "difference_seconds": diff_created,
                            "severity": "HIGH" if diff_created > 86400 else "MEDIUM",
                            "description": f"Creation time mismatch: SI={si.created_str}, FN={fn.created_str}",
                        }
                    )

            if si_modified and fn_modified:
                diff_modified = abs((si_modified - fn_modified).total_seconds())
                if diff_modified > 1:
                    anomalies.append(
                        {
                            "file": record.filename_primary,
                            "record_number": record.record_number,
                            "anomaly_type": "MODIFIED_MISMATCH",
                            "si_modified": si.modified_str,
                            "fn_modified": fn.modified_str,
                            "difference_seconds": diff_modified,
                            "severity": "HIGH" if diff_modified > 86400 else "MEDIUM",
                            "description": f"Modified time mismatch: SI={si.modified_str}, FN={fn.modified_str}",
                        }
                    )

            now = datetime.now()
            year_threshold = now.year + 1

            for ts, ts_name in [
                (si.created, "created"),
                (si.modified, "modified"),
                (si.accessed, "accessed"),
            ]:
                dt = ts.to_datetime()
                if dt and dt.year > year_threshold:
                    anomalies.append(
                        {
                            "file": record.filename_primary,
                            "record_number": record.record_number,
                            "anomaly_type": "FUTURE_TIMESTAMP",
                            "timestamp_type": ts_name,
                            "timestamp": ts.to_iso_string(),
                            "severity": "CRITICAL",
                            "description": f"Future {ts_name} timestamp detected: {ts}",
                        }
                    )

        return anomalies

    def export_to_dict(self) -> Dict[str, Any]:
        """Export parsed MFT data to dictionary"""
        return {
            "total_records": len(self.records),
            "files": [
                {
                    "record_number": r.record_number,
                    "filename": r.filename_primary,
                    "si_created": r.si_attribute.created_str
                    if r.si_attribute
                    else None,
                    "si_modified": r.si_attribute.modified_str
                    if r.si_attribute
                    else None,
                    "si_accessed": r.si_attribute.accessed_str
                    if r.si_attribute
                    else None,
                    "fn_created": r.fn_attributes[0].created_str
                    if r.fn_attributes
                    else None,
                    "fn_modified": r.fn_attributes[0].modified_str
                    if r.fn_attributes
                    else None,
                    "is_directory": r.is_directory,
                }
                for r in self.records
            ],
        }


def parse_mft_from_image(
    image_path: str, partition_offset: int = 0, image_type: str = "raw"
) -> MFTParser:
    """Parse MFT from a disk image using icat (The Sleuth Kit)"""
    import subprocess

    cmd = ["icat"]
    if image_type == "ewf":
        cmd.extend(["-i", "ewf"])
    cmd.extend(["-o", str(partition_offset)])
    cmd.append(image_path)
    cmd.append("$MFT")

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=120)
        if result.returncode == 0 and result.stdout:
            return MFTParser(result.stdout)
    except Exception as e:
        print(f"Error extracting MFT: {e}")

    return MFTParser(b"")
