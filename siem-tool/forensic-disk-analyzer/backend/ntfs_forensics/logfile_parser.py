#!/usr/bin/env python3
"""
NTFS $LogFile Parser
Parses raw $LogFile to extract transaction history and metadata modifications.

The $LogFile contains NTFS transaction log records that track:
- Metadata changes (MFT modifications, attribute updates)
- Transaction redo/undo operations
- File rename operations
- Security descriptor changes

Critical for forensic analysis - even if USN journal is cleared,
$LogFile may still contain evidence of timestamp modifications.

Author: Cyber Chakshu SIEM Team
"""

import struct
import os
from pathlib import Path
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


LFS_CLIENT_TYPES = {
    0x01: "NTFS",
    0x02: "FAT",
    0xFF: "Reserved",
}

LFS_OPERATION_TYPES = {
    0x00: "Noop",
    0x01: "CompensationLogRecord",
    0x02: "InitializeFileRecordSegment",
    0x03: "DeallocateFileRecordSegment",
    0x04: "WriteEndOfFileRecordSegment",
    0x05: "WriteFileRecordSegment",
    0x06: "DeleteFileRecordSegment",
    0x07: "CreateAttribute",
    0x08: "DeleteAttribute",
    0x09: "UpdateResidentValue",
    0x0A: "UpdateNonResidentValue",
    0x0B: "UpdateMappingPairs",
    0x0C: "DeleteDirtyClusters",
    0x0D: "SetNewAttributeSizes",
    0x0E: "AddIndexEntryRoot",
    0x0F: "DeleteIndexEntryRoot",
    0x10: "AddIndexEntryAllocation",
    0x11: "DeleteIndexEntryAllocation",
    0x12: "WriteEndOfIndexAllocation",
    0x13: "SetIndexEntryV",
    0x14: "UpdateFileNameRoot",
    0x15: "UpdateFileNameAllocation",
    0x16: "SetBitmap",
    0x17: "SetBitmapV",
    0x18: "HotFix",
    0x19: "EndTopLevelAction",
    0x1A: "Rollback",
    0x1B: "CommitTransaction",
    0x1C: "ForgetTransaction",
    0x1D: "OpenNonresidentAttribute",
    0x1E: "OpenAttributeTableDump",
    0x1F: "CheckDirtyTable",
    0x20: "QueryDirtyTable",
    0x21: "InvalidatePages",
    0x22: "ChangeAttributeSize",
    0x23: "WriteLogRecord",
    0x24: "UpdateRecord",
}

SET_FILE_INFORMATION_OPS = {
    0x01: "SetAllocationSize",
    0x02: "SetEndOfFile",
    0x03: "SetValidDataLength",
    0x04: "SetShortName",
    0x05: "SetFileInformation",
    0x06: "RenameFile",
    0x07: "MoveFile",
}


@dataclass
class LFSRestartHeader:
    """Log File Structure Restart Area"""

    magic: str
    fixup_values_offset: int
    fixup_values_size: int
    page_size: int
    restart_size: int
    minor_version: int
    major_version: int
    bytes_per_file_record: int
    sectors_per_file_record: int
    lfs_seQUENCE_number: int
    current_lsn: int
    log_clients: int
    client_free_list: int
    client_in_use_list: int
    flags: int
    seq_number_bits: int
    archive_bits: int
    sector_size: int
    cluster_factor: int
    first_record_lsn: int
    last_record_lsn: int
    last_restart_lsn: int
    log_file_size: int
    restart_lsn: int


@dataclass
class LFSClientRecord:
    """LFS Client Record"""

    client_id: int
    seq_number: int
    oldest_lsn: int
    client_restart_lsn: int
    name: str
    active: bool


@dataclass
class LFSRecordHeader:
    """Log Record Header"""

    record_length: int
    lsn: int
    transaction_id: int
    client_id: int
    record_type: int
    transaction_type: int
    segment_length: int
    previous_lsn: int
    undo_next_lsn: int
    redo_length: int
    undo_length: int
    target_attribute: int
    lsn_of_undo_target: int
    update_sequence_number: int
    num_update_sequences: int
    offset_to_update_sequences: int


@dataclass
class TransactionRecord:
    """Transaction record with parsed operation"""

    lsn: int
    timestamp: Optional[datetime]
    transaction_id: int
    operation_type: str
    operation_code: int
    file_reference: Optional[int]
    attribute_type: Optional[int]
    details: str
    raw_data: bytes


@dataclass
class LogFileAnalysis:
    """Analysis results from $LogFile"""

    has_restart_area: bool
    page_size: int
    log_file_size: int
    total_records: int
    restart_detected: bool
    transaction_count: int
    setfileinformation_ops: List[Dict]
    metadata_modifications: List[Dict]
    rename_operations: List[Dict]
    timestamp_modifications: List[Dict]
    recent_operations: List[Dict]
    lsn_gaps: List[Dict]


class LogFileParser:
    """Parser for raw NTFS $LogFile"""

    LFS_RESTART_AREA_MAGIC = b"RSTR"
    LFS_LOG_RECORD_MAGIC = b"LOG "
    LFS_CLIENT_AREA_MAGIC = b"CLNT"
    LFS_USE_ALWAYS_MAGIC = b"LOOP"

    RESTART_AREA_SIZE = 64
    RECORD_HEADER_SIZE = 64

    def __init__(self, logfile_data: bytes):
        self.data = logfile_data
        self.restart_header: Optional[LFSRestartHeader] = None
        self.client_records: List[LFSClientRecord] = []
        self.transaction_records: List[TransactionRecord] = []
        self.analysis: Optional[LogFileAnalysis] = None
        self._parse()

    def _read_timestamp(self, offset: int) -> Optional[datetime]:
        """Read 8-byte NTFS timestamp"""
        if offset + 8 > len(self.data):
            return None
        try:
            value = struct.unpack("<Q", self.data[offset : offset + 8])[0]
            if value == 0:
                return None
            return datetime(1601, 1, 1) + timedelta(microseconds=value // 10)
        except:
            return None

    def _parse_restart_area(self, offset: int = 0) -> Optional[LFSRestartHeader]:
        """Parse Log File Structure Restart Area"""
        if offset + 128 > len(self.data):
            return None

        try:
            magic = self.data[offset : offset + 4]
            if magic not in [self.LFS_RESTART_AREA_MAGIC, self.LFS_USE_ALWAYS_MAGIC]:
                return None

            return LFSRestartHeader(
                magic=magic.decode("ascii", errors="ignore"),
                fixup_values_offset=struct.unpack(
                    "<H", self.data[offset + 4 : offset + 6]
                )[0],
                fixup_values_size=struct.unpack(
                    "<H", self.data[offset + 6 : offset + 8]
                )[0],
                page_size=struct.unpack("<I", self.data[offset + 8 : offset + 12])[0],
                restart_size=struct.unpack("<I", self.data[offset + 12 : offset + 16])[
                    0
                ],
                minor_version=struct.unpack("<H", self.data[offset + 16 : offset + 18])[
                    0
                ],
                major_version=struct.unpack("<H", self.data[offset + 18 : offset + 20])[
                    0
                ],
                bytes_per_file_record=struct.unpack(
                    "<I", self.data[offset + 20 : offset + 24]
                )[0],
                sectors_per_file_record=struct.unpack(
                    "<H", self.data[offset + 24 : offset + 26]
                )[0],
                lfs_seQUENCE_number=struct.unpack(
                    "<I", self.data[offset + 26 : offset + 30]
                )[0],
                current_lsn=struct.unpack("<Q", self.data[offset + 32 : offset + 40])[
                    0
                ],
                log_clients=struct.unpack("<I", self.data[offset + 40 : offset + 44])[
                    0
                ],
                client_free_list=struct.unpack(
                    "<I", self.data[offset + 44 : offset + 48]
                )[0],
                client_in_use_list=struct.unpack(
                    "<I", self.data[offset + 48 : offset + 52]
                )[0],
                flags=struct.unpack("<I", self.data[offset + 52 : offset + 56])[0],
                seq_number_bits=struct.unpack(
                    "<I", self.data[offset + 56 : offset + 60]
                )[0],
                archive_bits=struct.unpack("<I", self.data[offset + 60 : offset + 64])[
                    0
                ],
                sector_size=struct.unpack("<I", self.data[offset + 64 : offset + 68])[
                    0
                ],
                cluster_factor=struct.unpack(
                    "<I", self.data[offset + 68 : offset + 72]
                )[0],
                first_record_lsn=struct.unpack(
                    "<Q", self.data[offset + 72 : offset + 80]
                )[0],
                last_record_lsn=struct.unpack(
                    "<Q", self.data[offset + 80 : offset + 88]
                )[0],
                last_restart_lsn=struct.unpack(
                    "<Q", self.data[offset + 88 : offset + 96]
                )[0],
                log_file_size=struct.unpack(
                    "<Q", self.data[offset + 96 : offset + 104]
                )[0],
                restart_lsn=struct.unpack("<Q", self.data[offset + 104 : offset + 112])[
                    0
                ],
            )
        except:
            return None

    def _parse_log_record(self, offset: int) -> Optional[TransactionRecord]:
        """Parse a log record"""
        if offset + self.RECORD_HEADER_SIZE > len(self.data):
            return None

        magic = self.data[offset : offset + 4]
        if magic != self.LFS_LOG_RECORD_MAGIC:
            return None

        try:
            record_length = struct.unpack("<I", self.data[offset + 4 : offset + 8])[0]
            if record_length == 0 or record_length > 1_000_000:
                return None

            lsn = struct.unpack("<Q", self.data[offset + 8 : offset + 16])[0]
            transaction_id = struct.unpack("<I", self.data[offset + 16 : offset + 20])[
                0
            ]
            client_id = struct.unpack("<I", self.data[offset + 20 : offset + 24])[0]
            record_type = struct.unpack("<H", self.data[offset + 24 : offset + 26])[0]
            transaction_type = struct.unpack(
                "<H", self.data[offset + 26 : offset + 28]
            )[0]
            segment_length = struct.unpack("<I", self.data[offset + 28 : offset + 32])[
                0
            ]
            previous_lsn = struct.unpack("<Q", self.data[offset + 32 : offset + 40])[0]
            undo_next_lsn = struct.unpack("<Q", self.data[offset + 40 : offset + 48])[0]
            redo_length = struct.unpack("<I", self.data[offset + 48 : offset + 52])[0]
            undo_length = struct.unpack("<I", self.data[offset + 52 : offset + 56])[0]
            target_attribute = struct.unpack(
                "<Q", self.data[offset + 56 : offset + 64]
            )[0]

            timestamp = self._read_timestamp(offset + 64)

            operation_code = 0
            operation_type = "Unknown"

            if segment_length > 64:
                attr_offset = offset + 76
                if attr_offset + 4 <= len(self.data):
                    operation_code = struct.unpack(
                        "<H", self.data[attr_offset : attr_offset + 2]
                    )[0]
                    operation_type = LFS_OPERATION_TYPES.get(
                        operation_code, f"Unknown(0x{operation_code:02X})"
                    )

            details = self._extract_operation_details(
                offset, record_length, operation_code, target_attribute
            )

            return TransactionRecord(
                lsn=lsn,
                timestamp=timestamp,
                transaction_id=transaction_id,
                operation_type=operation_type,
                operation_code=operation_code,
                file_reference=target_attribute
                if target_attribute != 0xFFFFFFFFFFFFFFFF
                else None,
                attribute_type=None,
                details=details,
                raw_data=self.data[offset : offset + min(record_length, 1000)],
            )
        except:
            return None

    def _extract_operation_details(
        self, offset: int, length: int, op_code: int, target_attr: int
    ) -> str:
        """Extract operation details from record"""
        details = []

        if op_code == 0x05:
            details.append("WriteFileRecordSegment")
        elif op_code == 0x06:
            details.append("DeleteFileRecordSegment")
        elif op_code == 0x13:
            details.append("SetIndexEntryV")
        elif op_code == 0x14:
            details.append("UpdateFileNameRoot")
        elif op_code == 0x06:
            details.append("RenameFile")

        if target_attr != 0 and target_attr != 0xFFFFFFFFFFFFFFFF:
            details.append(f"TargetAttr:0x{target_attr:016X}")

        return "; ".join(details) if details else "Standard log record"

    def _parse(self):
        """Parse the $LogFile"""
        self.restart_header = self._parse_restart_area(0)

        if self.restart_header and self.restart_header.page_size > 0:
            page_size = self.restart_header.page_size
        else:
            page_size = 4096

        offset = page_size
        max_offset = min(len(self.data), 10 * 1024 * 1024)

        while offset < max_offset:
            record = self._parse_log_record(offset)
            if record:
                self.transaction_records.append(record)
                record_length = struct.unpack("<I", self.data[offset + 4 : offset + 8])[
                    0
                ]
                offset += record_length if record_length > 0 else page_size
            else:
                offset += page_size

    def get_records(self) -> List[TransactionRecord]:
        """Get all transaction records"""
        return self.transaction_records

    def get_setfileinformation_ops(self) -> List[TransactionRecord]:
        """Get SetFileInformation operations (includes rename, size changes)"""
        target_ops = {0x05, 0x06, 0x14, 0x15, 0x03, 0x04}
        return [r for r in self.transaction_records if r.operation_code in target_ops]

    def get_rename_operations(self) -> List[TransactionRecord]:
        """Get rename operations"""
        return [
            r
            for r in self.transaction_records
            if "Rename" in r.details or r.operation_code == 0x06
        ]

    def analyze(self) -> LogFileAnalysis:
        """Perform comprehensive analysis of $LogFile"""
        lsn_values = sorted([r.lsn for r in self.transaction_records if r.lsn > 0])

        lsn_gaps = []
        for i in range(1, len(lsn_values)):
            if lsn_values[i] - lsn_values[i - 1] > 1000000:
                lsn_gaps.append(
                    {
                        "from_lsn": lsn_values[i - 1],
                        "to_lsn": lsn_values[i],
                        "gap_size": lsn_values[i] - lsn_values[i - 1],
                    }
                )

        setfileinfo = self.get_setfileinformation_ops()

        metadata_mods = [
            r
            for r in self.transaction_records
            if r.operation_code in [0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]
        ]

        renames = self.get_rename_operations()

        timestamp_mods = [
            r
            for r in self.transaction_records
            if "UpdateResident" in r.operation_type
            or "UpdateNonResident" in r.operation_type
        ]

        recent = sorted(
            self.transaction_records,
            key=lambda x: x.timestamp or datetime.min,
            reverse=True,
        )[:50]

        self.analysis = LogFileAnalysis(
            has_restart_area=self.restart_header is not None,
            page_size=self.restart_header.page_size if self.restart_header else 0,
            log_file_size=self.restart_header.log_file_size
            if self.restart_header
            else 0,
            total_records=len(self.transaction_records),
            restart_detected=self.restart_header is not None,
            transaction_count=len(self.transaction_records),
            setfileinformation_ops=[
                {
                    "lsn": r.lsn,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "operation": r.operation_type,
                    "file_ref": f"0x{r.file_reference:016X}"
                    if r.file_reference
                    else None,
                    "details": r.details,
                }
                for r in setfileinfo[:100]
            ],
            metadata_modifications=[
                {
                    "lsn": r.lsn,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "operation": r.operation_type,
                }
                for r in metadata_mods[:100]
            ],
            rename_operations=[
                {
                    "lsn": r.lsn,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "details": r.details,
                }
                for r in renames[:50]
            ],
            timestamp_modifications=[
                {
                    "lsn": r.lsn,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "operation": r.operation_type,
                }
                for r in timestamp_mods[:50]
            ],
            recent_operations=[
                {
                    "lsn": r.lsn,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "operation": r.operation_type,
                    "transaction_id": r.transaction_id,
                }
                for r in recent
            ],
            lsn_gaps=lsn_gaps[:10],
        )

        return self.analysis

    def detect_timestamp_tampering(
        self, mft_record_num: int, si_created: datetime
    ) -> Dict[str, Any]:
        """Detect potential timestamp tampering by correlating $LogFile with MFT timestamps"""
        relevant_records = [
            r
            for r in self.transaction_records
            if r.file_reference
            and (r.file_reference & 0xFFFFFFFFFFFF) == mft_record_num
        ]

        result = {
            "mft_record": mft_record_num,
            "si_created": si_created.isoformat() if si_created else None,
            "logfile_records_found": len(relevant_records),
            "is_suspicious": False,
            "reason": "",
            "severity": "LOW",
            "relevant_operations": [],
        }

        if not relevant_records:
            result["reason"] = "No $LogFile records found for this MFT entry"
            return result

        timestamps = [r.timestamp for r in relevant_records if r.timestamp]

        if timestamps:
            earliest = min(timestamps)
            if si_created and earliest > si_created:
                diff_days = (earliest - si_created).total_seconds() / 86400
                if diff_days > 1:
                    result["is_suspicious"] = True
                    result["reason"] = (
                        f"MFT timestamp ({si_created}) is {diff_days:.1f} days BEFORE earliest $LogFile activity"
                    )
                    result["severity"] = "HIGH"

        result["relevant_operations"] = [
            {
                "lsn": r.lsn,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "operation": r.operation_type,
            }
            for r in relevant_records[:10]
        ]

        return result

    def export_to_dict(self) -> Dict[str, Any]:
        """Export parsed $LogFile data to dictionary"""
        if not self.analysis:
            self.analyze()

        return {
            "header": {
                "magic": self.restart_header.magic if self.restart_header else None,
                "page_size": self.restart_header.page_size
                if self.restart_header
                else 0,
                "log_file_size": self.restart_header.log_file_size
                if self.restart_header
                else 0,
                "restart_detected": self.restart_header is not None,
            },
            "statistics": {
                "total_records": len(self.transaction_records),
                "setfileinformation_ops": len(self.get_setfileinformation_ops()),
                "rename_operations": len(self.get_rename_operations()),
                "metadata_modifications": len(
                    [
                        r
                        for r in self.transaction_records
                        if r.operation_code in [0x05, 0x06, 0x07, 0x08]
                    ]
                ),
            },
            "analysis": {
                "has_restart_area": self.analysis.has_restart_area,
                "restart_detected": self.analysis.restart_detected,
                "lsn_gaps": self.analysis.lsn_gaps,
            },
            "recent_transactions": [
                {
                    "lsn": r.lsn,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "operation": r.operation_type,
                    "transaction_id": r.transaction_id,
                }
                for r in sorted(
                    self.transaction_records, key=lambda x: x.lsn, reverse=True
                )[:100]
            ],
        }


def parse_logfile_from_image(
    image_path: str, partition_offset: int = 0, image_type: str = "raw"
) -> LogFileParser:
    """Parse $LogFile from a disk image using icat (The Sleuth Kit)"""
    import subprocess

    cmd = ["icat"]
    if image_type == "ewf":
        cmd.extend(["-i", "ewf"])
    cmd.extend(["-o", str(partition_offset)])
    cmd.append(image_path)
    cmd.append("$LogFile")

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=120)
        if result.returncode == 0 and result.stdout:
            return LogFileParser(result.stdout)
    except Exception as e:
        print(f"Error extracting $LogFile: {e}")

    return LogFileParser(b"")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python logfile_parser.py <logfile_binary_file>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    parser = LogFileParser(data)

    print("$LogFile Analysis")
    print("=" * 60)

    if parser.restart_header:
        print(f"Restart Area: Found")
        print(f"Page Size: {parser.restart_header.page_size}")
        print(f"Log File Size: {parser.restart_header.log_file_size:,} bytes")
    else:
        print("Restart Area: Not found or invalid")

    print(f"\nTransaction Records: {len(parser.transaction_records):,}")
    print(f"SetFileInformation Ops: {len(parser.get_setfileinformation_ops()):,}")
    print(f"Rename Operations: {len(parser.get_rename_operations()):,}")

    if parser.analysis:
        print(f"\nLSN Gaps: {len(parser.analysis.lsn_gaps)}")
        for gap in parser.analysis.lsn_gaps[:5]:
            print(
                f"  Gap: {gap['from_lsn']} -> {gap['to_lsn']} ({gap['gap_size']:,} bytes)"
            )
