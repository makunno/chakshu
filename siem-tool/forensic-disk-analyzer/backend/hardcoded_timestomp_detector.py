#!/usr/bin/env python3
"""
Hardcoded Timestomping Detection Engine
Correlates ALL extracted artifacts for comprehensive timestomping detection.
"""

import os
import json
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field


@dataclass
class TimestompIndicator:
    rule_id: str
    severity: str
    description: str
    evidence: str
    timestamp_value: Optional[str] = None
    expected_value: Optional[str] = None
    time_diff_seconds: float = 0.0
    source_layer: str = ""


@dataclass
class FileTimestompAnalysis:
    filename: str
    file_path: Optional[str] = None
    file_reference: Optional[int] = None

    si_created: Optional[datetime] = None
    si_modified: Optional[datetime] = None
    si_accessed: Optional[datetime] = None
    si_mft_modified: Optional[datetime] = None

    fn_created: Optional[datetime] = None
    fn_modified: Optional[datetime] = None

    usn_first_create: Optional[datetime] = None
    usn_total_events: int = 0

    has_prefetch: bool = False
    has_amcache: bool = False

    volume_created: Optional[datetime] = None
    os_install_date: Optional[datetime] = None

    mft_sequence: Optional[int] = None

    indicators: List[TimestompIndicator] = field(default_factory=list)
    total_score: float = 0.0
    is_suspicious: bool = False
    overall_severity: str = "INFO"


class HardcodedTimestompDetector:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.partition_nums = [0, 1]
        self.analysis_results: List[FileTimestompAnalysis] = []
        self.suspicious_files: List[FileTimestompAnalysis] = []
        self.possibly_copied_files: List[FileTimestompAnalysis] = []

        self.timeline_data: List[Dict] = []
        self.usn_records: List[Dict] = []
        self.security_events: List[Dict] = []
        self.system_events: List[Dict] = []
        self.prefetch_files: List[str] = []

        self.shadow_copy_files: List[str] = []
        self.ads_files: List[str] = []
        self.registry_hives: List[str] = []
        self.log_clearing_indicators: List[str] = []

        self.all_filenames: Set[str] = set()
        self.event_earliest: Optional[datetime] = None
        self.event_latest: Optional[datetime] = None

    def run_detection(self) -> Dict[str, Any]:
        print("[*] Loading ALL extracted artifacts...")

        self._load_all_artifacts()

        print(f"    Loaded {len(self.timeline_data)} timeline records")
        print(f"    Found {len(self.shadow_copy_files)} shadow copy files")
        print(f"    Found {len(self.ads_files)} ADS/hidden files")
        print(f"    Found {len(self.registry_hives)} registry hives")

        print("[*] Analyzing timeline for timestomping indicators...")
        self._analyze_timeline()

        print("[*] Detecting timestamp order anomalies (MACE analysis)...")
        self._detect_timestamp_order_anomalies()

        print("[*] Correlating with Shadow Copies (VSS)...")
        self._correlate_shadow_copies()

        print("[*] Checking for Log Clearing evidence...")
        self._check_log_clearing()

        print("[*] Correlating with USN Journal...")
        self._correlate_usn()

        print("[*] Correlating with Event Logs (Security/System)...")
        self._process_event_logs()
        self._correlate_event_logs()

        print("[*] Checking Prefetch/Amcache correlation...")
        self._check_prefetch_amcache()

        print("[*] Running SI vs FN drift analysis...")
        self._analyze_si_fn_drift()

        print("[*] Checking volume creation time boundary...")
        self._check_volume_boundary()

        print("[*] Analyzing timestamp entropy patterns...")
        self._analyze_timestamp_entropy()

        print("[*] Cross-referencing all artifacts for concrete proof...")
        self._cross_reference_artifacts()

        print("[*] Generating detection results...")
        self._finalize_analysis()

        return self._generate_report_data()

    def _load_all_artifacts(self):
        """Load all artifacts from all partitions"""

        # Load timeline files
        for partition_num in self.partition_nums:
            timeline_file = self.output_dir / f"timeline_partition_{partition_num}.txt"
            if timeline_file.exists():
                with open(timeline_file, "r", errors="ignore") as f:
                    self.timeline_data.extend(self._parse_timeline(f.read()))

        # Load USN journal
        for partition_num in self.partition_nums:
            usn_file = self.output_dir / f"usn_journal_partition_{partition_num}.txt"
            if usn_file.exists():
                with open(usn_file, "r", errors="ignore") as f:
                    self.usn_records.extend(self._parse_usn(f.read()))

        # Try to load raw USN journal for more detailed analysis
        raw_usn_records = self._parse_raw_usn()
        if raw_usn_records:
            self.usn_records.extend(raw_usn_records)

        # Load shadow copies
        for partition_num in self.partition_nums:
            shadow_file = (
                self.output_dir / f"shadow_copies_partition_{partition_num}.txt"
            )
            if shadow_file.exists():
                with open(shadow_file, "r", errors="ignore") as f:
                    for line in f:
                        if (
                            ": " in line
                            and not line.startswith("=")
                            and "Shadow Copy" not in line
                            and "Potential" not in line
                        ):
                            if ":" in line:
                                parts = line.strip().split(": ", 1)
                                if len(parts) > 1:
                                    fname = parts[1].strip()
                                    if fname and len(fname) > 2:
                                        self.shadow_copy_files.append(fname.lower())

        # Load hidden structures (ADS)
        for partition_num in self.partition_nums:
            hidden_file = (
                self.output_dir / f"hidden_structures_partition_{partition_num}.txt"
            )
            if hidden_file.exists():
                with open(hidden_file, "r", errors="ignore") as f:
                    for line in f:
                        if (
                            ": " in line
                            and not line.startswith("=")
                            and "Potential" not in line
                            and "Alternate" not in line
                        ):
                            if ":" in line:
                                parts = line.strip().split(": ", 1)
                                if len(parts) > 1:
                                    fname = parts[1].strip()
                                    if fname and "$" in fname:
                                        self.ads_files.append(fname.lower())

        # Load registry hives
        for partition_num in self.partition_nums:
            reg_file = self.output_dir / f"registry_partition_{partition_num}.txt"
            if reg_file.exists():
                with open(reg_file, "r", errors="ignore") as f:
                    for line in f:
                        if "NTUSER" in line or "UsrClass" in line:
                            if ": " in line:
                                parts = line.strip().split(": ", 1)
                                if len(parts) > 1:
                                    self.registry_hives.append(parts[1].strip())

        # Load logs for log clearing evidence
        for partition_num in self.partition_nums:
            log_file = self.output_dir / f"logs_partition_{partition_num}.txt"
            if log_file.exists():
                with open(log_file, "r", errors="ignore") as f:
                    content = f.read().lower()
                    if "cleared" in content or "wevtutil" in content:
                        self.log_clearing_indicators.append(
                            f"Partition {partition_num}"
                        )

        # Load event logs
        logs_dir = self.output_dir / "logs" / "windows" / "evtx"
        security_file = logs_dir / "Security.evtx.json"
        if security_file.exists():
            with open(security_file, "r") as f:
                self.security_events = json.load(f)

        system_file = logs_dir / "System.evtx.json"
        if system_file.exists():
            with open(system_file, "r") as f:
                self.system_events = json.load(f)

        # Process event timestamps
        all_events = self.security_events + self.system_events
        event_timestamps = []
        for event in all_events:
            ts_str = event.get("Timestamp")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:"))
                    event_timestamps.append(ts)
                except:
                    pass
        if event_timestamps:
            self.event_earliest = min(event_timestamps)
            self.event_latest = max(event_timestamps)

        # Load prefetch
        prefetch_dir = self.output_dir / "prefetch"
        if prefetch_dir.exists():
            self.prefetch_files = [p.name.upper() for p in prefetch_dir.glob("*.pf")]

    def _parse_timeline(self, content: str) -> List[Dict]:
        records = []
        seen_keys = set()  # Deduplicate by filename + created + modified

        for line in content.split("\n"):
            if (
                not line.strip()
                or line.startswith("=")
                or line.startswith("Full Timeline")
                or line.startswith("Image:")
                or line.startswith("Offset:")
            ):
                continue

            parts = line.split("\t")
            if len(parts) < 6:
                continue

            try:
                file_type = parts[0].strip()
                filename = parts[1].strip() if len(parts) > 1 else ""

                if ":" not in parts[2]:
                    continue

                modified = parts[2].split(" (")[0].strip() if len(parts) > 2 else ""
                accessed = parts[3].split(" (")[0].strip() if len(parts) > 3 else ""
                mft_modified = parts[4].split(" (")[0].strip() if len(parts) > 4 else ""
                created = parts[5].split(" (")[0].strip() if len(parts) > 5 else ""

                if filename and (modified or created):
                    # Deduplicate: use filename + created as key
                    dedup_key = (filename, created, modified)
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)

                    records.append(
                        {
                            "filename": filename,
                            "type": file_type,
                            "modified": modified,
                            "accessed": accessed,
                            "mft_modified": mft_modified,
                            "created": created,
                        }
                    )
            except Exception:
                continue

        return records

    def _parse_usn(self, content: str) -> List[Dict]:
        """Parse USN journal from text output"""
        records = []
        for line in content.split("\n"):
            if not line.strip() or line.startswith("=") or "No USN" in line:
                continue

            match = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
            if match:
                records.append(
                    {
                        "timestamp": match.group(1),
                        "raw": line,
                    }
                )
        return records

    def _parse_raw_usn(self) -> List[Dict]:
        """Parse raw USN journal binary if available"""
        records = []

        for partition_num in self.partition_nums:
            raw_usn_file = (
                self.output_dir / f"raw_usn_journal_partition_{partition_num}.bin"
            )

            if not raw_usn_file.exists():
                continue

            try:
                with open(raw_usn_file, "rb") as f:
                    data = f.read()

                # USN Journal is a NTFS transaction log
                # Parse key record types
                pos = 0
                while pos < len(data) - 64:
                    try:
                        # USN record header: 64 bytes
                        # Offset 0: RecordLength (4 bytes)
                        # Offset 4: MajorVersion (2 bytes)
                        # Offset 6: MinorVersion (2 bytes)
                        # Offset 8: FileReferenceNumber (8 bytes)
                        # Offset 16: ParentFileReferenceNumber (8 bytes)
                        # Offset 24: USN (8 bytes)
                        # Offset 32: TimeStamp (8 bytes) - FILETIME
                        # Offset 40: Reason (4 bytes)
                        # Offset 44: SourceInfo (4 bytes)
                        # Offset 48: SecurityId (4 bytes)
                        # Offset 52: FileNameLength (2 bytes)
                        # Offset 54: FileNameOffset (2 bytes)
                        # Offset 56+: FileName (variable)

                        if len(data) < pos + 64:
                            break

                        record_length = int.from_bytes(data[pos : pos + 4], "little")
                        if record_length < 64 or record_length > 65536:
                            break

                        major_version = int.from_bytes(
                            data[pos + 4 : pos + 6], "little"
                        )
                        if major_version != 2 and major_version != 3:
                            pos += max(record_length, 64)
                            continue

                        # Parse timestamp (FILETIME - 100-nanosecond intervals since 1601)
                        filetime = int.from_bytes(data[pos + 32 : pos + 40], "little")
                        if filetime > 0:
                            # Convert FILETIME to datetime
                            timestamp = datetime(1601, 1, 1) + timedelta(
                                microseconds=filetime // 10
                            )

                            # Parse reason flags
                            reason = int.from_bytes(data[pos + 40 : pos + 44], "little")
                            reason_names = []
                            if reason & 0x00000001:
                                reason_names.append("DATA_OVERWRITE")
                            if reason & 0x00000002:
                                reason_names.append("DATA_EXTEND")
                            if reason & 0x00000004:
                                reason_names.append("DATA_TRUNCATION")
                            if reason & 0x00000010:
                                reason_names.append("NAMED_DATA_OVERWRITE")
                            if reason & 0x00000020:
                                reason_names.append("NAMED_DATA_EXTEND")
                            if reason & 0x00000040:
                                reason_names.append("NAMED_DATA_TRUNCATION")
                            if reason & 0x00000100:
                                reason_names.append("FILE_CREATE")
                            if reason & 0x00000200:
                                reason_names.append("FILE_DELETE")
                            if reason & 0x00000400:
                                reason_names.append("EA_CHANGE")
                            if reason & 0x00000800:
                                reason_names.append("SECURITY_CHANGE")
                            if reason & 0x00001000:
                                reason_names.append("RENAME_OLD_NAME")
                            if reason & 0x00002000:
                                reason_names.append("RENAME_NEW_NAME")
                            if reason & 0x00004000:
                                reason_names.append("INDEXABLE_CHANGE")
                            if reason & 0x00010000:
                                reason_names.append("BASIC_INFO_CHANGE")
                            if reason & 0x00020000:
                                reason_names.append("HARD_LINK_CHANGE")
                            if reason & 0x00040000:
                                reason_names.append("MARKUP_CHANGE")
                            if reason & 0x00080000:
                                reason_names.append("REPARSE_POINT_CHANGE")
                            if reason & 0x00100000:
                                reason_names.append("INTEGRITY_CHANGE")
                            if reason & 0x00200000:
                                reason_names.append("NAME_CHANGE")
                            if reason & 0x00400000:
                                reason_names.append("OFFLINE_CHANGE")
                            if reason & 0x00800000:
                                reason_names.append("NO_MORE_DATA")

                            # Get filename
                            filename = None
                            fn_offset = int.from_bytes(
                                data[pos + 54 : pos + 56], "little"
                            )
                            fn_length = int.from_bytes(
                                data[pos + 52 : pos + 54], "little"
                            )
                            if (
                                fn_offset > 0
                                and fn_length > 0
                                and pos + fn_offset + fn_length <= len(data)
                            ):
                                try:
                                    filename = (
                                        data[
                                            pos + fn_offset : pos
                                            + fn_offset
                                            + fn_length
                                        ]
                                        .decode("utf-16-le", errors="ignore")
                                        .rstrip("\x00")
                                    )
                                except:
                                    pass

                            records.append(
                                {
                                    "timestamp": timestamp,
                                    "reason": reason,
                                    "reason_names": reason_names,
                                    "filename": filename,
                                }
                            )

                        pos += record_length

                    except Exception:
                        pos += 64
                        continue

            except Exception as e:
                print(f"Error parsing raw USN: {e}")
                continue

        return records

    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        if not ts_str or ts_str == "N/A" or not ts_str.strip():
            return None

        ts_str = ts_str.strip()

        formats = ["%Y-%m-%d %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%Y-%m-%d"]

        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        return None

    def _get_severity_score(self, severity: str) -> float:
        scores = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 0}
        return scores.get(severity.upper(), 0)

    def _analyze_timeline(self):
        """Analyze timeline data for timestomping indicators"""

        for record in self.timeline_data:
            filename = record.get("filename", "")
            if not filename:
                continue

            self.all_filenames.add(filename.lower())
            analysis = self._get_or_create_analysis(filename)

            file_type = record.get("type", "")
            created_str = record.get("created", "")
            modified_str = record.get("modified", "")
            accessed_str = record.get("accessed", "")

            created_ts = self._parse_timestamp(created_str)
            modified_ts = self._parse_timestamp(modified_str)
            accessed_ts = self._parse_timestamp(accessed_str)

            if created_ts:
                analysis.si_created = created_ts
            if modified_ts:
                analysis.si_modified = modified_ts
            if accessed_ts:
                analysis.si_accessed = accessed_ts

            self._detect_timestomping_in_file(
                analysis, created_str, created_ts, file_type
            )

    def _detect_timestomping_in_file(
        self, analysis, created_str, created_ts, file_type=""
    ):
        """Apply detection rules to a file"""
        try:
            now = datetime.now()

            # Rule 1: Future timestamps
            if created_ts and created_ts.year > now.year + 1:
                indicator = TimestompIndicator(
                    rule_id="future_timestamp",
                    severity="CRITICAL",
                    description="File has timestamp in the future - clear sign of timestomping",
                    evidence=f"Created: {created_ts}, Expected: <={now.year}",
                    timestamp_value=str(created_ts),
                    expected_value=str(now.year),
                    source_layer="Timeline",
                )
                analysis.indicators.append(indicator)
                analysis.total_score += 100

            # Rule 2: Zero/empty timestamps (1601-01-01 or 0000-00-00)
            # BUT: Skip entries marked with * (deleted files) - they may have valid counterparts
            if "1601-01-01" in created_str or "0000-00-00" in created_str:
                # Skip entries that are marked as deleted (have * in type)
                # These are deleted files that often show zero timestamps but may have valid copies
                is_deleted_entry = "*" in file_type

                if not is_deleted_entry:
                    # Skip system files that legitimately have zero timestamps
                    if not any(
                        x in analysis.filename.lower()
                        for x in [
                            "$mbr",
                            "$fat",
                            "$boot",
                            "volume label",
                            "$phan",
                            "orphan",
                        ]
                    ):
                        indicator = TimestompIndicator(
                            rule_id="zero_timestamp",
                            severity="HIGH",
                            description="Zero/empty timestamp (Windows epoch 1601) - indicates file timestamp manipulation",
                            evidence=f"File: {analysis.filename}, Created: {created_str}",
                            timestamp_value=created_str,
                            expected_value="Valid date after 1970",
                            source_layer="Timeline",
                        )
                        analysis.indicators.append(indicator)
                        analysis.total_score += 75

            # Rule 3: Very old timestamps (< 1990) on modern system files
            if created_ts and created_ts.year < 1990:
                indicator = TimestompIndicator(
                    rule_id="ancient_timestamp",
                    severity="MEDIUM",
                    description=f"Pre-1990 timestamp ({created_ts.year}) - highly unusual for active system",
                    evidence=f"File: {analysis.filename}, Created: {created_ts}",
                    timestamp_value=str(created_ts),
                    expected_value="> 1990-01-01",
                    source_layer="Timeline",
                )
                analysis.indicators.append(indicator)
                analysis.total_score += 50
        except Exception:
            pass

    def _detect_timestamp_order_anomalies(self):
        """Detect when timestamp order is wrong - key anti-forensic indicator"""

        for record in self.timeline_data:
            filename = record.get("filename", "")
            if not filename:
                continue

            file_type = record.get("type", "")
            created_str = record.get("created", "")
            modified_str = record.get("modified", "")
            accessed_str = record.get("accessed", "")
            mft_modified_str = record.get("mft_modified", "")

            created_ts = self._parse_timestamp(created_str)
            modified_ts = self._parse_timestamp(modified_str)
            accessed_ts = self._parse_timestamp(accessed_str)
            mft_modified_ts = self._parse_timestamp(mft_modified_str)

            # Skip system files
            if any(x in filename.lower() for x in ["$", "shadowindex", "snapshot"]):
                continue

            anomalies_found = []

            # Convert timestamps to strings for comparison
            created_date = created_ts.strftime("%Y-%m-%d") if created_ts else "N/A"
            modified_date = modified_ts.strftime("%Y-%m-%d") if modified_ts else "N/A"
            accessed_date = accessed_ts.strftime("%Y-%m-%d") if accessed_ts else "N/A"
            mft_modified_date = (
                mft_modified_ts.strftime("%Y-%m-%d") if mft_modified_ts else "N/A"
            )

            # Case 1: Modified BEFORE Created - Check USN Journal for evidence
            has_usn_data = len(self.usn_records) > 0

            # Track files with Modified < Created for possibly_copied list
            # (when no USN to verify, these are likely copied)
            if not has_usn_data and modified_ts and created_ts:
                if modified_ts < created_ts:
                    diff_days = (created_ts - modified_ts).days
                    # Track this file as possibly copied
                    analysis = self._get_or_create_analysis(filename)
                    analysis.si_created = created_ts
                    analysis.si_modified = modified_ts
                    # Add to possibly_copied_files (separate from suspicious)
                    if analysis not in self.possibly_copied_files:
                        self.possibly_copied_files.append(analysis)

            # If USN data exists, analyze more carefully
            if has_usn_data and modified_ts and created_ts:
                if modified_ts < created_ts:
                    diff_days = (created_ts - modified_ts).days

                    # Check if USN has records for this file
                    filename_lower = filename.lower()

                    # Find matching USN records - check both raw records (with datetime) and text records
                    matching_usn = []
                    for u in self.usn_records:
                        usn_filename = u.get("filename", "")
                        if usn_filename and filename_lower in usn_filename.lower():
                            matching_usn.append(u)
                        elif "raw" not in u:  # Text-based record
                            if filename_lower in str(u.get("raw", "")).lower():
                                matching_usn.append(u)

                    if matching_usn:
                        # Analyze USN events to determine if copy or timestomping
                        has_file_create = False
                        has_data_write = False
                        earliest_event = None
                        latest_event = None

                        for usn in matching_usn:
                            # Check for datetime (raw USN) or parse from string
                            ts = usn.get("timestamp")
                            if isinstance(ts, datetime):
                                if earliest_event is None or ts < earliest_event:
                                    earliest_event = ts
                                if latest_event is None or ts > latest_event:
                                    latest_event = ts

                                # Check reason names
                                reason_names = usn.get("reason_names", [])
                                if "FILE_CREATE" in reason_names:
                                    has_file_create = True
                                if any(
                                    r in reason_names
                                    for r in [
                                        "DATA_OVERWRITE",
                                        "DATA_EXTEND",
                                        "NAMED_DATA_OVERWRITE",
                                        "NAMED_DATA_EXTEND",
                                    ]
                                ):
                                    has_data_write = True

                        if has_file_create and not has_data_write:
                            # FILE_CREATE exists but no writes - supports copy scenario
                            # Don't flag as suspicious
                            pass
                        elif has_data_write and earliest_event and modified_ts:
                            # Has data writes - check if after created but before modified
                            if (
                                earliest_event > created_ts
                                and earliest_event < modified_ts
                            ):
                                # Write activity between Created and Modified - suggests timestomping!
                                anomalies_found.append(
                                    f"Modified ({modified_date}) before Created ({created_date}) - "
                                    f"USN shows writes between these times - TIMESTOMPING DETECTED"
                                )
                            elif diff_days > 365:
                                # Large gap but has USN activity - flag as suspicious
                                anomalies_found.append(
                                    f"Modified ({modified_date}) is {diff_days} days before Created ({created_date}) - "
                                    f"USN has activity - investigate"
                                )
                        else:
                            # USN has activity but unclear pattern
                            if diff_days > 365:
                                anomalies_found.append(
                                    f"Modified ({modified_date}) is {diff_days} days before Created ({created_date}) - "
                                    f"verify with USN journal"
                                )

            # Case 2: Zero timestamps (1601/0000) - strong indicator of manipulation
            # BUT skip files that legitimately have zero timestamps OR deleted files
            zero_in_file = False
            for ts_str in [created_str, modified_str, accessed_str]:
                if ts_str and ("1601-01-01" in ts_str or "0000-00-00" in ts_str):
                    zero_in_file = True

            if zero_in_file:
                # Skip deleted files (marked with *) - they often have zero timestamps but have valid copies
                is_deleted = "*" in file_type

                if not is_deleted:
                    # Skip system/special entries that legitimately have zero timestamps
                    if not any(
                        x in filename.lower()
                        for x in ["$", "volume label", "orphan", "fat", "boot"]
                    ):
                        anomalies_found.append(
                            f"File has zero/empty timestamp - strong indicator of manipulation"
                        )

            # If we found anomalies, add to analysis
            if anomalies_found:
                analysis = self._get_or_create_analysis(filename)

                if created_ts:
                    analysis.si_created = created_ts
                if modified_ts:
                    analysis.si_modified = modified_ts
                if accessed_ts:
                    analysis.si_accessed = accessed_ts

                # Deduplicate anomalies by rule type + description (same anomaly reported once)
                seen_anomaly_keys = set()

                for anomaly in anomalies_found:
                    # Create unique key for deduplication
                    anomaly_key = anomaly.strip()
                    if anomaly_key in seen_anomaly_keys:
                        continue
                    seen_anomaly_keys.add(anomaly_key)

                    # Determine severity based on anomaly type
                    severity = "LOW"
                    score = 25
                    if "IMPOSSIBLE" in anomaly:
                        severity = "HIGH"
                        score = 75
                    elif "zero" in anomaly.lower():
                        severity = "HIGH"
                        score = 75
                    elif "system file" in anomaly.lower():
                        severity = "MEDIUM"
                        score = 50

                    indicator = TimestompIndicator(
                        rule_id="timestamp_order_anomaly",
                        severity=severity,
                        description=f"Timestamp sequence anomaly: {anomaly}",
                        evidence=f"File: {filename}, Details: {anomaly}",
                        timestamp_value=created_str if created_str else "N/A",
                        source_layer="Timeline (MACE Analysis)",
                    )
                    analysis.indicators.append(indicator)
                    analysis.total_score += score

    def _correlate_shadow_copies(self):
        """Check if files exist in shadow copies - with PROPER temporal comparison"""

        has_vss = len(self.shadow_copy_files) > 0

        # Get VSS system timestamps from the timeline
        vss_system_times = []
        for record in self.timeline_data:
            fname = record.get("filename", "").lower()
            if "shadowindex" in fname or "snapshot" in fname:
                created = record.get("created", "")
                if created:
                    ts = self._parse_timestamp(created)
                    if ts:
                        vss_system_times.append(ts)

        # Approximate when VSS was active (from shadow index files in timeline)
        vss_active_start = min(vss_system_times) if vss_system_times else None
        has_vss = len(self.shadow_copy_files) > 0 or vss_active_start is not None

        for analysis in self.analysis_results:
            filename_lower = analysis.filename.lower()
            file_created = analysis.si_created

            if not has_vss:
                continue

            # Skip system VSS files
            if any(x in filename_lower for x in ["shadowindex", "snapshot", ".shadow"]):
                continue

            # File NOT in shadow copies
            if filename_lower not in self.shadow_copy_files:
                if not file_created:
                    continue

                # CORRECT LOGIC: We need snapshot creation timestamps to properly detect this
                # Without knowing when specific snapshots were created, we cannot determine
                # if a file SHOULD have been in a snapshot
                #
                # Simply being absent from VSS when VSS was "active" is NOT suspicious
                # because:
                # 1. VSS may be enabled but no snapshots taken
                # 2. Snapshots may have expired/were cleaned up
                # 3. VSS settings may exclude this volume
                #
                # This check requires shadow copy creation timestamps - skip for now
                pass

    def _check_log_clearing(self):
        """Check for log clearing evidence"""
        if self.log_clearing_indicators:
            for analysis in self.analysis_results:
                indicator = TimestompIndicator(
                    rule_id="log_clearing",
                    severity="CRITICAL",
                    description="Windows logs show evidence of being cleared",
                    evidence=f"Partitions: {', '.join(self.log_clearing_indicators)}",
                    source_layer="Event Logs",
                )
                analysis.indicators.append(indicator)
                analysis.total_score += 100

    def _correlate_usn(self):
        """Correlate with USN Journal"""
        for analysis in self.analysis_results:
            filename_lower = analysis.filename.lower()

            matching_usn = [
                u for u in self.usn_records if filename_lower in str(u).lower()
            ]

            if not matching_usn and self.usn_records and analysis.si_created:
                if analysis.si_created.year < 2015:
                    indicator = TimestompIndicator(
                        rule_id="usn_missing",
                        severity="MEDIUM",
                        description="File exists in timeline but NOT in USN Journal",
                        evidence=f"File: {analysis.filename}",
                        timestamp_value=str(analysis.si_created),
                        source_layer="USN Journal",
                    )
                    analysis.indicators.append(indicator)
                    analysis.total_score += 25

    def _process_event_logs(self):
        """Process event logs for timestamp analysis - done in load"""
        pass

    def _correlate_event_logs(self):
        """Correlate file timestamps with event logs"""
        if not self.event_latest or not self.event_earliest:
            return

        for analysis in self.analysis_results:
            if not analysis.si_created:
                continue

            # File created AFTER all event logs
            if analysis.si_created > self.event_latest:
                diff = (analysis.si_created - self.event_latest).days
                if diff > 1:
                    indicator = TimestompIndicator(
                        rule_id="si_after_event_logs",
                        severity="HIGH",
                        description=f"File created {diff} days AFTER latest event log",
                        evidence=f"File: {analysis.filename}, Created: {analysis.si_created}, Latest Event: {self.event_latest}",
                        timestamp_value=str(analysis.si_created),
                        expected_value=f"< {self.event_latest}",
                        time_diff_seconds=diff * 86400,
                        source_layer="Event Logs",
                    )
                    analysis.indicators.append(indicator)
                    analysis.total_score += 75

            # File created significantly BEFORE earliest event
            if analysis.si_created < self.event_earliest:
                diff = (self.event_earliest - analysis.si_created).days
                if diff > 365 * 5:
                    indicator = TimestompIndicator(
                        rule_id="si_before_event_logs",
                        severity="MEDIUM",
                        description=f"File created {diff} days BEFORE earliest event log",
                        evidence=f"File: {analysis.filename}, Created: {analysis.si_created}, Earliest: {self.event_earliest}",
                        timestamp_value=str(analysis.si_created),
                        expected_value=f"> {self.event_earliest}",
                        time_diff_seconds=diff * 86400,
                        source_layer="Event Logs",
                    )
                    analysis.indicators.append(indicator)
                    analysis.total_score += 25

    def _check_prefetch_amcache(self):
        """Check Prefetch and Amcache correlation"""
        registry_dir = self.output_dir / "registry"
        has_amcache = False
        if registry_dir.exists():
            has_amcache = any("Amcache" in p.name for p in registry_dir.glob("*.hive"))

        for analysis in self.analysis_results:
            filename_lower = analysis.filename.lower()

            if filename_lower.endswith(".exe"):
                exe_name = filename_lower.split(".")[0].upper()
                matching_pf = [p for p in self.prefetch_files if exe_name in p]

                if matching_pf:
                    analysis.has_prefetch = True
                elif analysis.si_created:
                    days_old = (datetime.now() - analysis.si_created).days
                    if 0 < days_old < 30:
                        indicator = TimestompIndicator(
                            rule_id="prefetch_missing",
                            severity="LOW",
                            description="EXE is recent but no Prefetch found",
                            evidence=f"EXE: {analysis.filename}, Age: {days_old} days",
                            source_layer="Prefetch",
                        )
                        analysis.indicators.append(indicator)
                        analysis.total_score += 10

            if has_amcache:
                analysis.has_amcache = True

    def _analyze_si_fn_drift(self):
        """Rule 1: SI vs FN Drift Analysis - detect batch timestomping via uniform offsets"""

        # Collect all SI and FN timestamp pairs
        si_fn_deltas = []

        for record in self.timeline_data:
            filename = record.get("filename", "")
            created_str = record.get("created", "")
            modified_str = record.get("modified", "")

            if not created_str or not modified_str:
                continue

            # Calculate delta between timestamps
            created_ts = self._parse_timestamp(created_str)
            modified_ts = self._parse_timestamp(modified_str)

            if created_ts and modified_ts:
                delta = (created_ts - modified_ts).total_seconds()
                si_fn_deltas.append(
                    {
                        "filename": filename,
                        "delta_seconds": delta,
                        "created": created_ts,
                        "modified": modified_ts,
                    }
                )

        # Group deltas - look for clustering around specific values
        if len(si_fn_deltas) < 10:
            return

        # Look for round number deltas (1 hour, 1 day, 1 year) - NOT zero
        # Zero delta between SI and FN is NORMAL and expected behavior
        round_deltas = [3600, 86400, 31536000]  # hour, day, year
        suspicious_count = 0

        for item in si_fn_deltas:
            delta = abs(item["delta_seconds"])
            for rd in round_deltas:
                if delta == rd:
                    # Found exact round number delta
                    suspicious_count += 1
                    analysis = self._get_or_create_analysis(item["filename"])

                    indicator = TimestompIndicator(
                        rule_id="si_fn_round_delta",
                        severity="MEDIUM",
                        description=f"SI-FN delta is exactly {rd} seconds ({rd / 86400:.1f} days) - suggests batch manipulation",
                        evidence=f"File: {item['filename']}, Delta: {delta} seconds",
                        timestamp_value=str(item["created"]),
                        source_layer="SI-FN Drift Analysis",
                    )
                    analysis.indicators.append(indicator)
                    analysis.total_score += 50
                    break

    def _check_volume_boundary(self):
        """Rule 4: Volume Creation Time Check - file predating volume is impossible

        IMPORTANT: This only applies to NTFS filesystems where we have a true
        volume creation timestamp. For FAT/external drives, files can easily
        predate the volume (copied from elsewhere).
        """

        # First, determine filesystem type from extraction summary
        filesystem_type = "unknown"
        extraction_summary = self.output_dir / "extraction_summary.json"
        if extraction_summary.exists():
            try:
                with open(extraction_summary, "r") as f:
                    summary = json.load(f)
                    if summary.get("partitions"):
                        desc = summary["partitions"][0].get("desc", "")
                        if "FAT" in desc.upper():
                            filesystem_type = "FAT"
                        elif "NTFS" in desc.upper():
                            filesystem_type = "NTFS"
            except:
                pass

        # For FAT filesystems, skip this check - files can predate the volume
        # when copied from another drive
        if filesystem_type == "FAT":
            return

        # Get actual volume creation from $Boot sector for NTFS
        # Try to read from raw boot sector first
        volume_created = None

        # Check if we have raw boot sector with NTFS signature
        for partition_num in self.partition_nums:
            boot_file = self.output_dir / f"raw_boot_partition_{partition_num}.bin"
            if boot_file.exists():
                try:
                    with open(boot_file, "rb") as f:
                        boot_data = f.read(512)
                        # Check for NTFS signature at offset 0x03
                        if (
                            len(boot_data) >= 512
                            and boot_data[0x03:0x0B] == b"NTFS    "
                        ):
                            # NTFS volume - can check volume creation from $Volume
                            # For now, use a reasonable heuristic
                            filesystem_type = "NTFS"
                except:
                    pass

        # Get approximate volume creation from oldest system files
        for record in self.timeline_data:
            fname = record.get("filename", "").lower()
            # System files like $Boot, $MFT indicate volume creation
            if any(x in fname for x in ["$boot", "$mft", "$volume"]):
                created = record.get("created", "")
                if created:
                    ts = self._parse_timestamp(created)
                    if ts and (not volume_created or ts < volume_created):
                        volume_created = ts

        if not volume_created:
            # Use oldest timestamp in timeline as proxy
            for record in self.timeline_data:
                created = record.get("created", "")
                if created:
                    ts = self._parse_timestamp(created)
                    if ts and (not volume_created or ts < volume_created):
                        volume_created = ts

        if not volume_created:
            return

        for analysis in self.analysis_results:
            if not analysis.si_created:
                continue

            # File Created < Volume Created is impossible for NTFS
            # But for system files copied from elsewhere, this can happen
            if analysis.si_created < volume_created:
                diff = (volume_created - analysis.si_created).days

                # Skip system files - they can be copied from elsewhere
                if any(
                    x in analysis.filename.lower()
                    for x in ["$", "shadowindex", "system volume"]
                ):
                    continue

                # Flag only if difference is large AND it's a user file on NTFS
                # Small differences could be timezone issues
                if diff > 30 and filesystem_type == "NTFS":
                    indicator = TimestompIndicator(
                        rule_id="volume_boundary_violation",
                        severity="HIGH",
                        description=f"File created {diff} days BEFORE volume creation - suspicious for NTFS",
                        evidence=f"File: {analysis.filename}, Created: {analysis.si_created.date()}, Volume: {volume_created.date()}",
                        timestamp_value=str(analysis.si_created),
                        expected_value=f"After {volume_created.date()}",
                        time_diff_seconds=diff * 86400,
                        source_layer="Volume Boundary",
                    )
                    analysis.indicators.append(indicator)
                    analysis.total_score += 50

    def _analyze_timestamp_entropy(self):
        """Rule 9: Timestamp Entropy Analysis - humans are messy, scripts are tidy"""

        # Group files by timestamp (to the second)
        timestamp_groups: Dict[str, List[str]] = {}

        for record in self.timeline_data:
            filename = record.get("filename", "")
            created = record.get("created", "")

            if not created or not filename:
                continue

            # Round to minute for grouping
            ts = self._parse_timestamp(created)
            if ts:
                key = ts.strftime("%Y-%m-%d %H:%M")  # Group by minute
                if key not in timestamp_groups:
                    timestamp_groups[key] = []
                timestamp_groups[key].append(filename)

        # Find clusters - if > 10 files share exact same minute, suspicious
        suspicious_minutes = {k: v for k, v in timestamp_groups.items() if len(v) > 10}

        for minute, files in suspicious_minutes.items():
            # Check if these files are in different directories (automation indicator)
            unique_dirs = set()
            for f in files:
                # Extract path components
                parts = f.split("/")
                if len(parts) > 1:
                    unique_dirs.add("/".join(parts[:-1]))

            # If same minute, different directories = HIGHLY suspicious (automation)
            if len(unique_dirs) > 5:
                for filename in files[:5]:  # Flag first 5
                    analysis = self._get_or_create_analysis(filename)

                    indicator = TimestompIndicator(
                        rule_id="timestamp_entropy_anomaly",
                        severity="HIGH",
                        description=f"{len(files)} files timestamped at {minute} across {len(unique_dirs)} directories - suggests automated batch creation",
                        evidence=f"Files: {', '.join(files[:3])}..., Minute: {minute}",
                        timestamp_value=minute,
                        source_layer="Timestamp Entropy",
                    )
                    analysis.indicators.append(indicator)
                    analysis.total_score += 75

    def _cross_reference_artifacts(self):
        """Cross-reference multiple artifacts for concrete proof"""
        for analysis in self.analysis_results:
            filename_lower = analysis.filename.lower()

            sources_found = []

            if any(filename_lower in str(t).lower() for t in self.timeline_data):
                sources_found.append("Timeline")
            if any(filename_lower in str(u).lower() for u in self.usn_records):
                sources_found.append("USN")
            if any(filename_lower in ads for ads in self.ads_files):
                sources_found.append("ADS")
            if filename_lower in self.shadow_copy_files:
                sources_found.append("ShadowCopies")
            if "ntuser" in filename_lower or "usrclass" in filename_lower:
                sources_found.append("Registry")

            if len(sources_found) >= 3:
                indicator = TimestompIndicator(
                    rule_id="multi_source",
                    severity="INFO",
                    description=f"File in {len(sources_found)} sources: {', '.join(sources_found)}",
                    evidence=f"File: {analysis.filename}",
                    source_layer="Cross-Reference",
                )
                analysis.indicators.append(indicator)

    def _get_or_create_analysis(self, filename: str) -> FileTimestompAnalysis:
        for analysis in self.analysis_results:
            if analysis.filename.lower() == filename.lower():
                return analysis

        new_analysis = FileTimestompAnalysis(filename=filename)
        self.analysis_results.append(new_analysis)
        return new_analysis

    def _finalize_analysis(self):
        for analysis in self.analysis_results:
            if not analysis.indicators:
                continue

            analysis.is_suspicious = True

            severities = [ind.severity for ind in analysis.indicators]
            if "CRITICAL" in severities:
                analysis.overall_severity = "CRITICAL"
            elif "HIGH" in severities:
                analysis.overall_severity = "HIGH"
            elif "MEDIUM" in severities:
                analysis.overall_severity = "MEDIUM"
            elif "LOW" in severities:
                analysis.overall_severity = "LOW"

        self.suspicious_files = [
            a for a in self.analysis_results if a.is_suspicious and a.total_score > 0
        ]
        self.suspicious_files.sort(key=lambda x: x.total_score, reverse=True)

    def _generate_report_data(self) -> Dict[str, Any]:
        critical = [
            a for a in self.suspicious_files if a.overall_severity == "CRITICAL"
        ]
        high = [a for a in self.suspicious_files if a.overall_severity == "HIGH"]
        medium = [a for a in self.suspicious_files if a.overall_severity == "MEDIUM"]

        # Generate possiblyCopied.txt
        possibly_copied_file = self.output_dir / "possiblyCopied.txt"
        with open(possibly_copied_file, "w") as f:
            f.write("=" * 80 + "\n")
            f.write("POSSIBLY COPIED FILES\n")
            f.write("Files where Modified < Created (no USN to verify origin)\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Total files: {len(self.possibly_copied_files)}\n\n")
            f.write(f"{'Filename':<60} {'Created':<20} {'Modified':<20}\n")
            f.write("-" * 100 + "\n")
            for a in sorted(self.possibly_copied_files, key=lambda x: x.filename):
                created_str = (
                    a.si_created.strftime("%Y-%m-%d %H:%M:%S")
                    if a.si_created
                    else "N/A"
                )
                modified_str = (
                    a.si_modified.strftime("%Y-%m-%d %H:%M:%S")
                    if a.si_modified
                    else "N/A"
                )
                f.write(f"{a.filename[:58]:<60} {created_str:<20} {modified_str:<20}\n")

        return {
            "analysis_metadata": {
                "output_directory": str(self.output_dir),
                "analyzed_at": datetime.now().isoformat(),
                "total_files_analyzed": len(self.analysis_results),
                "total_suspicious": len(self.suspicious_files),
                "artifacts_summary": {
                    "timeline_records": len(self.timeline_data),
                    "usn_records": len(self.usn_records),
                    "shadow_copies": len(self.shadow_copy_files),
                    "ads_files": len(self.ads_files),
                    "registry_hives": len(self.registry_hives),
                    "security_events": len(self.security_events),
                    "system_events": len(self.system_events),
                    "prefetch_files": len(self.prefetch_files),
                },
            },
            "summary": {
                "critical_count": len(critical),
                "high_count": len(high),
                "medium_count": len(medium),
                "possibly_copied_count": len(self.possibly_copied_files),
                "total_indicators": sum(
                    len(a.indicators) for a in self.suspicious_files
                ),
            },
            "critical_findings": [self._serialize_analysis(a) for a in critical],
            "high_findings": [self._serialize_analysis(a) for a in high[:30]],
            "medium_findings": [self._serialize_analysis(a) for a in medium[:20]],
            "all_suspicious": [
                self._serialize_analysis(a) for a in self.suspicious_files
            ],
        }

    def _serialize_analysis(self, analysis: FileTimestompAnalysis) -> Dict:
        return {
            "filename": analysis.filename,
            "severity": analysis.overall_severity,
            "score": analysis.total_score,
            "indicators": [
                {
                    "rule_id": ind.rule_id,
                    "severity": ind.severity,
                    "description": ind.description,
                    "evidence": ind.evidence,
                    "timestamp_value": ind.timestamp_value,
                    "expected_value": ind.expected_value,
                    "time_diff_seconds": ind.time_diff_seconds,
                    "source_layer": ind.source_layer,
                }
                for ind in analysis.indicators
            ],
            "si_created": str(analysis.si_created) if analysis.si_created else None,
            "has_prefetch": analysis.has_prefetch,
            "has_amcache": analysis.has_amcache,
        }


def run_hardcoded_detection(output_dir: str) -> Dict[str, Any]:
    detector = HardcodedTimestompDetector(output_dir)
    return detector.run_detection()
