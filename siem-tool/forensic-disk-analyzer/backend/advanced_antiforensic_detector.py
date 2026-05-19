#!/usr/bin/env python3
"""
Advanced Anti-Forensic Timestamp Manipulation Detector

Implements 11 forensic heuristics for detecting timestamp manipulation:
1. $SI vs $FN Drift Analysis
2. USN Temporal Forward Check
3. $LogFile LSN Monotonicity
4. Volume Creation Time Check
5. OS Install Time Check
6. Boot-Time Boundary Violations
7. Clock Rollback Detection
8. MFT Record Sequence Analysis
9. Timestamp Entropy Analysis
10. Microsecond/Nanosecond Patterns
11. Shadow Copy Differential Reconstruction

Author: Cyber Chakshu SIEM Team
"""

import struct
import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import math


@dataclass
class TimestompIndicator:
    """Single timestomp indicator with evidence"""

    check_number: int
    check_name: str
    is_suspicious: bool
    severity: str
    confidence: float
    description: str
    evidence: Dict[str, Any]
    delta_seconds: Optional[float] = None


@dataclass
class ForensicAnalysisResult:
    """Complete forensic analysis result"""

    filename: str
    file_reference: int
    record_sequence_number: int

    si_timestamps: Optional[Dict[str, str]] = None
    fn_timestamps: Optional[Dict[str, str]] = None

    indicators: List[TimestompIndicator] = field(default_factory=list)

    si_fn_created_delta: float = 0.0
    si_fn_modified_delta: float = 0.0

    overall_score: float = 0.0
    overall_severity: str = "INFO"
    is_timestomped: bool = False

    volume_created: Optional[datetime] = None
    os_install_time: Optional[datetime] = None
    boot_times: List[datetime] = field(default_factory=list)
    clock_rollbacks: List[Dict] = field(default_factory=list)


class DriftAnalyzer:
    """
    Check 1: $SI vs $FN Drift Analysis

    Measures deltas between Standard Information and File Name timestamps.
    Batch timestomping tools apply uniform offsets - attack tools are tidy,
    natural systems are messy.

    IMPORTANT: Zero delta between SI and FN is NORMAL and expected.
    Only flag LARGE deltas or round-number deltas.
    """

    ROUND_NUMBER_SECONDS = {
        3600: "1 hour",
        7200: "2 hours",
        86400: "1 day",
        172800: "2 days",
        604800: "1 week",
        2592000: "30 days",
        31536000: "1 year",
    }

    def __init__(self):
        self.all_deltas: List[float] = []
        self.delta_clusters: Dict[float, int] = {}

    def analyze_drift(
        self,
        si_created: Optional[datetime],
        fn_created: Optional[datetime],
        si_modified: Optional[datetime],
        fn_modified: Optional[datetime],
    ) -> List[TimestompIndicator]:
        indicators = []

        if not si_created or not fn_created:
            return indicators

        delta_created = abs((si_created - fn_created).total_seconds())
        delta_modified = (
            abs((si_modified - fn_modified).total_seconds())
            if si_modified and fn_modified
            else 0
        )

        # Only track deltas > 1 second - zero delta is NORMAL
        if delta_created > 1:
            self.all_deltas.append(delta_created)

            indicator = self._check_round_number(
                delta_created,
                "created",
                si_created,
                fn_created,
            )
            if indicator:
                indicators.append(indicator)

        # Only analyze modified delta if > 1 second
        if delta_modified > 1:
            self.all_deltas.append(delta_modified)

            indicator = self._check_round_number(
                delta_modified,
                "modified",
                si_modified,
                fn_modified,
            )
            if indicator:
                indicators.append(indicator)

        return indicators

    def _check_round_number(
        self,
        delta_seconds: float,
        ts_type: str,
        si_ts: datetime,
        fn_ts: datetime,
    ) -> Optional[TimestompIndicator]:
        # Only flag round-number deltas (not zero)
        for round_seconds, description in self.ROUND_NUMBER_SECONDS.items():
            if abs(delta_seconds - round_seconds) < 60:
                return TimestompIndicator(
                    check_number=1,
                    check_name="$SI vs $FN Round Delta",
                    is_suspicious=True,
                    severity="HIGH",
                    confidence=0.9,
                    description=f"{ts_type.capitalize()} delta is exactly {description} - suggests batch timestomping",
                    evidence={
                        "delta_seconds": delta_seconds,
                        "delta_description": description,
                        "si_timestamp": si_ts.isoformat(),
                        "fn_timestamp": fn_ts.isoformat(),
                        "delta_rounded": description,
                    },
                    delta_seconds=delta_seconds,
                )

        # Flag very large deltas only (> 30 days)
        if delta_seconds > 86400 * 30:
            return TimestompIndicator(
                check_number=1,
                check_name="$SI vs $FN Large Delta",
                is_suspicious=True,
                severity="HIGH",
                confidence=0.7,
                description=f"{ts_type.capitalize()} delta is {delta_seconds / 86400:.1f} days - unusual for normal file operations",
                evidence={
                    "delta_seconds": delta_seconds,
                    "delta_days": delta_seconds / 86400,
                    "si_timestamp": si_ts.isoformat(),
                    "fn_timestamp": fn_ts.isoformat(),
                },
                delta_seconds=delta_seconds,
            )

        return None

    def detect_batch_patterns(self) -> Optional[TimestompIndicator]:
        if len(self.all_deltas) < 3:
            return None

        counter = Counter()
        for delta in self.all_deltas:
            for round_sec in self.ROUND_NUMBER_SECONDS.keys():
                if abs(delta - round_sec) < 60:
                    counter[round_sec] += 1
                    break

        if counter:
            most_common_delta, count = counter.most_common(1)[0]
            if count >= 3:
                return TimestompIndicator(
                    check_number=1,
                    check_name="$SI vs $FN Batch Pattern",
                    is_suspicious=True,
                    severity="CRITICAL",
                    confidence=0.95,
                    description=f"Multiple files with identical {self.ROUND_NUMBER_SECONDS.get(most_common_delta, 'round number')} delta - automated timestomping detected",
                    evidence={
                        "matching_delta": most_common_delta,
                        "count": count,
                        "description": self.ROUND_NUMBER_SECONDS.get(most_common_delta),
                    },
                    delta_seconds=most_common_delta,
                )

        return None


class USNTemporalChecker:
    """
    Check 2: USN Temporal Forward Check

    If USN shows DATA_WRITE at T1, then Modified must be >= T1.
    If Modified < T1, that's a causality fracture.
    """

    def __init__(self, usn_records: List[Any] = None):
        self.usn_records = usn_records or []

    def check_causality(
        self,
        file_ref: int,
        si_modified: Optional[datetime],
        fn_modified: Optional[datetime],
    ) -> List[TimestompIndicator]:
        indicators = []

        file_usn_events = [
            r
            for r in self.usn_records
            if hasattr(r, "file_reference_number")
            and r.file_reference_number == file_ref
        ]

        if not file_usn_events:
            indicators.append(
                TimestompIndicator(
                    check_number=2,
                    check_name="USN Temporal Forward Check",
                    is_suspicious=True,
                    severity="MEDIUM",
                    confidence=0.5,
                    description="No USN records found for file - journal may have been cleared",
                    evidence={"file_reference": file_ref},
                )
            )
            return indicators

        data_writes = [
            r
            for r in file_usn_events
            if hasattr(r, "reason") and (r.reason & 0x00000001 or r.reason & 0x00000010)
        ]

        if data_writes:
            earliest_write = min(r.timestamp for r in data_writes if r.timestamp)

            if si_modified and earliest_write and si_modified < earliest_write:
                indicators.append(
                    TimestompIndicator(
                        check_number=2,
                        check_name="USN Temporal Forward Check",
                        is_suspicious=True,
                        severity="CRITICAL",
                        confidence=0.95,
                        description=f"SI Modified ({si_modified}) is BEFORE earliest USN DATA_WRITE ({earliest_write}) - causality violation",
                        evidence={
                            "si_modified": si_modified.isoformat(),
                            "earliest_usn_write": earliest_write.isoformat(),
                            "violation_seconds": (
                                earliest_write - si_modified
                            ).total_seconds(),
                        },
                    )
                )

            if fn_modified and earliest_write and fn_modified < earliest_write:
                indicators.append(
                    TimestompIndicator(
                        check_number=2,
                        check_name="USN Temporal Forward Check",
                        is_suspicious=True,
                        severity="CRITICAL",
                        confidence=0.95,
                        description=f"FN Modified ({fn_modified}) is BEFORE earliest USN DATA_WRITE ({earliest_write}) - causality violation",
                        evidence={
                            "fn_modified": fn_modified.isoformat(),
                            "earliest_usn_write": earliest_write.isoformat(),
                            "violation_seconds": (
                                earliest_write - fn_modified
                            ).total_seconds(),
                        },
                    )
                )

        return indicators


class LSNMonotonicityChecker:
    """
    Check 3: $LogFile LSN Monotonicity

    LSNs must increase over time. If transaction LSN indicates later event
    but file timestamp predates earlier LSN, there's timeline inconsistency.
    """

    def __init__(self, logfile_records: List[Any] = None):
        self.logfile_records = logfile_records or []

    def check_monotonicity(
        self,
        file_ref: int,
        si_timestamps: Dict[str, Optional[datetime]],
    ) -> List[TimestompIndicator]:
        indicators = []

        file_records = [
            r
            for r in self.logfile_records
            if r.file_reference and (r.file_reference & 0xFFFFFFFFFFFF) == file_ref
        ]

        if not file_records:
            return indicators

        sorted_records = sorted(
            [r for r in file_records if r.timestamp], key=lambda x: x.lsn
        )

        lsn_ts_pairs = [(r.lsn, r.timestamp) for r in sorted_records]

        for i in range(1, len(lsn_ts_pairs)):
            prev_lsn, prev_ts = lsn_ts_pairs[i - 1]
            curr_lsn, curr_ts = lsn_ts_pairs[i]

            if prev_ts and curr_ts and curr_ts < prev_ts:
                indicators.append(
                    TimestompIndicator(
                        check_number=3,
                        check_name="$LogFile LSN Monotonicity",
                        is_suspicious=True,
                        severity="HIGH",
                        confidence=0.8,
                        description=f"Non-monotonic timestamp in $LogFile: LSN {curr_lsn} has earlier timestamp than LSN {prev_lsn}",
                        evidence={
                            "prev_lsn": prev_lsn,
                            "prev_timestamp": prev_ts.isoformat(),
                            "curr_lsn": curr_lsn,
                            "curr_timestamp": curr_ts.isoformat(),
                        },
                    )
                )

        if lsn_ts_pairs and si_timestamps.get("created"):
            first_lsn_ts = lsn_ts_pairs[0][1]
            si_created = si_timestamps["created"]

            if first_lsn_ts and si_created and si_created < first_lsn_ts:
                diff_days = (first_lsn_ts - si_created).total_seconds() / 86400
                if diff_days > 1:
                    indicators.append(
                        TimestompIndicator(
                            check_number=3,
                            check_name="$LogFile LSN Temporal Order",
                            is_suspicious=True,
                            severity="HIGH",
                            confidence=0.85,
                            description=f"SI Created ({si_created}) is {diff_days:.1f} days BEFORE first $LogFile activity ({first_lsn_ts})",
                            evidence={
                                "si_created": si_created.isoformat(),
                                "first_lsn_timestamp": first_lsn_ts.isoformat(),
                                "difference_days": diff_days,
                            },
                        )
                    )

        return indicators


class VolumeCreationChecker:
    """
    Check 4: Volume Creation Time Check

    If file Created < Volume Created, that's impossible.
    """

    def __init__(self, volume_created: Optional[datetime] = None):
        self.volume_created = volume_created

    def check_file_against_volume(
        self,
        si_created: Optional[datetime],
        fn_created: Optional[datetime],
    ) -> List[TimestompIndicator]:
        indicators = []

        if not self.volume_created:
            return indicators

        if si_created and si_created < self.volume_created:
            indicators.append(
                TimestompIndicator(
                    check_number=4,
                    check_name="Volume Creation Time Check",
                    is_suspicious=True,
                    severity="CRITICAL",
                    confidence=0.99,
                    description=f"SI Created ({si_created}) is BEFORE Volume Creation ({self.volume_created}) - impossible",
                    evidence={
                        "file_created": si_created.isoformat(),
                        "volume_created": self.volume_created.isoformat(),
                        "difference_days": (
                            self.volume_created - si_created
                        ).total_seconds()
                        / 86400,
                    },
                )
            )

        if fn_created and fn_created < self.volume_created:
            indicators.append(
                TimestompIndicator(
                    check_number=4,
                    check_name="Volume Creation Time Check",
                    is_suspicious=True,
                    severity="CRITICAL",
                    confidence=0.99,
                    description=f"FN Created ({fn_created}) is BEFORE Volume Creation ({self.volume_created}) - impossible",
                    evidence={
                        "file_created": fn_created.isoformat(),
                        "volume_created": self.volume_created.isoformat(),
                        "difference_days": (
                            self.volume_created - fn_created
                        ).total_seconds()
                        / 86400,
                    },
                )
            )

        return indicators


class OSInstallTimeChecker:
    """
    Check 5: OS Install Time Check

    If user-created file predates OS install, that's a very strong
    anti-forensic indicator. System files may predate, user files should not.
    """

    def __init__(self, os_install_time: Optional[datetime] = None):
        self.os_install_time = os_install_time

    def check_file_against_os_install(
        self,
        filename: str,
        si_created: Optional[datetime],
        fn_created: Optional[datetime],
    ) -> List[TimestompIndicator]:
        indicators = []

        if not self.os_install_time:
            return indicators

        system_paths = [
            "\\windows\\",
            "\\program files",
            "\\system32\\",
            "\\programdata\\",
        ]
        is_system_file = any(p.lower() in filename.lower() for p in system_paths)

        check_times = [
            ("SI Created", si_created),
            ("FN Created", fn_created),
        ]

        for ts_name, ts in check_times:
            if ts and ts < self.os_install_time:
                if is_system_file:
                    severity = "LOW"
                    confidence = 0.3
                    description = f"{ts_name} ({ts}) predates OS install - acceptable for system file"
                else:
                    severity = "CRITICAL"
                    confidence = 0.95
                    description = f"{ts_name} ({ts}) predates OS install - impossible for user file"

                indicators.append(
                    TimestompIndicator(
                        check_number=5,
                        check_name="OS Install Time Check",
                        is_suspicious=not is_system_file,
                        severity=severity,
                        confidence=confidence,
                        description=description,
                        evidence={
                            "filename": filename,
                            "is_system_file": is_system_file,
                            "file_timestamp": ts.isoformat() if ts else None,
                            "os_install_time": self.os_install_time.isoformat(),
                            "difference_days": (
                                self.os_install_time - ts
                            ).total_seconds()
                            / 86400
                            if ts
                            else None,
                        },
                    )
                )

        return indicators


class BootTimeBoundaryChecker:
    """
    Check 6: Boot-Time Boundary Violations

    If file Modified at 03:12 but System booted at 08:00, and machine
    was off between those times, how did the file change?
    """

    def __init__(self, boot_times: List[datetime] = None):
        self.boot_times = boot_times or []

    def check_boundary_violations(
        self,
        si_modified: Optional[datetime],
        fn_modified: Optional[datetime],
    ) -> List[TimestompIndicator]:
        indicators = []

        if not self.boot_times or not si_modified:
            return indicators

        for boot_time in sorted(self.boot_times):
            boot_date = boot_time.date()

            for ts_name, ts in [
                ("SI Modified", si_modified),
                ("FN Modified", fn_modified),
            ]:
                if not ts:
                    continue

                if (
                    ts.year == boot_date.year
                    and ts.month == boot_date.month
                    and ts.day == boot_date.day
                ):
                    if ts < boot_time:
                        indicators.append(
                            TimestompIndicator(
                                check_number=6,
                                check_name="Boot-Time Boundary Violation",
                                is_suspicious=True,
                                severity="HIGH",
                                confidence=0.8,
                                description=f"{ts_name} ({ts}) is BEFORE boot time ({boot_time}) on same day",
                                evidence={
                                    "timestamp": ts.isoformat(),
                                    "boot_time": boot_time.isoformat(),
                                    "difference_minutes": (
                                        boot_time - ts
                                    ).total_seconds()
                                    / 60,
                                },
                            )
                        )

        return indicators


class ClockRollbackDetector:
    """
    Check 7: Clock Rollback Detection

    Look for time-change events, sudden backward jumps in event log
    timestamps, non-monotonic log ordering.
    """

    def __init__(self, event_logs: List[Dict] = None):
        self.event_logs = event_logs or []

    def detect_rollbacks(
        self,
        si_modified: Optional[datetime] = None,
        fn_modified: Optional[datetime] = None,
    ) -> List[TimestompIndicator]:
        indicators = []

        if not self.event_logs:
            return indicators

        sorted_events = sorted(
            [e for e in self.event_logs if e.get("timestamp")],
            key=lambda x: x["timestamp"],
        )

        for i in range(1, len(sorted_events)):
            prev_ts = sorted_events[i - 1]["timestamp"]
            curr_ts = sorted_events[i]["timestamp"]

            if isinstance(prev_ts, str):
                prev_ts = datetime.fromisoformat(prev_ts.replace("Z", "+00:00"))
            if isinstance(curr_ts, str):
                curr_ts = datetime.fromisoformat(curr_ts.replace("Z", "+00:00"))

            if curr_ts < prev_ts:
                indicators.append(
                    TimestompIndicator(
                        check_number=7,
                        check_name="Clock Rollback Detection",
                        is_suspicious=True,
                        severity="CRITICAL",
                        confidence=0.9,
                        description=f"Non-monotonic event log ordering: event at {curr_ts} appears AFTER event at {prev_ts}",
                        evidence={
                            "prev_event": sorted_events[i - 1],
                            "curr_event": sorted_events[i],
                            "rollback_seconds": (prev_ts - curr_ts).total_seconds(),
                        },
                    )
                )

        time_change_events = [
            e
            for e in self.event_logs
            if e.get("event_id") in [4616, 1]
            or "time change" in str(e.get("description", "")).lower()
        ]

        if time_change_events:
            indicators.append(
                TimestompIndicator(
                    check_number=7,
                    check_name="Clock Rollback - Time Change Events",
                    is_suspicious=True,
                    severity="HIGH",
                    confidence=0.85,
                    description=f"Found {len(time_change_events)} system time change events - potential clock manipulation",
                    evidence={
                        "time_change_events": time_change_events[:5],
                        "count": len(time_change_events),
                    },
                )
            )

        return indicators


class MFTRecordSequenceAnalyzer:
    """
    Check 8: MFT Record Sequence Analysis

    If file record sequence number incremented but timestamps appear
    very old, suggests Delete -> Recreate -> Timestomp.
    """

    def __init__(self, threshold_seq_jump: int = 10):
        self.threshold_seq_jump = threshold_seq_jump

    def analyze_sequence(
        self,
        record_sequence_number: int,
        si_created: Optional[datetime],
        fn_created: Optional[datetime],
        file_ref: int,
        all_records: List[Any] = None,
    ) -> List[TimestompIndicator]:
        indicators = []

        if not all_records:
            return indicators

        same_ref_records = [
            r
            for r in all_records
            if hasattr(r, "record_number") and r.record_number == file_ref
        ]

        if len(same_ref_records) > 1:
            seq_numbers = [
                r.sequence_number
                for r in same_ref_records
                if hasattr(r, "sequence_number")
            ]
            if len(seq_numbers) >= 2:
                max_seq = max(seq_numbers)
                if max_seq > record_sequence_number + self.threshold_seq_jump:
                    indicators.append(
                        TimestompIndicator(
                            check_number=8,
                            check_name="MFT Record Sequence Analysis",
                            is_suspicious=True,
                            severity="HIGH",
                            confidence=0.75,
                            description=f"Sequence number jumped by {max_seq - record_sequence_number} - suggests delete/recreate cycle",
                            evidence={
                                "current_sequence": record_sequence_number,
                                "max_sequence": max_seq,
                                "jump": max_seq - record_sequence_number,
                            },
                        )
                    )

        if si_created and si_created.year < 2000:
            indicators.append(
                TimestompIndicator(
                    check_number=8,
                    check_name="MFT Record Sequence vs Timestamp",
                    is_suspicious=True,
                    severity="MEDIUM",
                    confidence=0.6,
                    description=f"Old timestamp ({si_created.year}) with potentially new sequence number - possible timestomp",
                    evidence={
                        "timestamp": si_created.isoformat(),
                        "year": si_created.year,
                        "sequence": record_sequence_number,
                    },
                )
            )

        return indicators


class TimestampEntropyAnalyzer:
    """
    Check 9: Timestamp Entropy Analysis

    Natural systems have high entropy. Many files sharing identical
    second-level timestamps across directories suggests automation.
    """

    def __init__(self):
        self.second_timestamps: List[datetime] = []
        self.microsecond_patterns: Dict[int, int] = defaultdict(int)

    def add_timestamp(self, ts: datetime):
        if ts:
            self.second_timestamps.append(ts)
            if ts.microsecond > 0:
                self.microsecond_patterns[ts.microsecond] += 1

    def analyze_entropy(self) -> List[TimestompIndicator]:
        indicators = []

        if len(self.second_timestamps) < 10:
            return indicators

        second_counts = Counter(
            ts.replace(microsecond=0) for ts in self.second_timestamps
        )

        identical_seconds = [
            (ts, count) for ts, count in second_counts.items() if count >= 5
        ]

        if identical_seconds:
            ts, count = max(identical_seconds, key=lambda x: x[1])
            indicators.append(
                TimestompIndicator(
                    check_number=9,
                    check_name="Timestamp Entropy Analysis",
                    is_suspicious=True,
                    severity="HIGH",
                    confidence=0.8,
                    description=f"{count} files share identical timestamp at {ts} - suggests automated/batch modification",
                    evidence={
                        "timestamp": ts.isoformat(),
                        "file_count": count,
                        "total_files_analyzed": len(self.second_timestamps),
                    },
                )
            )

        return indicators


class MicrosecondPatternAnalyzer:
    """
    Check 10: Microsecond/Nanosecond Patterns

    Some timestomp tools zero out lower precision bits or copy
    timestamps exactly, producing unnatural precision patterns.
    """

    def __init__(self):
        self.timestamps: List[datetime] = []

    def add_timestamp(self, ts: datetime):
        if ts:
            self.timestamps.append(ts)

    def analyze_patterns(self) -> List[TimestompIndicator]:
        indicators = []

        if len(self.timestamps) < 5:
            return indicators

        zero_microsecond = sum(1 for ts in self.timestamps if ts.microsecond == 0)
        zero_ratio = zero_microsecond / len(self.timestamps)

        if zero_ratio > 0.9:
            indicators.append(
                TimestompIndicator(
                    check_number=10,
                    check_name="Microsecond Pattern - All Zero",
                    is_suspicious=True,
                    severity="MEDIUM",
                    confidence=0.7,
                    description=f"{zero_ratio * 100:.0f}% of timestamps have zero microseconds - unusual for real filesystem operations",
                    evidence={
                        "zero_microsecond_count": zero_microsecond,
                        "total_count": len(self.timestamps),
                        "zero_ratio": zero_ratio,
                    },
                )
            )

        common_microseconds = Counter(
            ts.microsecond for ts in self.timestamps if ts.microsecond > 0
        )
        if common_microseconds:
            most_common_us, count = common_microseconds.most_common(1)[0]
            if count > len(self.timestamps) * 0.3 and len(self.timestamps) > 10:
                indicators.append(
                    TimestompIndicator(
                        check_number=10,
                        check_name="Microsecond Pattern - Repetitive",
                        is_suspicious=True,
                        severity="HIGH",
                        confidence=0.75,
                        description=f"Microsecond value {most_common_us} appears {count} times ({count / len(self.timestamps) * 100:.1f}%) - suggests timestamp copying",
                        evidence={
                            "common_microsecond": most_common_us,
                            "count": count,
                            "percentage": count / len(self.timestamps) * 100,
                        },
                    )
                )

        return indicators


class ShadowCopyAnalyzer:
    """
    Check 11: Shadow Copy Differential Reconstruction

    CORRECT LOGIC:
    - Only flag HIGH if: ShadowCopyTime > FileCreated AND file NOT in that snapshot
    - File created after VSS activation but not in any snapshot = INFO (VSS may not have snapshotted)
    - File absent from older snapshot = INFO (normal)
    """

    def __init__(self, shadow_copy_data: Dict = None):
        self.shadow_copy_data = shadow_copy_data or {}

    def check_consistency(
        self,
        filename: str,
        file_created: Optional[datetime],
    ) -> List[TimestompIndicator]:
        indicators = []

        if not self.shadow_copy_data or not file_created:
            return indicators

        filename_lower = filename.lower()

        found_in_sc = False
        relevant_sc = None

        for sc_name, sc_data in self.shadow_copy_data.items():
            if not isinstance(sc_data, dict):
                continue

            sc_creation_time = sc_data.get("creation_time")
            if sc_creation_time:
                if isinstance(sc_creation_time, str):
                    sc_creation_time = datetime.fromisoformat(
                        sc_creation_time.replace("Z", "+00:00")
                    )

                if sc_creation_time and sc_creation_time > file_created:
                    relevant_sc = sc_name

                    sc_files = sc_data.get("files", [])
                    for sc_file in sc_files:
                        if (
                            isinstance(sc_file, dict)
                            and sc_file.get("path", "").lower() == filename_lower
                        ):
                            found_in_sc = True
                            break

        if relevant_sc and not found_in_sc:
            indicators.append(
                TimestompIndicator(
                    check_number=11,
                    check_name="VSS Temporal Inconsistency",
                    is_suspicious=True,
                    severity="HIGH",
                    confidence=0.85,
                    description=f"File created on {file_created.date()} but absent from shadow copy {relevant_sc} (created after file)",
                    evidence={
                        "filename": filename,
                        "file_created": file_created.isoformat(),
                        "shadow_copy": relevant_sc,
                        "explanation": "File created after snapshot, then snapshot taken but file not present - highly suspicious",
                    },
                )
            )

        return indicators


class AdvancedAntiForensicDetector:
    """
    Main detector that orchestrates all 11 forensic checks.
    """

    SEVERITY_SCORES = {
        "CRITICAL": 100,
        "HIGH": 75,
        "MEDIUM": 50,
        "LOW": 25,
        "INFO": 0,
    }

    def __init__(
        self,
        usn_records: List[Any] = None,
        logfile_records: List[Any] = None,
        mft_records: List[Any] = None,
        volume_created: Optional[datetime] = None,
        os_install_time: Optional[datetime] = None,
        boot_times: List[datetime] = None,
        event_logs: List[Dict] = None,
        shadow_copy_data: Dict = None,
    ):
        self.drift_analyzer = DriftAnalyzer()
        self.usn_checker = USNTemporalChecker(usn_records)
        self.lsn_checker = LSNMonotonicityChecker(logfile_records)
        self.volume_checker = VolumeCreationChecker(volume_created)
        self.os_install_checker = OSInstallTimeChecker(os_install_time)
        self.boot_checker = BootTimeBoundaryChecker(boot_times)
        self.clock_rollback_detector = ClockRollbackDetector(event_logs)
        self.mft_seq_analyzer = MFTRecordSequenceAnalyzer()
        self.entropy_analyzer = TimestampEntropyAnalyzer()
        self.microsecond_analyzer = MicrosecondPatternAnalyzer()
        self.shadow_copy_analyzer = ShadowCopyAnalyzer(shadow_copy_data)

        self.mft_records = mft_records or []

    def analyze_file(
        self,
        filename: str,
        file_ref: int,
        record_sequence_number: int,
        si_timestamps: Dict[str, Optional[datetime]],
        fn_timestamps: Dict[str, Optional[datetime]],
    ) -> ForensicAnalysisResult:
        result = ForensicAnalysisResult(
            filename=filename,
            file_reference=file_ref,
            record_sequence_number=record_sequence_number,
            si_timestamps={
                k: v.isoformat() if v else None for k, v in si_timestamps.items()
            },
            fn_timestamps={
                k: v.isoformat() if v else None for k, v in fn_timestamps.items()
            },
        )

        si_created = si_timestamps.get("created")
        si_modified = si_timestamps.get("modified")
        fn_created = fn_timestamps.get("created")
        fn_modified = fn_timestamps.get("modified")

        if si_created and fn_created:
            result.si_fn_created_delta = abs((si_created - fn_created).total_seconds())
        if si_modified and fn_modified:
            result.si_fn_modified_delta = abs(
                (si_modified - fn_modified).total_seconds()
            )

        result.indicators.extend(
            self.drift_analyzer.analyze_drift(
                si_created, fn_created, si_modified, fn_modified
            )
        )

        result.indicators.extend(
            self.usn_checker.check_causality(file_ref, si_modified, fn_modified)
        )

        result.indicators.extend(
            self.lsn_checker.check_monotonicity(file_ref, si_timestamps)
        )

        result.indicators.extend(
            self.volume_checker.check_file_against_volume(si_created, fn_created)
        )

        result.indicators.extend(
            self.os_install_checker.check_file_against_os_install(
                filename, si_created, fn_created
            )
        )

        result.indicators.extend(
            self.boot_checker.check_boundary_violations(si_modified, fn_modified)
        )

        result.indicators.extend(
            self.mft_seq_analyzer.analyze_sequence(
                record_sequence_number,
                si_created,
                fn_created,
                file_ref,
                self.mft_records,
            )
        )

        for ts in [si_created, si_modified, fn_created, fn_modified]:
            self.entropy_analyzer.add_timestamp(ts)
            self.microsecond_analyzer.add_timestamp(ts)

        result.indicators.extend(
            self.shadow_copy_analyzer.check_consistency(filename, si_created)
        )

        self._calculate_overall_score(result)

        return result

    def _calculate_overall_score(self, result: ForensicAnalysisResult):
        if not result.indicators:
            result.overall_score = 0
            result.overall_severity = "INFO"
            result.is_timestomped = False
            return

        weighted_score = 0
        max_possible = 0

        for indicator in result.indicators:
            weight = 1.0
            if indicator.check_number == 1:
                weight = 1.2
            elif indicator.check_number in [2, 4, 5]:
                weight = 1.5
            elif indicator.check_number == 7:
                weight = 1.3

            severity_score = self.SEVERITY_SCORES.get(indicator.severity, 0)
            weighted_score += severity_score * indicator.confidence * weight
            max_possible += 100 * weight

        result.overall_score = (
            min(100, weighted_score / max_possible * 100) if max_possible > 0 else 0
        )

        critical_count = sum(1 for i in result.indicators if i.severity == "CRITICAL")
        high_count = sum(1 for i in result.indicators if i.severity == "HIGH")

        if critical_count > 0 or result.overall_score > 75:
            result.overall_severity = "CRITICAL"
            result.is_timestomped = True
        elif high_count > 0 or result.overall_score > 50:
            result.overall_severity = "HIGH"
            result.is_timestomped = True
        elif result.overall_score > 25:
            result.overall_severity = "MEDIUM"
            result.is_timestomped = False
        else:
            result.overall_severity = "INFO"
            result.is_timestomped = False

    def analyze_batch_patterns(self) -> List[TimestompIndicator]:
        indicators = []

        indicators.extend(self.drift_analyzer.detect_batch_patterns())
        indicators.extend(self.entropy_analyzer.analyze_entropy())
        indicators.extend(self.microsecond_analyzer.analyze_patterns())

        return indicators

    def detect_clock_rollbacks(self) -> List[TimestompIndicator]:
        return self.clock_rollback_detector.detect_rollbacks()


def create_detector_from_parsers(
    mft_parser: Any = None,
    usn_parser: Any = None,
    logfile_parser: Any = None,
    volume_created: Optional[datetime] = None,
    os_install_time: Optional[datetime] = None,
    boot_times: List[datetime] = None,
    event_logs: List[Dict] = None,
    shadow_copy_data: Dict = None,
) -> AdvancedAntiForensicDetector:
    """Factory function to create detector from parser objects"""

    usn_records = usn_parser.get_records() if usn_parser else None
    logfile_records = logfile_parser.get_records() if logfile_parser else None
    mft_records = mft_parser.get_file_records() if mft_parser else None

    return AdvancedAntiForensicDetector(
        usn_records=usn_records,
        logfile_records=logfile_records,
        mft_records=mft_records,
        volume_created=volume_created,
        os_install_time=os_install_time,
        boot_times=boot_times,
        event_logs=event_logs,
        shadow_copy_data=shadow_copy_data,
    )


if __name__ == "__main__":
    print("Advanced Anti-Forensic Timestamp Manipulation Detector")
    print("=" * 60)
    print("This module implements 11 forensic checks for detecting timestomping.")
    print("Import and use AdvancedAntiForensicDetector class for analysis.")
