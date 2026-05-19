#!/usr/bin/env python3
"""
Advanced Anti-Forensic Detection Engine v2

New forensic detection techniques:
1. $LogFile LSN Ordering Analysis
2. Sequence Number Consistency Check
3. Volume-Wide Timestamp Distribution Analysis
4. Time-Change Event Detection
5. Sub-Second Precision Entropy
6. Cross-Artifact Temporal Voting
7. Journal Integrity Checks

Author: Cyber Chakshu SIEM Team
"""

import struct
import os
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import math


@dataclass
class ForensicIndicator:
    """Single forensic indicator with evidence"""

    check_id: str
    check_name: str
    is_suspicious: bool
    severity: str
    confidence: float
    description: str
    evidence: Dict[str, Any]
    votes: int = 1


@dataclass
class FileAnalysis:
    """Complete file analysis with multi-layer voting"""

    filename: str
    file_reference: int
    record_sequence_number: int

    si_timestamps: Dict[str, Optional[datetime]] = field(default_factory=dict)
    fn_timestamps: Dict[str, Optional[datetime]] = field(default_factory=dict)

    indicators: List[ForensicIndicator] = field(default_factory=list)

    mft_order_vote: str = "CONSISTENT"
    usn_vote: str = "CONSISTENT"
    logfile_vote: str = "CONSISTENT"
    vss_vote: str = "CONSISTENT"
    volume_vote: str = "CONSISTENT"
    install_vote: str = "CONSISTENT"

    total_votes_contradicting: int = 0

    si_fn_created_delta: float = 0.0
    si_fn_modified_delta: float = 0.0

    overall_score: float = 0.0
    overall_severity: str = "INFO"
    is_timestomped: bool = False


class LogFileLSNAnalyzer:
    """
    1. $LogFile LSN Ordering Analysis

    $LogFile contains transactional history.
    Extract LSN, Affected File Reference, Operation timestamps.
    If Transaction LSN indicates later change but file Modified predates that LSN = causality fracture.
    """

    def __init__(self, logfile_records: List[Any] = None):
        self.logfile_records = logfile_records or []
        self.file_ref_to_lsns: Dict[int, List[Tuple[int, datetime, str]]] = defaultdict(
            list
        )
        self._index_by_file()

    def _index_by_file(self):
        for record in self.logfile_records:
            if hasattr(record, "file_reference") and record.file_reference:
                file_ref = record.file_reference & 0xFFFFFFFFFFFF
                if hasattr(record, "timestamp") and record.timestamp:
                    self.file_ref_to_lsns[file_ref].append(
                        (
                            record.lsn,
                            record.timestamp,
                            getattr(record, "operation_type", "Unknown"),
                        )
                    )

    def analyze_lsn_ordering(
        self,
        file_ref: int,
        si_modified: Optional[datetime],
        fn_modified: Optional[datetime],
    ) -> List[ForensicIndicator]:
        indicators = []

        if file_ref not in self.file_ref_to_lsns:
            return indicators

        lsn_events = self.file_ref_to_lsns[file_ref]
        if not lsn_events:
            return indicators

        sorted_lsns = sorted(lsn_events, key=lambda x: x[0])

        for i in range(1, len(sorted_lsns)):
            prev_lsn, prev_ts, prev_op = sorted_lsns[i - 1]
            curr_lsn, curr_ts, curr_op = sorted_lsns[i]

            if prev_ts and curr_ts and curr_ts < prev_ts:
                indicators.append(
                    ForensicIndicator(
                        check_id="lsn_order",
                        check_name="$LogFile LSN Ordering",
                        is_suspicious=True,
                        severity="HIGH",
                        confidence=0.85,
                        description=f"Non-monotonic LSN: operation at {curr_ts} has earlier timestamp than earlier LSN",
                        evidence={
                            "prev_lsn": prev_lsn,
                            "prev_timestamp": prev_ts.isoformat(),
                            "prev_operation": prev_op,
                            "curr_lsn": curr_lsn,
                            "curr_timestamp": curr_ts.isoformat(),
                            "curr_operation": curr_op,
                        },
                        votes=1,
                    )
                )

        if si_modified and sorted_lsns:
            first_lsn_ts = sorted_lsns[0][1]
            if first_lsn_ts and si_modified < first_lsn_ts:
                diff_days = (first_lsn_ts - si_modified).total_seconds() / 86400
                if diff_days > 1:
                    indicators.append(
                        ForensicIndicator(
                            check_id="lsn_file_mismatch",
                            check_name="$LogFile vs File Timestamp",
                            is_suspicious=True,
                            severity="HIGH",
                            confidence=0.8,
                            description=f"SI Modified ({si_modified}) is {diff_days:.1f} days BEFORE first $LogFile activity",
                            evidence={
                                "si_modified": si_modified.isoformat(),
                                "first_lsn_timestamp": first_lsn_ts.isoformat(),
                                "difference_days": diff_days,
                            },
                            votes=1,
                        )
                    )

        return indicators


class SequenceNumberAnalyzer:
    """
    2. Sequence Number Consistency Check

    Each MFT record has Sequence Number.
    If Sequence number incremented (file deleted/recreated) but Created timestamp appears very old
    = delete → recreate → timestomp.
    """

    def __init__(self, threshold_seq_jump: int = 5):
        self.threshold_seq_jump = threshold_seq_jump

    def analyze_sequence(
        self,
        record_sequence_number: int,
        si_created: Optional[datetime],
        fn_created: Optional[datetime],
        file_ref: int,
        volume_created: Optional[datetime] = None,
    ) -> List[ForensicIndicator]:
        indicators = []

        if si_created and si_created.year < 2000:
            indicators.append(
                ForensicIndicator(
                    check_id="old_timestamp_new_seq",
                    check_name="Sequence Number vs Timestamp",
                    is_suspicious=True,
                    severity="MEDIUM",
                    confidence=0.6,
                    description=f"Created timestamp {si_created.year} is very old with sequence {record_sequence_number}",
                    evidence={
                        "sequence_number": record_sequence_number,
                        "created_year": si_created.year,
                        "created": si_created.isoformat(),
                    },
                    votes=1,
                )
            )

        if volume_created and si_created:
            if si_created < volume_created:
                diff_years = (volume_created - si_created).days / 365
                if diff_years > 1:
                    indicators.append(
                        ForensicIndicator(
                            check_id="seq_vs_volume",
                            check_name="Sequence Number vs Volume Creation",
                            is_suspicious=True,
                            severity="HIGH",
                            confidence=0.75,
                            description=f"File created {diff_years:.1f} years BEFORE volume - possible delete/recreate",
                            evidence={
                                "sequence_number": record_sequence_number,
                                "file_created": si_created.isoformat(),
                                "volume_created": volume_created.isoformat(),
                                "difference_years": diff_years,
                            },
                            votes=1,
                        )
                    )

        return indicators


class TimestampDistributionAnalyzer:
    """
    3. Volume-Wide Timestamp Distribution Analysis

    Statistical layer: histogram of Created/Modified times, clustering detection, Z-score anomaly.
    If 80% of files created on one exact minute → deployment event.
    """

    def __init__(self):
        self.created_times: List[datetime] = []
        self.modified_times: List[datetime] = []
        self.created_minute_counts: Dict[Tuple[int, int, int, int, int], int] = (
            Counter()
        )
        self.modified_minute_counts: Dict[Tuple[int, int, int, int, int], int] = (
            Counter()
        )

    def add_file(self, si_created: Optional[datetime], si_modified: Optional[datetime]):
        if si_created:
            self.created_times.append(si_created)
            minute_key = (
                si_created.year,
                si_created.month,
                si_created.day,
                si_created.hour,
                si_created.minute,
            )
            self.created_minute_counts[minute_key] += 1

        if si_modified:
            self.modified_times.append(si_modified)
            minute_key = (
                si_modified.year,
                si_modified.month,
                si_modified.day,
                si_modified.hour,
                si_modified.minute,
            )
            self.modified_minute_counts[minute_key] += 1

    def analyze_distribution(self) -> List[ForensicIndicator]:
        indicators = []

        if len(self.created_times) < 50:
            return indicators

        if self.created_minute_counts:
            max_minute_count = max(self.created_minute_counts.values())
            total_files = len(self.created_times)
            cluster_ratio = max_minute_count / total_files

            if cluster_ratio > 0.5:
                most_common_minute = max(
                    self.created_minute_counts.items(), key=lambda x: x[1]
                )
                indicators.append(
                    ForensicIndicator(
                        check_id="created_cluster",
                        check_name="Timestamp Clustering Detection",
                        is_suspicious=True,
                        severity="HIGH" if cluster_ratio > 0.8 else "MEDIUM",
                        confidence=0.85,
                        description=f"{cluster_ratio * 100:.1f}% of files created at same minute - suggests batch/deployment event",
                        evidence={
                            "cluster_minute": f"{most_common_minute[0][0]}-{most_common_minute[0][1]:02d}-{most_common_minute[0][2]:02d} {most_common_minute[0][3]:02d}:{most_common_minute[0][4]:02d}",
                            "file_count_in_cluster": most_common_minute[1],
                            "total_files": total_files,
                            "cluster_ratio": cluster_ratio,
                        },
                        votes=2 if cluster_ratio > 0.8 else 1,
                    )
                )

        years = [t.year for t in self.created_times if t]
        if years:
            year_counts = Counter(years)
            most_common_year = year_counts.most_common(1)[0]
            if most_common_year[1] / len(years) > 0.9:
                indicators.append(
                    ForensicIndicator(
                        check_id="year_cluster",
                        check_name="Year Clustering",
                        is_suspicious=True,
                        severity="MEDIUM",
                        confidence=0.7,
                        description=f"{most_common_year[1] / len(years) * 100:.0f}% of files from year {most_common_year[0]}",
                        evidence={
                            "year": most_common_year[0],
                            "count": most_common_year[1],
                            "total": len(years),
                        },
                        votes=1,
                    )
                )

        return indicators

    def find_zscore_outliers(self) -> List[Tuple[str, datetime, float]]:
        outliers = []

        for ts in self.created_times:
            if not ts:
                continue
            ts_value = ts.timestamp()
            mean = sum(t.timestamp() for t in self.created_times if t) / len(
                self.created_times
            )
            std = math.sqrt(
                sum((t.timestamp() - mean) ** 2 for t in self.created_times if t)
                / len(self.created_times)
            )

            if std > 0:
                zscore = abs(ts_value - mean) / std
                if zscore > 3:
                    outliers.append(("created", ts, zscore))

        return outliers


class TimeChangeDetector:
    """
    4. Time-Change Event Detection

    Search event logs for: System time changes, NTP adjustments, Clock rollback.
    Then correlate: Files modified during backward jump window.
    """

    def __init__(self, event_logs: List[Dict] = None):
        self.event_logs = event_logs or []
        self.time_changes: List[Dict] = []

    def detect_time_changes(self) -> List[ForensicIndicator]:
        indicators = []

        time_change_event_ids = {4616, 1, 4624}

        for event in self.event_logs:
            event_id = event.get("event_id")
            if event_id in time_change_event_ids:
                self.time_changes.append(event)

        if len(self.time_changes) > 0:
            indicators.append(
                ForensicIndicator(
                    check_id="time_change_events",
                    check_name="Time Change Event Detection",
                    is_suspicious=True,
                    severity="HIGH",
                    confidence=0.8,
                    description=f"Found {len(self.time_changes)} system time change events",
                    evidence={
                        "event_count": len(self.time_changes),
                        "event_ids": list(
                            set(e.get("event_id") for e in self.time_changes)
                        ),
                        "events": self.time_changes[:5],
                    },
                    votes=2,
                )
            )

        sorted_events = sorted(
            [e for e in self.event_logs if e.get("timestamp")],
            key=lambda x: x["timestamp"],
        )

        for i in range(1, len(sorted_events)):
            prev_ts = self._parse_ts(sorted_events[i - 1].get("timestamp"))
            curr_ts = self._parse_ts(sorted_events[i].get("timestamp"))

            if prev_ts and curr_ts and curr_ts < prev_ts:
                diff_seconds = (prev_ts - curr_ts).total_seconds()
                indicators.append(
                    ForensicIndicator(
                        check_id="clock_rollback",
                        check_name="Clock Rollback Detection",
                        is_suspicious=True,
                        severity="CRITICAL",
                        confidence=0.9,
                        description=f"Event log ordering shows rollback of {diff_seconds / 3600:.1f} hours",
                        evidence={
                            "rollback_seconds": diff_seconds,
                            "prev_timestamp": prev_ts.isoformat(),
                            "curr_timestamp": curr_ts.isoformat(),
                        },
                        votes=3,
                    )
                )
                break

        return indicators

    def _parse_ts(self, ts) -> Optional[datetime]:
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except:
                pass
        return None


class SubSecondPrecisionAnalyzer:
    """
    5. Sub-Second Precision Entropy

    Check nanoseconds. Natural writes show irregular fractional components.
    Many timestomp tools: Zero microseconds, Copy identical precision bits, Use uniform timestamp granularity.
    Machines are messy. Attack scripts are neat.
    """

    def __init__(self):
        self.microsecond_counts: Counter = Counter()
        self.nanosecond_patterns: Counter = Counter()
        self.total_timestamps: int = 0

    def add_timestamp(self, ts: Optional[datetime]):
        if not ts:
            return

        self.total_timestamps += 1

        if ts.microsecond == 0:
            self.microsecond_counts["zero"] += 1
        else:
            self.microsecond_counts[ts.microsecond] += 1

            us_bin = (ts.microsecond // 1000) * 1000
            self.nanosecond_patterns[us_bin] += 1

    def analyze_precision(self) -> List[ForensicIndicator]:
        indicators = []

        if self.total_timestamps < 20:
            return indicators

        zero_count = self.microsecond_counts.get("zero", 0)
        zero_ratio = zero_count / self.total_timestamps

        if zero_ratio > 0.95:
            indicators.append(
                ForensicIndicator(
                    check_id="all_zero_microseconds",
                    check_name="Sub-Second Precision - All Zero",
                    is_suspicious=True,
                    severity="MEDIUM",
                    confidence=0.75,
                    description=f"{zero_ratio * 100:.0f}% timestamps have zero microseconds - unusual",
                    evidence={
                        "zero_count": zero_count,
                        "total": self.total_timestamps,
                        "zero_ratio": zero_ratio,
                    },
                    votes=1,
                )
            )
        elif zero_ratio > 0.8:
            indicators.append(
                ForensicIndicator(
                    check_id="mostly_zero_microseconds",
                    check_name="Sub-Second Precision - Mostly Zero",
                    is_suspicious=True,
                    severity="LOW",
                    confidence=0.5,
                    description=f"{zero_ratio * 100:.0f}% timestamps have zero microseconds",
                    evidence={
                        "zero_count": zero_count,
                        "total": self.total_timestamps,
                        "zero_ratio": zero_ratio,
                    },
                    votes=1,
                )
            )

        if len(self.microsecond_counts) > 1:
            most_common_us = self.microsecond_counts.most_common(1)[0]
            if most_common_us[0] != "zero":
                common_ratio = most_common_us[1] / self.total_timestamps
                if common_ratio > 0.4:
                    indicators.append(
                        ForensicIndicator(
                            check_id="repetitive_microseconds",
                            check_name="Sub-Second Precision - Repetitive",
                            is_suspicious=True,
                            severity="HIGH",
                            confidence=0.8,
                            description=f"Microsecond value {most_common_us[0]} appears {common_ratio * 100:.1f}% - suggests copying",
                            evidence={
                                "common_microsecond": most_common_us[0],
                                "count": most_common_us[1],
                                "ratio": common_ratio,
                            },
                            votes=2,
                        )
                    )

        return indicators


class CrossArtifactVotingEngine:
    """
    6. Cross-Artifact Temporal Voting

    Build consensus scoring instead of rule scoring.
    Votes from: MFT order, USN, LogFile, Shadow copy, Volume boundary, Install boundary
    If 3+ independent layers contradict file timestamp → escalate.
    If only 1 layer contradicts → keep HIGH but not CRITICAL.
    """

    def __init__(self):
        self.VOTE_WEIGHTS = {
            "CRITICAL_CONTRADICTION": 3,
            "HIGH_CONTRADICTION": 2,
            "MEDIUM_CONTRADICTION": 1,
            "CONSISTENT": 0,
        }

    def vote(
        self,
        file_analysis: FileAnalysis,
        volume_created: Optional[datetime] = None,
        os_install_time: Optional[datetime] = None,
        has_usn_contradiction: bool = False,
        has_logfile_contradiction: bool = False,
    ) -> FileAnalysis:
        total_votes = 0

        if file_analysis.mft_order_vote == "CRITICAL_CONTRADICTION":
            total_votes += 3
        elif file_analysis.mft_order_vote == "HIGH_CONTRADICTION":
            total_votes += 2
        elif file_analysis.mft_order_vote == "MEDIUM_CONTRADICTION":
            total_votes += 1

        if has_usn_contradiction:
            total_votes += 2

        if has_logfile_contradiction:
            total_votes += 2

        if volume_created:
            si_created = file_analysis.si_timestamps.get("created")
            if si_created and si_created < volume_created:
                total_votes += 2
                file_analysis.volume_vote = "HIGH_CONTRADICTION"

        if os_install_time:
            si_created = file_analysis.si_timestamps.get("created")
            if si_created and si_created < os_install_time:
                total_votes += 2
                file_analysis.install_vote = "HIGH_CONTRADICTION"

        file_analysis.total_votes_contradicting = total_votes

        if total_votes >= 6:
            file_analysis.overall_severity = "CRITICAL"
            file_analysis.is_timestomped = True
            file_analysis.overall_score = 100
        elif total_votes >= 4:
            file_analysis.overall_severity = "HIGH"
            file_analysis.is_timestomped = True
            file_analysis.overall_score = 75
        elif total_votes >= 2:
            file_analysis.overall_severity = "MEDIUM"
            file_analysis.is_timestomped = False
            file_analysis.overall_score = 50
        else:
            file_analysis.overall_severity = "INFO"
            file_analysis.is_timestomped = False
            file_analysis.overall_score = 10

        return file_analysis


class JournalIntegrityChecker:
    """
    7. Journal Integrity Checks

    If:
    - USN journal abruptly starts at recent time
    - $LogFile unusually small
    - Shadow copies missing unexpectedly

    That suggests anti-forensic wiping.
    Absence of history can be history.
    """

    def __init__(
        self,
        usn_records: List[Any] = None,
        logfile_records: List[Any] = None,
        shadow_copy_count: int = 0,
    ):
        self.usn_records = usn_records or []
        self.logfile_records = logfile_records or []
        self.shadow_copy_count = shadow_copy_count

    def check_integrity(self) -> List[ForensicIndicator]:
        indicators = []

        if self.usn_records:
            usn_timestamps = [
                r.timestamp
                for r in self.usn_records
                if hasattr(r, "timestamp") and r.timestamp
            ]
            if usn_timestamps:
                earliest_usn = min(usn_timestamps)
                latest_usn = max(usn_timestamps)
                timespan = (latest_usn - earliest_usn).days

                if timespan < 7 and len(self.usn_records) > 100:
                    indicators.append(
                        ForensicIndicator(
                            check_id="usn_recent_start",
                            check_name="USN Journal Recent Start",
                            is_suspicious=True,
                            severity="MEDIUM",
                            confidence=0.6,
                            description=f"USN journal spans only {timespan} days - may have been cleared",
                            evidence={
                                "earliest_usn": earliest_usn.isoformat(),
                                "latest_usn": latest_usn.isoformat(),
                                "timespan_days": timespan,
                                "record_count": len(self.usn_records),
                            },
                            votes=1,
                        )
                    )

        if self.logfile_records:
            lsn_values = [
                r.lsn for r in self.logfile_records if hasattr(r, "lsn") and r.lsn
            ]
            if lsn_values:
                max_lsn = max(lsn_values)
                if max_lsn < 1000000 and len(self.logfile_records) < 100:
                    indicators.append(
                        ForensicIndicator(
                            check_id="logfile_small",
                            check_name="$LogFile Unusually Small",
                            is_suspicious=True,
                            severity="HIGH",
                            confidence=0.7,
                            description=f"$LogFile has only {len(self.logfile_records)} records - may have been wiped",
                            evidence={
                                "record_count": len(self.logfile_records),
                                "max_lsn": max_lsn,
                            },
                            votes=2,
                        )
                    )

        if self.shadow_copy_count == 0:
            indicators.append(
                ForensicIndicator(
                    check_id="no_shadow_copies",
                    check_name="No Shadow Copies Found",
                    is_suspicious=True,
                    severity="LOW",
                    confidence=0.4,
                    description="No shadow copies found - could indicate VSS disabled or wiped",
                    evidence={
                        "shadow_copy_count": 0,
                    },
                    votes=1,
                )
            )

        return indicators


class AdvancedForensicDetectorV2:
    """
    Main detector orchestrating all 7 new forensic checks
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
        mft_records: List[Any] = None,
        usn_records: List[Any] = None,
        logfile_records: List[Any] = None,
        event_logs: List[Dict] = None,
        volume_created: Optional[datetime] = None,
        os_install_time: Optional[datetime] = None,
        boot_times: List[datetime] = None,
        shadow_copy_count: int = 0,
    ):
        self.mft_records = mft_records or []
        self.usn_records = usn_records or []
        self.logfile_records = logfile_records or []
        self.event_logs = event_logs or []
        self.volume_created = volume_created
        self.os_install_time = os_install_time
        self.boot_times = boot_times or []
        self.shadow_copy_count = shadow_copy_count

        self.lsn_analyzer = LogFileLSNAnalyzer(logfile_records)
        self.seq_analyzer = SequenceNumberAnalyzer()
        self.dist_analyzer = TimestampDistributionAnalyzer()
        self.time_change_detector = TimeChangeDetector(event_logs)
        self.precision_analyzer = SubSecondPrecisionAnalyzer()
        self.voting_engine = CrossArtifactVotingEngine()
        self.integrity_checker = JournalIntegrityChecker(
            usn_records, logfile_records, shadow_copy_count
        )

    def analyze_file(
        self,
        filename: str,
        file_ref: int,
        record_sequence_number: int,
        si_timestamps: Dict[str, Optional[datetime]],
        fn_timestamps: Dict[str, Optional[datetime]],
    ) -> FileAnalysis:
        analysis = FileAnalysis(
            filename=filename,
            file_reference=file_ref,
            record_sequence_number=record_sequence_number,
            si_timestamps=si_timestamps,
            fn_timestamps=fn_timestamps,
        )

        si_created = si_timestamps.get("created")
        si_modified = si_timestamps.get("modified")
        fn_created = fn_timestamps.get("created")
        fn_modified = fn_timestamps.get("modified")

        if si_created and fn_created:
            analysis.si_fn_created_delta = abs(
                (si_created - fn_created).total_seconds()
            )
        if si_modified and fn_modified:
            analysis.si_fn_modified_delta = abs(
                (si_modified - fn_modified).total_seconds()
            )

        analysis.indicators.extend(
            self.lsn_analyzer.analyze_lsn_ordering(file_ref, si_modified, fn_modified)
        )

        analysis.indicators.extend(
            self.seq_analyzer.analyze_sequence(
                record_sequence_number,
                si_created,
                fn_created,
                file_ref,
                self.volume_created,
            )
        )

        self.dist_analyzer.add_file(si_created, si_modified)
        self.precision_analyzer.add_timestamp(si_created)
        self.precision_analyzer.add_timestamp(si_modified)

        has_usn_contradiction = any(
            "usn" in ind.check_id.lower() for ind in analysis.indicators
        )
        has_logfile_contradiction = any(
            "lsn" in ind.check_id.lower() for ind in analysis.indicators
        )

        analysis = self.voting_engine.vote(
            analysis,
            self.volume_created,
            self.os_install_time,
            has_usn_contradiction,
            has_logfile_contradiction,
        )

        return analysis

    def analyze_volume_distribution(self) -> List[ForensicIndicator]:
        indicators = []
        indicators.extend(self.dist_analyzer.analyze_distribution())
        indicators.extend(self.precision_analyzer.analyze_precision())
        indicators.extend(self.time_change_detector.detect_time_changes())
        indicators.extend(self.integrity_checker.check_integrity())
        return indicators


def create_detector_v2(
    mft_parser: Any = None,
    usn_parser: Any = None,
    logfile_parser: Any = None,
    event_logs: List[Dict] = None,
    volume_created: Optional[datetime] = None,
    os_install_time: Optional[datetime] = None,
    boot_times: List[datetime] = None,
    shadow_copy_count: int = 0,
) -> AdvancedForensicDetectorV2:
    """Factory function to create detector from parser objects"""

    mft_records = mft_parser.get_file_records() if mft_parser else None
    usn_records = usn_parser.get_records() if usn_parser else None
    logfile_records = logfile_parser.get_records() if logfile_parser else None

    return AdvancedForensicDetectorV2(
        mft_records=mft_records,
        usn_records=usn_records,
        logfile_records=logfile_records,
        event_logs=event_logs,
        volume_created=volume_created,
        os_install_time=os_install_time,
        boot_times=boot_times,
        shadow_copy_count=shadow_copy_count,
    )


if __name__ == "__main__":
    print("Advanced Forensic Detector v2 - 7 New Detection Techniques")
    print("=" * 60)
    print("""
1. $LogFile LSN Ordering Analysis
2. Sequence Number Consistency Check
3. Volume-Wide Timestamp Distribution Analysis  
4. Time-Change Event Detection
5. Sub-Second Precision Entropy
6. Cross-Artifact Temporal Voting
7. Journal Integrity Checks
    """)
