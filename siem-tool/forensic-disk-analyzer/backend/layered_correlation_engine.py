#!/usr/bin/env python3
"""
Layered Correlation Engine for NTFS Timestomp Detection

Implements the 5-layer detection model:
- Layer 1: MFT Internal ($SI vs $FN comparison) [Weight: 30%]
- Layer 2: USN Journal (Creation Event) [Weight: 30%]
- Layer 3: $LogFile (Transaction History) [Weight: 20%]
- Layer 4: External Artifacts [Weight: 20%]
- Layer 5: Windows Event Logs (Security/System correlation) [Weight: 15%]

Provides graduated risk scoring (0-100) instead of binary detection.

Author: Cyber Chakshu SIEM Team
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from concurrent.futures import ProcessPoolExecutor, as_completed

from ntfs_forensics.mft_parser import MFTParser, MFTRecord, SIAttribute, FNAttribute
from ntfs_forensics.usn_parser import USNJournalParser, USNRecord
from ntfs_forensics.logfile_parser import LogFileParser, TransactionRecord
from ntfs_forensics.volume_parser import VolumeInfoParser
from ntfs_forensics.mft_parser import MFTParser, MFTRecord, SIAttribute, FNAttribute


LAYER_WEIGHTS = {
    "si_fn_mismatch": 30.0,
    "usn_mismatch": 30.0,
    "logfile_mismatch": 20.0,
    "external_artifacts": 20.0,
    "event_logs": 15.0,
}


SEVERITY_SCORES = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "INFO": 0,
}


@dataclass
class Layer1Result:
    """Layer 1: SI vs FN timestamp comparison"""

    file_reference: int
    filename: str
    si_created: Optional[datetime]
    fn_created: Optional[datetime]
    si_modified: Optional[datetime]
    fn_modified: Optional[datetime]
    si_accessed: Optional[datetime]
    fn_accessed: Optional[datetime]
    si_mft_modified: Optional[datetime]
    fn_mft_modified: Optional[datetime]

    created_diff_seconds: float = 0.0
    modified_diff_seconds: float = 0.0
    accessed_diff_seconds: float = 0.0
    mft_modified_diff_seconds: float = 0.0

    anomalies: List[str] = field(default_factory=list)
    severity: str = "INFO"
    score: float = 0.0


@dataclass
class Layer2Result:
    """Layer 2: USN Journal comparison"""

    file_reference: int
    filename: str

    usn_first_create: Optional[datetime] = None
    usn_total_events: int = 0

    si_created_vs_usn_diff_seconds: float = 0.0
    fn_created_vs_usn_diff_seconds: float = 0.0

    usn_missing: bool = False
    anomalies: List[str] = field(default_factory=list)
    severity: str = "INFO"
    score: float = 0.0


@dataclass
class Layer3Result:
    """Layer 3: $LogFile analysis"""

    file_reference: int

    logfile_records: int = 0
    earliest_activity: Optional[datetime] = None
    latest_activity: Optional[datetime] = None

    si_created_vs_logfile_diff_seconds: float = 0.0

    logfile_missing: bool = False
    anomalies: List[str] = field(default_factory=list)
    severity: str = "INFO"
    score: float = 0.0


@dataclass
class Layer4Result:
    """Layer 4: External artifacts"""

    file_reference: int
    filename: str

    shadow_copies_exist: bool = False
    prefetch_exists: bool = False
    amcache_exists: bool = False

    volume_creation: Optional[datetime] = None
    file_vs_volume_diff_seconds: float = 0.0

    anomalies: List[str] = field(default_factory=list)
    severity: str = "INFO"
    score: float = 0.0


FILE_OPERATION_EVENT_IDS = {
    4656: "ObjectHandle",
    4658: "ObjectHandleClosed",
    4659: "ObjectHandleDeleted",
    4660: "ObjectDeleted",
    4661: "ObjectHandleQueried",
    4663: "ObjectAccessed",
    4664: "FileSystemCryptOperation",
    4665: "AttemptMadeToAudit",
    4666: "AttemptMadeToStart",
    4670: "ObjectPermissionsChanged",
    4688: "ProcessCreated",
    4689: "ProcessExited",
    4696: "PrimaryTokenDuplicated",
    4697: "ServiceInstalled",
    4698: "ScheduledTaskCreated",
    4699: "ScheduledTaskUpdated",
    4700: "ScheduledTaskDeleted",
    4701: "TaskTriggerEnabled",
    4702: "ScheduledTaskUpdated",
    4706: "TrustedAppDomain",
    4719: "SystemAuditPolicyChanged",
    4720: "UserAccountCreated",
    4722: "UserAccountEnabled",
    4723: "PasswordChangeAttempt",
    4724: "PasswordChangeAttempt",
    4725: "UserAccountDisabled",
    4726: "UserAccountDeleted",
    4732: "MemberAddedToSecurityLocal",
    4733: "MemberRemovedFromSecurityLocal",
    4738: "UserAccountChanged",
    4756: "MemberAddedToUniversal",
    4767: "AccountUnlocked",
    4768: "KerberosTGTRequested",
    4769: "KerberosServiceTicketRequested",
    4776: "CredentialValidated",
    5140: "NetworkShareObjectAccessed",
    5141: "NetworkShareObjectDeleted",
    5145: "NetworkShareObjectChecked",
    5156: "FilterPlatformConnection",
    5168: "FullTextIndexUpdated",
}


@dataclass
class Layer5Result:
    """Layer 5: Windows Event Logs correlation"""

    file_reference: int
    filename: str

    latest_security_event: Optional[datetime] = None
    earliest_security_event: Optional[datetime] = None
    latest_system_event: Optional[datetime] = None
    earliest_system_event: Optional[datetime] = None

    file_specific_events: List[Dict[str, Any]] = field(default_factory=list)
    file_object_events: List[Dict[str, Any]] = field(default_factory=list)
    process_events: List[Dict[str, Any]] = field(default_factory=list)
    scheduled_task_events: List[Dict[str, Any]] = field(default_factory=list)
    service_events: List[Dict[str, Any]] = field(default_factory=list)

    file_vs_latest_security_diff_seconds: float = 0.0
    file_vs_earliest_security_diff_seconds: float = 0.0

    anomalies: List[str] = field(default_factory=list)
    severity: str = "INFO"
    score: float = 0.0


@dataclass
class TimestompFinding:
    """Final combined finding with layered scoring"""

    file_reference: int
    filename: str

    layer1: Optional[Layer1Result] = None
    layer2: Optional[Layer2Result] = None
    layer3: Optional[Layer3Result] = None
    layer4: Optional[Layer4Result] = None
    layer5: Optional[Layer5Result] = None

    total_score: float = 0.0
    is_suspicious: bool = False
    severity: str = "INFO"

    confidence: float = 0.0
    explanation: str = ""
    recommendation: str = ""

    matching_layers: List[str] = field(default_factory=list)
    conflicting_layers: List[str] = field(default_factory=list)


class LayeredCorrelationEngine:
    """
    Implements the layered correlation model for timestomp detection.

    Instead of single timestamp comparison, uses weighted scoring across multiple
    NTFS layers to detect timestamp manipulation.
    """

    def __init__(self, output_dir: str, partition_num: int = 0):
        self.output_dir = Path(output_dir)
        self.partition_num = partition_num

        self.mft_parser: Optional[MFTParser] = None
        self.usn_parser: Optional[USNJournalParser] = None
        self.logfile_parser: Optional[LogFileParser] = None
        self.volume_parser: Optional[VolumeInfoParser] = None

        self.security_events: List[Dict[str, Any]] = []
        self.system_events: List[Dict[str, Any]] = []
        self.latest_security_timestamp: Optional[datetime] = None
        self.earliest_security_timestamp: Optional[datetime] = None
        self.latest_system_timestamp: Optional[datetime] = None
        self.earliest_system_timestamp: Optional[datetime] = None

        self.event_index_by_file: Dict[str, List[Dict[str, Any]]] = {}
        self.events_by_id: Dict[int, List[Dict[str, Any]]] = {}

        self.findings: List[TimestompFinding] = []
        self.file_ref_to_name: Dict[int, str] = {}
        self.file_ref_to_mft_record: Dict[int, MFTRecord] = {}

        self._load_parsers()
        self._load_event_logs()

    def _load_parsers(self):
        """Load all binary parsers with extracted data"""
        raw_mft_file = self.output_dir / f"raw_mft_partition_{self.partition_num}.bin"
        raw_usn_file = (
            self.output_dir / f"raw_usn_journal_partition_{self.partition_num}.bin"
        )
        raw_logfile_file = (
            self.output_dir / f"raw_logfile_partition_{self.partition_num}.bin"
        )
        raw_volume_file = (
            self.output_dir / f"raw_volume_partition_{self.partition_num}.bin"
        )
        raw_boot_file = self.output_dir / f"raw_boot_partition_{self.partition_num}.bin"

        if raw_mft_file.exists():
            with open(raw_mft_file, "rb") as f:
                self.mft_parser = MFTParser(f.read())
                for record in self.mft_parser.records:
                    self.file_ref_to_name[record.record_number] = (
                        record.filename_primary
                    )
                    self.file_ref_to_mft_record[record.record_number] = record

        if raw_usn_file.exists():
            with open(raw_usn_file, "rb") as f:
                self.usn_parser = USNJournalParser(f.read())

        if raw_logfile_file.exists():
            with open(raw_logfile_file, "rb") as f:
                self.logfile_parser = LogFileParser(f.read())

        if raw_volume_file.exists() and raw_boot_file.exists():
            with open(raw_volume_file, "rb") as f:
                volume_data = f.read()
            with open(raw_boot_file, "rb") as f:
                boot_data = f.read()
            self.volume_parser = VolumeInfoParser(
                volume_data=volume_data, boot_sector_data=boot_data
            )

    def _load_event_logs(self):
        """Load Windows Event Logs from JSON files"""
        logs_dir = self.output_dir / "logs" / "windows" / "evtx"
        if not logs_dir.exists():
            return

        security_file = logs_dir / "Security.evtx.json"
        system_file = logs_dir / "System.evtx.json"

        security_timestamps = []
        system_timestamps = []

        if security_file.exists():
            try:
                with open(security_file, "r") as f:
                    self.security_events = json.load(f)

                for event in self.security_events:
                    if "Timestamp" in event:
                        try:
                            ts = datetime.fromisoformat(
                                event["Timestamp"].replace("Z", "+00:00")
                            )
                            security_timestamps.append(ts)
                        except (ValueError, TypeError):
                            pass

                if security_timestamps:
                    self.earliest_security_timestamp = min(security_timestamps)
                    self.latest_security_timestamp = max(security_timestamps)
            except Exception as e:
                print(f"Error loading Security.evtx.json: {e}")

        if system_file.exists():
            try:
                with open(system_file, "r") as f:
                    self.system_events = json.load(f)

                for event in self.system_events:
                    if "Timestamp" in event:
                        try:
                            ts = datetime.fromisoformat(
                                event["Timestamp"].replace("Z", "+00:00")
                            )
                            system_timestamps.append(ts)
                        except (ValueError, TypeError):
                            pass

                if system_timestamps:
                    self.earliest_system_timestamp = min(system_timestamps)
                    self.latest_system_timestamp = max(system_timestamps)
            except Exception as e:
                print(f"Error loading System.evtx.json: {e}")

        self._index_events_by_file_and_id()

    def _index_events_by_file_and_id(self):
        """Index event logs by file paths and event IDs for faster correlation"""
        self.event_index_by_file = {}
        self.events_by_id = {}

        all_events = self.security_events + self.system_events

        for event in all_events:
            event_id = event.get("EventID")
            if not event_id:
                continue

            if event_id not in self.events_by_id:
                self.events_by_id[event_id] = []
            self.events_by_id[event_id].append(event)

            event_data = event.get("EventData", {})
            file_paths = []

            for key, value in event_data.items():
                if value and isinstance(value, str):
                    if "\\" in value or "/" in value:
                        if len(value) > 10 and not value.startswith("S-1-"):
                            file_paths.append(value.lower())

            for path in file_paths:
                if path not in self.event_index_by_file:
                    self.event_index_by_file[path] = []
                self.event_index_by_file[path].append(event)

    def analyze_all_files(self) -> List[TimestompFinding]:
        """Analyze all files using layered correlation"""
        if not self.mft_parser:
            return []

        for mft_record in self.mft_parser.records:
            if not mft_record.filename_primary:
                continue

            finding = self._analyze_file(mft_record)
            if finding:
                self.findings.append(finding)

        self._rank_findings()
        return self.findings

    def _analyze_file(self, mft_record: MFTRecord) -> Optional[TimestompFinding]:
        """Analyze a single file through all 5 layers"""
        file_ref = mft_record.record_number
        filename = mft_record.filename_primary

        finding = TimestompFinding(
            file_reference=file_ref,
            filename=filename,
        )

        has_layer1_anomaly = False
        has_layer2_anomaly = False

        if mft_record.si_attribute:
            finding.layer1 = self._analyze_layer1(mft_record)
            if finding.layer1 and finding.layer1.anomalies:
                has_layer1_anomaly = True

        if self.usn_parser:
            finding.layer2 = self._analyze_layer2(
                file_ref, filename, mft_record.si_attribute, mft_record.fn_attributes
            )
            if finding.layer2 and finding.layer2.anomalies:
                has_layer2_anomaly = True

        if self.logfile_parser:
            finding.layer3 = self._analyze_layer3(file_ref, mft_record.si_attribute)

        finding.layer4 = self._analyze_layer4(mft_record)

        if self.security_events or self.system_events:
            finding.layer5 = self._analyze_layer5(mft_record)

        self._calculate_total_score(finding)
        return finding

    def _analyze_layer1(self, mft_record: MFTRecord) -> Layer1Result:
        """Layer 1: Compare $SI vs $FN timestamps"""
        si = mft_record.si_attribute
        fn = mft_record.fn_attributes[0] if mft_record.fn_attributes else None

        if not si or not fn:
            return Layer1Result(
                file_reference=mft_record.record_number,
                filename=mft_record.filename_primary,
                si_created=None,
                fn_created=None,
                si_modified=None,
                fn_modified=None,
                si_accessed=None,
                fn_accessed=None,
                si_mft_modified=None,
                fn_mft_modified=None,
            )

        result = Layer1Result(
            file_reference=mft_record.record_number,
            filename=mft_record.filename_primary,
            si_created=si.created.to_datetime(),
            fn_created=fn.created.to_datetime(),
            si_modified=si.modified.to_datetime(),
            fn_modified=fn.modified.to_datetime(),
            si_accessed=si.accessed.to_datetime(),
            fn_accessed=fn.accessed.to_datetime(),
            si_mft_modified=si.mft_modified.to_datetime(),
            fn_mft_modified=fn.mft_modified.to_datetime(),
        )

        if si.created.to_datetime() and fn.created.to_datetime():
            result.created_diff_seconds = abs(
                (si.created.to_datetime() - fn.created.to_datetime()).total_seconds()
            )
            if result.created_diff_seconds > 1:
                result.anomalies.append(
                    f"Created mismatch: {result.created_diff_seconds:.0f}s"
                )

        if si.modified.to_datetime() and fn.modified.to_datetime():
            result.modified_diff_seconds = abs(
                (si.modified.to_datetime() - fn.modified.to_datetime()).total_seconds()
            )
            if result.modified_diff_seconds > 1:
                result.anomalies.append(
                    f"Modified mismatch: {result.modified_diff_seconds:.0f}s"
                )

        if si.accessed.to_datetime() and fn.accessed.to_datetime():
            result.accessed_diff_seconds = abs(
                (si.accessed.to_datetime() - fn.accessed.to_datetime()).total_seconds()
            )

        if si.mft_modified.to_datetime() and fn.mft_modified.to_datetime():
            result.mft_modified_diff_seconds = abs(
                (
                    si.mft_modified.to_datetime() - fn.mft_modified.to_datetime()
                ).total_seconds()
            )

        if result.anomalies:
            if (
                result.created_diff_seconds > 86400
                or result.modified_diff_seconds > 86400
            ):
                result.severity = "HIGH"
                result.score = LAYER_WEIGHTS["si_fn_mismatch"]
            else:
                result.severity = "MEDIUM"
                result.score = LAYER_WEIGHTS["si_fn_mismatch"] * 0.5

        return result

    def _analyze_layer2(
        self,
        file_ref: int,
        filename: str,
        si: Optional[SIAttribute],
        fn_attrs: List[FNAttribute],
    ) -> Layer2Result:
        """Layer 2: Compare with USN Journal"""
        result = Layer2Result(
            file_reference=file_ref,
            filename=filename,
        )

        if not self.usn_parser or not self.usn_parser.records:
            result.usn_missing = True
            result.anomalies.append("USN Journal missing or empty")
            result.severity = "HIGH"
            result.score = LAYER_WEIGHTS["usn_mismatch"]
            return result

        usn_records = self.usn_parser.get_records_for_file(file_ref)
        result.usn_total_events = len(usn_records)

        if usn_records:
            create_records = [r for r in usn_records if r.reason & 0x00000100]
            if create_records:
                result.usn_first_create = min(r.timestamp for r in create_records)

        if not result.usn_first_create:
            result.anomalies.append("No FILE_CREATE event in USN journal")
            result.severity = "MEDIUM"
            return result

        if si:
            si_created = si.created.to_datetime()
            if si_created:
                result.si_created_vs_usn_diff_seconds = abs(
                    (si_created - result.usn_first_create).total_seconds()
                )

                if si_created < result.usn_first_create:
                    result.anomalies.append(
                        f"SI created ({si_created}) is BEFORE USN create ({result.usn_first_create})"
                    )
                    result.severity = "CRITICAL"
                    result.score = LAYER_WEIGHTS["usn_mismatch"]
                elif result.si_created_vs_usn_diff_seconds > 86400:
                    result.anomalies.append(
                        f"SI created differs from USN by {result.si_created_vs_usn_diff_seconds / 86400:.1f} days"
                    )
                    result.severity = "HIGH"
                    result.score = LAYER_WEIGHTS["usn_mismatch"]
                elif result.si_created_vs_usn_diff_seconds > 60:
                    result.severity = "MEDIUM"
                    result.score = LAYER_WEIGHTS["usn_mismatch"] * 0.5

        if fn_attrs:
            fn_created = fn_attrs[0].created.to_datetime()
            if fn_created and result.usn_first_create:
                result.fn_created_vs_usn_diff_seconds = abs(
                    (fn_created - result.usn_first_create).total_seconds()
                )
                if result.fn_created_vs_usn_diff_seconds > 86400:
                    result.anomalies.append(
                        f"FN created differs from USN by {result.fn_created_vs_usn_diff_seconds / 86400:.1f} days"
                    )

        return result

    def _analyze_layer3(self, file_ref: int, si: Optional[SIAttribute]) -> Layer3Result:
        """Layer 3: Analyze $LogFile transactions"""
        result = Layer3Result(
            file_reference=file_ref,
        )

        if not self.logfile_parser or not self.logfile_parser.transaction_records:
            result.logfile_missing = True
            result.anomalies.append("$LogFile missing or empty")
            return result

        relevant_records = [
            r
            for r in self.logfile_parser.transaction_records
            if r.file_reference and (r.file_reference & 0xFFFFFFFFFFFF) == file_ref
        ]

        result.logfile_records = len(relevant_records)

        timestamps = [r.timestamp for r in relevant_records if r.timestamp]
        if timestamps:
            result.earliest_activity = min(timestamps)
            result.latest_activity = max(timestamps)

        if si and si.created.to_datetime() and result.earliest_activity:
            result.si_created_vs_logfile_diff_seconds = abs(
                (si.created.to_datetime() - result.earliest_activity).total_seconds()
            )

            if si.created.to_datetime() < result.earliest_activity:
                diff_days = (
                    result.earliest_activity - si.created.to_datetime()
                ).total_seconds() / 86400
                if diff_days > 1:
                    result.anomalies.append(
                        f"SI timestamp is {diff_days:.1f} days BEFORE $LogFile activity"
                    )
                    result.severity = "HIGH"
                    result.score = LAYER_WEIGHTS["logfile_mismatch"]
            elif result.si_created_vs_logfile_diff_seconds > 86400 * 7:
                result.anomalies.append(
                    f"SI timestamp differs from $LogFile by {result.si_created_vs_logfile_diff_seconds / 86400:.1f} days"
                )
                result.severity = "MEDIUM"
                result.score = LAYER_WEIGHTS["logfile_mismatch"] * 0.5

        return result

    def _analyze_layer4(self, mft_record: MFTRecord) -> Layer4Result:
        """Layer 4: External artifacts (volume info, shadow copies, prefetch)"""
        result = Layer4Result(
            file_reference=mft_record.record_number,
            filename=mft_record.filename_primary,
        )

        # Check for Prefetch files
        prefetch_dir = self.output_dir / "prefetch"
        if prefetch_dir.exists():
            # Standard prefetch naming: <EXE_NAME>-<HASH>.pf
            exe_name = mft_record.filename_primary.upper()
            if "." in exe_name:
                exe_name = exe_name.split(".")[0]

            pf_matches = list(prefetch_dir.glob(f"{exe_name}*.pf"))
            if pf_matches:
                result.prefetch_exists = True
                result.anomalies.append(
                    f"Found {len(pf_matches)} prefetch files for {mft_record.filename_primary}"
                )
            elif mft_record.filename_primary.lower().endswith(".exe"):
                # If it's an EXE but no prefetch exists, it might be suspicious if the system has prefetch enabled
                pass

        # Check for Registry hives
        registry_dir = self.output_dir / "registry"
        if registry_dir.exists():
            hives = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "Amcache"]
            found_hives = []
            for h in hives:
                if list(registry_dir.glob(f"{h}_partition_{self.partition_num}.hive")):
                    found_hives.append(h)

            if "Amcache" in found_hives:
                result.amcache_exists = True

        # Check for Shadow Copies
        shadow_file = (
            self.output_dir / f"shadow_copies_partition_{self.partition_num}.txt"
        )
        if shadow_file.exists():
            with open(shadow_file, "r") as f:
                if "Indicators Found" in f.read():
                    result.shadow_copies_exist = True

        if mft_record.si_attribute and mft_record.si_attribute.created.to_datetime():
            si_created = mft_record.si_attribute.created.to_datetime()

            now = datetime.now()
            if si_created.year > now.year + 1:
                result.anomalies.append(f"Future timestamp: {si_created}")
                result.severity = "CRITICAL"
                result.score = LAYER_WEIGHTS["external_artifacts"]

            if si_created.year == 1601:
                result.anomalies.append("Zero/empty timestamp detected")
                result.severity = "MEDIUM"
                result.score = LAYER_WEIGHTS["external_artifacts"] * 0.5

        if not result.anomalies:
            result.severity = "INFO"

        return result

    def _analyze_layer5(self, mft_record: MFTRecord) -> Layer5Result:
        """Layer 5: Windows Event Logs correlation with specific Event ID analysis"""
        result = Layer5Result(
            file_reference=mft_record.record_number,
            filename=mft_record.filename_primary,
        )

        result.latest_security_event = self.latest_security_timestamp
        result.earliest_security_event = self.earliest_security_timestamp
        result.latest_system_event = self.latest_system_timestamp
        result.earliest_system_event = self.earliest_system_timestamp

        if (
            not mft_record.si_attribute
            or not mft_record.si_attribute.created.to_datetime()
        ):
            return result

        si_created = mft_record.si_attribute.created.to_datetime()
        if not si_created:
            return result

        self._correlate_file_specific_events(mft_record, result, si_created)

        if self.latest_security_timestamp:
            result.file_vs_latest_security_diff_seconds = (
                si_created - self.latest_security_timestamp
            ).total_seconds()

            if si_created > self.latest_security_timestamp:
                days_after = result.file_vs_latest_security_diff_seconds / 86400
                if days_after > 1:
                    result.anomalies.append(
                        f"File created {days_after:.1f} days AFTER latest Security event"
                    )
                    result.severity = "HIGH"
                    result.score = LAYER_WEIGHTS["event_logs"]
            elif result.file_vs_latest_security_diff_seconds > 86400 * 30:
                result.anomalies.append(
                    f"File created {abs(result.file_vs_latest_security_diff_seconds) / 86400:.1f} days BEFORE earliest Security event"
                )
                result.severity = "MEDIUM"
                result.score = LAYER_WEIGHTS["event_logs"] * 0.5

        if self.latest_system_timestamp and si_created > self.latest_system_timestamp:
            diff = (si_created - self.latest_system_timestamp).total_seconds()
            if diff > 86400:
                result.anomalies.append(
                    f"File created {diff / 86400:.1f} days AFTER latest System event"
                )
                if result.severity == "INFO":
                    result.severity = "MEDIUM"
                    result.score = LAYER_WEIGHTS["event_logs"] * 0.5

        if not result.anomalies:
            result.severity = "INFO"

        return result

    def _correlate_file_specific_events(
        self, mft_record: MFTRecord, result: Layer5Result, si_created: datetime
    ):
        """Correlate specific file operations from Event Logs with MFT timestamps"""
        if not hasattr(self, "event_index_by_file"):
            return

        filename_lower = (
            mft_record.filename_primary.lower() if mft_record.filename_primary else ""
        )

        matched_paths = []
        if filename_lower:
            for indexed_path in self.event_index_by_file:
                if filename_lower in indexed_path or indexed_path.endswith(
                    filename_lower
                ):
                    matched_paths.append(indexed_path)

        relevant_event_ids = [
            4656,
            4663,
            4688,
            4696,
            4697,
            4698,
            4699,
            4700,
            4702,
            5140,
            5145,
        ]

        for path in matched_paths[:10]:
            events = self.event_index_by_file.get(path, [])
            for event in events:
                event_id = event.get("EventID")
                if event_id in relevant_event_ids:
                    event_time_str = event.get("Timestamp")
                    if event_time_str:
                        try:
                            event_time = datetime.fromisoformat(
                                event_time_str.replace("Z", "+00:00")
                            )
                            time_diff = (si_created - event_time).total_seconds()

                            event_info = {
                                "event_id": event_id,
                                "event_name": FILE_OPERATION_EVENT_IDS.get(
                                    event_id, "Unknown"
                                ),
                                "timestamp": event_time_str,
                                "path": path,
                                "time_diff_seconds": time_diff,
                            }

                            if event_id in [4688, 4689]:
                                result.process_events.append(event_info)
                            elif event_id in [4697, 4698, 4699, 4700, 4702]:
                                result.scheduled_task_events.append(event_info)
                            elif event_id in [4656, 4663, 4659, 4660]:
                                result.file_object_events.append(event_info)
                            else:
                                result.file_specific_events.append(event_info)

                            if time_diff > 300:
                                result.anomalies.append(
                                    f"EID {event_id} ({FILE_OPERATION_EVENT_IDS.get(event_id, 'Unknown')}): "
                                    f"Event at {event_time_str}, but SI timestamp is {time_diff:.0f}s AFTER"
                                )
                                if result.severity == "INFO":
                                    result.severity = "HIGH"
                                    result.score = LAYER_WEIGHTS["event_logs"]

                        except (ValueError, TypeError):
                            pass

        for event_id in relevant_event_ids:
            if event_id in self.events_by_id:
                events = self.events_by_id[event_id]
                if len(events) > 0 and not result.file_object_events:
                    pass

    def _calculate_total_score(self, finding: TimestompFinding):
        """Calculate total weighted score across all layers"""
        total_score = 0.0
        layers_with_anomalies = []

        if finding.layer1 and finding.layer1.score > 0:
            total_score += finding.layer1.score
            layers_with_anomalies.append("Layer1 (SI vs FN)")

        if finding.layer2 and finding.layer2.score > 0:
            total_score += finding.layer2.score
            layers_with_anomalies.append("Layer2 (USN Journal)")

        if finding.layer3 and finding.layer3.score > 0:
            total_score += finding.layer3.score
            layers_with_anomalies.append("Layer3 ($LogFile)")

        if finding.layer4 and finding.layer4.score > 0:
            total_score += finding.layer4.score
            layers_with_anomalies.append("Layer4 (External)")

        if finding.layer5 and finding.layer5.score > 0:
            total_score += finding.layer5.score
            layers_with_anomalies.append("Layer5 (Event Logs)")

        finding.total_score = total_score
        finding.matching_layers = layers_with_anomalies

        if total_score >= 75:
            finding.severity = "CRITICAL"
            finding.is_suspicious = True
            finding.confidence = 0.95
        elif total_score >= 50:
            finding.severity = "HIGH"
            finding.is_suspicious = True
            finding.confidence = 0.8
        elif total_score >= 25:
            finding.severity = "MEDIUM"
            finding.is_suspicious = True
            finding.confidence = 0.6
        else:
            finding.severity = "LOW"
            finding.is_suspicious = False
            finding.confidence = 0.3

        finding.explanation = self._generate_explanation(finding)
        finding.recommendation = self._generate_recommendation(finding)

    def _generate_explanation(self, finding: TimestompFinding) -> str:
        """Generate human-readable explanation"""
        parts = []

        if finding.layer1 and finding.layer1.anomalies:
            parts.append(f"SI/FN: {', '.join(finding.layer1.anomalies[:2])}")

        if finding.layer2 and finding.layer2.anomalies:
            parts.append(f"USN: {', '.join(finding.layer2.anomalies[:2])}")

        if finding.layer3 and finding.layer3.anomalies:
            parts.append(f"LogFile: {', '.join(finding.layer3.anomalies[:2])}")

        if finding.layer4 and finding.layer4.anomalies:
            parts.append(f"External: {', '.join(finding.layer4.anomalies[:2])}")

        if finding.layer5 and finding.layer5.anomalies:
            parts.append(f"EventLogs: {', '.join(finding.layer5.anomalies[:2])}")

        if not parts:
            return "No anomalies detected across any layer"

        return "; ".join(parts)

    def _generate_recommendation(self, finding: TimestompFinding) -> str:
        """Generate recommendation based on findings"""
        if finding.severity == "CRITICAL":
            return "Immediate investigation required. File timestamps appear artificially manipulated. Check for malicious tools usage."
        elif finding.severity == "HIGH":
            return "Review file in detail. Cross-reference with prefetch, Amcache, and event logs for execution evidence."
        elif finding.severity == "MEDIUM":
            return "Monitor file activity. Verify if timestamp modification was intentional (e.g., software installation)."
        else:
            return "No action required. File timestamps are consistent across all NTFS layers."

    def _rank_findings(self):
        """Rank findings by score"""
        self.findings.sort(key=lambda x: x.total_score, reverse=True)

    def get_suspicious_files(self) -> List[TimestompFinding]:
        """Get only suspicious files"""
        return [f for f in self.findings if f.is_suspicious]

    def export_to_dict(self) -> Dict[str, Any]:
        """Export all findings to dictionary"""
        # Filter out obviously wrong filenames (parsing artifacts)
        invalid_names = {"Low", "new", "tmp", "ver", "sys", "idb"}

        filtered_findings = [
            f for f in self.findings if f.filename not in invalid_names
        ]

        return {
            "analysis_summary": {
                "total_files_analyzed": len(filtered_findings),
                "suspicious_files": len(
                    [f for f in filtered_findings if f.is_suspicious]
                ),
                "critical": len(
                    [f for f in filtered_findings if f.severity == "CRITICAL"]
                ),
                "high": len([f for f in filtered_findings if f.severity == "HIGH"]),
                "medium": len([f for f in filtered_findings if f.severity == "MEDIUM"]),
            },
            "findings": [
                {
                    "file_reference": f.file_reference,
                    "filename": f.filename,
                    "total_score": f.total_score,
                    "severity": f.severity,
                    "is_suspicious": f.is_suspicious,
                    "confidence": f.confidence,
                    "explanation": f.explanation,
                    "recommendation": f.recommendation,
                    "affected_layers": f.matching_layers,
                }
                for f in filtered_findings[:500]
            ],
            "suspicious_files": [
                {
                    "file_reference": f.file_reference,
                    "filename": f.filename,
                    "severity": f.severity,
                    "score": f.total_score,
                    "explanation": f.explanation,
                }
                for f in self.get_suspicious_files()[:100]
            ],
        }


def run_layered_analysis(output_dir: str, partition_num: int = 0) -> Dict[str, Any]:
    """Run complete layered analysis for a single partition"""
    import multiprocessing as mp

    engine = LayeredCorrelationEngine(output_dir, partition_num)

    if not engine.mft_parser:
        return {"analysis_summary": {}, "findings": [], "suspicious_files": []}

    records = engine.mft_parser.records
    if not records:
        return {"analysis_summary": {}, "findings": [], "suspicious_files": []}

    num_workers = min(mp.cpu_count(), 8)
    chunk_size = max(1, len(records) // num_workers)

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        record_chunks = [
            records[i : i + chunk_size] for i in range(0, len(records), chunk_size)
        ]

        futures = []
        for chunk in record_chunks:
            future = executor.submit(_analyze_record_chunk, chunk, engine)
            futures.append(future)

        for future in as_completed(futures):
            try:
                chunk_findings = future.result()
                engine.findings.extend(chunk_findings)
            except Exception as e:
                print(f"Error in chunk analysis: {e}")

    engine._rank_findings()
    return engine.export_to_dict()


def _analyze_record_chunk(
    records: List[MFTRecord], engine: "LayeredCorrelationEngine"
) -> List[TimestompFinding]:
    """Analyze a chunk of MFT records in parallel"""
    findings = []
    for mft_record in records:
        if not mft_record.filename_primary:
            continue
        try:
            finding = engine._analyze_file(mft_record)
            if finding:
                findings.append(finding)
        except Exception:
            pass
    return findings


def run_layered_analysis_for_all_partitions(output_dir: str) -> Dict[str, Any]:
    """Run layered analysis for all partitions - supports both binary and text files"""
    import re
    from pathlib import Path

    output_path = Path(output_dir)

    summary_file = output_path / "extraction_summary.json"
    if not summary_file.exists():
        partitions = []
        for i in range(10):
            timeline_file = output_path / f"timeline_partition_{i}.txt"
            if timeline_file.exists():
                partitions.append(
                    {"slot": i, "start": i * 1000000, "desc": f"Partition {i}"}
                )

        if not partitions:
            partitions = [{"slot": 0, "start": 0, "desc": "Default"}]
    else:
        with open(summary_file, "r") as f:
            extraction = json.load(f)
        partitions = extraction.get("partitions", [])
        if not partitions:
            partitions = [{"slot": 0, "start": 0, "desc": "Default"}]

    all_findings = []
    all_suspicious = []
    total_files = 0
    critical_count = 0
    high_count = 0
    medium_count = 0

    partition_results = []

    for i in range(len(partitions)):
        raw_mft = output_path / f"raw_mft_partition_{i}.bin"

        if raw_mft.exists():
            try:
                result = run_layered_analysis(output_dir, i)
                partition_results.append(
                    {"partition": i, "result": result, "type": "binary"}
                )

                summary = result.get("analysis_summary", {})
                total_files += summary.get("total_files_analyzed", 0)
                critical_count += summary.get("critical", 0)
                high_count += summary.get("high", 0)
                medium_count += summary.get("medium", 0)

                all_findings.extend(result.get("findings", []))
                all_suspicious.extend(result.get("suspicious_files", []))
            except Exception as e:
                print(f"Error analyzing partition {i} (binary): {e}")
        else:
            timeline_file = output_path / f"timeline_partition_{i}.txt"
            if timeline_file.exists():
                try:
                    text_result = _analyze_text_timeline(output_path, i)
                    partition_results.append(
                        {"partition": i, "result": text_result, "type": "text"}
                    )

                    summary = text_result.get("analysis_summary", {})
                    total_files += summary.get("total_files_analyzed", 0)
                    critical_count += summary.get("critical", 0)
                    high_count += summary.get("high", 0)
                    medium_count += summary.get("medium", 0)

                    all_suspicious.extend(text_result.get("suspicious_files", []))
                    all_findings.extend(text_result.get("findings", []))
                except Exception as e:
                    print(f"Error analyzing partition {i} (text): {e}")

    all_suspicious.sort(key=lambda x: x.get("score", 0), reverse=True)

    return {
        "analysis_summary": {
            "total_files_analyzed": total_files,
            "suspicious_files": len(all_suspicious),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "partitions_analyzed": len(partition_results),
        },
        "partition_results": partition_results,
        "findings": all_findings,
        "suspicious_files": all_suspicious,
    }


def _analyze_text_timeline(output_path: Path, partition_num: int) -> Dict[str, Any]:
    """Fallback text-based timeline analysis when binary MFT is not available (e.g. FAT32)"""
    import re
    from datetime import datetime

    timeline_file = output_path / f"timeline_partition_{partition_num}.txt"
    suspicious_files = []
    all_findings = []
    seen_files = set()
    file_count = 0

    if not timeline_file.exists():
        return {"analysis_summary": {}, "suspicious_files": [], "findings": []}

    try:
        with open(timeline_file, "r", errors="ignore") as f:
            for line in f:
                if line.startswith("=") or not line.strip() or line.startswith("Timeline"):
                    continue

                # Basic fls/timeline parsing
                parts = line.strip().split("\t")
                if len(parts) < 2:
                    continue

                # Skip directories, keep only regular files
                if not line.lstrip().startswith("r/"):
                    continue

                # Filename extraction
                filename = None
                for p in parts:
                    # Skip mode/inode/timestamps
                    if p.strip().startswith(("r/", "d/", "+ ", "++ ")) or re.match(r"\d{4}-\d{2}-\d{2}", p):
                        continue
                    if p.strip():
                        filename = p.strip()
                        break

                if not filename or filename.startswith("$") or filename in [".", ".."]:
                    continue

                if filename in seen_files:
                    continue
                seen_files.add(filename)
                file_count += 1

                # Timestamp extraction
                ts_matches = re.findall(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
                
                finding = {
                    "filename": filename,
                    "file_reference": file_count,
                    "created": ts_matches[-1] if len(ts_matches) >= 1 else "Unknown",
                    "modified": ts_matches[0] if len(ts_matches) >= 1 else "Unknown",
                    "is_suspicious": False,
                    "reason": "Analyzed via text timeline",
                    "severity": "INFO",
                    "score": 0
                }

                if len(ts_matches) >= 2:
                    try:
                        mod = datetime.strptime(ts_matches[0], "%Y-%m-%d %H:%M:%S")
                        cre = datetime.strptime(ts_matches[-1], "%Y-%m-%d %H:%M:%S")
                        diff = abs((cre - mod).days)
                        if diff > 365:
                            finding.update({
                                "is_suspicious": True,
                                "reason": f"Significant timestamp gap ({diff} days)",
                                "severity": "MEDIUM",
                                "score": 25.0
                            })
                            suspicious_files.append(finding)
                    except:
                        pass

                all_findings.append(finding)

        return {
            "analysis_summary": {
                "total_files_analyzed": file_count,
                "suspicious_files": len(suspicious_files),
                "critical": 0,
                "high": 0,
                "medium": len(suspicious_files),
            },
            "suspicious_files": suspicious_files,
            "findings": all_findings
        }
    except Exception as e:
        print(f"Error in text timeline analysis: {e}")
        return {"analysis_summary": {"total_files_analyzed": 0}, "suspicious_files": [], "findings": []}
    except Exception as e:
        print(f"Error in text timeline analysis: {e}")
        return {"analysis_summary": {}, "suspicious_files": []}


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(
            "Usage: python layered_correlation_engine.py <output_directory> [partition_num]"
        )
        sys.exit(1)

    output_dir = sys.argv[1]
    partition_num = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    results = run_layered_analysis(output_dir, partition_num)

    print("\n" + "=" * 70)
    print("           LAYERED TIMESTOMP DETECTION RESULTS")
    print("=" * 70)

    print(f"\nFiles Analyzed: {results['analysis_summary']['total_files_analyzed']}")
    print(f"Suspicious Files: {results['analysis_summary']['suspicious_files']}")
    print(f"  - CRITICAL: {results['analysis_summary']['critical']}")
    print(f"  - HIGH: {results['analysis_summary']['high']}")
    print(f"  - MEDIUM: {results['analysis_summary']['medium']}")

    print("\nTop Suspicious Files:")
    for i, f in enumerate(results["suspicious_files"][:10], 1):
        print(f"  {i}. [{f['severity']}] {f['filename']} (Score: {f['score']:.1f})")
        print(f"     {f['explanation'][:100]}...")

    output_file = Path(output_dir) / "layered_timestomp_analysis.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {output_file}")
