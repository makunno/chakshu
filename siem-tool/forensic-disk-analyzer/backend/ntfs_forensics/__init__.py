#!/usr/bin/env python3
"""
NTFS Timestomp Detection System
A layered forensic analysis tool for detecting timestamp manipulation in NTFS volumes.

Architecture:
- Raw MFT Parser: Extracts $SI and $FN timestamps separately
- USN Journal Parser: Parses actual USN records
- $LogFile Parser: Detects transaction history and log restarts
- Correlation Engine: Multi-layer inconsistency detection with scoring

Author: Cyber Chakshu SIEM Team
"""

__version__ = "1.0.0"

from .mft_parser import MFTParser, MFTRecord, SIAttribute, FNAttribute
from .usn_parser import USNJournalParser, USNRecord
from .logfile_parser import LogFileParser, LogFileAnalysis

__all__ = [
    "MFTParser",
    "MFTRecord",
    "SIAttribute",
    "FNAttribute",
    "USNJournalParser",
    "USNRecord",
    "LogFileParser",
    "LogFileAnalysis",
]
