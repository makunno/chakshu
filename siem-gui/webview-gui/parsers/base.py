"""Base Parser Interface"""

from abc import ABC, abstractmethod
from typing import Optional, List
from .types import LogEntry, LogType, Severity


class Parser(ABC):
    """Base class for all log parsers"""

    def __init__(self, name: str, log_type: LogType):
        self.name = name
        self.log_type = log_type

    @abstractmethod
    def detect(self, line: str) -> bool:
        """Check if line matches this parser's pattern"""
        pass

    @abstractmethod
    def parse(self, line: str) -> Optional[LogEntry]:
        """Parse a line and return LogEntry or None"""
        pass

    def parse_safe(self, line: str) -> Optional[LogEntry]:
        """Parse line with error handling"""
        try:
            return self.parse(line)
        except Exception as e:
            # Return raw entry on parse error
            return LogEntry(
                line,
                log_type=self.log_type,
                severity=Severity.UNKNOWN,
                message=line,
                fields={'error': str(e)}
            )
