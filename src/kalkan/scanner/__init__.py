"""The scanning engine: ``await scan("firmaniz.com.tr")`` returns a :class:`ScanReport`."""

from kalkan.scanner.context import ScanOptions
from kalkan.scanner.engine import scan
from kalkan.scanner.models import Category, DetectedSoftware, Finding, ScanReport, Severity
from kalkan.scanner.target import TargetError

__all__ = [
    "Category",
    "DetectedSoftware",
    "Finding",
    "ScanOptions",
    "ScanReport",
    "Severity",
    "TargetError",
    "scan",
]
