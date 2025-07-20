# Patterns module initialization
"""
Evyl Framework Pattern Database

Contains comprehensive pattern databases for:
- Regex patterns for credential detection
- Endpoint lists for various services
- Signature databases for file identification
"""

from .regex_db import PATTERNS
from .endpoints import ENDPOINTS
from .signatures import SIGNATURES

__all__ = ["PATTERNS", "ENDPOINTS", "SIGNATURES"]