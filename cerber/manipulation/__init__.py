"""
Cerber Manipulation Detection Module

Based on: "Podręcznik Antymanipulacyjny" by Karen Tonoyanusun (2025)
Training corpus for Cerber's Constitutional AI layer.

This module implements psychological manipulation detection
to protect systems from social engineering attacks.
"""

from .detector import ManipulationDetector
from .patterns import MANIPULATION_PATTERNS
from .cialdini import CialdiniRules
from .constitution import CERBER_CONSTITUTION

__version__ = "1.0.0"
__all__ = [
    "ManipulationDetector",
    "MANIPULATION_PATTERNS",
    "CialdiniRules",
    "CERBER_CONSTITUTION"
]
