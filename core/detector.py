
from abc import ABC, abstractmethod


class ThreatDetector(ABC):
    """Abstract base class for security detectors."""

    def __init__(self, name):
        self._name = name
        self._enabled = True

    @property
    def name(self):
        return self._name

    def enable(self):
        self._enabled = True

    def disable(self):
        self._enabled = False

    @abstractmethod
    def detect(self, events):
        """Analyze events and return security alerts."""
        pass