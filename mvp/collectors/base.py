"""Base collector class."""

from abc import ABC, abstractmethod

from ..context import AnalysisContext


class BaseCollector(ABC):
    """Abstract base for all context collectors.

    Each collector:
    1. Checks if it's applicable (has required inputs)
    2. Collects its piece of data
    3. Returns the updated context
    """

    name: str = "base"

    @abstractmethod
    def is_applicable(self, ctx: AnalysisContext) -> bool:
        """Check whether this collector can run given the current context."""
        ...

    @abstractmethod
    def collect(self, ctx: AnalysisContext) -> AnalysisContext:
        """Run collection and return updated context."""
        ...
