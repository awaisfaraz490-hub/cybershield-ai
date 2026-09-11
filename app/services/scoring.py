"""
Transparent, easy-to-modify risk scoring engine.

The engine combines weighted "signals" produced by the URL and message
analyzers into a single 0-100 "Estimated Risk Score". This is explicitly
a heuristic assessment, not a scientific guarantee.
"""
from dataclasses import dataclass, field


@dataclass
class Signal:
    """A single detected indicator and the points it contributes."""
    name: str
    points: int
    description: str


@dataclass
class ScoreResult:
    score: int
    level: str
    signals: list[Signal] = field(default_factory=list)

    @property
    def findings(self) -> list[str]:
        return [s.description for s in self.signals]


class ScoringEngine:
    """
    Clean, centralized scoring engine.

    Weights below are intentionally simple and transparent so they can be
    tuned later without touching the analyzers that produce signals.
    """

    LEVELS = (
        (0, 20, "Low Risk"),
        (21, 50, "Moderate Risk"),
        (51, 75, "High Risk"),
        (76, 100, "Critical Risk"),
    )

    @classmethod
    def level_for_score(cls, score: int) -> str:
        for low, high, label in cls.LEVELS:
            if low <= score <= high:
                return label
        return "Critical Risk"

    @classmethod
    def compute(cls, signals: list[Signal]) -> ScoreResult:
        total = sum(s.points for s in signals)
        total = max(0, min(100, total))
        level = cls.level_for_score(total)
        return ScoreResult(score=total, level=level, signals=signals)
