"""Shared data shapes for Detonation Chamber.

An Event is one observed behaviour inside the sandbox. A Verdict is the
interpretation of a whole run. Everything the UI draws is one of these.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


# Material roles map one-to-one to the UI's false-colour layers.
#   file    -> orange     process -> green      network -> blue
#   blocked -> black/red  agent   -> ink        system  -> ink
class Kind(str, Enum):
    FILE = "file"
    PROCESS = "process"
    NETWORK = "network"
    BLOCKED = "blocked"
    AGENT = "agent"
    SYSTEM = "system"


class Result(str, Enum):
    OK = "ok"
    BLOCKED = "blocked"
    ERROR = "error"


class Label(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    PENDING = "pending"


@dataclass
class Event:
    seq: int
    ts: float              # seconds since run start
    kind: Kind
    op: str                # read | write | exec | connect | dns | fetch | note
    target: str            # path, domain:port, command, or message
    result: Result = Result.OK
    severity: int = 0      # 0 info, 1 notice, 2 warn, 3 critical
    duration: float = 0.0  # seconds this event spans on the time axis
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["result"] = self.result.value
        return d


@dataclass
class IOC:
    type: str              # domain | ip | path | hash | credential | url
    value: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Verdict:
    label: Label = Label.PENDING
    score: int = 0         # 0-100 risk
    headline: str = ""
    reasons: list[str] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label.value,
            "score": self.score,
            "headline": self.headline,
            "reasons": self.reasons,
            "iocs": [i.to_dict() for i in self.iocs],
        }


@dataclass
class Target:
    """A parsed submission."""
    raw: str
    type: str              # npm | pypi | github | url
    name: str              # package name, repo slug, or url
    version: str = ""


def parse_target(raw: str) -> Target:
    s = raw.strip()
    low = s.lower()
    if low.startswith("npm:"):
        rest = s[4:]
        name, _, ver = rest.partition("@") if not rest.startswith("@") else _scoped(rest)
        return Target(raw=s, type="npm", name=name, version=ver)
    if low.startswith("pypi:") or low.startswith("pip:"):
        rest = s.split(":", 1)[1]
        name, _, ver = rest.partition("==")
        return Target(raw=s, type="pypi", name=name, version=ver)
    if low.startswith("demo:"):
        return Target(raw=s, type="demo", name=s.split(":", 1)[1])
    if "github.com/" in low:
        slug = low.split("github.com/", 1)[1].strip("/")
        slug = "/".join(slug.split("/")[:2])
        return Target(raw=s, type="github", name=slug)
    if low.startswith("http://") or low.startswith("https://"):
        return Target(raw=s, type="url", name=s)
    # Bare scoped package "@scope/name[@ver]" -> npm.
    if s.startswith("@"):
        name, _, ver = _scoped(s)
        return Target(raw=s, type="npm", name=name, version=ver)
    # Bare "owner/repo" -> github; bare word -> npm by convention.
    if s.count("/") == 1 and " " not in s:
        return Target(raw=s, type="github", name=s)
    return Target(raw=s, type="npm", name=s)


def _scoped(rest: str) -> tuple[str, str, str]:
    # @scope/name@version
    at = rest.find("@", 1)
    if at == -1:
        return rest, "", ""
    return rest[:at], "@", rest[at + 1:]
