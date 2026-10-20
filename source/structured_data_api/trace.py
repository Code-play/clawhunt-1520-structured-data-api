"""时钟、轨迹与格式化工具。

时钟是显式注入的：
  - 演示（demo）与产物生成用 DeterministicClock，时间从固定起点按 1s 步进，
    所以连续两次 demo 产出的 jsonl 逐字节一致，可哈希比对；
  - 独立验证（verify）与真实服务用 SystemClock，记录真实 UTC 时间。

LayerTrace 给"每层单独取证"的结果加 seq 与时间，落成 out/layer_evidence.jsonl。
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator


def iso_z(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class SystemClock:
    """真实时间。verify 与 serve 用这个。"""

    name = "system"

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def advance(self) -> datetime:
        return self.now()


class DeterministicClock:
    """固定起点 + 每次请求步进，保证产物可复现。"""

    name = "deterministic"

    def __init__(self, start: datetime | None = None, step_seconds: int = 1) -> None:
        self.start = start or datetime(2026, 1, 5, 9, 0, 0, tzinfo=timezone.utc)
        self.step = timedelta(seconds=step_seconds)
        self._current = self.start
        self._lock = threading.Lock()

    def now(self) -> datetime:
        with self._lock:
            return self._current

    def advance(self) -> datetime:
        with self._lock:
            self._current = self._current + self.step
            return self._current


class LayerTrace:
    """分层取证轨迹（L1/L2/L3），seq 连续、时间单调。"""

    def __init__(self, clock: Any) -> None:
        self.clock = clock
        self._entries: list[dict[str, Any]] = []

    def add(self, evidence: dict[str, Any]) -> dict[str, Any]:
        item = {"seq": len(self._entries) + 1, "at": iso_z(self.clock.now())}
        item.update(evidence)
        self._entries.append(item)
        return item

    def extend(self, items: list[dict[str, Any]]) -> None:
        for item in items:
            self.add(item)

    @property
    def entries(self) -> list[dict[str, Any]]:
        return list(self._entries)

    def by_layer(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self._entries:
            layer = str(item.get("layer", "?"))
            counts[layer] = counts.get(layer, 0) + 1
        return counts

    def to_jsonl(self) -> str:
        return "".join(
            json.dumps(item, ensure_ascii=False, sort_keys=False) + "\n" for item in self._entries
        )


def iter_jsonl(text: str) -> Iterator[dict[str, Any]]:
    for line in text.splitlines():
        line = line.strip()
        if line:
            yield json.loads(line)


class Printer:
    """同时写屏幕与内存，用于把 demo 的完整屏幕输出落成 demo_run.log。"""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, text: str = "") -> None:
        self.lines.append(text)
        try:
            print(text)
        except UnicodeEncodeError:
            print(text.encode("utf-8", "replace").decode("utf-8", "replace"))

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"
