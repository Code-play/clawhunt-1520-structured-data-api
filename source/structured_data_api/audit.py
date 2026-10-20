"""审计日志：每一次数据访问都留痕（成功与拒绝都记）。

记录内容刻意只放"谁、何时、用什么模板、什么参数、结果如何"：
  - 令牌只记 id 与掩码，明文令牌不落盘；
  - 拒绝请求记错误码、所属防线与可读消息，便于事后追责与调参；
  - 超过 max_entries 后丢弃最早条目（演示够用；生产应落到 append-only 存储）。
"""

from __future__ import annotations

import json
import threading
from typing import Any, Callable, Mapping

from .model import AuditEntry
from .trace import iso_z


class AuditLog:
    def __init__(self, clock: Any, *, max_entries: int = 5000, enabled: bool = True) -> None:
        self.clock = clock
        self.max_entries = max(1, int(max_entries))
        self.enabled = enabled
        self._entries: list[AuditEntry] = []
        self._seq = 0
        self._request_seq = 0
        self._lock = threading.Lock()

    def next_request_id(self) -> str:
        with self._lock:
            self._request_seq += 1
            return f"req-{self._request_seq:04d}"

    def record(
        self,
        *,
        at: Any,
        request_id: str,
        source: str,
        method: str,
        path: str,
        template_id: str | None,
        outcome: str,
        status: int,
        error_code: str | None = None,
        rows: int | None = None,
        token_id: str = "-",
        client_ip: str = "-",
        params: Mapping[str, Any] | None = None,
        message: str | None = None,
        layer: str | None = None,
    ) -> AuditEntry:
        with self._lock:
            self._seq += 1
            entry = AuditEntry(
                seq=self._seq,
                at=iso_z(at),
                request_id=request_id,
                source=source,
                method=method,
                path=path,
                template_id=template_id,
                outcome=outcome,
                status=status,
                error_code=error_code,
                rows=rows,
                token_id=token_id,
                client_ip=client_ip,
                params=dict(params) if params is not None else None,
                message=message,
                layer=layer,
            )
            if self.enabled:
                self._entries.append(entry)
                if len(self._entries) > self.max_entries:
                    self._entries = self._entries[-self.max_entries :]
            return entry

    @property
    def entries(self) -> list[AuditEntry]:
        with self._lock:
            return list(self._entries)

    def tail(self, n: int) -> list[dict[str, Any]]:
        n = max(0, min(int(n), self.max_entries))
        with self._lock:
            return [e.to_dict() for e in self._entries[-n:]] if n else []

    def count(self, predicate: Callable[[AuditEntry], bool] | None = None) -> int:
        with self._lock:
            if predicate is None:
                return len(self._entries)
            return sum(1 for e in self._entries if predicate(e))

    def outcome_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self.entries:
            counts[entry.outcome] = counts.get(entry.outcome, 0) + 1
        return counts

    def to_jsonl(self) -> str:
        return "".join(
            json.dumps(entry.to_dict(), ensure_ascii=False, sort_keys=False) + "\n"
            for entry in self.entries
        )

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
