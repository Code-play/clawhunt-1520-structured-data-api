"""ClawHunt 订单 #1520：结构化数据与实时接口的受控只读访问契约。

纯标准库实现：sqlite3 搭 OLAP 星型模型，http.server 提供只读接口，
三层只读防线（数据库只读凭据 / 语句白名单 / 行级与超时上限）互不依赖。
"""

from __future__ import annotations

__all__ = ["__version__", "main"]

__version__ = "1.0.0"


def main(argv: list[str] | None = None) -> int:
    from .cli import main as _main

    return _main(argv)
