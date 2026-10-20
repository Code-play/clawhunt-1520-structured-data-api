"""数据源：用标准库 sqlite3 搭一个确定性的 OLAP 星型模型。

5 张维表 + 1 张事实表，数据全部合成（无任何真实客户信息）：
  dim_date      731 天（2024-01-01 ~ 2025-12-31）
  dim_region    4 个大区
  dim_channel   4 个渠道
  dim_product   12 个商品
  dim_customer  60 个客户分层标签（只有分层，没有姓名/联系方式）
  fact_sales    4000 条销售明细（金额以分为单位存整数，避免浮点累加误差）

生成用固定种子的 random.Random，同一版本代码重复构建得到逐字节一致的库文件内容
（verify 会断言两次构建的事实表校验和相同）。
"""

from __future__ import annotations

import os
import random
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Iterator

from . import views as views_module

SEED = 1520
FACT_ROWS = 4000
START_DATE = date(2024, 1, 1)
DAYS = 731

REGIONS = ("华东", "华南", "华北", "西南")
CHANNELS = ("online", "retail", "partner", "wholesale")
PRODUCTS = (
    ("电子", "智能音箱", 29900),
    ("电子", "无线耳机", 59900),
    ("电子", "便携投影仪", 189900),
    ("家居", "人体工学椅", 89900),
    ("家居", "香薰机", 15900),
    ("家居", "收纳柜", 45900),
    ("服饰", "冲锋衣", 69900),
    ("服饰", "跑鞋", 49900),
    ("服饰", "羊毛围巾", 19900),
    ("食品", "挂耳咖啡", 6900),
    ("食品", "坚果礼盒", 12900),
    ("食品", "气泡水", 3900),
)
SEGMENTS = ("enterprise", "smb", "consumer")
SEGMENT_LABELS = {"enterprise": "企业客户", "smb": "中小企业", "consumer": "个人消费者"}


def _dim_date_rows() -> list[tuple[Any, ...]]:
    rows: list[tuple[Any, ...]] = []
    for offset in range(DAYS):
        day = START_DATE + timedelta(days=offset)
        month = day.month
        quarter = (month - 1) // 3 + 1
        rows.append(
            (
                offset + 1,
                day.isoformat(),
                day.year,
                quarter,
                month,
                day.isoweekday(),
            )
        )
    return rows


def _fact_rows() -> list[tuple[Any, ...]]:
    rng = random.Random(SEED)
    discounts = (0.0, 0.0, 0.0, 0.05, 0.05, 0.1, 0.15)
    rows: list[tuple[Any, ...]] = []
    for sale_id in range(1, FACT_ROWS + 1):
        date_key = rng.randint(1, DAYS)
        region_key = rng.randint(1, len(REGIONS))
        channel_key = rng.randint(1, len(CHANNELS))
        product_key = rng.randint(1, len(PRODUCTS))
        customer_key = rng.randint(1, 60)
        quantity = rng.randint(1, 6)
        unit_price = PRODUCTS[product_key - 1][2]
        discount = rng.choice(discounts)
        amount_cents = int(round(unit_price * quantity * (1.0 - discount)))
        rows.append(
            (
                sale_id,
                date_key,
                region_key,
                channel_key,
                product_key,
                customer_key,
                quantity,
                amount_cents,
            )
        )
    return rows


def build_database(path: Path) -> dict[str, int]:
    """建库、灌数、建视图。返回行数统计。"""
    path = Path(path)
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(
            """
            PRAGMA journal_mode = DELETE;
            PRAGMA synchronous = OFF;

            CREATE TABLE dim_date (
                date_key   INTEGER PRIMARY KEY,
                date_iso   TEXT NOT NULL UNIQUE,
                year       INTEGER NOT NULL,
                quarter    INTEGER NOT NULL,
                month      INTEGER NOT NULL,
                day_of_week INTEGER NOT NULL
            );
            CREATE TABLE dim_region (
                region_key  INTEGER PRIMARY KEY,
                region_name TEXT NOT NULL UNIQUE
            );
            CREATE TABLE dim_channel (
                channel_key  INTEGER PRIMARY KEY,
                channel_name TEXT NOT NULL UNIQUE
            );
            CREATE TABLE dim_product (
                product_key      INTEGER PRIMARY KEY,
                product_name     TEXT NOT NULL,
                category         TEXT NOT NULL,
                unit_price_cents INTEGER NOT NULL
            );
            CREATE TABLE dim_customer (
                customer_key   INTEGER PRIMARY KEY,
                segment        TEXT NOT NULL,
                segment_label  TEXT NOT NULL
            );
            CREATE TABLE fact_sales (
                sale_id      INTEGER PRIMARY KEY,
                date_key     INTEGER NOT NULL REFERENCES dim_date(date_key),
                region_key   INTEGER NOT NULL REFERENCES dim_region(region_key),
                channel_key  INTEGER NOT NULL REFERENCES dim_channel(channel_key),
                product_key  INTEGER NOT NULL REFERENCES dim_product(product_key),
                customer_key INTEGER NOT NULL REFERENCES dim_customer(customer_key),
                quantity     INTEGER NOT NULL CHECK (quantity > 0),
                amount_cents INTEGER NOT NULL CHECK (amount_cents >= 0)
            );
            CREATE INDEX idx_fact_sales_date ON fact_sales(date_key);
            CREATE INDEX idx_fact_sales_product ON fact_sales(product_key);
            """
        )
        conn.executemany(
            "INSERT INTO dim_date VALUES (?, ?, ?, ?, ?, ?)",
            _dim_date_rows(),
        )
        conn.executemany(
            "INSERT INTO dim_region VALUES (?, ?)",
            [(i + 1, name) for i, name in enumerate(REGIONS)],
        )
        conn.executemany(
            "INSERT INTO dim_channel VALUES (?, ?)",
            [(i + 1, name) for i, name in enumerate(CHANNELS)],
        )
        conn.executemany(
            "INSERT INTO dim_product VALUES (?, ?, ?, ?)",
            [
                (i + 1, name, category, price)
                for i, (category, name, price) in enumerate(PRODUCTS)
            ],
        )
        conn.executemany(
            "INSERT INTO dim_customer VALUES (?, ?, ?)",
            [
                (i + 1, SEGMENTS[(i) % 3], SEGMENT_LABELS[SEGMENTS[(i) % 3]])
                for i in range(60)
            ],
        )
        conn.executemany(
            "INSERT INTO fact_sales VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            _fact_rows(),
        )
        views_module.create_views(conn)
        conn.commit()
        stats = {
            "dim_date": _count(conn, "dim_date"),
            "dim_region": _count(conn, "dim_region"),
            "dim_channel": _count(conn, "dim_channel"),
            "dim_product": _count(conn, "dim_product"),
            "dim_customer": _count(conn, "dim_customer"),
            "fact_sales": _count(conn, "fact_sales"),
            "views": len(views_module.VIEW_DEFINITIONS),
        }
        return stats
    finally:
        conn.close()


def _count(conn: sqlite3.Connection, table: str) -> int:
    row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    return int(row[0]) if row else 0


def fact_checksum(path: Path) -> str:
    """对事实表做顺序无关的校验和，用于断言生成确定性。"""
    conn = sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT sale_id, date_key, region_key, channel_key, product_key,"
            " customer_key, quantity, amount_cents FROM fact_sales ORDER BY sale_id"
        ).fetchall()
    finally:
        conn.close()
    total = 0
    for row in rows:
        total = (total * 131 + hash(tuple(int(x) for x in row))) % (2**61 - 1)
    return f"{total:016x}"


class DataSource:
    """临时库的句柄。只提供以只读 URI 打开的连接工厂。"""

    def __init__(self, path: Path, stats: dict[str, int]) -> None:
        self.path = Path(path)
        self.stats = dict(stats)

    def connect_ro(self) -> sqlite3.Connection:
        """以 SQLite 的 mode=ro URI 打开：数据库层面就拒绝写入。"""
        conn = sqlite3.connect(
            f"file:{self.path.as_posix()}?mode=ro", uri=True, isolation_level=None
        )
        conn.row_factory = None
        return conn

    def connect_rw(self) -> sqlite3.Connection:
        """可写连接，仅用于演示 query_only 与 authorizer（生产不会开）。"""
        return sqlite3.connect(str(self.path), isolation_level=None)

    def describe(self) -> dict[str, Any]:
        return {
            "path": self.path.name,
            "stats": dict(self.stats),
            "dialect": "sqlite",
            "mode": "read-only uri (mode=ro)",
            "tables": list(views_module.BASE_TABLES),
            "views": list(views_module.VIEW_DEFINITIONS),
            "synthetic": True,
        }

    def close(self) -> None:
        # 临时目录由 temporary_database 负责清理；这里保留显式接口。
        pass


@contextmanager
def temporary_database(seed_note: str = "synthetic") -> Iterator[DataSource]:
    tmpdir = Path(tempfile.mkdtemp(prefix="sdapi-"))
    db_path = tmpdir / "olap.db"
    try:
        stats = build_database(db_path)
        ds = DataSource(db_path, stats)
        try:
            yield ds
        finally:
            ds.close()
    finally:
        for name in os.listdir(tmpdir):
            try:
                (tmpdir / name).unlink()
            except OSError:
                pass
        try:
            tmpdir.rmdir()
        except OSError:
            pass
