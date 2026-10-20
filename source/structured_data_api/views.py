"""允许的 OLAP 视图（星型模型上的只读视图层）。

视图定义是配置的一部分，但放在代码里便于加载期核对：
access_contract.json 的 allowed_views 必须与这里的 VIEW_DEFINITIONS 完全对得上，
否则 ConfigError。这样改视图必须同时改两处，不会出现"文档说只读、实际多了一张表"的漂移。
"""

from __future__ import annotations

from typing import Any

VIEW_DEFINITIONS: dict[str, str] = {
    "v_sales_enriched": """
        CREATE VIEW v_sales_enriched AS
        SELECT f.sale_id            AS sale_id,
               d.date_iso           AS date_iso,
               d.year               AS year,
               d.month              AS month,
               r.region_name        AS region,
               c.channel_name       AS channel,
               p.category           AS category,
               p.product_name       AS product_name,
               cu.segment           AS segment,
               f.quantity           AS quantity,
               f.amount_cents       AS amount_cents
        FROM fact_sales f
        JOIN dim_date     d  ON d.date_key    = f.date_key
        JOIN dim_region   r  ON r.region_key  = f.region_key
        JOIN dim_channel  c  ON c.channel_key = f.channel_key
        JOIN dim_product  p  ON p.product_key = f.product_key
        JOIN dim_customer cu ON cu.customer_key = f.customer_key
    """,
    "v_sales_daily": """
        CREATE VIEW v_sales_daily AS
        SELECT date_iso,
               region,
               channel,
               COUNT(*)          AS orders,
               SUM(amount_cents) AS revenue_cents
        FROM v_sales_enriched
        GROUP BY date_iso, region, channel
    """,
    "v_category_revenue": """
        CREATE VIEW v_category_revenue AS
        SELECT date_iso,
               category,
               COUNT(*)          AS orders,
               SUM(amount_cents) AS revenue_cents
        FROM v_sales_enriched
        GROUP BY date_iso, category
    """,
    "v_channel_daily": """
        CREATE VIEW v_channel_daily AS
        SELECT date_iso,
               channel,
               COUNT(*)          AS orders,
               SUM(amount_cents) AS revenue_cents
        FROM v_sales_enriched
        GROUP BY date_iso, channel
    """,
    "v_segment_summary": """
        CREATE VIEW v_segment_summary AS
        SELECT date_iso,
               segment,
               COUNT(*)          AS orders,
               SUM(amount_cents) AS revenue_cents
        FROM v_sales_enriched
        GROUP BY date_iso, segment
    """,
    "v_product_rank": """
        CREATE VIEW v_product_rank AS
        SELECT date_iso,
               product_name,
               category,
               SUM(quantity)     AS quantity,
               SUM(amount_cents) AS revenue_cents
        FROM v_sales_enriched
        GROUP BY date_iso, product_name, category
    """,
}

# 视图列清单：只用于文档与契约展示，不参与鉴权（鉴权在语句层与结果列白名单）。
VIEW_COLUMNS: dict[str, tuple[str, ...]] = {
    "v_sales_enriched": (
        "sale_id", "date_iso", "year", "month", "region", "channel",
        "category", "product_name", "segment", "quantity", "amount_cents",
    ),
    "v_sales_daily": ("date_iso", "region", "channel", "orders", "revenue_cents"),
    "v_category_revenue": ("date_iso", "category", "orders", "revenue_cents"),
    "v_channel_daily": ("date_iso", "channel", "orders", "revenue_cents"),
    "v_segment_summary": ("date_iso", "segment", "orders", "revenue_cents"),
    "v_product_rank": ("date_iso", "product_name", "category", "quantity", "revenue_cents"),
}

BASE_TABLES: tuple[str, ...] = (
    "dim_date",
    "dim_region",
    "dim_channel",
    "dim_product",
    "dim_customer",
    "fact_sales",
)


def allowed_view_names() -> tuple[str, ...]:
    return tuple(VIEW_DEFINITIONS)


def create_views(conn: Any) -> None:
    for name in VIEW_DEFINITIONS:
        conn.execute(VIEW_DEFINITIONS[name])


def describe_views() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "columns": list(VIEW_COLUMNS[name]),
            "sql": " ".join(VIEW_DEFINITIONS[name].split()),
        }
        for name in VIEW_DEFINITIONS
    ]
