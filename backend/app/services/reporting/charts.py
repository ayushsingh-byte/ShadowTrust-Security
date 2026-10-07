"""SVG chart geometry for the report templates.

Pure functions: numbers in, coordinates out. The templates draw the result with plain
SVG elements, so WeasyPrint needs no chart library and no JavaScript. Nothing here
touches the database; providers pass in values they already queried.
"""
from __future__ import annotations

import math
from typing import Any, Dict, Iterable, List, Sequence, Tuple


def donut(items: Iterable[Tuple[str, float, str]], radius: float = 42.0) -> Dict[str, Any]:
    """items = [(label, value, colour)] -> ring segments drawn with stroke-dasharray.

    Each segment carries `dash` ("length gap") and `offset` for a circle of `radius`
    that is rotated to start at twelve o'clock. Zero and negative values are dropped.
    """
    rows = [(str(l), max(0.0, float(v or 0)), c) for l, v, c in items]
    total = sum(v for _, v, _ in rows)
    circ = 2 * math.pi * radius
    segments: List[Dict[str, Any]] = []
    run = 0.0
    for label, value, colour in rows:
        if not total or value <= 0:
            continue
        length = value / total * circ
        segments.append({
            "label": label,
            "value": int(value) if value == int(value) else round(value, 1),
            "pct": round(value / total * 100, 1),
            "colour": colour,
            "dash": f"{length:.2f} {circ - length:.2f}",
            "offset": f"{-run:.2f}",
        })
        run += length
    return {"total": int(total) if total == int(total) else round(total, 1), "radius": radius, "segments": segments}


def _nice_ceiling(value: float) -> float:
    """Smallest of 1, 2, 2.5, 5 x 10^k that is at least `value` (axis maximum)."""
    if value <= 0:
        return 1.0
    exp = math.floor(math.log10(value))
    for m in (1, 2, 2.5, 5, 10):
        if m * 10 ** exp >= value:
            return m * 10 ** exp
    return 10 ** (exp + 1)


def line(points: Sequence[Tuple[str, float]], width: float = 520.0, height: float = 150.0,
         left: float = 38.0, right: float = 6.0, top: float = 8.0, bottom: float = 20.0,
         max_labels: int = 8) -> Dict[str, Any]:
    """points = [(label, value)] -> a line, the area under it, y ticks and x labels.

    Returns {} for fewer than two points, so a template can skip the chart.
    """
    pts = [(str(l), max(0.0, float(v or 0))) for l, v in points]
    if len(pts) < 2:
        return {}
    peak = _nice_ceiling(max(v for _, v in pts))
    w, h = width - left - right, height - top - bottom
    step = w / (len(pts) - 1)
    xy = [(left + i * step, top + h - (v / peak) * h) for i, (_, v) in enumerate(pts)]
    path = "M" + " L".join(f"{x:.1f} {y:.1f}" for x, y in xy)
    area = f"{path} L{xy[-1][0]:.1f} {top + h:.1f} L{xy[0][0]:.1f} {top + h:.1f} Z"
    ticks = []
    for i in range(5):
        v = peak * i / 4
        ticks.append({"y": round(top + h - h * i / 4, 1), "label": f"{v:,.0f}" if peak >= 4 else f"{v:g}"})
    every = max(1, math.ceil(len(pts) / max_labels))
    labels = [{"x": round(xy[i][0], 1), "text": pts[i][0]} for i in range(0, len(pts), every)]
    return {
        "width": width, "height": height, "left": left, "right": width - right, "base": round(top + h, 1),
        "path": path, "area": area, "ticks": ticks, "labels": labels,
        "last": {"x": round(xy[-1][0], 1), "y": round(xy[-1][1], 1)},
        "peak": max(pts, key=lambda p: p[1]),
    }


def bubbles(points: Iterable[Dict[str, Any]], limit: int = 60, r_min: float = 1.6, r_max: float = 7.0) -> List[Dict[str, Any]]:
    """points = [{lat, lon, events}] -> circles on a 360 x 180 equirectangular map.

    Nearby points (same 2-degree cell) are merged; radius follows the square root of the
    event count so area, not width, tracks volume. Largest are drawn first.
    """
    cells: Dict[Tuple[int, int], Dict[str, float]] = {}
    for p in points:
        try:
            lat, lon, n = float(p["lat"]), float(p["lon"]), float(p.get("events") or 0)
        except (KeyError, TypeError, ValueError):
            continue
        if n <= 0 or (lat == 0 and lon == 0) or not (-90 <= lat <= 90 and -180 <= lon <= 180):
            continue
        key = (round(lat / 2), round(lon / 2))
        c = cells.setdefault(key, {"lat": 0.0, "lon": 0.0, "events": 0.0})
        c["lat"] += lat * n
        c["lon"] += lon * n
        c["events"] += n
    rows = sorted(cells.values(), key=lambda c: c["events"], reverse=True)[:limit]
    if not rows:
        return []
    top = math.sqrt(rows[0]["events"])
    out = []
    for c in rows:
        n = c["events"]
        out.append({
            "x": round(c["lon"] / n + 180, 2), "y": round(90 - c["lat"] / n, 2),
            "r": round(r_min + (r_max - r_min) * math.sqrt(n) / top, 2), "events": int(n),
        })
    return out


def _selfcheck() -> None:
    d = donut([("a", 3, "#000"), ("b", 1, "#111"), ("zero", 0, "#222")])
    assert d["total"] == 4 and len(d["segments"]) == 2
    assert d["segments"][0]["pct"] == 75.0 and d["segments"][1]["offset"].startswith("-")
    lengths = sum(float(s["dash"].split()[0]) for s in d["segments"])
    assert abs(lengths - 2 * math.pi * 42) < 0.05
    assert donut([])["segments"] == []

    assert line([("x", 1)]) == {}
    c = line([("mon", 0), ("tue", 50), ("wed", 100)])
    assert c["ticks"][0]["label"] == "0" and c["ticks"][-1]["label"] == "100"
    assert c["path"].startswith("M38.0 130.0") and c["peak"] == ("wed", 100.0)
    assert _nice_ceiling(81344) == 100000 and _nice_ceiling(230) == 250 and _nice_ceiling(0) == 1

    b = bubbles([{"lat": 10, "lon": 20, "events": 100}, {"lat": 10.4, "lon": 20.3, "events": 100},
                 {"lat": 0, "lon": 0, "events": 5}, {"lat": -33.9, "lon": 151.2, "events": 4}, {"lat": "x"}])
    assert len(b) == 2 and b[0]["events"] == 200 and b[0]["r"] == 7.0
    assert b[1]["x"] == 331.2 and b[1]["y"] == 123.9 and b[1]["r"] < b[0]["r"]


if __name__ == "__main__":
    _selfcheck()
    print("charts self-check ok")
