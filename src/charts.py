"""Shared chart style for the notebooks.

One blue for single-series charts, gray for context, light gridlines, no
top/right/left borders. Categorical colors are used in fixed order.
"""

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

BLUE = "#2a78d6"          # data, categorical slot 1
ORANGE = "#eb6834"        # categorical slot 2
AQUA = "#1baf7a"          # categorical slot 3
GRAY = "#c3c2b7"          # context / de-emphasized marks
INK = "#0b0b0b"           # titles
INK_2 = "#52514e"         # labels, annotations
MUTED = "#898781"         # axis ticks
GRID = "#e1e0d9"
SURFACE = "#fcfcfb"

SERIES = [BLUE, ORANGE, AQUA]


def apply_style() -> None:
    plt.rcParams.update({
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "axes.edgecolor": GRAY,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.spines.left": False,
        "axes.grid": True,
        "axes.grid.axis": "y",
        "grid.color": GRID,
        "grid.linewidth": 0.8,
        "axes.axisbelow": True,
        "axes.titlesize": 13,
        "axes.titleweight": "bold",
        "axes.titlecolor": INK,
        "axes.titlelocation": "left",
        "axes.titlepad": 24,
        "axes.labelcolor": INK_2,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "xtick.labelcolor": INK_2,
        "ytick.labelcolor": INK_2,
        "ytick.left": False,
        "legend.frameon": False,
        "legend.labelcolor": INK_2,
        "font.family": ["Segoe UI", "DejaVu Sans", "sans-serif"],
        "font.size": 10,
        "figure.dpi": 110,
        "savefig.dpi": 150,
        "savefig.bbox": "tight",
    })


thousands = mticker.FuncFormatter(lambda x, _: f"{x / 1000:.0f}k" if x >= 1000 else f"{x:.0f}")


def subtitle(ax, text: str) -> None:
    ax.text(0, 1.025, text, transform=ax.transAxes, color=INK_2, fontsize=9.5)


def pct(x: float) -> str:
    return f"{x:.1%}" if x < 0.01 else f"{x:.0%}"


def mask_ip(ip: str) -> str:
    """Hide the last octet: 203.0.113.45 -> 203.0.113.x"""
    return ip.rsplit(".", 1)[0] + ".x"
