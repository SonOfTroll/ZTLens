"""
helper utilities for ztlens

random stuff that doesnt fit anywhere else
printing tables banners etc
"""


# colors for terminal output
# not all of these are used yet
CLR_RED = "\033[91m"
CLR_GREEN = "\033[92m"
CLR_YELLOW = "\033[93m"
CLR_BLUE = "\033[94m"
CLR_MAGENTA = "\033[95m"
CLR_CYAN = "\033[96m"
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_DIM = "\033[2m"

# might use these for severity badges later
SEVERITY_COLORS = {
    "critical": CLR_RED,
    "high": CLR_MAGENTA,
    "medium": CLR_YELLOW,
    "low": CLR_CYAN,
}


def print_banner():
    """print the ztlens ascii banner"""
    banner = f"""
{CLR_CYAN}{CLR_BOLD}
  _______ _
 |__   __| |
    | |  | |     ___ _ __  ___
    | |  | |    / _ \\ '_ \\/ __|
    | |  | |___|  __/ | | \\__ \\
    |_|  |______\\___|_| |_|___/
{CLR_RESET}
{CLR_DIM}  zero trust configuration auditor{CLR_RESET}
{CLR_DIM}  v0.1.0{CLR_RESET}
"""
    print(banner)


def fmt_table(headers: list, rows: list, padding: int = 2) -> str:
    """format data as a simple text table

    nothing fancy just aligned columns
    good enough for terminal output
    """
    if not rows:
        return "  (no data)\n"

    # figure out column widths
    col_widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))

    # build the header
    pad = " " * padding
    header_line = pad.join(str(h).ljust(col_widths[i]) for i, h in enumerate(headers))
    separator = pad.join("-" * w for w in col_widths)

    # build the rows
    result = f"  {header_line}\n  {separator}\n"
    for row in rows:
        row_line = pad.join(
            str(cell).ljust(col_widths[i]) if i < len(col_widths) else str(cell)
            for i, cell in enumerate(row)
        )
        result += f"  {row_line}\n"

    return result


def color_text(text: str, color: str) -> str:
    """wrap text in ansi color codes"""
    return f"{color}{text}{CLR_RESET}"


def severity_badge(severity: str) -> str:
    """make a colored severity badge for terminal output"""
    color = SEVERITY_COLORS.get(severity.lower(), CLR_RESET)
    return f"{color}[{severity.upper()}]{CLR_RESET}"
