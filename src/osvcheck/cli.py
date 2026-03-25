"""Command-line interface."""

import argparse
import logging
from pathlib import Path
from typing import List


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="osvcheck",
        description="Lightweight vulnerability scanner for Python dependencies",
    )

    # Logging options
    parser.add_argument(
        "--log-file",
        type=Path,
        help="Write logs to file",
    )
    parser.add_argument(
        "--log-json",
        action="store_true",
        help="Output logs as JSON",
    )

    # Color options (mutually exclusive)
    color_group = parser.add_mutually_exclusive_group()
    color_group.add_argument(
        "--color",
        "--colour",
        action="store_true",
        dest="color",
        help="Force color output",
    )
    color_group.add_argument(
        "--no-color",
        "--no-colour",
        action="store_false",
        dest="color",
        help="Disable color output",
    )
    parser.set_defaults(color=None)  # Auto-detect

    # Verbosity options (mutually exclusive)
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    verbosity_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Only show warnings and errors",
    )

    parser.add_argument(
        "-x",
        "--exception",
        dest="exceptions",
        action="append",
        default=[],
        metavar="PKG[,PKG...]",
        help="Ignore vulnerability for package(s); comma-separated, repeatable",
    )

    return parser.parse_args()


def get_cli_exceptions(args: argparse.Namespace) -> List[str]:
    """Flatten and normalise -x/--exception values into a list of package names."""
    packages = []
    for value in args.exceptions:
        for pkg in value.split(","):
            pkg = pkg.strip().lower()
            if pkg:
                packages.append(pkg)
    return packages


def get_log_level(args: argparse.Namespace) -> int:
    """Determine log level from arguments."""
    if args.verbose:
        return logging.DEBUG
    if args.quiet:
        return logging.WARNING
    return logging.INFO
