"""Shared test helpers."""

import re

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def plain(text):
    """Strip ANSI escape codes and collapse whitespace.

    CLI output differs between a plain terminal and CI: rich adds color codes
    around option names, and long temp paths make table lines wrap. Message
    assertions should look at the words, not the rendering.
    """
    return " ".join(ANSI.sub("", text).split())
