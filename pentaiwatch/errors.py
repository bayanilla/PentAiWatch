"""The one exception type whose message is meant for the person running PentAIWatch."""
from __future__ import annotations


class UserError(ValueError):
    """Something the person can fix: a bad or missing input, an unreadable saved report, a
    machine that is too busy. The message is written for them, so the command line prints it
    and any page built on it can show it as is.

    Any other exception, including a plain ValueError from deep inside the analysis, is a bug:
    it is reported as a failure with its details. (It
    subclasses ValueError so callers that already catch ValueError keep working.)"""


class MissingField(UserError):
    """A log lacks a field the detection cannot work without. The run stops with this message
    instead of quietly scoring nothing."""
