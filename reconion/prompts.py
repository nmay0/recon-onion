"""Prompt wrappers that clean terminal line-editing junk out of every answer.

Every interactive question in the package goes through `ask`/`confirm` so a
terminal that hands over raw editing bytes instead of editing the line (see
config.sanitize_text for how that happens) can never write them into a config
value — or turn a perfectly valid answer into a rejected one.

Its own module rather than cli.py: pipeline.py and hosts.py prompt too, and
importing them from cli would be circular. This imports only rich + config, so
any layer can use it.
"""

from __future__ import annotations

from rich.prompt import Confirm, Prompt

from .config import sanitize_text


class CleanPrompt(Prompt):
    """Prompt whose answer is sanitized before validation.

    process_response() is the hook rather than the return value because it runs
    *before* `choices` are checked, so a stray keypress in an otherwise valid
    answer does not trigger a spurious "please select one of..." re-prompt. An
    empty answer short-circuits to rich's default without reaching here, which is
    correct: defaults come from the already-sanitized config.
    """

    def process_response(self, value: str) -> str:
        return super().process_response(sanitize_text(value))


class CleanConfirm(Confirm):
    """Confirm whose y/n answer is sanitized before validation."""

    def process_response(self, value: str) -> bool:
        return super().process_response(sanitize_text(value))


ask = CleanPrompt.ask
confirm = CleanConfirm.ask
