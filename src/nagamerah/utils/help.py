"""Plain-text, Cobra-style help output (the look used by Dalfox).

Place this file at ``src/nagamerah/utils/help.py``.

Instead of Typer's boxed Rich panels, help is printed as grouped plain text::

    Usage:
      nagamerah [flags] [command]

    Available Commands:
      lookup   Look up a single IOC

    Input:
          --column string   IOC column name for CSV input (default ioc)

Options are grouped with Typer's ``rich_help_panel`` argument. Options without a
panel fall into "Flags". Output has no colors and no box drawing, so it also
reads well when piped to a file or a pager.
"""

from __future__ import annotations

import inspect
import typing

from typer.core import TyperCommand, TyperGroup

try:  # Typer >= 0.2x ships its own copy of click
    from typer import _click as click
except ImportError:  # older Typer depends on the click package
    import click

DEFAULT_PANEL = "Flags"
INDENT = "  "
GAP = 3

_CLICK_TYPE_NAMES = {"integer": "int", "float": "float"}  # click ParamType.name
_PY_TYPE_NAMES = {int: "int", float: "float"}  # Python annotations


def _clean(text: str | None) -> str:
    return inspect.cleandoc(text or "").strip()


def _first_line(text: str | None) -> str:
    cleaned = _clean(text)
    return cleaned.splitlines()[0] if cleaned else ""


def _base_annotation(annotation: object) -> object:
    """Unwrap ``list[int]`` / ``int | None`` to the plain element type."""
    for _ in range(3):
        origin = typing.get_origin(annotation)
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        if origin is None or not args:
            break
        annotation = args[0]
    return annotation


def _type_name(param: click.Parameter) -> str:
    """Cobra-style value type: nothing for flags, ``string``/``int``, plural if repeatable."""
    if getattr(param, "is_flag", False) or getattr(param, "count", False):
        return ""
    descriptor = getattr(param, "type_descriptor", None)  # Typer with vendored click
    if descriptor is not None:
        base = _PY_TYPE_NAMES.get(_base_annotation(descriptor.annotation), "string")
    else:  # older Typer: a click ParamType
        base = _CLICK_TYPE_NAMES.get(getattr(getattr(param, "type", None), "name", ""), "string")
    return f"{base}s" if getattr(param, "multiple", False) else base


def _has_default(value: object) -> bool:
    if type(value).__name__ == "Sentinel":  # click >= 8.3 'no default' marker
        return False
    return value is not None and value not in ("", (), [])


def _option_row(param: click.Parameter) -> tuple[str, str]:
    names = [*param.opts, *param.secondary_opts]
    shorts = [n for n in names if not n.startswith("--")]
    longs = [n for n in names if n.startswith("--")]
    left = (f"{shorts[0]}, " if shorts else "    ") + (longs[0] if longs else "")
    type_name = _type_name(param)
    if type_name:
        left += f" {type_name}"
    text = (param.help or "").strip()
    is_flag = getattr(param, "is_flag", False)
    if not is_flag and not callable(param.default) and _has_default(param.default):
        text += f" (default {param.default})"
    return left, text


def _rows(rows: list[tuple[str, str]]) -> list[str]:
    width = max(len(left) for left, _ in rows) + GAP
    return [f"{INDENT}{left.ljust(width)}{text}".rstrip() for left, text in rows]


def _option_sections(command: click.Command, ctx: click.Context) -> dict[str, list[str]]:
    grouped: dict[str, list[tuple[str, str]]] = {}
    for param in command.get_params(ctx):
        if param.param_type_name != "option" or getattr(param, "hidden", False):
            continue
        panel = getattr(param, "rich_help_panel", None) or DEFAULT_PANEL
        grouped.setdefault(panel, []).append(_option_row(param))
    if DEFAULT_PANEL in grouped:  # generic flags (--help, --version) go last
        grouped[DEFAULT_PANEL] = grouped.pop(DEFAULT_PANEL)
    return {name: _rows(rows) for name, rows in grouped.items()}


def _argument_info(command: click.Command, ctx: click.Context) -> tuple[list[str], list[str]]:
    """Return (usage placeholders, rows for the Arguments section)."""
    placeholders: list[str] = []
    rows: list[tuple[str, str]] = []
    for param in command.get_params(ctx):
        if param.param_type_name != "argument":
            continue
        name = param.metavar or (param.name or "arg").upper()
        placeholders.append(name if param.required else f"[{name}]")
        help_text = (getattr(param, "help", None) or "").strip()
        if help_text:
            rows.append((name, help_text))
    return placeholders, _rows(rows) if rows else []


def _examples(command: click.Command) -> list[str]:
    epilog = _clean(command.epilog)
    return [f"{INDENT}{line}" for line in epilog.splitlines()] if epilog else []


def _join(blocks: list[list[str]]) -> str:
    return "\n\n".join("\n".join(block) for block in blocks if block) + "\n"


class CobraCommand(TyperCommand):
    """Command whose ``--help`` uses the plain grouped layout."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        placeholders, argument_rows = _argument_info(self, ctx)
        usage = " ".join([ctx.command_path, "[flags]", *placeholders])
        blocks: list[list[str]] = [
            _clean(self.help).splitlines(),
            ["Usage:", f"{INDENT}{usage}"],
        ]
        if argument_rows:
            blocks.append(["Arguments:", *argument_rows])
        for name, rows in _option_sections(self, ctx).items():
            blocks.append([f"{name}:", *rows])
        examples = _examples(self)
        if examples:
            blocks.append(["Examples:", *examples])
        formatter.write(_join(blocks))


class CobraGroup(TyperGroup):
    """Group whose ``--help`` lists commands first, then flags."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        commands: list[tuple[str, str]] = []
        for name in self.list_commands(ctx):
            command = self.get_command(ctx, name)
            if command is None or getattr(command, "hidden", False):
                continue
            commands.append((name, _first_line(command.help)))
        blocks: list[list[str]] = [
            _clean(self.help).splitlines(),
            ["Usage:", f"{INDENT}{ctx.command_path} [flags] [command]"],
        ]
        if commands:
            blocks.append(["Available Commands:", *_rows(commands)])
        for name, rows in _option_sections(self, ctx).items():
            blocks.append([f"{name}:", *rows])
        examples = _examples(self)
        if examples:
            blocks.append(["Examples:", *examples])
        blocks.append(
            [f'Use "{ctx.command_path} [command] --help" for more information about a command.']
        )
        formatter.write(_join(blocks))