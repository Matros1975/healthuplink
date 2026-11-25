"""Optional extensions named in HU_EXTENSIONS (comma-separated module names).

Each module has `register(ctx: Context)`. It can add an ingest hook (called with the batch id after a batch is
stored), a periodic job for the scheduler, a CLI command, and ask stored batches to be copied into `sink_queue`.
Hooks and periodic jobs run under one shared lock, so an extension never runs two of its jobs at once. Ingest hooks
run on a separate worker (see `cli.build_server`), never on the request path.
"""

import functools
import importlib
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Mapping

from healthuplink.config import Settings
from healthuplink.db import connect

log = logging.getLogger(__name__)

BUILTIN_JOBS = ("watchdog", "backup", "prune")


class ExtensionError(Exception):
    """An extension could not be loaded. The message names the module and is safe to print."""


@dataclass
class Context:
    settings: Settings
    store_path: Path
    clock: Callable[[], datetime]
    env: Mapping[str, str] = field(default_factory=lambda: os.environ)  # where an extension reads its own HU_* vars
    timeout: float = 5.0  # seconds an extension may wait on a busy external database
    lock: threading.Lock = field(default_factory=threading.Lock)
    ingest_hooks: list[Callable[[str], None]] = field(default_factory=list)
    periodic: list[tuple[str, timedelta, Callable[[], None]]] = field(default_factory=list)
    commands: dict[str, tuple[str, Callable[[list[str]], int]]] = field(default_factory=dict)
    sink_queue: bool = False

    def connect(self) -> sqlite3.Connection:
        """A new connection to the receiver's store; the caller closes it."""
        return connect(self.store_path)

    def _locked(self, fn):
        @functools.wraps(fn)
        def run(*args):
            with self.lock:
                return fn(*args)
        return run

    def add_ingest_hook(self, fn: Callable[[str], None]) -> None:
        self.ingest_hooks.append(self._locked(fn))

    def add_periodic(self, name: str, every: timedelta, fn: Callable[[], None]) -> None:
        if name in BUILTIN_JOBS or any(n == name for n, _, _ in self.periodic):
            raise ValueError(f"periodic job name already taken: {name}")
        if every <= timedelta(0):
            raise ValueError("every must be positive")
        self.periodic.append((name, every, self._locked(fn)))

    def add_command(self, name: str, help: str, run: Callable[[list[str]], int]) -> None:
        """`healthuplink <name> ...` calls run(remaining argv) and exits with its return value."""
        if name in self.commands:
            raise ValueError(f"command name already taken: {name}")
        self.commands[name] = (help, run)

    def use_sink_queue(self) -> None:
        """Copy every stored batch's body into `sink_queue` for this extension to consume."""
        self.sink_queue = True


def load(names: tuple[str, ...] | list[str], ctx: Context) -> None:
    """Import each module and call its register(ctx). Raises ExtensionError naming the first module that fails."""
    for name in names:
        try:
            module = importlib.import_module(name)
        except Exception as e:
            raise ExtensionError(f"HU_EXTENSIONS: cannot import {name} ({type(e).__name__})") from e
        register = getattr(module, "register", None)
        if not callable(register):
            raise ExtensionError(f"HU_EXTENSIONS: {name} has no register(ctx)")
        try:
            register(ctx)
        except Exception as e:
            raise ExtensionError(f"HU_EXTENSIONS: {name}.register failed ({type(e).__name__})") from e
