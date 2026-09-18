import importlib
import pkgutil
from typing import Callable


def load_tools() -> tuple[list[dict], dict[str, Callable]]:
    """Collect SCHEMA + run from every module in this package. Adding a tool = adding a file."""
    schemas: list[dict] = []
    handlers: dict[str, Callable] = {}
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda i: i.name):
        if info.name == "base":
            continue
        mod = importlib.import_module(f"{__name__}.{info.name}")
        if hasattr(mod, "SCHEMA") and hasattr(mod, "run"):
            schemas.append(mod.SCHEMA)
            handlers[mod.SCHEMA["function"]["name"]] = mod.run
    return schemas, handlers
