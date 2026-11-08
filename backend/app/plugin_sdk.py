"""Small validation and typing helpers for trusted, in-process SurfaceMap adapters.

Plugins are never discovered from arbitrary folders. An application embedding this
SDK must explicitly install and enable a trusted Python distribution first.
"""
from dataclasses import dataclass
import re
from typing import Any, Protocol

from .importers import ParseResult


@dataclass(frozen=True)
class PluginManifest:
    id: str
    name: str
    version: str
    category: str
    description: str
    source: str
    documentation: str
    license: str
    capabilities: tuple[str, ...]
    config_schema: dict[str, Any]


class SurfaceMapAdapter(Protocol):
    manifest: PluginManifest

    def command(self, target: str, options: dict[str, Any], output_path: str) -> list[str]: ...

    def parse_output(self, content: str) -> ParseResult: ...


class PluginRegistry:
    """Explicit registry for applications that choose to load trusted plugins."""

    def __init__(self, reserved_ids: set[str] | None = None):
        self._reserved_ids = set(reserved_ids or ())
        self._adapters: dict[str, SurfaceMapAdapter] = {}

    def register(self, adapter: SurfaceMapAdapter) -> None:
        manifest = adapter.manifest
        if not re.fullmatch(r"[a-z][a-z0-9_-]{1,39}", manifest.id):
            raise ValueError("Plugin id must use lowercase letters, digits, dash, or underscore")
        if manifest.id in self._reserved_ids or manifest.id in self._adapters:
            raise ValueError(f"Plugin id is already registered: {manifest.id}")
        if not re.fullmatch(r"\d+\.\d+\.\d+", manifest.version):
            raise ValueError("Plugin version must use semantic versioning")
        if not manifest.name.strip() or not manifest.category.strip() or not manifest.description.strip():
            raise ValueError("Plugin name, category, and description are required")
        for url in (manifest.source, manifest.documentation):
            if not url.startswith("https://"):
                raise ValueError("Plugin source and documentation must use HTTPS")
        if not manifest.license.strip():
            raise ValueError("Plugin license is required")
        if not callable(getattr(adapter, "command", None)) or not callable(getattr(adapter, "parse_output", None)):
            raise ValueError("Plugin must provide command() and parse_output() methods")
        self._adapters[manifest.id] = adapter

    def get(self, plugin_id: str) -> SurfaceMapAdapter:
        return self._adapters[plugin_id]

    def list(self) -> list[PluginManifest]:
        return [adapter.manifest for adapter in self._adapters.values()]
