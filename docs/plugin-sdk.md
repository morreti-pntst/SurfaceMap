# Adapter SDK

SurfaceMap's built-in adapters use a shared contract: a metadata manifest, a list-based command builder, and a parser that returns normalized `ParseResult` records. The helper types and registry live in `backend/app/plugin_sdk.py`.

```python
from app.importers import ParseResult
from app.plugin_sdk import PluginManifest, PluginRegistry

class ExampleAdapter:
    manifest = PluginManifest(
        id="example_adapter",
        name="Example Adapter",
        version="1.0.0",
        category="Discovery",
        description="An example adapter contract.",
        source="https://example.org/source",
        documentation="https://example.org/docs",
        license="MIT",
        capabilities=("domain_discovery",),
        config_schema={},
    )

    def command(self, target: str, options: dict, output_path: str) -> list[str]:
        return ["example-tool", "--target", target, "--output", output_path]

    def parse_output(self, content: str) -> ParseResult:
        return ParseResult()

registry = PluginRegistry(reserved_ids={"nmap", "subfinder", "dnsx", "httpx", "amass", "nuclei", "katana", "ffuf"})
registry.register(ExampleAdapter())
```

The registry validates IDs, versions, required metadata, HTTPS source links, and the command/parser contract. The command builder must return an argv list; it must never build a shell command. A parser must reject malformed data and return bounded, normalized records. Plugin authors must apply the same project scope and request limits as the built-in adapters.

The shipped first release does not auto-discover or execute third-party plugin packages. The registry is an SDK building block; adding a plugin requires trusted backend integration and review because in-process Python plugins have the backend's filesystem and process permissions. This is intentionally not presented as a user-installable plugin marketplace.
