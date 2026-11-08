# Architecture

SurfaceMap is a local Docker Compose application. Nginx serves the React/TypeScript single-page UI and proxies `/api` to FastAPI. PostgreSQL stores projects, scope entries, imports, normalized assets, relationships, observations, findings, snapshots, tool operations, scan jobs, workflows, and settings. Redis is the Celery broker/result backend. A worker performs tool installation, scan execution, and sequential workflow runs.

```text
Browser → Nginx → FastAPI → PostgreSQL
                    │          └─ projects / scope / assets / findings / jobs
                    └─ Redis → Celery worker → versioned tool binaries
                                           ├─ result parsers → import service
                                           └─ artifacts / logs → persistent volume
```

## Tool execution path

The adapter registry contains pinned metadata, parameter schemas, a command builder, and parser selection for eight real tools. API requests validate target identity, explicit project scope, exclusions, tool-specific options, and allowlisted advanced flags. The worker reads the current scope a second time before it launches a subprocess. Arguments are passed as a list without a shell. The worker bounds run time, artifact size, and concurrency, records command/version/exit/result metadata, and feeds supported output into the same import/deduplication service used by file uploads.

Tool installation runs asynchronously. Go module versions are pinned and built to a persistent staged directory; Nmap is built from its official source archive after digest verification. A version probe must pass before an atomic symlink activation. Previous version directories support rollback.

## Asset model

Assets are unique within a project by type and canonical identity. Imports create observations with source, kind, timestamp, evidence, and a stable fingerprint. Relationship evidence resolves to typed graph edges, such as hostname-to-address `resolves_to` and host-to-service `exposes`. Findings are deduplicated by project, template, match, and title while preserving first/last-seen times and review state. Snapshots store counts over time; the graph API is bounded to 500 nodes and 1,000 links per response.

## Local deployment boundaries

Named Docker volumes preserve database, Redis, tool, wordlist, and scan-artifact data. The web server binds to localhost by default. This deployment is single-user and does not include authentication, authorization between users, remote plugin code loading, workflow branching, or realtime WebSockets. Treat the instance as trusted local software and do not expose it to an untrusted network.
