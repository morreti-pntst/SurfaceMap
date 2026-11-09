# Third-party components

The [SurfaceMap Community License](LICENSE) applies only to material offered under that license by the relevant rights holders. Third-party software, templates, fonts, and image layers retain their upstream terms and notices. The lists below are starting points for a version-specific inventory before distributing binaries or container images.

| Area | Where to verify exact versions and terms |
| --- | --- |
| JavaScript | [Frontend dependency lock](frontend/package-lock.json) and each package's shipped notices. This includes MIT, Apache-2.0, ISC, BSD-3-Clause, and MPL-2.0 entries. |
| Python | [Backend requirements](backend/requirements.txt) and license files in installed wheel metadata. Review transitive packages and native libraries in the actual build. |
| Scanners | [Adapter manifest](backend/app/tool_registry.py) and license files in the pinned upstream releases. Nuclei templates have their own upstream notice. |
| Containers | [Compose](compose.yaml), [backend Dockerfile](backend/Dockerfile), and [frontend Dockerfile](frontend/Dockerfile). Review Nginx, PostgreSQL, Redis, Debian and Alpine packages, Go, Node.js, and Python at the exact image digests used for delivery. |

Before distributing a prebuilt bundle, review [Nmap's terms](https://nmap.org/npsl/) for integration and redistribution and [Redis's version-specific terms](https://redis.io/legal/licenses/). Check license and notice obligations for dependencies, including applicable MPL source availability obligations. A SurfaceMap commercial agreement cannot grant those third-party rights.

The prior repository snapshot carried an MIT notice naming SurfaceMap contributors. Preserve rights and notices that apply to previously licensed copies. Confirm the rights to relicense each contribution before distributing a new version under different terms.
