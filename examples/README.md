# Sample data

`sample-nmap.xml` is synthetic training data. It uses RFC 5737 documentation IP ranges and the reserved `.test` domain; it does not describe live infrastructure.

To try the first version:

1. Start SurfaceMap with `./surfacemap start` (Windows: `bash ./surfacemap start` from WSL in the project folder).
2. Create a project and open **Import Center**.
3. Choose **Nmap XML**, preview `examples/sample-nmap.xml`, then import it.
4. Open **Attack Surface Map**. The expected graph contains two domains, two IP addresses, three open services, DNS resolution links, and host-to-service links.

The sample is only for checking import and visualization. SurfaceMap does not run a scan from this file.
