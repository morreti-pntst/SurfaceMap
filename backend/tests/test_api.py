import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db import Base, get_db
from app.main import app
from app.importers import parse_import

@pytest.fixture
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(engine)
    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()

def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["database"] == "connected"


def test_manual_maps_are_isolated_and_reject_stale_or_invalid_graphs(client):
    project = client.post("/api/projects", json={"name": "Manual topology"}).json()["id"]
    other = client.post("/api/projects", json={"name": "Other topology"}).json()["id"]
    root = f"/api/projects/{project}/surface-drafts"
    created = client.post(root, json={"name": "Perimeter"})
    assert created.status_code == 201
    draft = created.json()
    url = f"{root}/{draft['id']}"
    assert draft["nodes"] == [] and draft["links"] == []
    assert client.get(f"/api/projects/{other}/surface-drafts/{draft['id']}").status_code == 404
    nodes = [
        {"id": "hostname", "kind": "domain", "label": "Portal", "value": "Portal.Example.Test.", "x": 25, "y": -80},
        {"id": "address", "kind": "ip", "label": "Reverse proxy", "value": "2001:0db8::20", "x": 210, "y": 75},
    ]
    link = {"id": "dns", "source": "hostname", "target": "address", "relation": "Resolves to"}
    payload = {"name": "Perimeter and proxy", "revision": draft["revision"], "nodes": nodes, "links": [link]}
    assert client.put(url, json={**payload, "nodes": nodes[:1]}).status_code == 422
    assert client.put(url, json={**payload, "links": [link, {**link, "id": "duplicate"}]}).status_code == 422
    assert client.put(url, json={**payload, "nodes": [nodes[0], {**nodes[1], "value": "192.0.2.1:443"}]}).status_code == 422
    saved = client.put(url, json=payload)
    assert saved.status_code == 200
    saved = saved.json()
    assert saved["nodes"][0]["value"] == "portal.example.test"
    assert saved["nodes"][1]["value"] == "2001:db8::20" and saved["nodes"][1]["x"] == 210
    assert saved["links"][0]["relation"] == "Resolves to"
    assert client.put(url, json=payload).status_code == 409
    assert client.delete(url, params={"revision": draft["revision"]}).status_code == 409
    assert client.get(url).json() == saved
    assert client.get(root).json()[0]["name"] == saved["name"]
    assert client.get(f"/api/projects/{project}/graph").json()["nodes"] == []
    assert client.delete(url, params={"revision": saved["revision"]}).status_code == 204
    assert client.get(root).json() == []

def test_create_project_and_scope(client):
    project = client.post("/api/projects", json={"name": "Authorized assessment", "description": "Internal test"})
    assert project.status_code == 201
    project_id = project.json()["id"]
    scope = client.post(f"/api/projects/{project_id}/scope", json={"value": "Example.COM", "kind": "domain"})
    assert scope.status_code == 201
    assert scope.json()["value"] == "example.com"
    assert client.get(f"/api/projects/{project_id}").json()["scopes"][0]["value"] == "example.com"

def test_duplicate_project_and_bad_scope_kind(client):
    assert client.post("/api/projects", json={"name": "Duplicate"}).status_code == 201
    assert client.post("/api/projects", json={"name": "Duplicate"}).status_code == 409
    project_id = client.get("/api/projects").json()[0]["id"]
    assert client.post(f"/api/projects/{project_id}/scope", json={"value": "example.com", "kind": "url"}).status_code == 422
    assert client.post(f"/api/projects/{project_id}/scope", json={"value": "not a domain", "kind": "domain"}).status_code == 422

def test_excluded_ip_scope(client):
    project_id = client.post("/api/projects", json={"name": "Scope project"}).json()["id"]
    response = client.post(f"/api/projects/{project_id}/scope", json={"value": "192.168.1.22", "kind": "ip", "excluded": True})
    assert response.status_code == 201
    assert response.json()["excluded"] is True
    assert client.post(f"/api/projects/{project_id}/scope", json={"value":"*.192.0.2.9", "kind":"ip"}).status_code == 422

def test_scope_normalizes_idn_and_network(client):
    project_id = client.post("/api/projects", json={"name": "IDN scope"}).json()["id"]
    domain = client.post(f"/api/projects/{project_id}/scope", json={"value":"*.BÜCHER.example", "kind":"domain"})
    network = client.post(f"/api/projects/{project_id}/scope", json={"value":"192.0.2.3/24", "kind":"cidr"})
    assert domain.json()["value"] == "*.xn--bcher-kva.example"
    assert network.json()["value"] == "192.0.2.0/24"

def test_missing_project(client):
    assert client.get("/api/projects/404").status_code == 404

def test_subfinder_normalization_and_invalid_record():
    parsed = parse_import("subfinder", "API.Example.COM.\nnot a domain\n\nwww.example.com\n")
    assert [record.asset_value for record in parsed.records] == ["api.example.com", "www.example.com"]
    assert len(parsed.warnings) == 1

def test_nmap_xml_parses_host_and_open_port():
    xml = '<nmaprun><host><status state="up"/><address addr="192.0.2.8" addrtype="ipv4"/><hostnames><hostname name="scan.example.test" type="PTR"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx"/></port><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>'
    parsed = parse_import("nmap_xml", xml)
    assert len(parsed.records) == 3
    assert parsed.records[0].asset_value == "192.0.2.8"
    assert parsed.records[1].asset_value == "scan.example.test"
    assert parsed.records[1].related_assets == ["192.0.2.8"]
    assert parsed.records[2].asset_type == "service"
    assert parsed.records[2].data["port"] == 443
    assert parsed.records[2].data["name"] == "https"
    assert parsed.records[2].related_assets == [("ipv4", "192.0.2.8", "exposes")]

def test_nmap_invalid_port_is_reported_not_a_server_error():
    xml = '<nmaprun><host><address addr="192.0.2.8" addrtype="ipv4"/><ports><port protocol="tcp" portid="999999999999999999999"><state state="open"/></port></ports></host></nmaprun>'
    parsed = parse_import("nmap_xml", xml)
    assert len(parsed.records) == 1
    assert parsed.warnings and "invalid Nmap port" in parsed.warnings[0]

def test_nuclei_import_normalizes_finding():
    line = '{"template-id":"tls-check","host":"https://api.example.test:443","matched-at":"https://api.example.test:443/","info":{"name":"TLS issue","severity":"high"},"matcher-name":"weak-cipher"}'
    parsed = parse_import("nuclei_jsonl", line)
    assert len(parsed.records) == 1
    assert parsed.records[0].asset_value == "https://api.example.test/"
    assert parsed.records[0].finding["severity"] == "high"

def test_import_endpoint_deduplicates_assets(client):
    project_id = client.post("/api/projects", json={"name": "Import test"}).json()["id"]
    payload = {"file_format": "subfinder"}
    file1 = {"file": ("subs.txt", b"api.example.test\nwww.example.test\n")}
    preview = client.post(f"/api/projects/{project_id}/imports/preview", data=payload, files=file1)
    assert preview.status_code == 200
    assert preview.json()["records"] == 2
    first = client.post(f"/api/projects/{project_id}/imports", data=payload, files=file1)
    second = client.post(f"/api/projects/{project_id}/imports", data=payload, files=file1)
    assert first.status_code == second.status_code == 201
    assert first.json()["assets_created"] == 2
    assert second.json()["assets_created"] == 0
    assets = client.get(f"/api/projects/{project_id}/assets")
    assert len(assets.json()) == 2
    assert len(client.get(f"/api/projects/{project_id}/imports").json()) == 2

def test_import_rejects_external_entity_xml(client):
    project_id = client.post("/api/projects", json={"name": "XML test"}).json()["id"]
    malicious = b'<!DOCTYPE x [<!ENTITY file SYSTEM "file:///etc/passwd">]><nmaprun>&file;</nmaprun>'
    response = client.post(f"/api/projects/{project_id}/imports", data={"file_format":"nmap_xml"}, files={"file":("scan.xml", malicious)})
    assert response.status_code == 422

def test_nuclei_import_persists_and_deduplicates_finding(client):
    project_id = client.post("/api/projects", json={"name": "Finding import"}).json()["id"]
    line = '{"template-id":"tls-check","host":"https://api.example.test:443","matched-at":"https://api.example.test:443/","info":{"name":"TLS issue","severity":"high"}}'
    for _ in range(2):
        response = client.post(f"/api/projects/{project_id}/imports", data={"file_format":"nuclei_jsonl"}, files={"file":("nuclei.jsonl", line.encode())})
        assert response.status_code == 201
    findings = client.get(f"/api/projects/{project_id}/findings")
    assert findings.status_code == 200
    assert len(findings.json()) == 1
    assert findings.json()[0]["severity"] == "high"
    finding_id = findings.json()[0]["id"]
    updated = client.patch(f"/api/projects/{project_id}/findings/{finding_id}", json={"status":"confirmed"})
    assert updated.status_code == 200 and updated.json()["status"] == "confirmed"
    assert client.patch(f"/api/projects/{project_id}/findings/{finding_id}", json={"status":"arbitrary"}).status_code == 422

def test_nmap_import_builds_dns_relationship(client):
    project_id = client.post("/api/projects", json={"name": "Graph import"}).json()["id"]
    xml = '<nmaprun><host><address addr="192.0.2.15" addrtype="ipv4"/><hostnames><hostname name="edge.example.test"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>'
    imported = client.post(f"/api/projects/{project_id}/imports", data={"file_format":"nmap_xml"}, files={"file":("nmap.xml", xml.encode())})
    assert imported.status_code == 201
    graph = client.get(f"/api/projects/{project_id}/graph")
    assert graph.status_code == 200
    assert len(graph.json()["nodes"]) == 3
    assert {edge["type"] for edge in graph.json()["edges"]} == {"resolves_to", "exposes"}

def test_timeline_and_inventory_snapshots(client):
    project_id = client.post("/api/projects", json={"name": "Timeline test"}).json()["id"]
    xml = '<nmaprun><host><address addr="192.0.2.19" addrtype="ipv4"/><hostnames><hostname name="timeline.example.test"/></hostnames></host></nmaprun>'
    imported = client.post(f"/api/projects/{project_id}/imports", data={"file_format":"nmap_xml"}, files={"file":("scan.xml", xml.encode())})
    assert imported.status_code == 201
    events = client.get(f"/api/projects/{project_id}/timeline?limit=1")
    assert events.status_code == 200 and len(events.json()) == 1
    assert events.json()[0]["event_type"] == "import"
    assert events.json()[0]["details"]["assets_created"] == 2
    snapshot = client.post(f"/api/projects/{project_id}/snapshots")
    assert snapshot.status_code == 201
    assert snapshot.json()["asset_count"] == 2
    assert snapshot.json()["relationship_count"] == 1
    assert client.get(f"/api/projects/{project_id}/snapshots").json()[0]["id"] == snapshot.json()["id"]

def test_full_scope_is_reversible_and_keeps_exclusions(client):
    project_id = client.post("/api/projects", json={"name": "Full scope test"}).json()["id"]
    root = f"/api/projects/{project_id}"
    preview = {"tool_id": "nmap", "target": "192.0.2.5", "options": {"ports": "80"}}
    assert client.post(f"{root}/scan-jobs/preview", json=preview).status_code == 422
    for _ in range(2):
        assert client.put(f"{root}/scope/full-access?enabled=true").status_code == 204
    assert len(client.get(root).json()["scopes"]) == 1
    assert client.post(f"{root}/scan-jobs/preview", json=preview).status_code == 200
    assert client.post(f"{root}/scope", json={"kind": "ip", "value": "192.0.2.5", "excluded": True}).status_code == 201
    assert client.post(f"{root}/scan-jobs/preview", json=preview).status_code == 422
    assert client.post(f"{root}/scan-jobs/preview", json={**preview, "target": "192.0.2.0/24"}).status_code == 422
    assert client.put(f"{root}/scope/full-access?enabled=false").status_code == 204
    assert client.post(f"{root}/scan-jobs/preview", json={**preview, "target": "192.0.2.6"}).status_code == 422


def test_tcpwrapped_ports_are_grouped_as_host_evidence():
    xml = """<nmaprun><host><address addr="192.0.2.5" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="81"><state state="open"/><service name="tcpwrapped"/></port>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    <port protocol="tcp" portid="82"><state state="filtered"/></port></ports></host></nmaprun>"""
    parsed = parse_import("nmap_xml", xml)
    assert len([r for r in parsed.records if r.asset_type == "service"]) == 1
    wrapped = next(r for r in parsed.records if r.kind == "nmap_wrapped_ports")
    assert wrapped.data["ports"] == ["tcp/81"]


def test_map_projects_legacy_and_grouped_tcpwrapped_ports_with_audit_provenance(client):
    from app.import_service import store_import
    from app.importers import ParseResult, ParsedRecord
    from app.models import AuditRun, ScanJob

    host = "192.0.2.5"
    xml = """<nmaprun><host><address addr="192.0.2.5" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="81"><state state="open"/><service name="tcpwrapped"/></port>
    <port protocol="tcp" portid="82"><state state="open"/><service name="tcpwrapped"/></port>
    <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
    </ports></host></nmaprun>"""
    root = f"/api/projects/{client.post('/api/projects', json={'name': 'Wrapped ports'}).json()['id']}"
    project_id = int(root.rsplit("/", 1)[-1])
    source = app.dependency_overrides[get_db]()
    try:
        db = next(source)
        parsed = parse_import("nmap_xml", xml)
        grouped = store_import(db, project_id, "nmap_xml", "grouped.xml", parsed)
        repeated = store_import(db, project_id, "nmap_xml", "repeated.xml", parsed)
        legacy = store_import(db, project_id, "nmap_xml", "legacy.xml", ParseResult(records=[
            ParsedRecord("service", f"{host}|tcp/{port} (tcpwrapped)", "nmap_port", {"name": "tcpwrapped"},
                         related_assets=[("ipv4", host, "exposes")]) for port in (81, 83)
        ]))
        runs = []
        for batch in (repeated, legacy):
            run = AuditRun(project_id=project_id, profile="web", target=f"http://{host}/", status="completed")
            db.add(run)
            db.flush()
            db.add(ScanJob(project_id=project_id, audit_run_id=run.id, tool_id="nmap", target=host,
                           status="completed", result_summary={"import_id": batch.id}))
            runs.append(run.id)
        db.commit()
        first_seen, last_seen = grouped.imported_at, repeated.imported_at
    finally:
        source.close()

    graph = client.get(root + "/graph").json()
    assert [row["port"] for row in graph["wrapped_ports"]] == [81, 82, 83]
    assert {node["type"] for node in graph["nodes"]} == {"service", "ipv4"}
    host_id = next(node["id"] for node in graph["nodes"] if node["type"] == "ipv4")
    assert all(row["host_id"] == host_id for row in graph["wrapped_ports"])
    assert graph["wrapped_ports"][1]["first_seen"] == first_seen.isoformat()
    assert graph["wrapped_ports"][1]["last_seen"] == last_seen.isoformat()
    focus = client.get(root + "/graph", params={"focus_id": host_id}).json()
    assert focus["wrapped_ports"] == graph["wrapped_ports"]
    search = client.get(root + "/graph", params={"q": "tcp/82"}).json()
    assert [node["id"] for node in search["nodes"]] == [host_id]
    assert [row["port"] for row in search["wrapped_ports"]] == [82]
    for run_id, ports in zip(runs, ([81, 82], [81, 83]), strict=True):
        historical = client.get(root + "/graph", params={"audit_id": run_id}).json()
        assert [row["port"] for row in historical["wrapped_ports"]] == ports


def test_map_distinguishes_port_number_hints_and_uses_latest_sighting(client):
    project_id = client.post("/api/projects", json={"name": "Nmap service evidence"}).json()["id"]
    root = f"/api/projects/{project_id}"
    table = '<service name="ms-sql-m" method="table" conf="3"/>'
    probed = '<service name="http" product="nginx" version="1.27.5" method="probed" conf="10"/>'

    def upload(service):
        xml = ('<nmaprun><host><address addr="192.0.2.5" addrtype="ipv4"/><ports>'
               '<port protocol="tcp" portid="1434"><state state="open" reason="syn-ack"/>'
               f'{service}</port></ports></host></nmaprun>')
        result = client.post(root + "/imports", data={"file_format": "nmap_xml"},
                             files={"file": ("scan.xml", xml.encode())})
        assert result.status_code == 201
        graph = client.get(root + "/graph").json()
        return next(node for node in graph["nodes"] if node["type"] == "service")

    old = upload(probed)
    unknown = upload(table)
    assert unknown["label"] == "tcp/1434 · service unknown"
    assert unknown["facts"]["identification"] == "unidentified"
    assert (unknown["facts"]["state"], unknown["facts"]["reason"], unknown["facts"]["name"]) == (
        "open", "syn-ack", "ms-sql-m",
    )
    refreshed = upload(probed)
    assert refreshed["label"] == "tcp/1434 · nginx 1.27.5"
    assert refreshed["facts"]["identification"] == "identified"
    assert refreshed["facts"]["observed_at"] > old["facts"]["observed_at"]


def test_duplicate_rows_in_one_upload(client):
    project_id = client.post("/api/projects", json={"name": "Duplicate rows"}).json()["id"]
    response = client.post(f"/api/projects/{project_id}/imports", data={"file_format": "subfinder"},
                           files={"file": ("subs.txt", b"api.example.test\napi.example.test\n")})
    assert response.status_code == 201
    assert response.json()["assets_created"] == 1


def test_tool_setup_shows_existing_nmap_update_and_reuses_it(client, monkeypatch):
    from app import main as api
    from app.models import ToolOperation
    from app.tool_registry import TOOLS

    installed = {tool.id: tool.version.lstrip("v") for tool in TOOLS[1:4]}
    installed["nmap"] = "7.95"
    monkeypatch.setattr(api, "installed_version", lambda tool: installed.get(tool.id))
    monkeypatch.setattr(api, "_dispatch_tool_operation", lambda *_: None)
    from contextlib import closing
    with closing(app.dependency_overrides[get_db]()) as session:
        db = next(session)
        operation = ToolOperation(tool_id="nmap", action="update", version=TOOLS[0].version,
                                  status="running", log="Compiling Nmap · 30s elapsed")
        db.add(operation)
        db.commit()
        operation_id = operation.id
    response = client.post("/api/tools/nmap/operations", json={"action": "update"})
    assert response.status_code == 202
    assert response.json()["id"] == operation_id
    progress = client.get("/api/tools/setup-progress")
    assert progress.status_code == 200
    assert "Ready tools: 3/8" in progress.text
    assert "detected 7.95" in progress.text
    assert "Compiling Nmap" in progress.text
    assert "Setup needs attention." not in progress.text
    assert len([op for op in client.get("/api/tool-operations").json() if op["tool_id"] == "nmap"]) == 1


def test_tool_recovery_requeues_only_transient_failures(monkeypatch):
    from datetime import datetime, timedelta, timezone
    from app import tool_operations as recovery
    from app.models import SystemSetting, ToolOperation
    from app.tool_registry import TOOL_BY_ID

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(recovery, "SessionLocal", sessions)
    old = datetime.now(timezone.utc) - timedelta(minutes=6)
    with sessions.begin() as db:
        for tool, status, error in (
            ("nuclei", "failed", "TLS handshake timeout"),
            ("ffuf", "failed", "Staged binary failed its version health check"),
            ("amass", "running", ""),
        ):
            db.add(ToolOperation(tool_id=tool, action="install", version=TOOL_BY_ID[tool].version,
                                 status=status, error=error, completed_at=old if status == "failed" else None))
    pending = recovery.reconcile_tool_operations()
    with sessions.begin() as db:
        assert {db.get(ToolOperation, id_).tool_id for id_ in pending} == {"nuclei", "amass"}
        assert len(pending) == 2
        assert set(recovery.reconcile_tool_operations()) == set(pending)
        db.add(SystemSetting(key="tool_manager", value={"automatic_updates": False}))
        db.add(ToolOperation(tool_id="httpx", action="install", version=TOOL_BY_ID["httpx"].version,
                             status="failed", error="unexpected EOF", completed_at=old))
    assert set(recovery.reconcile_tool_operations()) == set(pending)


def test_scan_diagnostics_distinguish_protection_from_normal_http_responses():
    from app.scan_diagnostics import ScanBlocked, live_web_problem, nuclei_coverage_gap, nuclei_progress, response_problem

    assert response_problem(429, {"Retry-After": "120"}).find("120") >= 0
    assert "refused" in response_problem(403, {})
    assert "challenge" in response_problem(403, {"cf-mitigated": "challenge"})
    assert ScanBlocked.from_scanner(response_problem(503, {})).category == "upstream"
    assert nuclei_coverage_gap({"requests": "32", "total": "32", "errors": "0"}) is None
    assert "30/32" in nuclei_coverage_gap({"requests": "30", "total": "32", "errors": "2"})
    assert nuclei_coverage_gap({})
    assert live_web_problem("katana", "", '{"response":{"status_code":403}}') is None
    assert live_web_problem("ffuf", "", '{"status":429}')
    assert live_web_problem("nuclei", "HTTP/1.1 400 Bad Request", "") is None
    assert nuclei_progress('{"requests":"20","total":"150","errors":"2"}')["requests"] == "20"


def test_audit_plan_requires_scope_and_rejects_stale_confirmation(client, monkeypatch):
    from app import audit_plan
    from app.tool_registry import TOOL_BY_ID

    monkeypatch.setattr(audit_plan, "installed_version", lambda tool: tool.version.lstrip("v"))
    root = f"/api/projects/{client.post('/api/projects', json={'name': 'Guided plan'}).json()['id']}"
    draft = {"target": "https://shop.example.test:8443/admin", "profile": "domain", "root_domain": "example.test"}
    assert client.post(f"{root}/audits/preview", json=draft).status_code == 422
    assert client.post(f"{root}/scope", json={"kind": "domain", "value": "*.example.test"}).status_code == 201
    preview = client.post(f"{root}/audits/preview", json=draft)
    assert preview.status_code == 200
    plan = preview.json()
    assert plan["target"] == draft["target"]
    assert [stage["tool_id"] for stage in plan["stages"]] == ["subfinder", "dnsx", "httpx", "katana", "nuclei"]
    assert plan["max_jobs"] == 8
    for ports in ({}, {"ports": "  "}, {"ports": "22,443"}):
        extended = client.post(f"{root}/audits/preview", json={**draft, "include_ports": True, **ports})
        assert extended.status_code == 200
        stage = next(stage for stage in extended.json()["stages"] if stage["tool_id"] == "nmap")
        args = TOOL_BY_ID["nmap"].command("shop.example.test", stage["options"])
        assert "-sV" in args
        if ports.get("ports", "").strip():
            assert args[args.index("-p") + 1] == "22,443"
        else:
            assert "-p" not in args and "-Pn" not in args
    assert client.get(f"{root}/audits").json() == []
    assert client.post(f"{root}/audits/preview", json={**draft, "root_domain": "other.test"}).status_code == 422
    assert client.post(f"{root}/scope", json={"kind": "domain", "value": "other.test"}).status_code == 201
    stale = client.post(f"{root}/audits", json={**draft, "plan_token": plan["plan_token"], "confirm_scope": True})
    assert stale.status_code == 409
    assert client.get(f"{root}/audits").json() == []


def test_full_surface_plan_runs_all_adapters_and_limits_discovered_targets(client, monkeypatch):
    from app import audit_plan
    from app.audit_runner import _targets
    from app.custom_commands import BUILTIN_WORDLIST
    from app.models import AuditRun, ScopeEntry
    from app.tool_registry import TOOL_BY_ID

    monkeypatch.setattr(audit_plan, "installed_version", lambda tool: tool.version.lstrip("v"))
    project = client.post("/api/projects", json={"name": "Full surface plan"}).json()
    root = f"/api/projects/{project['id']}"
    rules = [{"kind": "domain", "value": "*.example.test"},
             {"kind": "domain", "value": "blocked.example.test", "excluded": True}]
    for rule in rules:
        assert client.post(f"{root}/scope", json=rule).status_code == 201
    draft = {"target": "https://example.test/", "profile": "full", "additional_hosts": 1, "nuclei_mode": "baseline",
             "nmap_timeout_minutes": 45}
    response = client.post(f"{root}/audits/preview", json=draft)
    assert response.status_code == 200
    plan = response.json()
    stages = {stage["id"]: stage for stage in plan["stages"]}
    assert set(stages) == {"subfinder", "amass", "dnsx", "httpx", "nmap", "katana", "ffuf", "nuclei"}
    assert stages["ffuf"]["options"]["wordlist"] == str(BUILTIN_WORDLIST)
    assert "-w" in TOOL_BY_ID["ffuf"].command(plan["target"], stages["ffuf"]["options"])
    assert "-p" not in TOOL_BY_ID["nmap"].command("example.test", stages["nmap"]["options"])
    assert stages["nmap"]["options"]["timeout_minutes"] == 45
    assert plan["config"]["timeout_seconds"] == (30 + 2 * 45) * 60
    for payload in ({"target": "example.test"}, {"custom_command": "-sV example.test"}):
        scan = client.post(f"{root}/scan-jobs/preview", json={
            **payload, "tool_id": "nmap", "options": {"timeout_minutes": 45},
        })
        assert scan.status_code == 200
        assert scan.json()["limits"]["timeout_seconds"] == 2700
        assert "2692s" in scan.json()["command"] and "--stats-every" in scan.json()["command"]
    bad = client.post(f"{root}/scan-jobs/preview", json={
        "tool_id": "nmap", "target": "example.test", "options": {"timeout_minutes": 61},
    })
    assert bad.status_code == 422
    run = AuditRun(target=plan["target"], config=plan["config"])
    approved = [ScopeEntry(**rule) for rule in rules]
    found = {"api.example.test", "blocked.example.test", "extra.example.test", "unrelated.test"}
    assert _targets(stages["nmap"], run, found, [], approved) == ["example.test", "api.example.test"]
    assert stages["nmap"]["excluded_or_over_limit"] == 3
    assert _targets(stages["ffuf"], run, found, [plan["target"]], approved) == [plan["target"]]
    assert client.post(f"{root}/audits/preview", json={**draft, "nuclei_mode": "off"}).status_code == 422


def test_guided_audit_scopes_discovery_stops_blocked_origin_and_reports_evidence(client, monkeypatch):
    import json
    from email.message import Message

    from app import audit_plan, audit_runner, worker
    from app.import_service import store_import
    from app.models import ScanJob
    from app.scan_diagnostics import response_posture

    monkeypatch.setattr(audit_plan, "installed_version", lambda tool: tool.version.lstrip("v"))
    monkeypatch.setattr(audit_runner, "installed_version", lambda tool: tool.version.lstrip("v"))
    monkeypatch.setattr(worker.run_audit, "apply_async", lambda **kwargs: None)
    source = app.dependency_overrides[get_db]()
    try:
        sessions = sessionmaker(bind=next(source).get_bind(), autoflush=False, expire_on_commit=False)
    finally:
        source.close()
    monkeypatch.setattr(audit_runner, "SessionLocal", sessions)
    project_id = client.post("/api/projects", json={"name": "<Guided audit>"}).json()["id"]
    root = f"/api/projects/{project_id}"
    for rule in (
        {"kind": "domain", "value": "*.example.test"},
        {"kind": "domain", "value": "blocked.example.test", "excluded": True},
    ):
        assert client.post(f"{root}/scope", json=rule).status_code == 201
    draft = {"target": "https://app.example.test/", "profile": "domain", "root_domain": "example.test",
             "expand_subdomains": True, "additional_hosts": 1}
    plan = client.post(f"{root}/audits/preview", json=draft).json()
    payload = {**draft, "plan_token": plan["plan_token"], "confirm_scope": True}
    response = client.post(f"{root}/audits", json=payload)
    assert response.status_code == 202
    run_id = response.json()["id"]
    assert client.post(f"{root}/audits", json=payload).status_code == 429
    invocations = []
    headers = Message()
    headers["Content-Security-Policy"] = "default-src 'self'"
    headers["Set-Cookie"] = "session=private-token; Secure; HttpOnly; SameSite=Lax"
    posture = response_posture(draft["target"], headers)

    def execute(job_id, *, audit_deadline):
        with sessions.begin() as db:
            job = db.get(ScanJob, job_id)
            invocations.append((job.tool_id, job.target))
            result = {"status": "completed", "results": 1}
            if job.tool_id == "subfinder":
                result["discovered_hosts"] = ["a.example.test", "b.example.test", "blocked.example.test", "example.test.invalid"]
            if job.tool_id == "httpx":
                observation = {"url": job.target, "status": 200, "probe_status": 200, "redirect": None, "posture": posture}
                if job.target == draft["target"]:
                    result["http"] = observation
                else:
                    result.update(results=0, reachable={**observation, "address": "192.0.2.1", "source": "preflight"})
            if job.tool_id == "katana" and job.target == draft["target"]:
                result = {"status": "failed", "failure_kind": "blocked", "error": "HTTP 429. Honor Retry-After."}
            elif job.tool_id == "katana":
                result = {"status": "failed", "failure_kind": "blocked", "error": "Connection timed out.",
                          "diagnostic": {"category": "connection", "http_status": None}}
            if job.tool_id == "nuclei":
                findings = set()
                output = json.dumps({"template-id": "review-demo", "matched-at": job.target + "Demo?api_key=private-token",
                                     "info": {"name": "Test evidence", "severity": "medium", "remediation": "Review settings."}})
                batch = store_import(db, project_id, "nuclei_jsonl", f"scan-{job.id}-nuclei.jsonl",
                                     parse_import("nuclei_jsonl", output), commit=False, finding_ids=findings)
                job.result_summary = {"import_id": batch.id, "finding_ids": list(findings)}
            job.status = result["status"]
            job.results_count = result.get("results", 0)
            return result

    monkeypatch.setattr(audit_runner, "execute_scan", execute)
    assert audit_runner.execute_audit(run_id) == {"status": "partial"}
    run = client.get(f"{root}/audits/{run_id}").json()
    assert run["stages"][1]["excluded_or_over_limit"] == 3
    assert run["stages"][2]["executions"][1]["http"]["source"] == "preflight"
    assert run["stages"][3]["executions"][1]["status"] == "unreachable"
    assert ("dnsx", "example.test") in invocations
    assert ("httpx", "https://a.example.test/") in invocations
    assert ("nuclei", draft["target"]) not in invocations
    assert ("nuclei", "https://a.example.test/") in invocations
    assert all("blocked.example.test" not in target and "example.test.invalid" not in target for _, target in invocations)
    assert client.patch(f"{root}/audits/{run_id}/review/access", json={"status": "gap", "notes": "Tenant accounts pending"}).status_code == 200
    assert client.patch(f"{root}/audits/{run_id}/review/unknown", json={"status": "reviewed"}).status_code == 404
    finding = client.get(f"{root}/findings").json()[0]
    evidence = client.get(f"{root}/assets/{finding['asset_id']}/evidence").json()
    assert evidence["observations"][0]["job_id"] is not None
    updated = client.patch(f"{root}/findings/{finding['id']}", json={"status": "confirmed", "notes": "Verified <test>"})
    assert updated.status_code == 200
    report = client.get(f"{root}/audits/{run_id}/report/json").json()
    assert report["findings"][0]["status"] == "confirmed"
    assert report["findings"][0]["matched_at"].endswith("/Demo?api_key=")
    assert report["coverage"]["findings"] == 1
    assert any(check["status"] == "gap" for check in report["manual_checks"])
    html = client.get(f"{root}/audits/{run_id}/report/html").text
    assert "&lt;Guided audit&gt;" in html and "Verified &lt;test&gt;" in html and "Tenant accounts pending" in html
    assert "private-token" not in html and "private-token" not in json.dumps(report)
    assert posture["cookies"] == {"observed": 1, "secure": 1, "httponly": 1, "samesite": 1}
    assert posture["headers_present"]["content-security-policy"] is True


@pytest.mark.parametrize(("destination", "expected_path", "reason"), [
    ("https://app.example.test/portal", "https://app.example.test/portal", "queued for verification"),
    ("http://app.example.test/", None, "already checked"),
    ("https://other.example.test/", None, "different host"),
    ("https://app.example.test:9443/", None, "non-default port"),
    ("https://app.example.test/portal?ticket=", None, "query parameters"),
])
def test_audit_checks_redirect_destinations_before_scanning(client, monkeypatch, destination, expected_path, reason):
    from app import audit_plan, audit_runner, worker
    from app.models import ScanJob

    for module in (audit_plan, audit_runner):
        monkeypatch.setattr(module, "installed_version", lambda tool: tool.version.lstrip("v"))
    monkeypatch.setattr(worker.run_audit, "apply_async", lambda **kwargs: None)
    source = app.dependency_overrides[get_db]()
    try:
        sessions = sessionmaker(bind=next(source).get_bind(), autoflush=False, expire_on_commit=False)
    finally:
        source.close()
    monkeypatch.setattr(audit_runner, "SessionLocal", sessions)
    project_id = client.post("/api/projects", json={"name": "Redirect coverage"}).json()["id"]
    root = f"/api/projects/{project_id}"
    assert client.post(f"{root}/scope", json={"kind": "domain", "value": "*.example.test"}).status_code == 201
    target = "http://app.example.test/"
    draft = {"target": target, "profile": "web", "nuclei_mode": "off"}
    plan = client.post(f"{root}/audits/preview", json=draft).json()
    response = client.post(f"{root}/audits", json={**draft, "plan_token": plan["plan_token"], "confirm_scope": True})
    assert response.status_code == 202
    run_id = response.json()["id"]
    checked = []

    def execute(job_id, *, audit_deadline):
        with sessions.begin() as db:
            job = db.get(ScanJob, job_id)
            checked.append((job.tool_id, job.target))
            result = {"status": "completed", "results": 1}
            if job.tool_id == "httpx":
                status = 301 if job.target == target else 200
                result["http"] = {"status": status, "probe_status": status, "url": job.target,
                                  "redirect": destination if status == 301 else None}
            job.status = "completed"
            return result

    monkeypatch.setattr(audit_runner, "execute_scan", execute)
    outcome = audit_runner.execute_audit(run_id)
    executions = client.get(f"{root}/audits/{run_id}").json()["stages"][0]["executions"]
    assert reason in executions[0]["reason"]
    if expected_path:
        assert outcome["status"] == "completed"
        assert checked == [("httpx", target), ("httpx", expected_path), ("katana", expected_path)]
    else:
        assert outcome["status"] == "partial"
        assert checked == [("httpx", target)]


def test_www_downgrade_only_reuses_an_already_verified_https_url():
    from app.audit_runner import _verified_www_redirect

    www = "https://www.example.test/"
    verified = ["https://example.test/"]
    assert _verified_www_redirect(www, "http://example.test/", verified) == (
        "http://example.test/", "https://example.test/",
    )
    assert _verified_www_redirect(www, "http://example.test/other", verified) is None
    assert _verified_www_redirect(www, "http://example.test/?x=", verified) is None
    assert _verified_www_redirect(www, "http://example.test:8080/", verified) is None
    assert _verified_www_redirect("https://other.example.test/", "http://example.test/", verified) is None


def test_nuclei_flags_native_host_skip_and_uses_the_approved_budget():
    from app.scan_diagnostics import nuclei_stopped_for_network_errors
    from app.scan_runner import scan_timeout_seconds

    assert nuclei_stopped_for_network_errors(
        '[INF] Skipped example.test:443 from target list as found unresponsive permanently: cause="i/o timeout"'
    )
    assert not nuclei_stopped_for_network_errors('[INF] Scan completed in 12m. 0 matches found.')
    assert scan_timeout_seconds("nuclei", 1) == 1500
    assert scan_timeout_seconds("nuclei", 1, {"time_budget_seconds": 3600}) == 3600


def test_workflow_queue_survives_broker_error_and_terminal_run_cannot_replay(client, monkeypatch):
    from kombu.exceptions import OperationalError
    from app import main, worker, workflow_runner
    from app.models import ScanJob

    for module in (main, workflow_runner):
        monkeypatch.setattr(module, "installed_version", lambda tool: tool.version.lstrip("v"))
    source = app.dependency_overrides[get_db]()
    try:
        sessions = sessionmaker(bind=next(source).get_bind(), autoflush=False, expire_on_commit=False)
    finally:
        source.close()
    monkeypatch.setattr(workflow_runner, "SessionLocal", sessions)

    def broker_down(**kwargs):
        raise OperationalError("broker is offline")

    monkeypatch.setattr(worker.execute_workflow, "apply_async", broker_down)
    project_id = client.post("/api/projects", json={"name": "Workflow recovery"}).json()["id"]
    root = f"/api/projects/{project_id}"
    assert client.post(f"{root}/scope", json={"kind": "domain", "value": "example.test"}).status_code == 201
    workflow = client.post(f"{root}/workflows", json={"name": "DNS", "steps": [{"tool_id": "dnsx"}]})
    assert workflow.status_code == 201
    url = f"{root}/workflows/{workflow.json()['id']}/runs"
    payload = {"target": "example.test"}
    queued = client.post(url, json=payload)
    assert queued.status_code == 202 and queued.json()["task_id"] is None
    assert client.post(url, json=payload).status_code == 429
    run_id = queued.json()["id"]
    scans = []

    def execute(job_id):
        scans.append(job_id)
        with sessions.begin() as db:
            db.get(ScanJob, job_id).status = "completed"
        return {"status": "completed"}

    monkeypatch.setattr(workflow_runner, "execute_scan", execute)
    assert workflow_runner.execute_workflow(run_id) == {"status": "completed"}
    assert workflow_runner.execute_workflow(run_id) == {"status": "completed"}
    assert len(scans) == 1

    pending = client.post(url, json=payload).json()
    stopped = client.post(f"{root}/workflow-runs/{pending['id']}/cancel")
    assert stopped.json()["cancelled_jobs"] == 0
    assert workflow_runner.execute_workflow(pending["id"]) == {"status": "cancelled"}
    assert len(scans) == 1


def test_nmap_console_phase_does_not_reuse_previous_percent():
    from app.scan_diagnostics import nmap_progress

    report = "Connect Scan Timing: About 57.19% done; ETC: 16:35 (0:00:10 remaining)\n"
    assert nmap_progress(report) == {"phase": "Connect Scan", "phase_percent": 57.19, "phase_remaining_seconds": 10}
    assert nmap_progress(report + "Initiating Service scan at 16:35\n") == {"phase": "Service scan"}


def test_project_report_keeps_finding_dates_and_spreadsheet_text(client):
    import csv
    import io
    import json

    project_id = client.post("/api/projects", json={"name": "Report evidence"}).json()["id"]
    root = f"/api/projects/{project_id}"
    formula = "  =1+1"
    records = [
        {"template-id": "informational", "matched-at": "https://example.test/",
         "info": {"name": "Informational lead", "severity": "info"}},
        {"template-id": "medium-test", "matched-at": "https://example.test/",
         "info": {"name": formula, "severity": "medium"}},
    ]
    output = "\n".join(json.dumps(record) for record in records).encode()
    assert client.post(f"{root}/imports", data={"file_format": "nuclei_jsonl"},
                       files={"file": ("nuclei.jsonl", output)}).status_code == 201
    report = client.get(f"{root}/reports/json").json()
    assert [finding["severity"] for finding in report["findings"]] == ["medium", "info"]
    finding = report["findings"][0]
    assert finding["title"] == formula
    rows = csv.DictReader(io.StringIO(client.get(f"{root}/reports/csv").text))
    exported = next(row for row in rows if row["record_type"] == "finding")
    assert exported["value_or_title"] == "'" + formula
    assert exported["first_seen"] == finding["first_seen"]
    assert exported["last_seen"] == finding["last_seen"]


def test_focused_map_preserves_case_sensitive_web_routes(client):
    import json

    project_id = client.post("/api/projects", json={"name": "Web relationships"}).json()["id"]
    root = f"/api/projects/{project_id}"
    rows = [{"template-id": "demo", "matched-at": f"https://portal.example.test:8443/{path}?id=hidden",
             "info": {"name": "Demo match", "severity": "medium"}} for path in ("Admin", "admin")]
    for _ in range(2):
        result = client.post(f"{root}/imports", data={"file_format": "nuclei_jsonl"},
                             files={"file": ("scan.json", json.dumps(rows).encode())})
        assert result.status_code == 201
    assert len(client.get(f"{root}/findings").json()) == 2
    assets = client.get(f"{root}/assets").json()
    endpoint = next(asset for asset in assets if asset["canonical_value"].endswith("/Admin?id="))
    origin = next(asset for asset in assets if asset["asset_type"] == "web_origin")
    graph = client.get(f"{root}/graph", params={"focus_id": origin["id"]}).json()
    assert {node["type"] for node in graph["nodes"]} == {"domain", "web_origin", "endpoint"}
    assert {edge["type"] for edge in graph["edges"]} == {"serves_web", "contains_endpoint"}
    assert len(graph["nodes"]) == 4
    assert next(node for node in graph["nodes"] if node["id"] == str(endpoint["id"]))["findings"][0]["title"] == "Demo match"
    assert len(client.get(f"{root}/graph", params={"q": "/admin?id="}).json()["nodes"]) == 2
    assert client.get(f"/api/projects/999/assets/{endpoint['id']}/evidence").status_code == 404


def test_web_target_normalization_and_resolved_exclusions(monkeypatch):
    from app import scope_guard
    from app.models import ScopeEntry
    from app.tool_registry import TOOL_BY_ID

    assert scope_guard.normalize_web_target("http://[2001:db8::1]:8443/Api?a=1#page") == "http://[2001:db8::1]:8443/Api?a=1"
    assert scope_guard.normalize_web_target("https://BÜCHER.example:443/Api") == "https://xn--bcher-kva.example/Api"
    for target in ("http://user:secret@example.test/", "http://127.1/", "http://0x7f000001/"):
        with pytest.raises(ValueError):
            scope_guard.normalize_web_target(target)
    monkeypatch.setattr(scope_guard.socket, "getaddrinfo", lambda *args, **kwargs: [(0, 0, 0, "", ("::ffff:192.0.2.4", 0))])
    with pytest.raises(ValueError, match="excluded"):
        scope_guard.check_resolved_exclusions("https://api.example.test/", [
            ScopeEntry(kind="cidr", value="192.0.2.0/24", excluded=True),
        ])
    command = TOOL_BY_ID["nuclei"].command("https://api.example.test/", {
        "template_id": "nginx-version", "raw_arguments": "-exclude-tags experimental", "rate": 2,
    })
    assert command[command.index("-id") + 1] == "nginx-version"
    assert {"dos", "fuzz", "intrusive", "experimental"} == set(command[command.index("-etags") + 1].split(","))


def test_nmap_modes_and_filtered_report_distinguish_reachability():
    from app.tool_registry import TOOL_BY_ID

    nmap = TOOL_BY_ID["nmap"]
    default = nmap.command("192.0.2.8")
    assert "-sV" in default and not {"-p", "-Pn", "--top-ports", "-F"}.intersection(default)
    discovery = nmap.command("192.0.2.0/24", {"mode": "discovery"})
    assert "-sn" in discovery and "-Pn" not in discovery and "-sV" not in discovery
    ports = nmap.command("192.0.2.8", {"mode": "ports", "ports": "443"})
    assert ports[ports.index("-p") + 1] == "443"
    with pytest.raises(ValueError, match="TCP port"):
        nmap.command("192.0.2.8", {"mode": "ports"})
    xml = '''<nmaprun><host><status state="up" reason="syn-ack"/>
      <address addr="192.0.2.8" addrtype="ipv4"/>
      <address addr="00:00:00:00:00:01" addrtype="mac" vendor="Test"/>
      <ports>
        <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="nginx" version="1.27.5" ostype="Linux"/></port>
        <port protocol="tcp" portid="8080"><state state="filtered" reason="no-response"/></port>
        <port protocol="tcp" portid="22"><state state="closed" reason="reset"/></port>
        <extraports state="filtered" count="2"><extrareasons reason="no-response" count="2" proto="tcp" ports="80,8443"/></extraports>
        <extraports state="closed" count="30"/>
      </ports>
      <os><osmatch name="Linux 6" accuracy="95"/></os>
    </host><host><status state="down"/><address addr="192.0.2.9" addrtype="ipv4"/></host></nmaprun>'''
    records = parse_import("nmap_xml", xml).records
    assert [row.asset_type for row in records] == ["ipv4", "service", "filtered_port", "ipv4"]
    assert records[0].data["os_matches"] == [{"name": "Linux 6", "accuracy": "95"}]
    assert records[0].data["hardware"][0]["vendor"] == "Test"
    assert records[1].data["version"] == "1.27.5"
    assert records[2].data["state"] == "filtered" and "version" not in records[2].data
    assert records[3].data["groups"][0]["ports"] == "80,8443"


def test_web_probe_falls_back_from_ipv6_and_preserves_http_host(monkeypatch):
    import socket
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    from app.scan_diagnostics import ScanBlocked, web_preflight

    observed = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            observed.append((self.path, self.headers["Host"]))
            self.send_response(429 if self.path == "/limited" else 302)
            self.send_header("Retry-After", "90")
            self.send_header("Location", "http://different.example.test/")
            self.end_headers()

        def log_message(self, *_):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        port = server.server_port
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [
            (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", port, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", port)),
        ])
        root = f"http://app.example.test:{port}"
        events = []
        try:
            probe = web_preflight(root + "/start", events.append)
            assert probe.status == 302 and probe.address == "127.0.0.1"
            assert observed == [("/start", f"app.example.test:{port}")]
            assert any("IPv6 ::1" in event for event in events)
            with pytest.raises(ScanBlocked, match="90") as blocked:
                web_preflight(root + "/limited")
            assert blocked.value.category == "rate_limit" and blocked.value.status == 429
            assert len(observed) == 2
        finally:
            server.shutdown()
            worker.join(timeout=2)


def test_command_editor_validates_each_adapter_and_scope(client, monkeypatch, tmp_path):
    from app import custom_commands
    from app import main as api

    monkeypatch.setattr(api, "installed_version", lambda tool: tool.version.lstrip("v"))
    monkeypatch.setattr(custom_commands, "WORDLIST_ROOT", tmp_path)
    wordlist = tmp_path / "smoke paths.txt"
    wordlist.write_text("health\n", encoding="utf-8")
    project = client.post("/api/projects", json={"name": "Command editor"}).json()
    root = f"/api/projects/{project['id']}"
    client.post(root + "/scope", json={"kind": "domain", "value": "example.test"})
    commands = {
        "nmap": "-sV -p80,443 -T3 example.test",
        "subfinder": "-d example.test -recursive -s crtsh",
        "dnsx": "-l example.test -mx -txt",
        "httpx": "-u https://example.test/ -title -rl=1",
        "amass": "enum -d example.test -passive",
        "nuclei": "-u https://example.test/ -id nginx-version -s info -rl 2",
        "katana": "-u https://example.test/ -d 3 -kf robotstxt",
        "ffuf": f'-u https://example.test/search?q=FUZZ -w "{wordlist.as_posix()}" -mc 200-299,403',
    }
    for tool, custom in commands.items():
        response = client.post(root + "/scan-jobs/preview", json={"tool_id": tool, "custom_command": custom})
        assert response.status_code == 200, response.text
        assert response.json()["scope_checked"]
        assert response.json()["command"][0] == tool
    nmap = client.post(root + "/scan-jobs/preview", json={"tool_id": "nmap", "custom_command": commands["nmap"]}).json()
    assert nmap["command"][nmap["command"].index("-p") + 1] == "80,443"
    for tool, custom in [
        ("nmap", "-sn -p443 example.test"),
        ("nmap", "-p99999 example.test"),
        ("nmap", "-sT other.test"),
        ("nmap", "-p443 example.test other.test"),
        ("nmap", "-oX /tmp/override.xml example.test"),
        ("httpx", "-u https://example.test -rl 40"),
        ("httpx", "-u https://example.test -fr"),
        ("nuclei", "-u https://example.test -t custom.yaml"),
        ("ffuf", f'-u https://FUZZ.example.test/ -w "{wordlist.as_posix()}"'),
    ]:
        response = client.post(root + "/scan-jobs/preview", json={"tool_id": tool, "custom_command": custom})
        assert response.status_code == 422, (custom, response.text)


def test_project_edit_duplicate_search_and_delete(client):
    project = client.post("/api/projects", json={"name": "Original"}).json()
    root = f"/api/projects/{project['id']}"
    assert client.patch(root, json={"name": "Renamed", "description": "Engagement"}).json()["name"] == "Renamed"
    assert client.post(root + "/scope", json={"kind": "domain", "value": "example.test"}).status_code == 201
    assert client.post(root + "/scope", json={"kind": "domain", "value": "dev.example.test", "excluded": True}).status_code == 201
    assert client.put(root + "/scope/full-access", params={"enabled": True}).status_code == 204
    clone = client.post(root + "/duplicate", json={"name": "Scope copy"})
    assert clone.status_code == 201
    assert {rule["value"] for rule in clone.json()["scopes"]} == {"example.test", "dev.example.test"}
    assert client.post(root + "/imports", data={"file_format": "subfinder"}, files={"file": ("test.txt", b"api.example.test\n")}).status_code == 201
    assert client.get(root + "/search", params={"q": "api.example"}).json()["assets"][0]["label"] == "api.example.test"
    clone_root = f"/api/projects/{clone.json()['id']}"
    assert client.get(clone_root + "/search", params={"q": "api.example"}).json()["assets"] == []
    assert client.delete(clone_root).status_code == 204
    assert client.get(clone_root).status_code == 404
    assert client.get(root).status_code == 200


def test_observed_map_links_subdomains_to_their_nearest_known_parent(client):
    project_id = client.post("/api/projects", json={"name": "Subdomain hierarchy"}).json()["id"]
    root = f"/api/projects/{project_id}"
    names = "example.test\nwww.example.test\napi.example.test\nv2.api.example.test\notherexample.test\n"
    result = client.post(root + "/imports", data={"file_format": "subfinder"}, files={"file": ("domains.txt", names)})
    assert result.status_code == 201
    graph = client.get(root + "/graph").json()
    by_id = {node["id"]: node["label"] for node in graph["nodes"]}
    assert {(by_id[edge["source"]], by_id[edge["target"]]) for edge in graph["edges"]} == {
        ("example.test", "www.example.test"), ("example.test", "api.example.test"),
        ("api.example.test", "v2.api.example.test"),
    }
    assert all(edge["type"] == "has_subdomain" and edge["evidence"]["basis"] == "hostname_suffix"
               for edge in graph["edges"])
    child = next(key for key, label in by_id.items() if label == "v2.api.example.test")
    focused = client.get(root + "/graph", params={"focus_id": child, "hops": 2}).json()
    assert {node["label"] for node in focused["nodes"]} == {"example.test", "api.example.test", "v2.api.example.test"}
    copy = client.post(root + "/surface-drafts/from-observations").json()
    assert len(copy["links"]) == 3
    assert all(link["relation"] == "Has subdomain" and link["notes"] for link in copy["links"])


def test_repeated_observation_remains_visible_in_its_audit_graph(client):
    import json

    from app.import_service import store_import
    from app.models import AuditRun, ScanJob

    project_id = client.post("/api/projects", json={"name": "Sighting lineage"}).json()["id"]
    root = f"/api/projects/{project_id}"
    source = app.dependency_overrides[get_db]()
    try:
        db = next(source)
        run = AuditRun(project_id=project_id, profile="web", target="https://example.test/", status="completed")
        db.add(run)
        db.flush()
        run_id = run.id
        httpx = json.dumps({"url": "https://example.test/", "status_code": 200,
                            "host_ip": "192.0.2.10", "a": ["192.0.2.10"]})
        parsed = parse_import("httpx_jsonl", httpx)
        store_import(db, project_id, "httpx_jsonl", "first.jsonl", parsed)
        batch = store_import(db, project_id, "httpx_jsonl", "second.jsonl", parsed, commit=False)
        db.add(ScanJob(project_id=project_id, audit_run_id=run.id, tool_id="httpx", target=run.target,
                       status="completed", result_summary={"import_id": batch.id}))
        store_import(db, project_id, "subfinder", "unrelated.txt", parse_import("subfinder", "other.test"))
    finally:
        source.close()
    graph = client.get(root + "/graph", params={"audit_id": run_id}).json()
    assert not graph["historical"]
    assert {node["type"] for node in graph["nodes"]} == {"domain", "ipv4", "web_origin"}
    assert {edge["type"] for edge in graph["edges"]} == {"serves_web", "responded_from"}
    ip = next(node["id"] for node in graph["nodes"] if node["type"] == "ipv4")
    focused = client.get(root + "/graph", params={"audit_id": run_id, "focus_id": ip, "hops": 2}).json()
    assert len(focused["nodes"]) == 3

    copy_url = root + "/surface-drafts/from-observations"
    positions = {node["id"]: {"x": index * 150, "y": 220} for index, node in enumerate(graph["nodes"])}
    copied = client.post(copy_url, params={"audit_id": run_id}, json={"positions": positions})
    assert copied.status_code == 200
    draft = copied.json()
    assert draft["source_key"] == f"audit:{run_id}"
    assert {node["observed_asset_id"] for node in draft["nodes"]} == {int(node["id"]) for node in graph["nodes"]}
    assert {node["id"]: {"x": node["x"], "y": node["y"]} for node in draft["nodes"]} == positions
    assert {link["relation"] for link in draft["links"]} == {"Hosts web origin", "Responded from"}
    ip_node = next(node for node in draft["nodes"] if node["id"] == ip)
    ip_node["label"] = "Reviewed address"
    ip_node["x"] = 99
    draft["links"][0]["relation"] = "Confirmed relationship"
    saved = client.put(f"{root}/surface-drafts/{draft['id']}", json=draft)
    assert saved.status_code == 200
    reopened = client.post(copy_url, params={"audit_id": run_id}).json()
    assert reopened == saved.json()
    assert any(node["label"] == "Reviewed address" and node["x"] == 99 for node in reopened["nodes"])
    assert reopened["links"][0]["relation"] == "Confirmed relationship"
    assert client.get(root + "/graph", params={"audit_id": run_id}).json() == graph
    project_copy = client.post(copy_url).json()
    assert project_copy["source_key"] == "project" and project_copy["id"] != reopened["id"]
    assert any(node["value"] == "other.test" for node in project_copy["nodes"])
    assert client.post(copy_url, params={"audit_id": run_id + 1}).status_code == 404


def test_audit_comparison_uses_run_observations_and_scope(client):
    import json

    from app.import_service import store_import
    from app.models import AuditRun, ObservationSighting, ScanJob
    from sqlalchemy import delete

    project_id = client.post("/api/projects", json={"name": "Compare audits"}).json()["id"]
    root = f"/api/projects/{project_id}"
    other = client.post("/api/projects", json={"name": "Outside comparison"}).json()["id"]
    source = app.dependency_overrides[get_db]()
    try:
        db = next(source)

        def add_audit(server, route):
            run = AuditRun(project_id=project_id, profile="web", target="https://example.test/", status="completed")
            db.add(run)
            db.flush()
            payloads = {
                "httpx": ("httpx_jsonl", [{"url": run.target, "webserver": server, "status_code": 200}]),
                "katana": ("katana_jsonl", [{"request": {"endpoint": run.target + path, "method": "GET"},
                                            "response": {"status_code": 200}} for path in ("stable", route)]),
                "nuclei": ("nuclei_jsonl", [{"template-id": "check-" + route, "matched-at": run.target + route,
                                            "info": {"name": route, "severity": "low"}}]),
            }
            for tool, (format_name, records) in payloads.items():
                finding_ids = set()
                batch = store_import(db, project_id, format_name, f"{tool}-{route}.jsonl",
                                     parse_import(format_name, json.dumps(records)), commit=False, finding_ids=finding_ids)
                db.add(ScanJob(project_id=project_id, audit_run_id=run.id, tool_id=tool, target=run.target,
                               tool_version="1.0", status="completed",
                               result_summary={"import_id": batch.id, "finding_ids": sorted(finding_ids)}))
            db.commit()
            return run.id

        first_id = add_audit("nginx/1", "before")
        second_id = add_audit("nginx/2", "after")
        store_import(db, project_id, "httpx_jsonl", "later.jsonl", parse_import("httpx_jsonl",
            '{"url":"https://example.test/","webserver":"nginx/3","status_code":200}'))
    finally:
        source.close()
    url = root + f"/audits/{second_id}/compare/{first_id}"
    response = client.get(url)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["coverage"]["aligned"] and data["coverage"]["shared_checks"] == 3
    assert [row["value"] for row in data["assets"]["new"]] == ["https://example.test/after"]
    assert [row["value"] for row in data["assets"]["only_before"]] == ["https://example.test/before"]
    assert [row["title"] for row in data["findings"]["new"]] == ["after"]
    assert [row["title"] for row in client.get(root + "/findings", params={"audit_id": first_id}).json()] == ["before"]
    changes = data["changed_details"]
    assert len(changes) == 1
    assert changes[0]["before"][0]["webserver"] == "nginx/1"
    assert changes[0]["after"][0]["webserver"] == "nginx/2"
    assert "attachment" in client.get(url, params={"download": True}).headers["content-disposition"]
    assert client.get(url.replace(f"projects/{project_id}", f"projects/{other}")).status_code == 404
    stable = next(node for node in client.get(root + "/graph", params={"audit_id": second_id}).json()["nodes"]
                  if node["canonical_value"] == "https://example.test/stable")
    provenance = client.get(root + f"/assets/{stable['id']}/evidence", params={"audit_id": second_id}).json()
    assert [row["filename"] for row in provenance["observations"]] == ["katana-after.jsonl"]

    source = app.dependency_overrides[get_db]()
    try:
        db = next(source)
        db.execute(delete(ObservationSighting))
        run = db.get(AuditRun, first_id)
        run.status = "partial"
        db.commit()
    finally:
        source.close()
    older = client.get(url).json()
    assert not older["coverage"]["aligned"]
    assert older["coverage"]["historical_details"]
    assert older["changed_details"] == []


def test_finding_retest_binds_template_and_route(client, monkeypatch):
    from app import main as api, worker

    monkeypatch.setattr(api, "installed_version", lambda tool: tool.version.lstrip("v"))
    monkeypatch.setattr(worker, "dispatch_scan", lambda *_: None)
    project_id = client.post("/api/projects", json={"name": "Retest original"}).json()["id"]
    root = f"/api/projects/{project_id}"
    client.post(root + "/scope", json={"kind": "domain", "value": "example.test"})
    artifact = b'{"template-id":"test-check","matched-at":"https://example.test/Path?id=value","info":{"name":"Demo","severity":"medium"}}'
    assert client.post(root + "/imports", data={"file_format": "nuclei_jsonl"},
                       files={"file": ("finding.jsonl", artifact)}).status_code == 201
    finding = client.get(root + "/findings").json()[0]
    draft = {"tool_id": "nuclei", "target": "https://example.test/Path?id=representative",
             "retest_finding_id": finding["id"], "options": {"rate": 1}}
    preview = client.post(root + "/scan-jobs/preview", json=draft)
    assert preview.status_code == 200, preview.text
    argv = preview.json()["command"]
    assert argv[argv.index("-id") + 1] == "test-check"
    for update in [{"tool_id": "httpx"}, {"target": "https://example.test/path?id=representative"},
                   {"target": finding["matched_at"]}, {"options": {"template_id": "other-check"}}]:
        assert client.post(root + "/scan-jobs/preview", json={**draft, **update}).status_code == 422
    other = client.post("/api/projects", json={"name": "Outside retest"}).json()["id"]
    assert client.post(f"/api/projects/{other}/scan-jobs/preview", json=draft).status_code == 404
    created = client.post(root + "/scan-jobs", json=draft)
    assert created.status_code == 202, created.text
    retests = client.get(root + f"/findings/{finding['id']}/retests").json()
    assert retests[0]["id"] == created.json()["id"] and retests[0]["result"]["outcome"] == "pending"
    assert client.get(root + "/findings").json()[0]["status"] == "open"


def test_retest_requires_evidence_for_a_negative_result():
    from app.importers import ParseResult
    from app.retests import evaluate_retest

    args = ("check", "https://example.test/Path")
    stats = {"templates": "1", "requests": "2", "total": "2", "errors": "0"}
    assert evaluate_retest(*args, ParseResult(), stats, 200)["outcome"] == "not_reproduced"
    assert evaluate_retest(*args, ParseResult(), stats, 301)["outcome"] == "inconclusive"
    assert evaluate_retest(*args, ParseResult(), {**stats, "requests": "1"}, 200)["outcome"] == "inconclusive"
    assert evaluate_retest(*args, ParseResult(), {**stats, "errors": "1"}, 200)["outcome"] == "inconclusive"
    assert evaluate_retest(*args, ParseResult(), stats, 200, source_known=False)["outcome"] == "inconclusive"
    match = b'{"template-id":"check","matched-at":"https://example.test/Path","matcher-name":"matcher","info":{"name":"Demo","severity":"low"}}'
    parsed = parse_import("nuclei_jsonl", match.decode())
    assert evaluate_retest(*args, parsed, {}, 200)["matchers"] == ["matcher"]
    assert evaluate_retest("check", "https://example.test/", parsed, stats, 200,
                           expected_match="https://example.test/Path")["outcome"] == "reproduced"
    different = parse_import("nuclei_jsonl", match.decode().replace("/Path", "/path"))
    assert evaluate_retest(*args, different, stats, 200)["outcome"] == "inconclusive"


def test_comparison_reconstructs_deduplicated_membership_from_archived_scan(client, monkeypatch, tmp_path):
    from sqlalchemy import delete
    from app import scan_runner
    from app.import_service import store_import
    from app.models import AssetSighting, AuditRun, ScanJob

    monkeypatch.setattr(scan_runner, "ARTIFACT_ROOT", tmp_path)
    project_id = client.post("/api/projects", json={"name": "Archived audits"}).json()["id"]
    root = f"/api/projects/{project_id}"
    source = app.dependency_overrides[get_db]()
    try:
        db = next(source)
        store_import(db, project_id, "subfinder", "pre-existing.txt", parse_import("subfinder", "shared.example.test"))

        def add_run(output, archive):
            run = AuditRun(project_id=project_id, profile="passive", target="example.test", status="completed")
            db.add(run)
            db.flush()
            parsed = parse_import("subfinder", output)
            batch = store_import(db, project_id, "subfinder", "discovery.txt", parsed, commit=False)
            job = ScanJob(project_id=project_id, audit_run_id=run.id, tool_id="subfinder", target=run.target,
                          status="completed", results_count=len(parsed.records), result_summary={"import_id": batch.id})
            db.add(job)
            db.flush()
            path = tmp_path / f"project-{project_id}" / f"scan-{job.id}" / "output.txt"
            if archive:
                path.parent.mkdir(parents=True)
                path.write_text(output, encoding="utf-8")
                job.artifact_path = str(path)
                db.execute(delete(AssetSighting).where(AssetSighting.import_id == batch.id))
            db.commit()
            return run.id, path

        baseline, path = add_run("shared.example.test\nold.example.test\n", True)
        current, _ = add_run("shared.example.test\nnew.example.test\n", False)
    finally:
        source.close()
    url = root + f"/audits/{current}/compare/{baseline}"
    result = client.get(url).json()
    assert result["coverage"]["recovered_membership"] and not result["coverage"]["historical_membership"]
    assert result["assets"]["shared_count"] == 1
    assert [row["value"] for row in result["assets"]["new"]] == ["new.example.test"]
    path.unlink()
    assert client.get(url).json()["coverage"]["historical_membership"]
