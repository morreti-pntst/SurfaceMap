import { useEffect, useMemo, useRef, useState } from 'react'

import cytoscape, { type Core } from 'cytoscape'

import { ArrowLeft, ArrowRight, Box, CircleHelp, Download, FileCode2, Globe2, Image, Network, RefreshCw, Search, Shield, Target, ZoomIn, ZoomOut } from 'lucide-react'
import type { ScanSeed } from './ScanJobsPage'
import type { SurfacePositions } from './BuilderCanvas'
import FindingVerification from './FindingVerification'
import {emptyMapVisibility, persistMapVisibility, readMapVisibility, type MapVisibility} from './mapVisibility'

type MapFinding = { id: number; title: string; severity: string; status: string;
  template_id: string; matched_at: string; matchers: string[] }

type MapNode = { id: string; label: string; canonical_value?: string; type: string; first_seen: string; last_seen: string; findings: MapFinding[]; sources: string[]; facts?: Record<string, string | number>; wrapped_host?: string }

type MapEdge = { id: string; source: string; target: string; type: string; first_seen?: string; last_seen?: string; evidence?: Record<string, unknown> }

type WrappedPort = {host_id: string; protocol: string; port: number; first_seen: string; last_seen: string}
type GraphData = { nodes: MapNode[]; edges: MapEdge[]; truncated: boolean; historical?: boolean; wrapped_truncated?: boolean }
type GraphResponse = GraphData & {wrapped_ports?: WrappedPort[]}
type AssetEvidence = {
  observations: { id: number; import_id: number; source: string; kind: string; filename: string; job_id: number | null; observed_at: string; data: Record<string, unknown> }[]
  truncated: boolean
}
const typeNames: Record<string, string> = {
  domain: 'Domain', ipv4: 'IPv4 address', ipv6: 'IPv6 address', service: 'Open port',
  filtered_port: 'Filtered port', wrapped_port: 'tcpwrapped port', web_origin: 'Web origin', endpoint: 'Web route',
}
const relationshipNames: Record<string, string> = {
  resolves_to: 'DNS resolves to', aliases_to: 'DNS alias', exposes: 'Reported open',
  serves_web: 'Hosts web origin', contains_endpoint: 'Contains route',
  endpoint_host: 'Hosted on', has_filtered_port: 'Filtered port', related_to: 'Related to',
  responded_from: 'Responded from', hosts: 'Hosts', serves: 'Serves', redirects_to: 'Redirects to', depends_on: 'Depends on',
  has_subdomain: 'Has subdomain', has_wrapped_port: 'Reported tcpwrapped',
}
const relationName = (type: string) => relationshipNames[type] ?? type.replaceAll('_', ' ')
const unidentified = (node: MapNode) => node.type === 'service' && node.facts?.identification === 'unidentified'
const inUnidentifiedGroup = (node: MapNode) => unidentified(node) ||
  (node.type === 'service' && node.facts?.name === 'domain')
const nodeTypeName = (node: MapNode) => unidentified(node) ? 'Open when scanned · service unknown'
  : typeNames[node.type] ?? node.type.replaceAll('_', ' ')

function expandWrappedPorts({wrapped_ports = [], ...graph}: GraphResponse): GraphData {
  const hosts = new Map(graph.nodes.map(node => [node.id, nodeValue(node)]))
  const nodes: MapNode[] = []
  const edges: MapEdge[] = []
  for (const port of wrapped_ports) {
    const host = hosts.get(port.host_id)
    if (!host) continue
    const socket = port.protocol + '/' + port.port
    const id = ['wrapped', port.host_id, port.protocol, port.port].join('-')
    nodes.push({id, label: socket + ' · tcpwrapped', canonical_value: host + '|' + socket,
      type: 'wrapped_port', wrapped_host: port.host_id, first_seen: port.first_seen, last_seen: port.last_seen,
      sources: ['nmap_xml'], findings: [], facts: {name: 'tcpwrapped', port: port.port, protocol: port.protocol}})
    edges.push({id, source: port.host_id, target: id, type: 'has_wrapped_port',
      first_seen: port.first_seen, last_seen: port.last_seen})
  }
  return {...graph, nodes: [...graph.nodes, ...nodes], edges: [...graph.edges, ...edges]}
}

function EvidenceSummary({data, kind}: {data: Record<string, unknown>; kind: string}) {
  const fields: [string, string][] = []
  const add = (key: string, value: unknown) => {
    if (value !== null && value !== undefined && value !== '') fields.push([key, String(value)])
  }
  if (kind === 'nmap_port') {
    add('State', data.state)
    if (data.method === 'table') add('Port-number hint', data.name)
    else add('Service', [data.name, data.product, data.version].filter(Boolean).join(' '))
    add('OS indicated by service', data.ostype)
    add('Device type', data.devicetype)
    add('Reason', data.reason)
  }
  if (kind === 'nmap_host') {
    if (Array.isArray(data.hostnames)) add('Hostnames', data.hostnames.join(', '))
    if (Array.isArray(data.os_matches)) add('OS matches', data.os_matches.map(item => item.name + ' (' + item.accuracy + '%)').join(', '))
    if (Array.isArray(data.hardware)) add('MAC and vendor', data.hardware.map(item => [item.mac, item.vendor].filter(Boolean).join(' ')).join(', '))
    add('Discovery', data.discovery_reason === 'user-set' ? 'Host assumed reachable for this scan' : data.discovery_reason)
  }
  if (kind === 'nmap_filtered_group') {
    add('Filtered ports', data.count)
    if (Array.isArray(data.groups)) {
      const ranges = data.groups.flatMap(group => String(group.ports ?? '').split(',')).filter(Boolean)
      add('Known port numbers', ranges.slice(0, 12).join(', ') + (ranges.length > 12 ? ' … See observation for all ranges.' : ''))
    }
  }
  if (kind === 'nmap_wrapped_ports') add('Unidentified ports (tcpwrapped)', data.count)
  if (kind === 'http_service') {
    add('HTTP', data.status_code)
    add('Server', data.webserver)
    add('Connected IP', data.host_ip)
    if (Array.isArray(data.tech)) add('Technologies', data.tech.join(', '))
  }
  if (kind === 'web_endpoint' || kind === 'ffuf_endpoint') {
    add('HTTP', data.status_code ?? data.status)
    add('Method', data.method)
  }
  return fields.length ? <dl className="asset-facts">{fields.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl> : null
}

function ObservedEvidence({projectId, nodeId, auditId, wrappedPort}: {
  projectId: number; nodeId: string; auditId?: number; wrappedPort?: string
}) {
  const [data, setData] = useState<AssetEvidence>()
  const [error, setError] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    fetch('/api/projects/' + projectId + '/assets/' + nodeId + '/evidence' + (auditId ? '?audit_id=' + auditId : ''), {signal: controller.signal})
      .then(async response => {
        if (!response.ok) throw new Error('Could not load asset evidence.')
        const payload = await response.json()
        if (!controller.signal.aborted) setData(payload)
      })
      .catch(() => { if (!controller.signal.aborted) setError('Could not load asset evidence.') })
    return () => controller.abort()
  }, [projectId, nodeId, auditId])
  const observations = (data?.observations ?? []).filter(item => !wrappedPort || (
    item.kind === 'nmap_wrapped_ports' && Array.isArray(item.data.ports) && item.data.ports.includes(wrappedPort)
  ))
  return <div className="asset-evidence neighbor-list">
    <b>{wrappedPort ? 'NMAP EVIDENCE' : 'OBSERVATIONS'}</b>
    {error && <small role="alert">{error}</small>}
    {!data && !error && <small>Loading observations…</small>}
    {observations.filter((item, index, list) => list.findIndex(other => other.kind === item.kind) === index)
      .map(item => <EvidenceSummary key={item.id} data={item.data} kind={item.kind}/>)}
    {observations.map(item => <details key={item.id + ':' + item.import_id}>
      <summary>{item.kind.replaceAll('_', ' ')} · {item.source}{item.job_id ? ' · Scan #' + item.job_id : ''}</summary>
      <small>{item.filename} · {new Date(item.observed_at).toLocaleString()}</small>
      <pre>{JSON.stringify(item.data, null, 2)}</pre>
    </details>)}
    {data && !observations.length && <small>{wrappedPort ? 'No matching grouped record in the latest host observations.'
      : auditId ? 'No observation payload was retained for this node in the selected audit.' : 'This node was inferred from a relationship.'}</small>}
    {data?.truncated && <small>Latest 30 observations shown.</small>}
  </div>
}


const severityOrder = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
const isOpen = (finding: MapFinding) => finding.status === 'open' || finding.status === 'confirmed'
function MapFindingReview({finding, onOpen}: {finding: MapFinding; onOpen: () => void}) {
  return <details className="map-finding-review">
    <summary><span className={'severity severity-' + finding.severity}>{finding.severity}</span><span>{finding.title}</span></summary>
    <FindingVerification templateId={finding.template_id} target={finding.matched_at} matchers={finding.matchers}/>
    <button className="button secondary compact" onClick={onOpen}>Open evidence and retest <ArrowRight size={13}/></button>
  </details>
}
const nodeValue = (node: MapNode) => node.canonical_value ?? node.label
const routeStatus = (node: MapNode) => node.facts?.status_code ?? node.facts?.status
const lanes = [['domain'], ['web_origin'], ['ipv4', 'ipv6'], ['service', 'filtered_port'], ['endpoint']]
const colors: Record<string, string> = {
  domain: '#a1b2ef', ipv4: '#71d1ad', ipv6: '#71d1ad', service: '#e9b272',
  filtered_port: '#a9967c', wrapped_port: '#a49cbb', web_origin: '#62d2e9', endpoint: '#c69bf1',
}
type MapView = 'topology' | 'routes' | 'risk'
type AuditOption = {id: number; target: string; status: string}

function topologyPositions(nodes: MapNode[], edges: MapEdge[], width: number, references: Set<string>) {
  const degree = new Map<string, number>()
  for (const edge of edges) {
    if (edge.type === 'has_wrapped_port') continue
    degree.set(edge.source, (degree.get(edge.source) ?? 0) + 1)
    degree.set(edge.target, (degree.get(edge.target) ?? 0) + 1)
  }
  const columns = Math.max(2, Math.min(6, Math.floor(width / 184)))
  const positions: Record<string, {x: number; y: number}> = {}
  const layoutNodes = nodes.filter(node => !node.wrapped_host && !unidentified(node))
  const subdomains = new Set(edges.filter(edge => edge.type === 'has_subdomain').map(edge => edge.target))
  let y = 0
  const unknown = [...new Set(layoutNodes.map(node => node.type))].filter(type => !lanes.some(lane => lane.includes(type)))
  for (const referenceGroup of [false, true]) {
    for (const lane of [...lanes, unknown]) {
      const group = layoutNodes.filter(node => lane.includes(node.type) && references.has(node.id) === referenceGroup)
        .sort((a, b) => lane[0] === 'endpoint' ? nodeValue(a).localeCompare(nodeValue(b))
          : (degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0) || a.label.localeCompare(b.label))
      if (!group.length) continue
      const bands = lane[0] === 'domain'
        ? [group.filter(node => !subdomains.has(node.id)), group.filter(node => subdomains.has(node.id))]
        : [group]
      for (const band of bands) {
        for (let i = 0; i < band.length; i += columns) {
          const row = band.slice(i, i + columns)
          row.forEach((node, column) => {positions[node.id] = {x: (column - (row.length - 1) / 2) * 184, y}})
          y += 68
        }
      }
      y += 36
    }
  }
  const unknownPorts = nodes.filter(unidentified).sort((a, b) =>
    a.label.localeCompare(b.label, undefined, {numeric: true}))
  unknownPorts.forEach((node, index) => {
    positions[node.id] = {x: (index % columns - (columns - 1) / 2) * 184, y: y + Math.floor(index / columns) * 68}
  })
  return positions
}

function layoutWrappedPorts(cy: Core, columns: number) {
  const base = cy.nodes('[type != "wrapped_port"]')
  const end = Math.max(0, ...base.map(node => node.hasClass('user-hidden') ? 0 : node.position('y')))
  const ports = cy.nodes('[type = "wrapped_port"]').not('.user-hidden')
  ports.positions((_, index) => ({x: (index % columns - (columns - 1) / 2) * 184,
    y: end + 108 + Math.floor(index / columns) * 60}))
}

function canvasLabel(node: MapNode) {
  if (node.type !== 'endpoint') return node.label
  try {
    const url = new URL(nodeValue(node))
    return url.pathname + url.search
  } catch {
    return node.label
  }
}

function relationshipLabel(edge: MapEdge, source?: MapNode) {
  if (edge.type === 'resolves_to' && source?.type === 'web_origin') return 'DNS address'
  return relationName(edge.type)
}

function saveFile(name: string, blob: Blob) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = name
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function saveSvg(cy: Core, filename: string) {
  const nodes = cy.nodes(':visible')
  if (!nodes.length) return
  const safe = (value: unknown) => String(value).replace(/[&<>"']/g, char =>
    ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;'}[char] ?? char))
  const bounds = nodes.boundingBox({includeLabels: true})
  const edges = cy.edges(':visible').map(edge => {
    const a = edge.source().position()
    const b = edge.target().position()
    const x = (a.x + b.x) / 2
    const y = (a.y + b.y) / 2
    return '<line x1="' + a.x + '" y1="' + a.y + '" x2="' + b.x + '" y2="' + b.y
      + '" stroke="#7294a8"/><text x="' + x + '" y="' + (y - 5) + '">' + safe(edge.data('label')) + '</text>'
  }).join('')
  const markers = nodes.map(node => {
    const {x, y} = node.position()
    const color = colors[String(node.data('type'))] ?? '#85a3b5'
    return '<circle cx="' + x + '" cy="' + y + '" r="12" fill="' + color + '"/><text x="' + x + '" y="' + (y + 28) + '">'
      + safe(String(node.data('label')).slice(0, 68)) + '</text>'
  }).join('')
  const box = [bounds.x1 - 45, bounds.y1 - 45, bounds.w + 90, bounds.h + 90].join(' ')
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="' + box + '"><rect x="' + (bounds.x1 - 45)
    + '" y="' + (bounds.y1 - 45) + '" width="' + (bounds.w + 90) + '" height="' + (bounds.h + 90)
    + '" fill="#0c1520"/><g fill="#dceafa" font-family="sans-serif" text-anchor="middle" font-size="11">'
    + edges + markers + '</g></svg>'
  saveFile(filename, new Blob([svg], {type: 'image/svg+xml;charset=utf-8'}))
}

const VISIBILITY_PAGE_SIZE = 100

function ObjectVisibility({nodes, hidden, wrappedCount, wrappedHidden, onToggle, onReset, onToggleWrapped, onLocate}: {
  nodes: MapNode[]; hidden: Set<string>; wrappedCount: number; wrappedHidden: number
  onToggle: (node: MapNode, show: boolean) => void; onReset: () => void; onToggleWrapped: () => void
  onLocate: (id: string) => void
}) {
  const [search, setSearch] = useState('')
  const [onlyWrapped, setOnlyWrapped] = useState(false)
  const [limit, setLimit] = useState(VISIBILITY_PAGE_SIZE)
  const query = search.trim().toLowerCase()
  const filtered = nodes.filter(node => (!onlyWrapped || node.wrapped_host) &&
    [node.label, nodeValue(node), nodeTypeName(node)].some(value => value.toLowerCase().includes(query)))
  return <section className="surface-object-visibility" aria-label="Object visibility" id="surface-object-visibility">
    <div className="surface-visibility-head">
      <h2>Object visibility</h2>
      <button type="button" className="text-action" onClick={onReset} disabled={!hidden.size}>Show all</button>
    </div>
    {wrappedCount > 0 && <div className="surface-visibility-actions">
      <button type="button" className="button secondary compact" aria-pressed={onlyWrapped}
        onClick={() => {setOnlyWrapped(!onlyWrapped); setLimit(VISIBILITY_PAGE_SIZE)}}>tcpwrapped ({wrappedCount})</button>
      <button type="button" className="text-action" onClick={onToggleWrapped}>
        {wrappedHidden === wrappedCount ? 'Show all tcpwrapped' : 'Hide all tcpwrapped'}
      </button>
    </div>}
    <input type="search" aria-label="Find objects to show or hide" placeholder="Find host, port or object…"
      value={search} onChange={event => {setSearch(event.target.value); setLimit(VISIBILITY_PAGE_SIZE)}}/>
    <div className="surface-visibility-list">
      {filtered.slice(0, limit).map(node => <div className="surface-visibility-row" key={node.id}>
        <label className={hidden.has(node.id) ? 'is-hidden' : ''}>
          <input type="checkbox" checked={!hidden.has(node.id)} onChange={event => onToggle(node, event.target.checked)}/>
          <span><span>{node.label}</span><small>{node.wrapped_host ? nodeValue(node).split('|')[0] : nodeTypeName(node)}</small></span>
        </label>
        {node.wrapped_host && !hidden.has(node.id) && <button className="icon-btn" type="button"
          aria-label={'Locate ' + node.label + ' on map'} onClick={() => onLocate(node.id)}><Target size={13}/></button>}
      </div>)}
      {!filtered.length && <small>No matching objects.</small>}
      {filtered.length > limit && <button type="button" className="text-action"
        onClick={() => setLimit(limit + VISIBILITY_PAGE_SIZE)}>Show more ({filtered.length - limit})</button>}
    </div>
    <small role="status">{hidden.size} hidden in this view{wrappedCount > 0 && ` · ${wrappedHidden} / ${wrappedCount} tcpwrapped hidden`}</small>
  </section>
}

function portScan(node: MapNode): ScanSeed {
  const value = nodeValue(node)
  const [host, service] = value.split('|')
  const port = service?.match(/^tcp\/(\d+)/)?.[1]
  return port ? {toolId: 'nmap', target: host, mode: 'ports', options: {mode: 'ports', ports: port}}
    : {toolId: 'nmap', target: host}
}

export default function AttackMap({projectId, projectName, initialFocus, initialAudit, onFinding, onAudit, onScan, onBack, onBuild}: {
  projectId: number; projectName: string; initialFocus?: string; initialAudit?: number
  onFinding: (id: number, auditId?: number) => void; onAudit: (target: string) => void; onScan: (seed: ScanSeed) => void;
  onBack: () => void; onBuild: (draftId?: number, auditId?: number, positions?: SurfacePositions) => void
}) {
  const container = useRef<HTMLDivElement>(null)
  const instance = useRef<Core | undefined>(undefined)
  const pendingCenter = useRef<string | undefined>(undefined)
  const fitAfterBulk = useRef(false)
  const [graph, setGraph] = useState<GraphData>({nodes: [], edges: [], truncated: false})
  const [audits, setAudits] = useState<AuditOption[]>([])
  const [auditId, setAuditId] = useState<number | undefined>(initialAudit)
  const visibilityKey = 'surfacemap.hidden-assets.' + projectId + '.' + (auditId ?? 'project')
  const [savedVisibility, setSavedVisibility] = useState(() => ({key: visibilityKey, value: readMapVisibility(visibilityKey, projectId)}))
  const visibility = useMemo(() => savedVisibility.key === visibilityKey
    ? savedVisibility.value : readMapVisibility(visibilityKey, projectId), [savedVisibility, visibilityKey, projectId])
  const wrappedNodes = useMemo(() => graph.nodes.filter(node => node.wrapped_host), [graph.nodes])
  const unidentifiedNodes = useMemo(() => graph.nodes.filter(inUnidentifiedGroup), [graph.nodes])
  const hiddenIds = useMemo(() => new Set(graph.nodes.filter(node =>
    visibility.ids.has(node.id) || (node.wrapped_host && visibility.hideWrapped && !visibility.shownWrapped.has(node.id)) ||
    (inUnidentifiedGroup(node) && visibility.hideUnidentified && !visibility.shownUnidentified.has(node.id)),
  ).map(node => node.id)), [graph.nodes, visibility])
  const wrappedHidden = wrappedNodes.filter(node => hiddenIds.has(node.id)).length
  const unidentifiedHidden = unidentifiedNodes.filter(node => hiddenIds.has(node.id)).length
  const [focus, setFocus] = useState(initialFocus)
  const [selectedId, setSelectedId] = useState(initialFocus)
  const [edgeId, setEdgeId] = useState<string>()
  const [view, setView] = useState<MapView>('topology')
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [sourceFilter, setSourceFilter] = useState('all')
  const [labels, setLabels] = useState(false)
  const [includeIsolated, setIncludeIsolated] = useState(true)
  const [includeReferences, setIncludeReferences] = useState(true)
  const [error, setError] = useState('')
  const [copyError, setCopyError] = useState('')
  const [openingEditor, setOpeningEditor] = useState(false)
  const copyRequest = useRef<AbortController>(null)
  const [loading, setLoading] = useState(true)
  const [reload, setReload] = useState(0)
  const byId = new Map(graph.nodes.map(node => [node.id, node]))
  const selected = selectedId ? byId.get(selectedId) : undefined
  const selectedEdge = graph.edges.find(edge => edge.id === edgeId && !hiddenIds.has(edge.source) && !hiddenIds.has(edge.target))
  const risky = graph.nodes.filter(node => node.findings.some(isOpen))
  const leads = risky.filter(node => !hiddenIds.has(node.id)).flatMap(node => node.findings.filter(isOpen)).sort((a, b) =>
    severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity))
  const routes = graph.nodes.filter(node => node.type === 'endpoint' || node.type === 'web_origin')
  const observedRoutes = new Set(routes.filter(node => routeStatus(node) || node.findings.length).map(node => node.id))
  const confirmedOrigins = new Set(routes.filter(node => node.type === 'web_origin' && observedRoutes.has(node.id)).map(node => node.id))
  for (const edge of graph.edges) {
    if (edge.type === 'contains_endpoint' && observedRoutes.has(edge.target)) confirmedOrigins.add(edge.source)
  }
  const observedWebCount = routes.filter(node => observedRoutes.has(node.id) || confirmedOrigins.has(node.id)).length
  const referenceOrigins = new Set(graph.nodes.filter(node => node.type === 'web_origin' && !confirmedOrigins.has(node.id)).map(node => node.id))
  const referenceNodes = new Set(referenceOrigins)
  for (const edge of graph.edges) {
    if (edge.type === 'contains_endpoint' && referenceOrigins.has(edge.source)) referenceNodes.add(edge.target)
    if (edge.type === 'serves_web' && referenceOrigins.has(edge.target) && !byId.get(edge.source)?.sources.length) {
      referenceNodes.add(edge.source)
    }
  }
  const linkedNodes = new Set(graph.edges.flatMap(edge => [edge.source, edge.target]))
  const hideReferences = !includeReferences && !focus && !query && typeFilter === 'all' && sourceFilter === 'all' && confirmedOrigins.size > 0
  const topologyNodes = graph.nodes.filter(node => !hideReferences || !referenceNodes.has(node.id))
  const isolated = topologyNodes.filter(node => !linkedNodes.has(node.id) && !(node.type === 'domain' && node.sources.length))
  const isolatedIds = new Set(isolated.map(node => node.id))
  const hideIsolated = !includeIsolated && !focus && !query && typeFilter === 'all' && sourceFilter === 'all' && linkedNodes.size > 0
  const firstLayer = view === 'risk' ? risky : topologyNodes.filter(node => !hideIsolated || !isolatedIds.has(node.id))
  const matches = firstLayer.filter(node => (typeFilter === 'all' || typeFilter === node.type)
    && (sourceFilter === 'all' || node.sources.includes(sourceFilter)))
  const matchedIds = new Set(matches.map(node => node.id))
  const visibleIds = new Set(matchedIds)
  if (view === 'risk' || (typeFilter !== 'all' && !focus)) {
    for (const edge of graph.edges) {
      if (view === 'risk' && edge.type === 'has_wrapped_port') continue
      if (matchedIds.has(edge.source)) visibleIds.add(edge.target)
      if (matchedIds.has(edge.target)) visibleIds.add(edge.source)
    }
  }
  const canvasNodes = graph.nodes.filter(node => visibleIds.has(node.id))
  const canvasEdges = graph.edges.filter(edge => visibleIds.has(edge.source) && visibleIds.has(edge.target))
  const visible = canvasNodes.filter(node => !hiddenIds.has(node.id))
  const navigatorNodes = [...visible].sort((a, b) => a.type.localeCompare(b.type) ||
    a.label.localeCompare(b.label, undefined, {numeric: true}))
  const edges = canvasEdges.filter(edge => !hiddenIds.has(edge.source) && !hiddenIds.has(edge.target))
  const childLinks = graph.edges.filter(edge => edge.type === 'has_subdomain' && !hiddenIds.has(edge.source) && !hiddenIds.has(edge.target))
  const connections = selected ? graph.edges.flatMap(edge => {
    if (edge.source !== selected.id && edge.target !== selected.id) return []
    const other = byId.get(edge.source === selected.id ? edge.target : edge.source)
    return other && !hiddenIds.has(other.id) ? [{edge, other}] : []
  }) : []
  const sources = [...new Set(graph.nodes.flatMap(node => node.sources))].sort()
  const routeRows = routes.filter(node => !hiddenIds.has(node.id) && (typeFilter === 'all' || typeFilter === node.type)
    && (includeReferences || query || focus || observedRoutes.has(node.id) || confirmedOrigins.has(node.id) || observedWebCount === 0)
    && (sourceFilter === 'all' || node.sources.includes(sourceFilter))).sort((a, b) =>
    Number(b.findings.some(isOpen)) - Number(a.findings.some(isOpen)) || nodeValue(a).localeCompare(nodeValue(b)))

  useEffect(() => {
    const controller = new AbortController()
    fetch('/api/projects/' + projectId + '/audits', {signal: controller.signal})
      .then(response => response.ok ? response.json() : [])
      .then(rows => { if (!controller.signal.aborted) setAudits(rows) }).catch(() => {})
    return () => controller.abort()
  }, [projectId])

  useEffect(() => () => copyRequest.current?.abort(), [])

  useEffect(() => {
    const controller = new AbortController()
    const params = new URLSearchParams()
    if (focus) { params.set('focus_id', focus); params.set('hops', '2') }
    if (query) params.set('q', query)
    if (auditId) params.set('audit_id', String(auditId))
    setLoading(true)
    setError('')
    fetch('/api/projects/' + projectId + '/graph?' + params, {signal: controller.signal, cache: 'no-store'})
      .then(async response => {
        const body = await response.json()
        if (!response.ok) throw new Error(typeof body.detail === 'string' ? body.detail : 'Could not load project graph.')
        if (!controller.signal.aborted) {
          const next = expandWrappedPorts(body)
          setGraph(next)
          setSelectedId(current => focus ?? (next.nodes.some(node => node.id === current) ? current : undefined))
          setEdgeId(undefined)
        }
      }).catch(reason => {
        if (!controller.signal.aborted) {
          setGraph({nodes: [], edges: [], truncated: false})
          setSelectedId(undefined)
          setEdgeId(undefined)
          setError(reason.message)
        }
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [projectId, auditId, focus, query, reload])

  useEffect(() => {
    if (!container.current || view === 'routes' || loading || error || !canvasNodes.length) return
    const surface = container.current
    const positions = topologyPositions(canvasNodes, canvasEdges, surface.clientWidth, referenceNodes)
    const cy = cytoscape({
      container: surface,
      elements: [
        ...canvasNodes.map(node => ({
          position: positions[node.id],
          classes: hiddenIds.has(node.id) ? 'user-hidden' : '',
          data: {id: node.id, label: canvasLabel(node), type: node.type, tone: colors[node.type] ?? '#85a3b5',
            unidentified: Number(unidentified(node)),
            reference: Number(referenceNodes.has(node.id) || (node.type === 'endpoint' && !observedRoutes.has(node.id))),
            risk: Number(node.findings.some(isOpen))},
        })),
        ...canvasEdges.map(edge => ({classes: hiddenIds.has(edge.source) || hiddenIds.has(edge.target) ? 'user-hidden' : '',
          data: {id: 'e' + edge.id, source: edge.source, target: edge.target,
          label: relationshipLabel(edge, byId.get(edge.source)), kind: edge.type}})),
      ],
      style: [
        {selector: 'node', style: {shape: 'round-rectangle', width: 154, height: 34, 'background-color': '#162736',
          'border-width': 1.4, 'border-color': 'data(tone)', label: 'data(label)', color: '#e5eef7',
          'font-size': 11, 'font-weight': 600, 'text-valign': 'center', 'text-wrap': 'ellipsis', 'text-max-width': '136px'}},
        {selector: 'node[type = "ipv4"], node[type = "ipv6"]', style: {'background-color': '#14352f'}},
        {selector: 'node[type = "endpoint"]', style: {'background-color': '#332742'}},
        {selector: 'node[type = "filtered_port"]', style: {'border-style': 'dashed', 'background-color': '#352c25'}},
        {selector: 'node[type = "wrapped_port"]', style: {'border-style': 'dashed', 'background-color': '#292738'}},
        {selector: 'node[unidentified = 1]', style: {'border-style': 'dashed', 'border-color': '#879bab', 'background-color': '#1c2b37'}},
        {selector: 'node[reference = 1]', style: {'border-style': 'dashed', 'border-color': '#7c8aa2'}},
        {selector: 'node[risk = 1]', style: {'border-color': '#ff9b76', 'border-width': 3}},
        {selector: 'edge', style: {width: 1.5, 'line-color': '#46667a', 'target-arrow-color': '#729fb7',
          'target-arrow-shape': 'triangle', 'curve-style': 'bezier', label: canvasEdges.length <= 6 ? 'data(label)' : '',
          color: '#b3c8d9', 'font-size': 10, 'text-background-opacity': 1, 'text-background-color': '#0c1520', 'text-background-padding': '3px'}},
        {selector: 'edge[kind = "responded_from"]', style: {'line-color': '#58c6e2', 'target-arrow-color': '#58c6e2', width: 2.5}},
        {selector: 'edge[kind = "has_subdomain"]', style: {'line-color': '#8c9cdb', 'target-arrow-color': '#8c9cdb'}},
        {selector: 'edge[kind = "contains_endpoint"]', style: {'line-opacity': .42, 'target-arrow-color': '#9988b7'}},
        {selector: 'edge[kind = "redirects_to"]', style: {'line-style': 'dashed', 'line-color': '#c1a870', 'target-arrow-color': '#c1a870'}},
        {selector: 'edge[kind = "has_wrapped_port"]', style: {'line-style': 'dashed', 'line-color': '#8f86a5', 'target-arrow-color': '#8f86a5', 'line-opacity': .45}},
        {selector: 'edge[kind = "resolves_to"], edge[kind = "has_filtered_port"]', style: {'line-style': 'dashed'}},
        {selector: '.context-faded', style: {opacity: .25}},
        {selector: 'edge.show-label, edge.context-active', style: {label: 'data(label)'}},
        {selector: 'edge.context-active', style: {'line-color': '#8dd7e9', 'target-arrow-color': '#8dd7e9', 'line-opacity': 1}},
        {selector: 'edge.wrapped-bundled', style: {visibility: 'hidden'}},
        {selector: 'edge.wrapped-bundled.context-active', style: {visibility: 'visible'}},
        {selector: 'node.context-selected', style: {'border-color': '#f2cb80', 'border-width': 3}},
        {selector: '.user-hidden', style: {display: 'none'}},
      ],
      layout: {name: 'preset', fit: false},
      minZoom: .025, maxZoom: 3,
    })
    instance.current = cy
    const columns = () => Math.max(2, Math.min(6, Math.floor(surface.clientWidth / 184)))
    layoutWrappedPorts(cy, columns())
    const base = cy.nodes().not('[type = "wrapped_port"]').not('.user-hidden')
    if (base.length && visible.filter(node => node.wrapped_host).length > 48 && typeFilter !== 'wrapped_port' && !query) {
      cy.fit(base, 48)
    } else if (visible.length) {
      cy.fit(cy.elements().not('.user-hidden'), 48)
    }
    const resize = new ResizeObserver(() => {cy.resize(); layoutWrappedPorts(cy, columns())})
    resize.observe(surface)
    cy.on('tap', 'node', event => {setSelectedId(event.target.id()); setEdgeId(undefined)})
    cy.on('tap', 'edge', event => {setEdgeId(event.target.id().slice(1)); setSelectedId(undefined)})
    cy.on('tap', event => {if (event.target === cy) {setSelectedId(undefined); setEdgeId(undefined)}})
    return () => {resize.disconnect(); cy.destroy(); instance.current = undefined}
  }, [graph, focus, view, loading, error, typeFilter, sourceFilter, includeIsolated, includeReferences, reload])

  useEffect(() => {
    const cy = instance.current
    const surface = container.current
    if (!cy || !surface) return
    cy.batch(() => {
      cy.nodes().forEach(node => {node.toggleClass('user-hidden', hiddenIds.has(node.id()))})
      cy.edges().forEach(edge => {
        edge.toggleClass('user-hidden', hiddenIds.has(edge.source().id()) || hiddenIds.has(edge.target().id()))
      })
      const wrappedEdges = cy.edges('[kind = "has_wrapped_port"]').not('.user-hidden')
      const linksPerHost = new Map<string, number>()
      wrappedEdges.forEach(edge => {
        const host = edge.source().id()
        linksPerHost.set(host, (linksPerHost.get(host) ?? 0) + 1)
      })
      wrappedEdges.forEach(edge => {
        edge.toggleClass('wrapped-bundled', (linksPerHost.get(edge.source().id()) ?? 0) > 24)
      })
      layoutWrappedPorts(cy, Math.max(2, Math.min(6, Math.floor(surface.clientWidth / 184))))
    })
    if (fitAfterBulk.current) {
      fitAfterBulk.current = false
      const base = cy.nodes().not('[type = "wrapped_port"]').not('.user-hidden')
      const visibleElements = cy.elements().not('.user-hidden')
      if (visibleElements.length) cy.fit(base.length && typeFilter !== 'wrapped_port' ? base : visibleElements, 48)
    }
    if (pendingCenter.current) {
      const port = cy.getElementById(pendingCenter.current)
      if (port.length && !port.hasClass('user-hidden')) {
        pendingCenter.current = undefined
        cy.zoom(Math.max(cy.zoom(), .9))
        cy.center(port)
        surface.scrollIntoView({block: 'nearest'})
      }
    }
  }, [hiddenIds, graph, focus, view, loading, error, typeFilter, sourceFilter, includeIsolated, includeReferences, reload])

  useEffect(() => {
    const cy = instance.current
    if (!cy) return
    cy.edges().toggleClass('show-label', labels)
    cy.elements().removeClass('context-faded context-selected context-active')
    const node = selectedId && !hiddenIds.has(selectedId) ? cy.getElementById(selectedId) : null
    if (node?.length) {
      const neighbors = node.closedNeighborhood()
      cy.elements().difference(neighbors).addClass('context-faded')
      node.addClass('context-selected')
      node.connectedEdges().not('edge.wrapped-bundled').addClass('context-active')
      if (node.data('type') === 'wrapped_port') node.connectedEdges().addClass('context-active')
    } else if (selectedEdge) {
      const edge = cy.getElementById('e' + selectedEdge.id)
      if (edge.length) {
        cy.elements().difference(edge.union(edge.connectedNodes())).addClass('context-faded')
        edge.addClass('context-active')
      }
    }
  }, [selectedId, selectedEdge, graph, focus, view, loading, typeFilter, sourceFilter, labels, includeIsolated, includeReferences, hiddenIds])

  function saveVisibility(value: MapVisibility) {
    setSavedVisibility({key: visibilityKey, value})
    persistMapVisibility(visibilityKey, value)
  }

  function toggleAsset(node: MapNode, show: boolean) {
    const ids = new Set(visibility.ids)
    const shownWrapped = new Set(visibility.shownWrapped)
    const shownUnidentified = new Set(visibility.shownUnidentified)
    if (show) ids.delete(node.id)
    else ids.add(node.id)
    if (node.wrapped_host) {
      if (show && visibility.hideWrapped) shownWrapped.add(node.id)
      else shownWrapped.delete(node.id)
    }
    if (inUnidentifiedGroup(node)) {
      if (show && visibility.hideUnidentified) shownUnidentified.add(node.id)
      else shownUnidentified.delete(node.id)
    }
    saveVisibility({...visibility, ids, shownWrapped, shownUnidentified})
  }

  function toggleWrappedPorts() {
    const hideWrapped = wrappedHidden < wrappedNodes.length
    fitAfterBulk.current = true
    saveVisibility({...visibility, hideWrapped, shownWrapped: new Set(),
      ids: new Set([...visibility.ids].filter(id => !id.startsWith('wrapped-')))})
  }

  function toggleUnidentifiedPorts() {
    const group = new Set(unidentifiedNodes.map(node => node.id))
    fitAfterBulk.current = true
    saveVisibility({...visibility, hideUnidentified: unidentifiedHidden < group.size, shownUnidentified: new Set(),
      ids: new Set([...visibility.ids].filter(id => !group.has(id)))})
  }

  function showAll() {
    fitAfterBulk.current = true
    saveVisibility(emptyMapVisibility())
  }

  function locatePort(id: string) {
    const cy = instance.current
    const port = cy?.getElementById(id)
    if (cy && port?.length) {
      cy.zoom(Math.max(cy.zoom(), .9))
      cy.center(port)
      container.current?.scrollIntoView({block: 'nearest'})
    } else {
      pendingCenter.current = id
      chooseView('topology')
    }
    setSelectedId(id)
    setEdgeId(undefined)
  }

  function clearFilters() {setTypeFilter('all'); setSourceFilter('all')}
  function focusNode(id: string) {
    setView('topology')
    setFocus(id); setSelectedId(id); setEdgeId(undefined)
    setQuery(''); setSearch(''); clearFilters()
  }
  function clearFocus() {setFocus(undefined); setQuery(''); setSearch(''); setSelectedId(undefined); setEdgeId(undefined); clearFilters()}
  function chooseView(next: MapView) {setView(next); clearFilters()}
  const filename = 'surfacemap-' + (projectName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || projectId)
  const exportGraph = () => saveFile(filename + '-map.json', new Blob([JSON.stringify({
    project: projectName, audit_id: auditId ?? null, nodes: view === 'routes' ? routeRows : visible,
    edges: view === 'routes' ? [] : edges,
  }, null, 2)], {type: 'application/json'}))

  async function editObservedMap() {
    if (copyRequest.current) return
    if (!graph.nodes.length && !focus && !query && !error) {
      onBuild(undefined, auditId)
      return
    }
    const controller = new AbortController()
    copyRequest.current = controller
    setOpeningEditor(true)
    setCopyError('')
    try {
      const url = '/api/projects/' + projectId + '/surface-drafts/from-observations' + (auditId ? '?audit_id=' + auditId : '')
      const cy = instance.current
      const base = cy?.nodes('[type != "wrapped_port"]')
      const positions = view === 'topology' && !focus && !query && base?.length === graph.nodes.length - wrappedNodes.length
        ? Object.fromEntries(base.map(node => [node.id(), node.position()])) as SurfacePositions : undefined
      const response = await fetch(url, {method: 'POST', signal: controller.signal,
        headers: positions ? {'Content-Type': 'application/json'} : undefined,
        body: positions ? JSON.stringify({positions}) : undefined})
      const body = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(typeof body.detail === 'string' ? body.detail : 'Could not open the editable map.')
      if (!controller.signal.aborted) onBuild(body.id, auditId, positions)
    } catch (failure) {
      if (!controller.signal.aborted) setCopyError((failure as Error).message)
    } finally {
      copyRequest.current = null
      if (!controller.signal.aborted) setOpeningEditor(false)
    }
  }

  return <section className="map-page surface-explorer">
    <header className="page-heading"><div>
      <div className="eyebrow"><span className="live-pulse"/> ASSET INTELLIGENCE / {projectName}</div>
      <h1>Attack Surface Map</h1><p className="subtitle">Trace the route from a domain to an IP, an exposed service or a finding.</p>
    </div><div className="surface-pivots">
      <button className="button secondary" onClick={onBack}><ArrowLeft size={14}/> Overview</button>
      <button className="button primary" onClick={() => void editObservedMap()} disabled={loading || openingEditor}>
        <Network size={14}/> {openingEditor ? 'Opening editor…' : 'Edit discovered map'}
      </button>
    </div></header>
    <div className="surface-metrics">
      <button className="panel" aria-pressed={view === 'topology'} onClick={() => chooseView('topology')}><Network size={16}/>
        <span><strong>{graph.nodes.length}</strong><small>Topology · {wrappedNodes.length ? `${wrappedNodes.length} tcpwrapped` : 'inventory assets'}</small></span></button>
      <button className="panel" aria-pressed={view === 'routes'} onClick={() => chooseView('routes')}><Globe2 size={16}/>
        <span><strong>{routes.length}</strong><small>Web inventory · {routes.filter(node => node.type === 'endpoint').length} endpoints</small></span></button>
      <button className="panel" aria-pressed={view === 'risk'} onClick={() => chooseView('risk')}><Shield size={16}/>
        <span><strong>{risky.length}</strong><small>Risk view · assets with open findings</small></span></button>
    </div>
    <div className="map-toolbar">
      <form className="map-search" role="search" onSubmit={event => {
        event.preventDefault(); setFocus(undefined); setQuery(search.trim()); clearFilters()
      }}><Search size={14}/><input value={search} onChange={event => setSearch(event.target.value)} maxLength={160}
        placeholder="Search domain, IP, port or URL" aria-label="Search the map"/>
        <button type="submit" className="button secondary compact">Search</button>
      </form>
      <select aria-label="Audit evidence filter" value={auditId ?? ''} disabled={openingEditor} onChange={event => {
        setAuditId(event.target.value ? Number(event.target.value) : undefined); clearFocus()
      }}><option value="">All project evidence</option>
        {initialAudit && !audits.some(item => item.id === initialAudit) && <option value={initialAudit}>Audit #{initialAudit}</option>}
        {audits.map(item => <option value={item.id} key={item.id}>#{item.id} · {item.target} · {item.status}</option>)}
      </select>
      <select aria-label="Filter asset type" value={typeFilter} onChange={event => setTypeFilter(event.target.value)}>
        <option value="all">All asset types</option>
        {Object.entries(typeNames).filter(([key]) => view !== 'routes' || ['web_origin', 'endpoint'].includes(key))
          .map(([key, name]) => <option key={key} value={key}>{name}</option>)}
      </select>
      <select aria-label="Filter by scanner" value={sourceFilter} onChange={event => setSourceFilter(event.target.value)}>
        <option value="all">All sources</option>{sources.map(source => <option key={source}>{source}</option>)}
      </select>
      <button className="button secondary compact" onClick={() => setReload(value => value + 1)}><RefreshCw size={13}/> Refresh</button>
    </div>
    {focus || query || auditId || unidentifiedNodes.length > 0 ? <div className="surface-scope-strip">
      {auditId && <span>Audit #{auditId} assets · relationships from the project</span>}
      {!auditId && unidentifiedNodes.length > 0 && <span>Port states are historical observations from saved scans</span>}
      {query && <span>Search · {query}</span>}
      {focus && <span>Neighborhood · {byId.get(focus)?.label ?? focus} · two links deep</span>}
      {(focus || query) && <button className="text-action" onClick={clearFocus}>Clear search or focus</button>}
    </div> : null}
    {(graph.truncated || graph.historical) && <div className="map-notice"><CircleHelp size={15}/>
      <span>{graph.truncated ? 'The main inventory is limited to 500 assets and 1,000 links per view. Search or focus to reach the rest.' : 'This earlier run uses reconstructed asset provenance.'}</span>
    </div>}
    {graph.wrapped_truncated && <div className="map-notice"><CircleHelp size={15}/>
      <span>This view lists up to 5,000 tcpwrapped ports. Search by host or port to reach the rest.</span></div>}
    {error && <div className="form-error" role="alert">{error}</div>}
    {copyError && <div className="form-error" role="alert">{copyError}</div>}
    {!loading && leads.length > 0 && <section className="panel surface-review-leads" aria-label="Findings to verify">
      <div><strong>Findings to verify</strong><span>{leads.length} on this map · expand a finding for verification steps</span></div>
      {leads.slice(0, 3).map(finding => <MapFindingReview key={finding.id} finding={finding} onOpen={() => onFinding(finding.id, auditId)}/>)}
      {leads.length > 3 && <button className="text-action" onClick={() => chooseView('risk')}>Show all in Risk view</button>}
    </section>}
    <div className="map-workspace surface-workspace">
      <div className="panel surface-viewport">
        <div className="surface-controls">
          <span>{view === 'routes' ? routeRows.length + ' web entries' : visible.length + ' nodes · ' + edges.length + ' links'}</span>
          {!loading && graph.nodes.length > 0 && <button className="button secondary compact" onClick={() => {
            const panel = document.getElementById('surface-object-visibility')
            panel?.scrollIntoView({block: 'nearest'})
            panel?.querySelector<HTMLInputElement>('input')?.focus({preventScroll: true})
          }}>Objects{hiddenIds.size > 0 ? ' · ' + hiddenIds.size + ' hidden' : ''}</button>}
          {!loading && view === 'topology' && wrappedNodes.length > 0 && <button className="button secondary compact" onClick={toggleWrappedPorts}>
            {wrappedHidden === wrappedNodes.length ? `Show tcpwrapped ports (${wrappedNodes.length})`
              : `Hide tcpwrapped ports (${wrappedNodes.length - wrappedHidden})`}
          </button>}
          {!loading && view === 'topology' && unidentifiedNodes.length > 0 &&
            <button className="button secondary compact" title="Includes ports labeled domain by Nmap" onClick={toggleUnidentifiedPorts}>
              {unidentifiedHidden === unidentifiedNodes.length ? `Show unidentified ports (${unidentifiedNodes.length})`
                : `Hide unidentified ports (${unidentifiedNodes.length - unidentifiedHidden})`}
            </button>}
          {view === 'routes' && observedWebCount > 0 && observedWebCount < routes.length &&
            <button className="button secondary compact" onClick={() => setIncludeReferences(!includeReferences)} aria-pressed={includeReferences}>
              Link-only URLs ({routes.length - observedWebCount})
            </button>}
          {view !== 'routes' && <>
            {view === 'topology' && !focus && !query && confirmedOrigins.size > 0 && referenceOrigins.size > 0 &&
              <button className="button secondary compact" onClick={() => setIncludeReferences(!includeReferences)} aria-pressed={includeReferences}>
                Link-only origins ({referenceOrigins.size})
              </button>}
            {view === 'topology' && !focus && !query && !!isolated.length && linkedNodes.size > 0 &&
              <button className="button secondary compact" onClick={() => setIncludeIsolated(!includeIsolated)} aria-pressed={includeIsolated}>
                Unlinked ({isolated.length})
              </button>}
            <button className="button secondary compact" onClick={() => setLabels(!labels)} aria-pressed={labels}>Edge labels</button>
            <button className="button secondary compact" aria-label="Zoom in" onClick={() => {const cy = instance.current; if (cy) cy.zoom(cy.zoom() * 1.2)}}><ZoomIn size={14}/></button>
            <button className="button secondary compact" aria-label="Zoom out" onClick={() => {const cy = instance.current; if (cy) cy.zoom(cy.zoom() / 1.2)}}><ZoomOut size={14}/></button>
            <button className="button secondary compact" disabled={!visible.length} onClick={() => {
              const cy = instance.current
              if (cy) cy.fit(cy.elements().not('.user-hidden'), 48)
            }}>Fit</button>
            <button className="button secondary compact" disabled={!visible.length} onClick={() => {
              const cy = instance.current
              if (cy) saveFile(filename + '-map.png', cy.png({full: true, scale: 2, bg: '#0c1520', output: 'blob'}))
            }}><Image size={13}/> PNG</button>
            <button className="button secondary compact" disabled={!visible.length} onClick={() => {if (instance.current) saveSvg(instance.current, filename + '-map.svg')}}><FileCode2 size={13}/> SVG</button>
          </>}
          <button className="button secondary compact" onClick={exportGraph}><Download size={13}/> JSON</button>
        </div>
        {view !== 'routes' && !loading && navigatorNodes.length > 0 && <div className="surface-navigator">
          <label>Jump to asset
            <select value={selectedId && visibleIds.has(selectedId) && !hiddenIds.has(selectedId) ? selectedId : ''} onChange={event => {
              const id = event.target.value || undefined
              if (id && byId.get(id)?.wrapped_host) locatePort(id)
              else {
                setSelectedId(id); setEdgeId(undefined)
                if (id) instance.current?.center(instance.current.getElementById(id))
              }
            }}>
              <option value="">Select a node</option>
              {navigatorNodes.map(node => <option key={node.id} value={node.id}>{node.wrapped_host
                ? `${node.label} · ${nodeValue(node).split('|')[0]}` : `${nodeTypeName(node)} · ${node.label}`}</option>)}
            </select>
          </label>
          {(selected || selectedEdge) && <button className="button secondary compact" onClick={() =>
            document.getElementById('surface-inspector')?.scrollIntoView({block: 'nearest'})}>View details <ArrowRight size={13}/></button>}
        </div>}
        {loading ? <div key="loading" className="data-empty">Loading asset evidence…</div> : view === 'routes' ?
          <div key="routes" className="surface-routes"><table>
            <thead><tr><th>Observed URL</th><th>HTTP</th><th>Findings</th><th>Action</th></tr></thead>
            <tbody>{routeRows.map(node => <tr key={node.id} className={selectedId === node.id ? 'selected' : ''}>
              <td><button className="text-action" onClick={() => {setSelectedId(node.id); setEdgeId(undefined)}}>{nodeValue(node)}</button>
                <small>{typeNames[node.type]}{node.facts?.method && ' · ' + node.facts.method}</small></td>
              <td>{routeStatus(node) ?? (node.findings.length ? 'Finding evidence' : 'Link only')}</td><td>{node.findings.filter(isOpen).length}</td>
              <td><button className="button secondary compact" onClick={() => focusNode(node.id)}>Trace <ArrowRight size={12}/></button></td>
            </tr>)}</tbody>
          </table>{!routeRows.length && <div className="data-empty">No web entries match this view.</div>}</div>
          : canvasNodes.length && !error ? <div key="canvas">
            <div className="surface-canvas" ref={container} hidden={!visible.length}/>
            {!visible.length && <div className="map-no-data"><Network size={24}/><b>All objects in this view are hidden</b>
              <button className="button secondary compact" onClick={showAll}>Show all objects</button></div>}
          </div> :
          <div key="empty" className="map-no-data"><Network size={24}/><b>{view === 'risk' ? 'No open findings in this view' : 'No matching assets'}</b>
            <span>Change filters or collect more evidence through an audit.</span></div>}
        {view === 'risk' && !!matches.length && <div className="surface-risk-list">{matches.filter(node => !hiddenIds.has(node.id)).flatMap(node => node.findings.filter(isOpen)
          .sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity))
          .map(finding => <button key={finding.id} onClick={() => {setSelectedId(node.id); setEdgeId(undefined)}}>
            <span className={'severity severity-' + finding.severity}>{finding.severity}</span><span>{finding.title}</span>
            <small>{node.label}</small>
          </button>))}</div>}
      </div>
      <aside className="map-inspector surface-inspector" id="surface-inspector" aria-label="Map details">
        {!loading && graph.nodes.length > 0 && <ObjectVisibility key={visibilityKey} nodes={graph.nodes} hidden={hiddenIds}
          wrappedCount={wrappedNodes.length} wrappedHidden={wrappedHidden} onToggle={toggleAsset} onReset={showAll}
          onToggleWrapped={toggleWrappedPorts} onLocate={locatePort}/>}
        <div className="panel-title">{selectedEdge ? 'Relationship' : 'Asset inspector'}</div>
        {selected ? <div className="inspector-content">
          <label className="surface-selected-visibility">
            <input type="checkbox" checked={!hiddenIds.has(selected.id)} onChange={event => toggleAsset(selected, event.target.checked)}/>
            Show selected object on map
          </label>
          <span className="asset-type">{nodeTypeName(selected)}</span>
          <code>{nodeValue(selected)}</code>
          <small>Last observed {new Date(String(selected.facts?.observed_at ?? selected.last_seen)).toLocaleString()}</small>
          {selected.facts && <dl className="asset-facts">
            {routeStatus(selected) && <div><dt>HTTP</dt><dd>{routeStatus(selected)}</dd></div>}
            {selected.facts.webserver && <div><dt>Web server</dt><dd>{selected.facts.webserver}</dd></div>}
            {selected.facts.host_ip && <div><dt>Connected IP</dt><dd>{selected.facts.host_ip}</dd></div>}
            {selected.facts.state && <div><dt>State in scan</dt><dd>{selected.facts.state}{selected.facts.reason && ' · ' + selected.facts.reason}</dd></div>}
            {selected.facts.method === 'table' && selected.facts.name && <div><dt>Port-number hint</dt><dd>{selected.facts.name}</dd></div>}
            {selected.facts.identification === 'identified' && <div><dt>Service</dt><dd>
              {[selected.facts.product || selected.facts.name, selected.facts.version].filter(Boolean).join(' ')}</dd></div>}
            {selected.facts.ostype && <div><dt>OS indicator</dt><dd>{selected.facts.ostype}</dd></div>}
          </dl>}
          {selected.wrapped_host && <small>Nmap reported tcpwrapped for this port. The connection ended before a service could be identified.</small>}
          {referenceOrigins.has(selected.id) && <small>Discovered in links. No HTTP response is recorded for this origin.</small>}
          <div className="surface-pivots">
            {focus !== (selected.wrapped_host ?? selected.id) && <button className="button secondary compact"
              onClick={() => focusNode(selected.wrapped_host ?? selected.id)}><Network size={13}/> {selected.wrapped_host ? 'Focus host' : 'Focus links'}</button>}
            {['domain', 'web_origin', 'endpoint'].includes(selected.type) ?
              <button className="button primary compact" onClick={() => onAudit(nodeValue(selected))}><Target size={13}/> Plan audit</button>
              : <button className="button primary compact" onClick={() => onScan(portScan(selected))}><Target size={13}/> Prepare Nmap</button>}
          </div>
          {!!selected.findings.length && <div className="neighbor-list"><b>FINDINGS · {selected.findings.length}</b>
            {selected.findings.map(finding => <MapFindingReview key={finding.id} finding={finding} onOpen={() => onFinding(finding.id, auditId)}/>)}
          </div>}
          {!!connections.length && <div className="neighbor-list"><b>CONNECTIONS · {connections.length}</b>
            {connections.slice(0, 18).map(({edge, other}) => <button key={edge.id} onClick={() => {
              setSelectedId(other.id); setEdgeId(undefined)
            }}><span>{edge.source === selected.id ? '→' : '←'} {relationshipLabel(edge, byId.get(edge.source))}</span><code>{other.label}</code></button>)}
            {connections.length > 18 && <small>Use the asset filter or Object visibility to find more connected objects.</small>}
          </div>}
          <ObservedEvidence key={selected.id + ':' + auditId} projectId={projectId}
            nodeId={selected.wrapped_host ?? selected.id} auditId={auditId}
            wrappedPort={selected.wrapped_host ? nodeValue(selected).split('|')[1] : undefined}/>
        </div> : selectedEdge ? <div className="inspector-content">
          <b>{relationshipLabel(selectedEdge, byId.get(selectedEdge.source))}</b>
          {selectedEdge.evidence?.basis === 'hostname_suffix' && <small>Inferred from the hostname hierarchy.</small>}
          {[selectedEdge.source, selectedEdge.target].map(id => <button key={id} className="text-action" onClick={() => {
            setSelectedId(id); setEdgeId(undefined)
          }}>{byId.get(id)?.label}</button>)}
          {selectedEdge.last_seen && <small>Last observed {new Date(selectedEdge.last_seen).toLocaleString()}</small>}
        </div> : <div className="inspector-empty">
          <p>Select a node, link or web entry to trace evidence and prepare its next check.</p>
          {childLinks.length > 0 && <div className="neighbor-list"><b>SUBDOMAINS · {childLinks.length}</b>
            {childLinks.slice(0, 8).map(edge => <button key={edge.id}
              onClick={() => {setSelectedId(edge.target); setEdgeId(undefined)}}>
              <span>Subdomain of {byId.get(edge.source)?.label}</span><code>{byId.get(edge.target)?.label}</code>
            </button>)}
          </div>}
          {confirmedOrigins.size > 0 && <div className="neighbor-list"><b>OBSERVED WEB ORIGINS</b>
            {graph.nodes.filter(node => confirmedOrigins.has(node.id) && !hiddenIds.has(node.id)).slice(0, 6).map(node => <button key={node.id}
              onClick={() => {setSelectedId(node.id); setEdgeId(undefined)}}>
              <span>{node.facts?.status_code ? 'HTTP ' + node.facts.status_code : 'Observed origin'}</span><code>{node.label}</code>
            </button>)}
          </div>}
        </div>}
        <div className="surface-legend">
          {Object.entries(colors).map(([type, color]) => <span key={type}><i style={{backgroundColor: color}}/>{typeNames[type]}</span>)}
          <small>Dashed web nodes mark URLs found in links. Bright cyan shows the address that answered HTTP.</small>
          {wrappedNodes.length > 24 && <small>Select a tcpwrapped port to trace its link to the host. Dense groups keep those links collapsed on the canvas.</small>}
        </div>
      </aside>
    </div>
  </section>
}
