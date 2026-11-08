import {useEffect, useRef, type RefObject} from 'react'
import cytoscape, {type Core} from 'cytoscape'

export const nodeKinds = {
  domain: ['Domain', '#a5b4fc', 'example.com'],
  ip: ['IP address', '#6ed8ae', '192.0.2.10 or 2001:db8::10'],
  network: ['Network / CIDR', '#6ecbc3', '192.0.2.0/24'],
  origin: ['Web origin', '#67d8ee', 'https://example.com'],
  endpoint: ['Endpoint', '#c6a5f5', 'https://example.com/api/v1'],
  service: ['Port / service', '#f3bd77', '443/tcp'],
  filtered_port: ['Filtered port', '#c5ab91', '443/tcp'],
  device: ['Device', '#8caaff', 'web-01'],
  application: ['Application', '#90c8fb', 'Customer portal'],
  datastore: ['Data store', '#d5adf2', 'PostgreSQL'],
  finding: ['Finding', '#fb9d99', 'Public administration panel'],
  note: ['Note', '#a5b6c7', 'Assessment note'],
} as const

export type NodeKind = keyof typeof nodeKinds
export type BuilderNode = {
  id: string; kind: NodeKind; label: string; value: string; technology: string; version: string; os: string; notes: string;
  x: number; y: number
  observed_asset_id?: number | null
}
export type BuilderLink = {id: string; source: string; target: string; relation: string; notes: string}
export type Selection = {kind: 'node' | 'link'; id: string}
export type SurfacePositions = Record<string, {x: number; y: number}>

export default function BuilderCanvas({nodes, links, selection, onSelect, onMove, graph, observed}: {
  nodes: BuilderNode[]; links: BuilderLink[]; selection?: Selection;
  onSelect: (selection?: Selection) => void; onMove: (id: string, x: number, y: number) => void;
  graph: RefObject<Core | null>; observed: boolean
}) {
  const surface = useRef<HTMLDivElement>(null)
  const handlers = useRef({onSelect, onMove})
  useEffect(() => {handlers.current = {onSelect, onMove}}, [onSelect, onMove])

  useEffect(() => {
    const element = surface.current
    if (!element) return
    const cy = cytoscape({
      container: element, elements: [], layout: {name: 'preset', fit: false},
      zoom: 1, minZoom: .15, maxZoom: 2.5, boxSelectionEnabled: false, autounselectify: true,
      style: [
        {selector: 'node', style: {shape: 'round-rectangle', width: 154, height: observed ? 34 : 52,
          'background-color': '#16293b', 'border-width': 1.5, 'border-color': 'data(tone)',
          label: 'data(label)', color: '#e6eff8', 'font-size': 12, 'font-weight': 600,
          'text-valign': 'center', 'text-wrap': 'wrap', 'text-max-width': '130px'}},
        {selector: 'edge', style: {width: 1.8, 'curve-style': 'bezier', 'line-color': '#54748d',
          'target-arrow-color': '#789bb4', 'target-arrow-shape': 'triangle', label: 'data(relation)',
          color: '#bbd0e2', 'font-size': 11, 'text-margin-y': -32, 'text-wrap': 'ellipsis', 'text-max-width': '125px',
          'text-background-opacity': 1, 'text-background-color': '#0d1926', 'text-background-padding': '3px'}},
        {selector: 'node.current', style: {'border-color': '#f0d193', 'border-width': 3, 'background-color': '#223b50'}},
        {selector: 'edge.current', style: {'line-color': '#80d7ec', 'target-arrow-color': '#80d7ec', width: 3}},
        {selector: 'edge.incident', style: {'line-color': '#6c9ab4', 'target-arrow-color': '#9cc9df'}},
      ],
    })
    graph.current = cy
    cy.on('tap', 'node', event => handlers.current.onSelect({kind: 'node', id: event.target.id()}))
    cy.on('tap', 'edge', event => handlers.current.onSelect({kind: 'link', id: event.target.data('linkId')}))
    cy.on('tap', event => {if (event.target === cy) handlers.current.onSelect()})
    cy.on('dragfree', 'node', event => {
      const {x, y} = event.target.position()
      handlers.current.onMove(event.target.id(), Math.round(x), Math.round(y))
    })
    const observer = new ResizeObserver(() => cy.resize())
    observer.observe(element)
    return () => {observer.disconnect(); cy.destroy(); graph.current = null}
  }, [graph, observed])

  useEffect(() => {
    const cy = graph.current
    if (!cy) return
    const first = cy.nodes().length === 0
    const nodeIds = new Set(nodes.map(node => node.id))
    const linkIds = new Set(links.map(link => link.id))
    cy.batch(() => {
      cy.edges().filter(edge => !linkIds.has(edge.data('linkId'))).remove()
      cy.nodes().filter(node => !nodeIds.has(node.id())).remove()
      for (const node of nodes) {
        let label = node.label
        if (observed && node.kind === 'endpoint' && label === node.value) {
          try { const url = new URL(label); label = url.pathname + url.search } catch { /* keep the supplied label */ }
        }
        const data = {id: node.id, tone: nodeKinds[node.kind][1], label: label.slice(0, 44)}
        const position = {x: node.x, y: node.y}
        const current = cy.getElementById(node.id)
        if (current.length) current.data(data).position(position)
        else cy.add({group: 'nodes', data, position})
      }
      for (const link of links) {
        const id = 'link:' + link.id
        const current = cy.getElementById(id)
        if (current.length && (current.data('source') !== link.source || current.data('target') !== link.target)) current.remove()
        if (cy.getElementById(id).length) current.data('relation', link.relation)
        else cy.add({group: 'edges', data: {...link, id, linkId: link.id}})
      }
    })
    if (first && nodes.length) {
      cy.fit(undefined, 45)
      if (cy.zoom() > 1) {cy.zoom(1); cy.center()}
    }
  }, [graph, nodes, links, observed])

  useEffect(() => {
    const cy = graph.current
    if (!cy) return
    cy.elements().removeClass('current incident')
    if (!selection) return
    const element = cy.getElementById(selection.kind === 'link' ? 'link:' + selection.id : selection.id)
    element.addClass('current')
    if (selection.kind === 'node') element.connectedEdges().addClass('incident')
  }, [graph, selection, nodes, links])

  const lastRow = Math.max(0, ...nodes.map(node => node.y))
  return <div className="builder-canvas" ref={surface} role="group" aria-label="Attack surface canvas"
    style={observed ? {minHeight: Math.min(1400, lastRow + 120)} : undefined}/>
}
