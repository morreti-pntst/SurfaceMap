import {readTcpwrappedVisibility} from './tcpwrappedVisibility'

export type MapVisibility = {ids: Set<string>; hideWrapped: boolean; shownWrapped: Set<string>;
  hideUnidentified: boolean; shownUnidentified: Set<string>}

const stringSet = (items: unknown) => new Set<string>(
  Array.isArray(items) ? items.filter(item => typeof item === 'string') : [],
)

export function emptyMapVisibility(): MapVisibility {
  return {ids: new Set(), hideWrapped: false, shownWrapped: new Set(), hideUnidentified: false, shownUnidentified: new Set()}
}

export function readMapVisibility(key: string, projectId: number): MapVisibility {
  const legacy = {...emptyMapVisibility(), hideWrapped: readTcpwrappedVisibility(projectId), hideUnidentified: true}
  try {
    const value = JSON.parse(localStorage.getItem(key) ?? 'null')
    if (!value || Array.isArray(value)) return {...legacy, ids: stringSet(value)}
    return {ids: stringSet(value.ids), hideWrapped: value.hideWrapped === true, shownWrapped: stringSet(value.shownWrapped),
      hideUnidentified: value.hideUnidentified !== false, shownUnidentified: stringSet(value.shownUnidentified)}
  } catch {
    return legacy
  }
}

export function persistMapVisibility(key: string, visibility: MapVisibility) {
  try {
    localStorage.setItem(key, JSON.stringify({...visibility, ids: [...visibility.ids], shownWrapped: [...visibility.shownWrapped],
      shownUnidentified: [...visibility.shownUnidentified]}))
  } catch { /* Visibility still works while the map is open. */ }
}
