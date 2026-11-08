type Evidence = {templateId: string; target: string; matchers?: string[]}

export default function FindingVerification({templateId, target, matchers = []}: Evidence) {
  let steps: string[]
  let meaning: string
  switch (templateId) {
    case 'http-missing-security-headers': {
      const headers = matchers.filter(name => /^[a-z0-9-]+$/i.test(name))
      steps = [
        'Open the matched URL in a browser. In Developer Tools → Network, reload and select the document request. Check the status and final URL so you are looking at the intended response.',
        headers.length ? 'Under Response Headers, check for ' + headers.join(', ') + '. Repeat on representative pages and after login if the response depends on authentication.'
          : 'Under Response Headers, compare the response with the headers reported by the template. Repeat on representative pages.',
      ]
      meaning = 'Confirm the absence on the intended response. Prioritize it when the missing header protects a behavior that applies there, such as scripts on an HTML page for CSP or HTTPS downgrade protection for HSTS.'
      break
    }
    case 'cors-misconfig':
      steps = [
        'Repeat a read-only request to the matched URL with an Origin header from a domain you control. Compare Access-Control-Allow-Origin and Access-Control-Allow-Credentials with a request from the approved origin.',
        'Using an approved test account, check in a browser whether a page on the test origin can read the response. Use a harmless endpoint or test data.',
      ]
      meaning = 'A meaningful result shows an unexpected origin can read data that should be restricted. An echoed origin alone leaves browser behavior and data exposure to verify.'
      break
    case 'git-config':
      steps = [
        'Make a single GET request to the matched URL and check the status, Content-Type and response shape. Compare against a deliberately nonexistent path to rule out a generic success page.',
        'Look for Git configuration structure, such as a [core] section. Record the status and the minimum evidence needed to confirm exposure.',
      ]
      meaning = 'Treat a real Git configuration returned to an unauthenticated request as evidence of exposure. A generic HTML page, redirect or access challenge does not confirm it.'
      break
    case 'nginx-version':
      steps = [
        'Open the matched URL and inspect the Server response header in Developer Tools → Network. Compare it with the recorded scanner evidence.',
        'Where you have server access, verify the running package version and security patches with the server owner before mapping it to a CVE.',
      ]
      meaning = 'The banner helps identify a component. A vulnerability requires a matching version or build, a missing fix and applicable configuration.'
      break
    default:
      steps = [
        'Open the recorded evidence and identify the exact template and matcher. Check which response, header or value made the template match.',
        'Run Prepare retest with that exact template. If the match repeats, inspect the same route with a read-only request and rule out a generic error page, redirect or access challenge.',
      ]
      meaning = 'Record the observed behavior, the affected asset and the practical impact before marking the finding confirmed.'
  }
  return <div className="finding-verification">
    {target && <code>{target}</code>}
    <ol>{steps.map(step => <li key={step}>{step}</li>)}</ol>
    <p><strong>What makes it useful</strong><br/>{meaning}</p>
  </div>
}
