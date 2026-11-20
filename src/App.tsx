import { useRef, useState, type FormEvent } from 'react'
import { analyze, summarize, type Finding } from './analyze'
import { bareDomain, DomainError, normalizeDomain } from './domain'
import { fetchDomainRecords, LookupError, type DomainRecords } from './dns'

type State =
  | { kind: 'idle' }
  | { kind: 'loading'; domain: string }
  | { kind: 'error'; message: string; domain?: string }
  | { kind: 'done'; domain: string; records: DomainRecords; findings: Finding[] }

const LABEL: Record<Finding['severity'], string> = { error: 'Problem', warn: 'Warning', info: 'Note', ok: 'Looks good' }

export default function App({ fetchRecords = fetchDomainRecords }: { fetchRecords?: typeof fetchDomainRecords }) {
  const [input, setInput] = useState('')
  const [state, setState] = useState<State>({ kind: 'idle' })
  const [copied, setCopied] = useState(false)
  const runId = useRef(0)

  async function run(raw: string) {
    let domain: string
    try {
      domain = bareDomain(normalizeDomain(raw))
    } catch (err) {
      setState({ kind: 'error', message: err instanceof DomainError ? err.message : 'Enter a domain name.' })
      return
    }
    const id = ++runId.current
    setCopied(false)
    setState({ kind: 'loading', domain })
    try {
      const records = await fetchRecords(domain)
      if (id !== runId.current) return // a newer check replaced this one
      setState({ kind: 'done', domain, records, findings: analyze(records) })
    } catch (err) {
      if (id !== runId.current) return
      setState({ kind: 'error', domain, message: err instanceof LookupError ? err.message : 'Something went wrong. Try again.' })
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault()
    void run(input)
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  return (
    <main>
      <h1>DNS Doctor</h1>
      <p className="lead">Type a domain. Get its live DNS records and a plain-words list of what is wrong and how to fix it.</p>

      <form onSubmit={submit} noValidate aria-label="Check a domain">
        <label htmlFor="domain">Domain</label>
        <div className="row">
          <input id="domain" value={input} onChange={(e) => setInput(e.target.value)} placeholder="example.com" autoComplete="off" autoCapitalize="none" spellCheck={false}
            aria-invalid={state.kind === 'error' && !state.domain} aria-describedby="status" />
          <button type="submit" className="primary" disabled={state.kind === 'loading'}>Check</button>
        </div>
      </form>

      <div id="status" aria-live="polite">
        {state.kind === 'loading' && <p>Checking {state.domain}...</p>}
        {state.kind === 'error' && (
          <div role="alert" className="alert">
            <p>{state.message}</p>
            {state.domain && <button type="button" onClick={() => void run(state.domain!)}>Retry</button>}
          </div>
        )}
      </div>

      {state.kind === 'done' && <Results domain={state.domain} records={state.records} findings={state.findings} copied={copied} onCopy={copy} />}

      <footer>
        Personal project built with Claude Code from a written spec (see SPEC.md). Lookups go from your browser to Cloudflare's public DNS-over-HTTPS service. Nothing is stored.
      </footer>
    </main>
  )
}

function Results({ domain, records, findings, copied, onCopy }: { domain: string; records: DomainRecords; findings: Finding[]; copied: boolean; onCopy: (t: string) => void }) {
  const summary = summarize(domain, findings)
  const issues = findings.filter((f) => f.severity !== 'ok')
  const good = findings.filter((f) => f.severity === 'ok')
  const rows = [
    ...Object.values(records.apex).flatMap((r) => r?.records ?? []),
    ...Object.values(records.www).flatMap((r) => r?.records ?? []),
    ...records.dmarc.records,
  ]
  return (
    <section aria-label={`Results for ${domain}`}>
      <h2>Results for {domain}</h2>
      <div className="actions">
        <button onClick={() => onCopy(summary)}>Copy summary for a ticket</button>
        {copied && <span role="status">Copied</span>}
      </div>

      {issues.length === 0 ? <p>No problems found by these checks.</p> : (
        <ul className="findings">
          {issues.map((f) => (
            <li key={f.id} className={`finding ${f.severity}`}>
              <span className="tag">{LABEL[f.severity]}</span>
              <h3>{f.title}</h3>
              <p>{f.meaning}</p>
              <p><strong>What to do:</strong> {f.action}</p>
            </li>
          ))}
        </ul>
      )}

      {good.length > 0 && <p className="good">{good.map((g) => g.title).join(' · ')}</p>}

      <details>
        <summary>Raw records ({rows.length})</summary>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Type</th><th>TTL</th><th>Value</th></tr></thead>
            <tbody>
              {rows.map((r, i) => <tr key={i}><td>{r.name}</td><td>{r.type}</td><td>{r.ttl}</td><td>{r.data}</td></tr>)}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  )
}
