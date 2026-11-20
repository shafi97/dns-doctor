import type { DomainRecords, DnsRecord, LookupResult } from './dns'

export type Severity = 'error' | 'warn' | 'info' | 'ok'

export interface Finding {
  id: string
  severity: Severity
  title: string
  meaning: string
  action: string
}

const ORDER: Severity[] = ['error', 'warn', 'info', 'ok']

const recs = (r?: LookupResult): DnsRecord[] => r?.records ?? []

export function isPrivateIp(ip: string): boolean {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!m) return false
  const [a, b] = [Number(m[1]), Number(m[2])]
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a >= 224
}

/** Counts the DNS lookups an SPF record asks the receiver to make (the limit is 10). */
export function spfLookupCount(spf: string): number {
  return spf
    .split(/\s+/)
    .filter((t) => /^(include:|a(:|\/|$)|mx(:|\/|$)|ptr(:|$)|exists:|redirect=)/i.test(t.replace(/^[+\-~?]/, ''))).length
}

export function analyze(data: DomainRecords): Finding[] {
  const out: Finding[] = []
  const add = (f: Finding) => out.push(f)
  const { apex, www } = data

  // R1: domain does not exist
  const anyApex = Object.values(apex)
  if (anyApex.length > 0 && anyApex.every((r) => r?.status === 3)) {
    add({
      id: 'R1', severity: 'error', title: 'This domain does not exist',
      meaning: 'The internet has no record of this name. It may be misspelled, expired, or not registered yet.',
      action: 'Check the spelling, then look up the domain with the registrar to see if it is registered and active.',
    })
    return sort(out)
  }

  // R2: apex resolves
  const apexAddr = [...recs(apex.A), ...recs(apex.AAAA), ...recs(apex.CNAME)]
  if (apexAddr.length === 0) {
    add({
      id: 'R2', severity: 'error', title: `${data.domain} has no website address`,
      meaning: `Visitors who type ${data.domain} without www will not reach a site.`,
      action: 'Add an A record (or ALIAS/ANAME) for the bare domain that points to the website host.',
    })
  } else add(ok('R2', 'Bare domain points to a host'))

  // R3: www resolves
  const wwwAddr = [...recs(www.A), ...recs(www.AAAA), ...recs(www.CNAME)]
  if (wwwAddr.length === 0) {
    add({
      id: 'R3', severity: 'warn', title: 'www has no record',
      meaning: `Visitors who type www.${data.domain} will get an error.`,
      action: 'Add a CNAME for www that points to the bare domain or to the website host.',
    })
  } else add(ok('R3', 'www points to a host'))

  // R4: private addresses
  const privateIps = [...recs(apex.A), ...recs(www.A)].filter((r) => isPrivateIp(r.data))
  if (privateIps.length > 0) {
    add({
      id: 'R4', severity: 'error', title: 'A record points to a private address',
      meaning: `${privateIps.map((r) => r.data).join(', ')} is not reachable from the internet, so the site will not load for visitors.`,
      action: 'Replace it with the public IP address of the website host.',
    })
  }

  // R5: name servers
  const ns = recs(apex.NS)
  if (ns.length < 2) {
    add({
      id: 'R5', severity: 'warn', title: ns.length === 0 ? 'No name servers found' : 'Only one name server',
      meaning: 'If that one server has a problem, the whole domain stops working.',
      action: 'Use at least two name servers, as your DNS provider recommends.',
    })
  } else add(ok('R5', `${ns.length} name servers`))

  // R6: MX
  const mx = recs(apex.MX)
  const nullMx = mx.length === 1 && /^0\s+\.?$/.test(mx[0].data)
  if (mx.length === 0) {
    add({
      id: 'R6', severity: 'warn', title: 'No email servers (MX)',
      meaning: 'Email sent to this domain will bounce or go missing.',
      action: 'Add the MX records from your email provider. If this domain should not receive email, add a null MX (priority 0 and a single dot).',
    })
  } else if (nullMx) {
    add({ id: 'R6', severity: 'info', title: 'Domain is set to receive no email', meaning: 'A null MX record tells senders this domain does not accept email.', action: 'Nothing to do if that is on purpose.' })
  } else add(ok('R6', `${mx.length} email server${mx.length === 1 ? '' : 's'} set`))

  // R7-R10: SPF
  const spfs = recs(apex.TXT).filter((r) => /^v=spf1(\s|$)/i.test(r.data))
  if (spfs.length === 0) {
    add({
      id: 'R7', severity: 'warn', title: 'No SPF record',
      meaning: 'Receivers cannot confirm who may send email for this domain, so messages are more likely to land in spam.',
      action: 'Add a TXT record that starts with v=spf1 and lists your email providers.',
    })
  } else if (spfs.length > 1) {
    add({
      id: 'R8', severity: 'error', title: 'More than one SPF record',
      meaning: 'Receivers treat this as invalid and may ignore SPF completely.',
      action: 'Merge them into a single SPF record that lists every sender.',
    })
  } else {
    const spf = spfs[0].data
    let healthy = true
    if (/(^|\s)\+all(\s|$)/i.test(spf)) {
      healthy = false
      add({ id: 'R9', severity: 'error', title: 'SPF allows anyone to send', meaning: 'Ending with +all lets any server send email as this domain.', action: 'End the record with -all (strict) or ~all (softer) instead.' })
    }
    const lookups = spfLookupCount(spf)
    if (lookups > 10) {
      healthy = false
      add({ id: 'R10', severity: 'error', title: `SPF needs ${lookups} DNS lookups (limit is 10)`, meaning: 'Above 10, receivers fail the SPF check, so legitimate email can be rejected.', action: 'Remove services you no longer use or flatten the includes.' })
    }
    if (healthy) add(ok('R7', 'One valid-looking SPF record'))
  }

  // R11-R12: DMARC
  const dmarc = data.dmarc.records.filter((r) => /^v=DMARC1/i.test(r.data))
  if (dmarc.length === 0) {
    add({
      id: 'R11', severity: 'warn', title: 'No DMARC record',
      meaning: 'Without DMARC, anyone can pretend to be this domain more easily, and big mailbox providers may treat the domain as less trustworthy.',
      action: 'Add a TXT record at _dmarc with v=DMARC1; p=none; rua=mailto:you@example.com to start, then tighten it later.',
    })
  } else if (/;\s*p=none/i.test(dmarc[0].data) || /^v=DMARC1;\s*p=none/i.test(dmarc[0].data)) {
    add({ id: 'R12', severity: 'info', title: 'DMARC is in monitor-only mode', meaning: 'Reports are collected but spoofed email is not blocked yet.', action: 'Once reports look clean, move to p=quarantine and then p=reject.' })
  } else add(ok('R11', 'DMARC policy is set'))

  // R13: CAA
  if (recs(apex.CAA).length === 0) {
    add({ id: 'R13', severity: 'info', title: 'No CAA record', meaning: 'Any certificate authority may issue certificates for this domain. That is normal, but CAA adds control.', action: 'Optional: add a CAA record naming the certificate authority you use.' })
  }

  // R14: DKIM
  add({ id: 'R14', severity: 'info', title: 'DKIM was not checked', meaning: 'DKIM records live under a selector name that only the email provider knows.', action: 'Ask the provider for the selector, then look up selector._domainkey.' + data.domain + ' as a TXT record.' })

  return sort(out)
}

function ok(id: string, title: string): Finding {
  return { id, severity: 'ok', title, meaning: '', action: '' }
}

function sort(list: Finding[]): Finding[] {
  return [...list].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity))
}

export function summarize(domain: string, findings: Finding[], date = new Date()): string {
  const errors = findings.filter((f) => f.severity === 'error')
  const warns = findings.filter((f) => f.severity === 'warn')
  const lines = [
    `DNS check for ${domain} on ${date.toISOString().slice(0, 10)}`,
    `${errors.length} problem${errors.length === 1 ? '' : 's'} and ${warns.length} warning${warns.length === 1 ? '' : 's'} found.`,
  ]
  for (const f of errors) lines.push(`- Problem: ${f.title}. ${f.action}`)
  for (const f of warns) lines.push(`- Warning: ${f.title}. ${f.action}`)
  if (errors.length + warns.length === 0) lines.push('Nothing needs fixing from this check.')
  return lines.join('\n')
}
