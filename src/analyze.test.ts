import { describe, expect, it } from 'vitest'
import { analyze, isPrivateIp, spfLookupCount, summarize } from './analyze'
import type { DnsRecord, DomainRecords, LookupResult, RecordType } from './dns'

const r = (type: string, data: string, name = 'example.com'): DnsRecord => ({ name, type, ttl: 300, data })
const res = (records: DnsRecord[] = [], status = 0): LookupResult => ({ status, records })

/** A healthy domain. Tests change one thing at a time. */
function healthy(over: { apex?: Partial<Record<RecordType, LookupResult>>; www?: Partial<Record<RecordType, LookupResult>>; dmarc?: LookupResult } = {}): DomainRecords {
  return {
    domain: 'example.com',
    apex: {
      A: res([r('A', '93.184.216.34')]), AAAA: res(), CNAME: res(),
      MX: res([r('MX', '10 mail.example.com')]),
      NS: res([r('NS', 'ns1.host.com'), r('NS', 'ns2.host.com')]),
      TXT: res([r('TXT', 'v=spf1 include:_spf.google.com ~all')]),
      CAA: res([r('CAA', '0 issue "letsencrypt.org"')]),
      ...over.apex,
    },
    www: { A: res(), AAAA: res(), CNAME: res([r('CNAME', 'example.com', 'www.example.com')]), ...over.www },
    dmarc: over.dmarc ?? res([r('TXT', 'v=DMARC1; p=reject; rua=mailto:d@example.com', '_dmarc.example.com')]),
  }
}
const ids = (d: DomainRecords, sev?: string) => analyze(d).filter((f) => !sev || f.severity === sev).map((f) => f.id)

describe('analyze (AC2)', () => {
  it('has no errors or warnings for a healthy domain', () => {
    expect(ids(healthy(), 'error')).toEqual([])
    expect(ids(healthy(), 'warn')).toEqual([])
  })
  it('R1: NXDOMAIN stops with one error', () => {
    const d = healthy()
    for (const k of Object.keys(d.apex) as RecordType[]) d.apex[k] = res([], 3)
    expect(ids(d)).toEqual(['R1'])
  })
  it('R2: bare domain without a host', () => {
    expect(ids(healthy({ apex: { A: res(), AAAA: res(), CNAME: res() } }), 'error')).toContain('R2')
  })
  it('R3: www missing', () => {
    expect(ids(healthy({ www: { A: res(), AAAA: res(), CNAME: res() } }), 'warn')).toContain('R3')
  })
  it('R4: private address', () => {
    expect(ids(healthy({ apex: { A: res([r('A', '192.168.1.10')]) } }), 'error')).toContain('R4')
    expect(isPrivateIp('172.16.0.1')).toBe(true)
    expect(isPrivateIp('172.32.0.1')).toBe(false)
    expect(isPrivateIp('8.8.8.8')).toBe(false)
    expect(isPrivateIp('100.64.1.1')).toBe(true)
  })
  it('R5: fewer than two name servers', () => {
    expect(ids(healthy({ apex: { NS: res([r('NS', 'ns1.host.com')]) } }), 'warn')).toContain('R5')
  })
  it('R6: no MX, and null MX is only a note', () => {
    expect(ids(healthy({ apex: { MX: res() } }), 'warn')).toContain('R6')
    const nullMx = analyze(healthy({ apex: { MX: res([r('MX', '0 .')]) } })).find((f) => f.id === 'R6')
    expect(nullMx?.severity).toBe('info')
  })
  it('R7: no SPF', () => {
    expect(ids(healthy({ apex: { TXT: res() } }), 'warn')).toContain('R7')
  })
  it('R8: two SPF records', () => {
    const txt = res([r('TXT', 'v=spf1 -all'), r('TXT', 'v=spf1 include:x.com ~all')])
    expect(ids(healthy({ apex: { TXT: txt } }), 'error')).toContain('R8')
  })
  it('R9: +all', () => {
    expect(ids(healthy({ apex: { TXT: res([r('TXT', 'v=spf1 a mx +all')]) } }), 'error')).toContain('R9')
    expect(ids(healthy({ apex: { TXT: res([r('TXT', 'v=spf1 a mx ~all')]) } }), 'error')).not.toContain('R9')
  })
  it('R10: more than 10 lookups', () => {
    const many = 'v=spf1 ' + Array.from({ length: 11 }, (_, i) => `include:s${i}.com`).join(' ') + ' ~all'
    expect(spfLookupCount(many)).toBe(11)
    expect(ids(healthy({ apex: { TXT: res([r('TXT', many)]) } }), 'error')).toContain('R10')
    expect(spfLookupCount('v=spf1 ip4:1.2.3.4 -all')).toBe(0)
    expect(spfLookupCount('v=spf1 a mx include:x.com redirect=y.com ~all')).toBe(4)
  })
  it('R11 and R12: DMARC', () => {
    expect(ids(healthy({ dmarc: res() }), 'warn')).toContain('R11')
    const none = res([r('TXT', 'v=DMARC1; p=none', '_dmarc.example.com')])
    expect(analyze(healthy({ dmarc: none })).find((f) => f.id === 'R12')?.severity).toBe('info')
  })
  it('R13 and R14: info notes', () => {
    expect(ids(healthy({ apex: { CAA: res() } }), 'info')).toContain('R13')
    expect(ids(healthy(), 'info')).toContain('R14')
  })
})

describe('ordering and summary (AC3, AC5)', () => {
  it('sorts error, warn, info, ok', () => {
    const order = ['error', 'warn', 'info', 'ok']
    const sevs = analyze(healthy({ apex: { A: res(), MX: res() }, dmarc: res() })).map((f) => order.indexOf(f.severity))
    expect(sevs).toEqual([...sevs].sort((a, b) => a - b))
  })
  it('builds a ticket-ready summary', () => {
    const f = analyze(healthy({ apex: { MX: res() }, dmarc: res() }))
    const text = summarize('example.com', f, new Date('2026-11-19T12:00:00Z'))
    expect(text).toContain('example.com')
    expect(text).toContain('2026-11-19')
    expect(text).toContain('0 problems and 2 warnings')
    expect(text).toContain('Warning: No email servers (MX)')
  })
  it('says so when nothing needs fixing', () => {
    expect(summarize('example.com', analyze(healthy()))).toMatch(/Nothing needs fixing|0 problems and 0 warnings/)
  })
})
