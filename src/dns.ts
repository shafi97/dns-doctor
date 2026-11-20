export type RecordType = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'NS' | 'TXT' | 'CAA'

export interface DnsRecord {
  name: string
  type: string
  ttl: number
  data: string
}

export interface LookupResult {
  /** DNS status code. 0 = ok, 3 = domain does not exist. */
  status: number
  records: DnsRecord[]
}

export class LookupError extends Error {}

const TYPE_NUMBERS: Record<number, string> = { 1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 16: 'TXT', 28: 'AAAA', 257: 'CAA' }

interface DohAnswer { name: string; type: number; TTL: number; data: string }
interface DohResponse { Status: number; Answer?: DohAnswer[] }

export type Fetcher = (url: string, init?: RequestInit) => Promise<Response>

/** One DNS-over-HTTPS question to Cloudflare's public resolver. */
export async function lookup(
  name: string,
  type: RecordType,
  opts: { fetcher?: Fetcher; timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<LookupResult> {
  const fetcher = opts.fetcher ?? ((u, i) => fetch(u, i))
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 8000)
  opts.signal?.addEventListener('abort', () => controller.abort())
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`
    const res = await fetcher(url, { headers: { accept: 'application/dns-json' }, signal: controller.signal })
    if (!res.ok) throw new LookupError(`The DNS service answered with status ${res.status}.`)
    const body = (await res.json()) as DohResponse
    if (typeof body?.Status !== 'number') throw new LookupError('The DNS service returned an unexpected answer.')
    const records = (body.Answer ?? [])
      .filter((a) => TYPE_NUMBERS[a.type] === type || (type !== 'CNAME' && TYPE_NUMBERS[a.type] === 'CNAME'))
      .map((a) => ({ name: a.name.replace(/\.$/, ''), type: TYPE_NUMBERS[a.type], ttl: a.TTL, data: cleanData(TYPE_NUMBERS[a.type], a.data) }))
    return { status: body.Status, records }
  } catch (err) {
    if (err instanceof LookupError) throw err
    if (controller.signal.aborted) throw new LookupError('The DNS lookup took too long or was cancelled.')
    throw new LookupError('Could not reach the DNS service. Check your connection and try again.')
  } finally {
    clearTimeout(timer)
  }
}

function cleanData(type: string, data: string): string {
  if (type === 'TXT') return data.replace(/^"|"$/g, '').replace(/"\s*"/g, '')
  if (type === 'CNAME' || type === 'NS') return data.replace(/\.$/, '')
  if (type === 'MX') return data.replace(/\.$/, '')
  return data
}

export interface DomainRecords {
  domain: string
  apex: Partial<Record<RecordType, LookupResult>>
  www: Partial<Record<RecordType, LookupResult>>
  dmarc: LookupResult
}

const APEX_TYPES: RecordType[] = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA']
const WWW_TYPES: RecordType[] = ['A', 'AAAA', 'CNAME']

/** Fetches everything the analyzer needs. If any single lookup fails, the whole check fails (no partial results). */
export async function fetchDomainRecords(domain: string, opts: Parameters<typeof lookup>[2] = {}): Promise<DomainRecords> {
  const apexEntries = await Promise.all(APEX_TYPES.map(async (t) => [t, await lookup(domain, t, opts)] as const))
  const wwwEntries = await Promise.all(WWW_TYPES.map(async (t) => [t, await lookup(`www.${domain}`, t, opts)] as const))
  const dmarc = await lookup(`_dmarc.${domain}`, 'TXT', opts)
  return { domain, apex: Object.fromEntries(apexEntries), www: Object.fromEntries(wwwEntries), dmarc }
}
