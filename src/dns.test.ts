import { describe, expect, it } from 'vitest'
import { fetchDomainRecords, lookup, LookupError } from './dns'

const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status }))

describe('lookup (AC4)', () => {
  it('parses answers and cleans values', async () => {
    const out = await lookup('example.com', 'TXT', {
      fetcher: () => json({ Status: 0, Answer: [{ name: 'example.com.', type: 16, TTL: 60, data: '"v=spf1 " "-all"' }] }),
    })
    expect(out.records[0]).toMatchObject({ name: 'example.com', type: 'TXT', data: 'v=spf1 -all' })
  })
  it('keeps CNAME answers when asking for A (resolver follows the chain)', async () => {
    const out = await lookup('www.example.com', 'A', {
      fetcher: () => json({ Status: 0, Answer: [{ name: 'www.example.com.', type: 5, TTL: 60, data: 'example.com.' }, { name: 'example.com.', type: 1, TTL: 60, data: '1.2.3.4' }] }),
    })
    expect(out.records.map((r) => r.type)).toEqual(['CNAME', 'A'])
  })
  it('reports NXDOMAIN as a status, not an error', async () => {
    expect((await lookup('nope.example', 'A', { fetcher: () => json({ Status: 3 }) })).status).toBe(3)
  })
  it('throws a clear error for HTTP failures, bad bodies and network errors', async () => {
    await expect(lookup('a.com', 'A', { fetcher: () => json({}, 500) })).rejects.toThrow(/status 500/)
    await expect(lookup('a.com', 'A', { fetcher: () => json({ nope: true }) })).rejects.toThrow(LookupError)
    await expect(lookup('a.com', 'A', { fetcher: () => Promise.reject(new TypeError('failed')) })).rejects.toThrow(/Could not reach/)
  })
  it('times out', async () => {
    const slow = (_u: string, init?: RequestInit) => new Promise<Response>((_res, rej) => init?.signal?.addEventListener('abort', () => rej(new Error('aborted'))))
    await expect(lookup('a.com', 'A', { fetcher: slow, timeoutMs: 20 })).rejects.toThrow(/too long/)
  })
  it('fails the whole check if any lookup fails (no partial result)', async () => {
    let n = 0
    const flaky = () => (++n === 5 ? Promise.reject(new TypeError('x')) : json({ Status: 0 }))
    await expect(fetchDomainRecords('example.com', { fetcher: flaky })).rejects.toThrow(LookupError)
  })
})
