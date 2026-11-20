import { describe, expect, it } from 'vitest'
import { bareDomain, DomainError, normalizeDomain } from './domain'

describe('normalizeDomain (AC1)', () => {
  it('cleans pasted addresses', () => {
    expect(normalizeDomain('https://WWW.Example.com:8080/about?x=1#top')).toBe('www.example.com')
    expect(normalizeDomain('  example.com.  ')).toBe('example.com')
    expect(normalizeDomain('http://user@example.co.uk/')).toBe('example.co.uk')
  })
  it('rejects bad input with a clear message', () => {
    for (const bad of ['', '   ', 'localhost', 'not a domain', '-bad.com', 'a..com', '1.2.3.4', '[::1]', 'exa_mple.com', 'x'.repeat(64) + '.com']) {
      expect(() => normalizeDomain(bad), bad).toThrow(DomainError)
    }
  })
  it('accepts internationalised names in punycode', () => {
    expect(normalizeDomain('xn--bcher-kva.example')).toBe('xn--bcher-kva.example')
  })
  it('strips www for the bare domain', () => {
    expect(bareDomain('www.example.com')).toBe('example.com')
    expect(bareDomain('example.com')).toBe('example.com')
  })
})
