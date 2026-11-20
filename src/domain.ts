export class DomainError extends Error {}

/** Turns "https://WWW.Example.com:8080/path?x=1" into "www.example.com" and rejects anything that is not a hostname. */
export function normalizeDomain(input: string): string {
  let value = input.trim().toLowerCase()
  if (!value) throw new DomainError('Enter a domain name, for example example.com.')
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '') // protocol
  value = value.replace(/^[^@/]*@/, '') // user info
  value = value.split(/[/?#]/)[0] // path, query, fragment
  value = value.replace(/:\d+$/, '') // port
  value = value.replace(/\.$/, '') // trailing dot
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.includes(':')) {
    throw new DomainError('That looks like an IP address. Enter a domain name instead.')
  }
  const label = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/
  const parts = value.split('.')
  if (value.length > 253 || parts.length < 2 || !parts.every((p) => label.test(p)) || !/^[a-z]{2,}$|^xn--[a-z0-9-]+$/.test(parts[parts.length - 1])) {
    throw new DomainError('That does not look like a valid domain name.')
  }
  return value
}

/** Strips a leading www. so we can check both the bare domain and www. */
export function bareDomain(domain: string): string {
  return domain.replace(/^www\./, '')
}
