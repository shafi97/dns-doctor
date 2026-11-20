import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import App from './App'
import { LookupError, type DomainRecords } from './dns'

const empty = { status: 0, records: [] }
const records = (domain: string): DomainRecords => ({
  domain,
  apex: { A: { status: 0, records: [{ name: domain, type: 'A', ttl: 60, data: '93.184.216.34' }] }, AAAA: empty, CNAME: empty, MX: empty, NS: empty, TXT: empty, CAA: empty },
  www: { A: empty, AAAA: empty, CNAME: empty },
  dmarc: empty,
})

describe('App', () => {
  it('shows a clear message for an invalid domain and does not look anything up (AC1)', async () => {
    const fetchRecords = vi.fn()
    render(<App fetchRecords={fetchRecords} />)
    await userEvent.type(screen.getByLabelText('Domain'), '1.2.3.4')
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/IP address/)
    expect(fetchRecords).not.toHaveBeenCalled()
  })

  it('cleans the input, shows findings and a copyable summary (AC2, AC3, AC5)', async () => {
    const fetchRecords = vi.fn(async (d: string) => records(d))
    render(<App fetchRecords={fetchRecords} />)
    await userEvent.type(screen.getByLabelText('Domain'), 'https://www.Example.com/x')
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    expect(await screen.findByRole('heading', { name: 'Results for example.com' })).toBeInTheDocument()
    expect(fetchRecords).toHaveBeenCalledWith('example.com')
    expect(screen.getByText('No email servers (MX)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /copy summary/i })).toBeInTheDocument()
  })

  it('shows an error with retry when the lookup fails, and no results (AC4)', async () => {
    const fetchRecords = vi.fn().mockRejectedValueOnce(new LookupError('Could not reach the DNS service.')).mockResolvedValueOnce(records('example.com'))
    render(<App fetchRecords={fetchRecords} />)
    await userEvent.type(screen.getByLabelText('Domain'), 'example.com')
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/Could not reach/)
    expect(screen.queryByRole('heading', { name: /Results/ })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Results for example.com' })).toBeInTheDocument())
  })
})
