import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { Findings, type Finding } from './Findings';

const conflicted: Finding = {
  clusterId: 'c1',
  displayId: 'CVE-2021-23337',
  aliases: ['GHSA-35jh-r3h4-6jhm', 'OSV-2021-1234'],
  severity: 'high',
  cvssVersion: '3.1',
  cvssScore: '7.2',
  severityConflict: true,
  severitySources: [
    {
      engine: 'grype',
      severity: 'critical',
      cvssVersion: '3.1',
      cvssScore: '9.8',
      cvssVector: 'AV:N/AC:L',
    },
    {
      engine: 'trivy-fs',
      severity: 'high',
      cvssVersion: '2.0',
      cvssScore: '7.2',
      cvssVector: 'AV:N/AC:M',
    },
  ],
  components: [{ key: 'k1', name: 'lodash', version: '4.17.20' }],
  fixedInMin: '4.17.21',
  fixOrdering: 'known',
  detectedBy: ['grype', 'osv-scanner'],
  vexStatus: '',
  vexJustification: '',
};

const noComparator: Finding = {
  ...conflicted,
  clusterId: 'c2',
  displayId: 'CVE-2020-0001',
  severityConflict: false,
  severitySources: [],
  fixedInMin: '2.0.0',
  fixOrdering: 'unknown',
};

function renderFindings(findings: Finding[]) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  client.setQueryData(['findings', 'p1'], { findings });

  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/projects/p1/findings']}>
        <Routes>
          <Route path="/projects/:id/findings" element={<Findings />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('severity conflict', () => {
  /**
   * ⚠ THE PHASE REQUIREMENT: `severity_conflict` IS AN EXPANDABLE BADGE
   * SHOWING WHO SAID WHAT — NEVER HIDDEN.
   *
   * A reviewer WILL ask why Trivy said High and Grype said Critical. Hiding the
   * disagreement leaves them with a number they cannot defend; averaging it
   * invents one no source asserted, and across CVSS v2/v3.1/v4.0 the arithmetic
   * is meaningless anyway.
   */
  it('is visible on the row and expands to every source', async () => {
    const user = userEvent.setup();
    renderFindings([conflicted]);

    const badge = await screen.findByRole('button', { name: /sources disagree/i });
    expect(badge).toHaveAttribute('aria-expanded', 'false');

    // Collapsed: the disagreement is announced but the detail is not on screen.
    expect(screen.queryByText(/are not comparable/i)).not.toBeInTheDocument();

    await user.click(badge);

    expect(badge).toHaveAttribute('aria-expanded', 'true');
    // Every source, with its own scale.
    expect(screen.getByText('9.8 (v3.1)')).toBeInTheDocument();
    expect(screen.getByText('7.2 (v2.0)')).toBeInTheDocument();
    // And the reason the product refuses to reduce them to one number.
    expect(screen.getByText(/are not comparable/i)).toBeInTheDocument();
  });

  it('is absent when the sources agreed', async () => {
    renderFindings([noComparator]);
    await screen.findByText('CVE-2020-0001');
    expect(screen.queryByRole('button', { name: /sources disagree/i })).not.toBeInTheDocument();
  });
});

describe('fix versions', () => {
  /**
   * ⚠ AN `unknown` ORDERING MEANS THE MINIMUM IS NOT A CLAIM WE CAN MAKE.
   *
   * Showing the raw value would assert an ordering a lexical sort gets wrong
   * for every ecosystem: 1.10.0 sorts before 1.9.0, and 1.9.0 does not contain
   * the fix. A user who upgrades to the wrong version believes they are patched.
   */
  it('says the lowest is unknown rather than showing a version it cannot rank', async () => {
    renderFindings([noComparator]);
    await screen.findByText(/lowest unknown/i);
    expect(screen.queryByText('2.0.0')).not.toBeInTheDocument();
  });

  it('shows the version when the ordering is known', async () => {
    renderFindings([conflicted]);
    expect(await screen.findByText('4.17.21')).toBeInTheDocument();
  });
});

describe('deduplication is visible', () => {
  it('shows one row per cluster and names the aliases', async () => {
    renderFindings([conflicted]);

    // One row, not three — the same vulnerability under GHSA, OSV and CVE.
    expect(await screen.findByText('CVE-2021-23337')).toBeInTheDocument();
    expect(screen.getByText('+2 aliases')).toBeInTheDocument();
    // The displayed id is the CVE, which is what a remediation ticket quotes.
    expect(screen.queryByText('GHSA-35jh-r3h4-6jhm')).not.toBeInTheDocument();
  });
});

describe('the empty state', () => {
  /**
   * ⚠ "NO FINDINGS" IS NOT THE SAME AS "NOTHING WRONG", and the empty state has
   * to say so. An ecosystem with no available engine produces zero findings for
   * a completely different reason, and a reader who takes the first for the
   * second has a false negative they trust.
   */
  it('points at Engine Coverage rather than declaring the project clean', async () => {
    renderFindings([]);
    expect(await screen.findByText(/Engine Coverage/)).toBeInTheDocument();
    expect(screen.getByText(/no available engine/i)).toBeInTheDocument();
  });
});
