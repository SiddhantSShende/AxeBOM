import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BomTypeChip, NotProvided, SeverityBadge, StatusPill, Value } from './Chips';
import { BOM_TYPES, SEVERITIES } from '../design/theme';

/**
 * ⚠ THE ACCESSIBILITY TESTS THAT MATTER MOST IN THIS PRODUCT.
 *
 * A colour-blind user reading a vulnerability report is a compliance risk, not
 * an edge case. These assert the property directly: the WORD is present, so the
 * colour is reinforcement rather than the signal (WCAG 1.4.1).
 */
describe('every chip carries its label', () => {
  it('renders the BOM type as text, not only as a colour', () => {
    for (const b of BOM_TYPES) {
      const { unmount } = render(<BomTypeChip type={b.type} />);
      expect(screen.getByText(b.label)).toBeInTheDocument();
      unmount();
    }
  });

  it('renders the severity word, not only a dot', () => {
    for (const s of SEVERITIES) {
      const { unmount } = render(<SeverityBadge severity={s.severity} />);
      expect(screen.getByText(s.label)).toBeInTheDocument();
      unmount();
    }
  });

  it('hides the decorative glyph from screen readers', () => {
    const { container } = render(<SeverityBadge severity="critical" />);
    const glyph = container.querySelector('[aria-hidden="true"]');
    // Announcing "large circle Critical" is noise on top of a label the reader
    // already gets.
    expect(glyph).not.toBeNull();
    expect(glyph?.textContent).not.toBe('Critical');
  });

  it('keeps the word when a count is shown', () => {
    render(<SeverityBadge severity="high" count={12} />);
    // "High · 12" and not "12" — the count must never become the only content.
    expect(screen.getByText('High')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
  });
});

describe('unknown values', () => {
  it('renders an unknown BOM type visibly rather than nothing', () => {
    render(<BomTypeChip type="XBOM" />);
    // A row silently losing a column is worse than a visibly odd chip.
    expect(screen.getByText('XBOM')).toBeInTheDocument();
  });

  // ⚠ `unknown` MUST NOT COLLAPSE INTO `none`. "No severity was asserted" and
  // "assessed as no severity" are different claims, and rendering the first as
  // the second understates risk in a document a customer acts on.
  it('keeps unknown severity distinct from none', () => {
    const { unmount } = render(<SeverityBadge severity={null} />);
    expect(screen.getByText('Unknown')).toBeInTheDocument();
    unmount();

    render(<SeverityBadge severity="none" />);
    expect(screen.getByText('None')).toBeInTheDocument();
    expect(screen.queryByText('Unknown')).not.toBeInTheDocument();
  });
});

describe('not-provided', () => {
  // ⚠ NEVER A BLANK CELL. Blank reads as "we did not look"; `not-provided` says
  // we looked and there was nothing. Both score zero for completeness, but only
  // one is a statement the reader can act on.
  it('renders explicitly for an empty value', () => {
    render(
      <span>
        <Value>{''}</Value>
      </span>,
    );
    expect(screen.getByText('not-provided')).toBeInTheDocument();
  });

  it('renders explicitly for a null value', () => {
    render(
      <span>
        <Value>{null}</Value>
      </span>,
    );
    expect(screen.getByText('not-provided')).toBeInTheDocument();
  });

  it('does not double-render an already-not-provided value', () => {
    render(
      <span>
        <Value>{'not-provided'}</Value>
      </span>,
    );
    expect(screen.getAllByText('not-provided')).toHaveLength(1);
  });

  it('explains what it means on hover', () => {
    render(<NotProvided />);
    expect(screen.getByText('not-provided')).toHaveAttribute(
      'title',
      expect.stringContaining('zero for completeness'),
    );
  });

  it('passes a real value through untouched', () => {
    render(
      <span>
        <Value>{'4.17.21'}</Value>
      </span>,
    );
    expect(screen.getByText('4.17.21')).toBeInTheDocument();
    expect(screen.queryByText('not-provided')).not.toBeInTheDocument();
  });
});

describe('status pills', () => {
  /**
   * ⚠ `partial` AND `unavailable` ARE WARNINGS, NOT FAILURES.
   *
   * One engine covering eleven of twelve ecosystems is useful output plus a
   * known gap. Painting it the same red as a crash teaches a user to ignore the
   * one status that means "look here", which is how a stated gap becomes an
   * unnoticed one.
   */
  it('treats partial and unavailable as warnings rather than failures', () => {
    for (const status of ['partial', 'unavailable', 'no-engine', 'completed_with_errors']) {
      const { container, unmount } = render(<StatusPill status={status} />);
      expect(container.firstElementChild).toHaveAttribute('data-status', 'warn');
      unmount();
    }

    for (const status of ['failed', 'timeout', 'revoked', 'expired']) {
      const { container, unmount } = render(<StatusPill status={status} />);
      expect(container.firstElementChild).toHaveAttribute('data-status', 'down');
      unmount();
    }
  });

  it('renders the status as readable words', () => {
    render(<StatusPill status="completed_with_errors" />);
    expect(screen.getByText('completed with errors')).toBeInTheDocument();
  });
});
