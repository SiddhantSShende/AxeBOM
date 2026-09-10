/**
 * The live discovery tally.
 *
 * ⚠ THESE TWO FUNCTIONS ARE THE ONLY PLACE THIS PAGE TURNS ENGINE CLAIMS INTO
 * A NUMBER A CUSTOMER READS, and both of their rules are the kind that look
 * like polish and are not. Summing agreeing engines would print a count nobody
 * found; a label table would silently swallow every kind a future engine
 * reports. Each is pinned here.
 */

import { describe, expect, it } from 'vitest';
import { metricLabel, sortedCounts, tallyDiscoveries } from './discoveries';

describe('tallyDiscoveries', () => {
  it('does not add up engines that agree', () => {
    // The ai-langchain fixture holds ONE model, and three engines each report
    // it. Summing would say three.
    const totals = tallyDiscoveries({
      'ai-bom': { ai_models: 1 },
      airom: { ai_models: 1 },
      'cdxgen-ai': { ai_models: 1 },
    });
    expect(totals.ai_models).toBe(1);
  });

  it('reports the largest single claim when engines disagree', () => {
    // airom reads file:line evidence ai-bom cannot; it legitimately sees more.
    // The answer is what the better engine saw, not the lower bound and not
    // the sum.
    expect(
      tallyDiscoveries({ 'ai-bom': { ai_models: 1 }, airom: { ai_models: 3 } }).ai_models,
    ).toBe(3);
  });

  it('keeps kinds only one engine reports', () => {
    const totals = tallyDiscoveries({
      'ai-bom': { ai_models: 2 },
      airom: { ai_models: 2, 'ai_asset.vector_store': 1 },
    });
    expect(totals).toEqual({ ai_models: 2, 'ai_asset.vector_store': 1 });
  });

  it('keeps a measured zero', () => {
    // 0 means "looked, found none" — a real answer, and different from the
    // kind being absent entirely.
    expect(tallyDiscoveries({ airom: { ai_datasets: 0 } })).toEqual({ ai_datasets: 0 });
  });

  it('is empty when no engine has reported', () => {
    expect(tallyDiscoveries({})).toEqual({});
  });
});

describe('sortedCounts', () => {
  it('is largest first, and stable on a tie', () => {
    // The chips re-render on every event. Object key order would reshuffle
    // them under a reader's eye.
    const rows = sortedCounts({ b: 1, a: 1, big: 9 });
    expect(rows).toEqual([
      ['big', 9],
      ['a', 1],
      ['b', 1],
    ]);
  });
});

describe('metricLabel', () => {
  it('reads an asset key as what a person calls the thing', () => {
    expect(metricLabel('ai_asset.vector_store', 2)).toBe('vector stores');
    expect(metricLabel('ai_asset.rag_pipeline', 2)).toBe('RAG pipelines');
    expect(metricLabel('ai_asset.mcp_server', 1)).toBe('MCP server');
  });

  it('renders a kind it has never seen, rather than nothing', () => {
    // The point of deriving from the key: a new engine's new kind shows up
    // legibly on the day it ships, with no change here.
    expect(metricLabel('quantum_widget', 3)).toBe('quantum widgets');
  });

  it('does not pluralize one, or pluralize twice', () => {
    expect(metricLabel('ai_models', 1)).toBe('AI model');
    expect(metricLabel('ai_models', 4)).toBe('AI models');
    expect(metricLabel('vulnerabilities', 4)).toBe('vulnerabilities');
  });

  it('falls back to the raw key rather than rendering an empty label', () => {
    expect(metricLabel('_', 2)).toBe('_');
  });
});
