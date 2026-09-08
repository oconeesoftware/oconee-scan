import { describe, expect, it } from 'vitest';
import {
  CATEGORY_CAP,
  CONFIDENCE_FACTOR,
  SEVERITY_WEIGHT,
  calculateScore,
  pointsFor,
  riskLevelFor,
} from '../src/scoring/index.js';
import type { Category, Confidence, Finding, Severity } from '../src/types/index.js';
import { scanFixture } from './helpers.js';

function finding(
  severity: Severity,
  confidence: Confidence = 'high',
  category: Category = 'Agent Configuration',
): Finding {
  return {
    rule_id: 'TEST-001',
    title: 'test',
    category,
    severity,
    confidence,
    description: 'test finding',
    evidence: [{ detail: 'test' }],
    affected_path: '.',
    recommendation: 'test',
    documentation_url: 'https://example.com',
  };
}

describe('scoring methodology', () => {
  it('scores an empty finding set at zero', () => {
    const score = calculateScore([]);
    expect(score.score).toBe(0);
    expect(score.level).toBe('Minimal');
    expect(score.breakdown).toEqual([]);
  });

  it('weights a finding by severity and confidence', () => {
    expect(pointsFor(finding('critical', 'high'))).toBe(SEVERITY_WEIGHT.critical);
    expect(pointsFor(finding('high', 'low'))).toBe(SEVERITY_WEIGHT.high * CONFIDENCE_FACTOR.low);
    expect(pointsFor(finding('info', 'high'))).toBe(0);
  });

  it('is reproducible by hand from the published weights', () => {
    const findings = [
      finding('high', 'high', 'Agent Configuration'), // 20
      finding('medium', 'medium', 'Auditability'), // 6.4
      finding('low', 'low', 'Repository Risk'), // 1.5
    ];
    expect(calculateScore(findings).score).toBe(Math.round(20 + 6.4 + 1.5));
  });

  it('caps the contribution of any single category', () => {
    const many = Array.from({ length: 20 }, () =>
      finding('critical', 'high', 'Credential Exposure'),
    );
    const score = calculateScore(many);
    const entry = score.breakdown.find((item) => item.category === 'Credential Exposure');
    expect(entry?.rawPoints).toBe(20 * SEVERITY_WEIGHT.critical);
    expect(entry?.cappedPoints).toBe(CATEGORY_CAP);
    expect(score.score).toBe(CATEGORY_CAP);
  });

  it('clamps the total to 0-100', () => {
    const across = (
      ['Agent Configuration', 'Command Execution', 'File Access', 'Repository Risk'] as const
    ).flatMap((category) => Array.from({ length: 5 }, () => finding('critical', 'high', category)));
    expect(calculateScore(across).score).toBe(100);
  });

  it('counts findings by severity', () => {
    const score = calculateScore([
      finding('high'),
      finding('high'),
      finding('low'),
      finding('info'),
    ]);
    expect(score.counts).toMatchObject({ critical: 0, high: 2, medium: 0, low: 1, info: 1 });
  });

  it('maps scores to documented risk levels at the band boundaries', () => {
    expect(riskLevelFor(0)).toBe('Minimal');
    expect(riskLevelFor(9)).toBe('Minimal');
    expect(riskLevelFor(10)).toBe('Low');
    expect(riskLevelFor(29)).toBe('Low');
    expect(riskLevelFor(30)).toBe('Moderate');
    expect(riskLevelFor(54)).toBe('Moderate');
    expect(riskLevelFor(55)).toBe('High');
    expect(riskLevelFor(79)).toBe('High');
    expect(riskLevelFor(80)).toBe('Critical');
    expect(riskLevelFor(100)).toBe('Critical');
  });

  it('produces a breakdown that sums to the reported score', () => {
    const result = scanFixture('risky-claude');
    const total = result.score.breakdown.reduce((sum, entry) => sum + entry.cappedPoints, 0);
    expect(result.score.score).toBe(Math.max(0, Math.min(100, Math.round(total))));
  });

  it('ranks a risky repository above a safe one', () => {
    expect(scanFixture('risky-claude').score.score).toBeGreaterThan(
      scanFixture('safe-project').score.score,
    );
  });

  it('is deterministic across runs', () => {
    expect(scanFixture('risky-mcp').score).toEqual(scanFixture('risky-mcp').score);
  });
});
