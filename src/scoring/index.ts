import {
  CATEGORIES,
  SEVERITIES,
  type Category,
  type Confidence,
  type Finding,
  type RiskLevel,
  type RiskScore,
  type ScoreBreakdownEntry,
  type Severity,
} from '../types/index.js';

/**
 * Scoring methodology (deliberately simple and fully documented so a reader
 * can reproduce the number by hand from the JSON report):
 *
 *   1. Each finding contributes SEVERITY_WEIGHT x CONFIDENCE_FACTOR points.
 *   2. Points are summed per category, then each category is capped, so no
 *      single noisy category can dominate the result.
 *   3. Capped category totals are summed and clamped to 0-100.
 *
 * The score expresses governance *exposure*, not compliance and not a
 * probability of compromise.
 */
export const SEVERITY_WEIGHT: Readonly<Record<Severity, number>> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 0,
};

export const CONFIDENCE_FACTOR: Readonly<Record<Confidence, number>> = {
  high: 1,
  medium: 0.8,
  low: 0.5,
};

/** No category may contribute more than this many points to the total. */
export const CATEGORY_CAP = 35;

export const METHODOLOGY_URL = 'https://github.com/oconeesoftware/oconee-scan#scoring-methodology';

const LEVEL_BANDS: ReadonlyArray<{ min: number; level: RiskLevel }> = [
  { min: 80, level: 'Critical' },
  { min: 55, level: 'High' },
  { min: 30, level: 'Moderate' },
  { min: 10, level: 'Low' },
  { min: 0, level: 'Minimal' },
];

export function riskLevelFor(score: number): RiskLevel {
  return LEVEL_BANDS.find((band) => score >= band.min)?.level ?? 'Minimal';
}

export function pointsFor(finding: Finding): number {
  return SEVERITY_WEIGHT[finding.severity] * CONFIDENCE_FACTOR[finding.confidence];
}

export function calculateScore(findings: readonly Finding[]): RiskScore {
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])) as Record<
    Severity,
    number
  >;
  const rawByCategory = new Map<Category, number>();
  const countByCategory = new Map<Category, number>();

  for (const finding of findings) {
    counts[finding.severity] += 1;
    rawByCategory.set(
      finding.category,
      (rawByCategory.get(finding.category) ?? 0) + pointsFor(finding),
    );
    countByCategory.set(finding.category, (countByCategory.get(finding.category) ?? 0) + 1);
  }

  const breakdown: ScoreBreakdownEntry[] = CATEGORIES.filter((category) =>
    countByCategory.has(category),
  ).map((category) => {
    const rawPoints = round2(rawByCategory.get(category) ?? 0);
    return {
      category,
      rawPoints,
      cappedPoints: round2(Math.min(rawPoints, CATEGORY_CAP)),
      findingCount: countByCategory.get(category) ?? 0,
    };
  });

  const total = breakdown.reduce((sum, entry) => sum + entry.cappedPoints, 0);
  const score = Math.max(0, Math.min(100, Math.round(total)));

  return {
    score,
    level: riskLevelFor(score),
    counts,
    breakdown,
    methodologyUrl: METHODOLOGY_URL,
  };
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}
