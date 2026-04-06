// utils/finding_queue.mjs

import { validateFinding, generateFindingId } from './finding_schema.mjs';

const SEVERITY_SCORE = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

export class FindingQueue {
  constructor() {
    this.findings = [];
  }

  add(finding) {
    const errors = validateFinding(finding);
    if (errors.length > 0) throw new Error(`Invalid finding: ${errors.join(', ')}`);
    const id = finding.id || generateFindingId();
    this.findings.push({ ...finding, id });
    return id;
  }

  getByCategory(cat) {
    return this.findings.filter(f => f.category === cat);
  }

  getByStatus(status) {
    return this.findings.filter(f => f.status === status);
  }

  getUnverified() {
    return this.getByStatus('UNVERIFIED');
  }

  markVerified(id, verification) {
    const f = this._find(id);
    f.status = 'VERIFIED';
    f.evidence = { ...(f.evidence ?? {}), verification };
  }

  markFalsePositive(id, reason) {
    const f = this._find(id);
    f.status = 'FALSE_POSITIVE';
    f.falsePositiveReason = reason;
  }

  prioritize() {
    this.findings.sort(
      (a, b) => (SEVERITY_SCORE[b.severity] ?? 0) - (SEVERITY_SCORE[a.severity] ?? 0)
    );
    return this;
  }

  toJSON() {
    return JSON.parse(JSON.stringify(this.findings));
  }

  get size() {
    return this.findings.length;
  }

  _find(id) {
    const f = this.findings.find(f => f.id === id);
    if (!f) throw new Error(`Finding not found: ${id}`);
    return f;
  }
}
