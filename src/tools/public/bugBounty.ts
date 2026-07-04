/**
 * Bug Bounty — Public API
 * Automated vulnerability submission & payout tracking.
 * import { bugBounty } from 'anvilwing/tools';
 */
import { bugBounty as engine, createBugBountySubmission, createBountyStats, formatHackerOneSubmission, formatBugcrowdSubmission, formatDirectDisclosure, type BugBountyOptions, type BugBountyResult, type BountySubmission, type BountyStats } from '../../core/bugBounty.js';

export const bugBounty = {
  submit: (opts: BugBountyOptions) => createBugBountySubmission(opts),
  stats: (submissions: BountySubmission[]) => createBountyStats(submissions),
  hackerone: (sub: BountySubmission) => formatHackerOneSubmission(sub),
  bugcrowd: (sub: BountySubmission) => formatBugcrowdSubmission(sub),
  direct: (sub: BountySubmission) => formatDirectDisclosure(sub),
};

export type { BugBountyOptions, BugBountyResult, BountySubmission, BountyStats };
