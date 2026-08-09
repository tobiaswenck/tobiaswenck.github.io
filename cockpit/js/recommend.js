// Next-action recommendation. Deterministic, explainable, no randomness.
// Returns one primary action, up to two alternatives, and human-readable
// reasons for each. Pure function — no DOM, no persistence.

import { isEligible, actionMinutes } from './model.js';
import { isSameDay, startOfDay, toDate, fmtTime } from './timeutil.js';
import { phaseEnergy } from './timestate.js';

export function recommend({ actions, now, timeState, momentum = [], lastCompletedProject = null, activeSessionActionId = null }) {
  const eligible = actions.filter((a) => isEligible(a, now));
  const today = startOfDay(now);

  const momentumByProject = new Map(momentum.map((m) => [m.project, m]));

  const scored = eligible.map((a) => {
    let score = 0;
    const reasons = [];
    const mins = actionMinutes(a);

    if (a.pinned) {
      score += 1000;
      reasons.push('Pinned by you.');
    }

    if (a.id === activeSessionActionId || a.status === 'active') {
      score += 500;
      reasons.push('Already in motion — picking up where you left off.');
    }

    const due = toDate(a.dueAt);
    if (due) {
      if (due < now) { score += 170; reasons.push('Past its due time.'); }
      else if (isSameDay(due, now)) { score += 140; reasons.push('Due today.'); }
      else if (due - now < 2 * 86400000) { score += 60; }
    }

    const follow = toDate(a.followUpAt);
    if (follow && follow <= now && a.type === 'followUp') {
      score += 130;
      reasons.push('Follow-up is due.');
    }

    const sched = toDate(a.scheduledFor);
    if (sched && isSameDay(sched, now)) {
      if (sched <= now) {
        score += 120;
        reasons.push(`Scheduled for ${sched.getHours() < 12 ? 'this morning' : 'today'} at ${fmtTime(sched)}.`);
      } else {
        score += 40;
      }
    } else if (sched && sched < today) {
      score += 90;
      reasons.push('Carried over — was planned for an earlier day.');
    }

    // Fit into the window before the next hard commitment.
    const avail = timeState.availableMinutes;
    if (avail > 0 && mins <= avail) {
      score += 55;
      if (timeState.nextCommitment && avail <= 90) {
        reasons.push(`Fits the ${avail}-minute window before ${timeState.nextCommitment.title}.`);
      }
    } else if (avail > 0 && mins > avail) {
      score -= 70;
    }

    // Momentum: decisions can release blocked or waiting work in a project.
    const m = momentumByProject.get(a.project);
    if (a.type === 'decide' && m && (m.state === 'blocked' || m.state === 'decision_needed')) {
      score += 95;
      reasons.push(`A decision here can get ${a.project} moving again.`);
    }
    if (m && m.state === 'quiet') {
      score += 30;
      reasons.push(`${a.project} has gone quiet — this would restart it.`);
    }

    // Energy fit for this part of the day.
    const pe = phaseEnergy(timeState);
    if (a.energy !== 'any') {
      if (a.energy === pe) score += 25;
      else if (a.energy === 'high' && pe === 'low') score -= 45;
    }

    // Continuity with what was just finished.
    if (lastCompletedProject && a.project && a.project === lastCompletedProject) {
      score += 40;
      reasons.push('Continues the context you were already working in.');
    }

    // Staleness nudge.
    const touched = toDate(a.lastTouchedAt);
    if (touched && (now - touched) > 7 * 86400000) {
      score += 18;
      reasons.push('Has been sitting untouched for a while.');
    }

    // A clear finish line lowers activation energy.
    if (a.definitionOfDone) score += 12;

    // Small actions win late in the day; big ones are quietly excluded.
    if (timeState.discourageLargeWork) {
      if (mins > 45 && !a.pinned && !(due && isSameDay(due, now))) score = -Infinity;
      else if (mins <= 20) { score += 30; reasons.push('Small enough to still fit today.'); }
    }

    if (a.type === 'followUp' && !reasons.length) reasons.push('An open loop worth closing.');

    return { action: a, score, reasons };
  })
  .filter((s) => s.score > -Infinity)
  .sort((x, y) => (y.score - x.score)
    || x.action.createdAt.localeCompare(y.action.createdAt)
    || x.action.id.localeCompare(y.action.id));

  if (!scored.length) {
    return { primary: null, alternatives: [], nothing: true };
  }

  const [first, ...rest] = scored;
  if (!first.reasons.length) first.reasons.push('The most reasonable next step right now.');
  const primaryReasons = first.reasons.slice(0, 2);

  return {
    primary: { action: first.action, reasons: primaryReasons },
    alternatives: rest.slice(0, 2).map((s) => {
      // Prefer a reason that distinguishes it from the primary.
      const distinct = s.reasons.find((r) => !primaryReasons.includes(r)) || s.reasons[0];
      return { action: s.action, reasons: distinct ? [distinct] : [] };
    }),
    nothing: false,
  };
}
