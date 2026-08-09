// Project momentum engine. Derives operational state per project from
// action activity and the trail — no manual percentages. Pure function.

import { isOpen } from './model.js';
import { startOfDay, fmtDaysSince, toDate, DAY } from './timeutil.js';

const MOVEMENT_KINDS = ['completed', 'decision', 'unblocked', 'response'];

// -> [{ project, state, detail, lastMovementAt, needsAttention }]
export function computeMomentum(actions, trail, now, { quietDays = 5 } = {}) {
  const projects = new Map();

  for (const a of actions) {
    if (!a.project) continue;
    if (!projects.has(a.project)) projects.set(a.project, { open: [], all: [] });
    projects.get(a.project).all.push(a);
    if (isOpen(a)) projects.get(a.project).open.push(a);
  }

  const lastMove = new Map();
  for (const t of trail) {
    if (!t.project || !MOVEMENT_KINDS.includes(t.kind)) continue;
    const at = new Date(t.at);
    if (!lastMove.has(t.project) || at > lastMove.get(t.project)) lastMove.set(t.project, at);
  }

  const out = [];
  for (const [project, { open, all }] of projects) {
    if (!open.length && !lastMove.has(project)) continue;

    const movedAt = lastMove.get(project) || null;
    const movedRecently = movedAt && (startOfDay(now) - startOfDay(movedAt)) / DAY < quietDays;
    const movedToday = movedAt && startOfDay(movedAt).getTime() === startOfDay(now).getTime();

    const blocked = open.filter((a) => a.status === 'blocked');
    const waiting = open.filter((a) => a.status === 'waiting');
    const decisions = open.filter((a) => a.type === 'decide' && !['waiting', 'blocked'].includes(a.status));

    let state, detail;

    if (blocked.length) {
      state = 'blocked';
      detail = blocked[0].blockedReason
        ? blocked[0].blockedReason
        : `${blocked.length} item${blocked.length > 1 ? 's' : ''} blocked`;
    } else if (decisions.length && !movedToday) {
      state = 'decision_needed';
      detail = decisions.length === 1
        ? `“${decisions[0].title}” is undecided`
        : `${decisions.length} decisions open`;
    } else if (waiting.length && !movedRecently) {
      state = 'waiting';
      const w = waiting[0];
      const since = toDate(w.waitingSince);
      detail = `${w.waitingFor || 'Response'} outstanding${since ? ` · ${fmtDaysSince(since, now)}` : ''}`;
    } else if (movedRecently) {
      state = 'moving';
      detail = `Last meaningful movement: ${movedToday ? 'today' : fmtDaysSince(movedAt, now) + ' ago'}`;
    } else {
      state = 'quiet';
      const ref = movedAt || toDate(all.reduce((m, a) => (a.createdAt > m ? a.createdAt : m), all[0].createdAt));
      detail = `No meaningful movement in ${fmtDaysSince(ref, now)}`;
    }

    out.push({
      project,
      state,
      detail,
      lastMovementAt: movedAt,
      // Only states that change management attention are surfaced by default.
      needsAttention: state !== 'moving' || movedToday,
    });
  }

  const order = { blocked: 0, decision_needed: 1, waiting: 2, quiet: 3, moving: 4 };
  out.sort((a, b) => order[a.state] - order[b.state] || a.project.localeCompare(b.project));
  return out;
}

export const MOMENTUM_LABEL = {
  moving: 'Moving',
  waiting: 'Waiting',
  blocked: 'Blocked',
  quiet: 'Quiet',
  decision_needed: 'Decision needed',
};
