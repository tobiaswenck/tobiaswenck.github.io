// Time-state engine. Derives the current experiential state of the workday
// and workweek from local time plus activity. Pure function — no DOM.

import { atTime, isSameDay, isWeekend, minutesBetween, toDate } from './timeutil.js';

export const STATES = [
  'week_opening',
  'morning_orientation',
  'active_work',
  'midday_recalibration',
  'afternoon_compression',
  'day_shutdown',
  'week_convergence',
  'week_closure',
];

// { id, phase, isWeekend, workStart, workEnd, fractionElapsed,
//   minutesRemaining, completedToday, commitmentsToday, nextCommitment,
//   availableMinutes, discourageLargeWork }
export function deriveTimeState({ now, actions, trail, session, settings }) {
  const weekday = now.getDay(); // 0 Sun .. 6 Sat
  const workStart = atTime(now, settings.workStart);
  const workEnd = atTime(now, settings.workEnd);
  const weekend = isWeekend(now);

  const completedToday = trail.filter(
    (t) => ['completed', 'decision', 'unblocked', 'response'].includes(t.kind) && isSameDay(new Date(t.at), now)
  ).length;

  const commitmentsToday = actions
    .filter((a) => a.hard && a.status !== 'done' && a.status !== 'dropped')
    .filter((a) => { const d = toDate(a.scheduledFor); return d && isSameDay(d, now); })
    .sort((a, b) => a.scheduledFor.localeCompare(b.scheduledFor));

  const nextCommitment = commitmentsToday.find((a) => toDate(a.scheduledFor) > now) || null;

  const boundary = nextCommitment ? toDate(nextCommitment.scheduledFor) : workEnd;
  const availableMinutes = Math.max(0, minutesBetween(now, boundary));

  const total = Math.max(1, minutesBetween(workStart, workEnd));
  const elapsed = Math.min(total, Math.max(0, minutesBetween(workStart, now)));
  const fractionElapsed = elapsed / total;
  const minutesRemaining = Math.max(0, minutesBetween(now, workEnd));

  // --- base phase from clock position ---
  const h = now.getHours() + now.getMinutes() / 60;
  const startH = workStart.getHours() + workStart.getMinutes() / 60;
  const endH = workEnd.getHours() + workEnd.getMinutes() / 60;

  let id;
  let phase;
  if (h >= endH - 0.75 || h < 5) {
    id = 'day_shutdown'; phase = 'evening';
  } else if (h < startH + 2.5) {
    phase = 'morning';
    // Orientation fades into execution once work is actually moving.
    id = (completedToday >= 1 || session) && h >= startH ? 'active_work' : 'morning_orientation';
  } else if (h >= 11.75 && h < 13.25) {
    id = 'midday_recalibration'; phase = 'midday';
  } else if (h >= endH - 3.5) {
    id = 'afternoon_compression'; phase = 'afternoon';
  } else {
    id = 'active_work'; phase = h < 12 ? 'morning' : 'afternoon';
  }

  // --- weekly overlays ---
  if (weekend) {
    id = 'week_closure';
  } else if (weekday === 1 && phase === 'morning' && completedToday < 2 && !session) {
    id = 'week_opening';
  } else if (weekday === 4 && (phase === 'afternoon' || id === 'midday_recalibration') && id !== 'day_shutdown') {
    id = 'week_convergence';
  } else if (weekday === 5 && (h >= 14.5 || id === 'day_shutdown')) {
    id = 'week_closure';
  }

  const discourageLargeWork =
    id === 'day_shutdown' || id === 'week_closure' ||
    (id === 'afternoon_compression' && minutesRemaining < 90);

  return {
    id,
    phase,
    weekday,
    isWeekend: weekend,
    workStart,
    workEnd,
    fractionElapsed,
    minutesRemaining,
    completedToday,
    commitmentsToday,
    nextCommitment,
    availableMinutes,
    discourageLargeWork,
  };
}

// Which energy level the current phase realistically supports.
export function phaseEnergy(ts) {
  if (ts.phase === 'morning') return 'high';
  if (ts.phase === 'midday') return 'medium';
  if (ts.phase === 'afternoon') return 'medium';
  return 'low';
}
