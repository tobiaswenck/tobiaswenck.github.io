// Recurrence engine. Pure functions — no DOM, no persistence.
//
// Rule shape:
//   { freq: 'daily' | 'weekdays' | 'customDays' | 'weekly' | 'monthly'
//         | 'everyNDays' | 'afterCompletion',
//     weekdays: [1..7]  (customDays; 1 = Monday),
//     n: number         (everyNDays / afterCompletion),
//     unit: 'days'|'weeks' (afterCompletion),
//     paused: boolean }
//
// Occurrences are never pre-generated. The next one is created when the
// current one is completed or skipped.

import { startOfDay, addDays, isWorkday, toDate } from './timeutil.js';
import { newId } from './model.js';

export const FREQ_LABEL = {
  daily: 'Every day',
  weekdays: 'Every weekday',
  customDays: 'Selected weekdays',
  weekly: 'Every week',
  monthly: 'Every month',
  everyNDays: 'Every N days',
  afterCompletion: 'After completion',
};

// The anchor is the date the current occurrence was scheduled for (falling
// back to today). afterCompletion anchors on the completion date instead.
export function nextOccurrenceDate(rule, anchor, now) {
  if (!rule || rule.paused) return null;
  const base = startOfDay(anchor);
  const today = startOfDay(now);

  switch (rule.freq) {
    case 'daily': {
      let d = addDays(base, 1);
      if (d < today) d = today;
      return d;
    }
    case 'weekdays': {
      let d = addDays(base, 1);
      if (d < today) d = today;
      while (!isWorkday(d)) d = addDays(d, 1);
      return d;
    }
    case 'customDays': {
      const days = (rule.weekdays || []).slice().sort();
      if (!days.length) return null;
      let d = addDays(base < today ? today : base, 1);
      for (let i = 0; i < 8; i++) {
        const iso = d.getDay() === 0 ? 7 : d.getDay();
        if (days.includes(iso)) return d;
        d = addDays(d, 1);
      }
      return null;
    }
    case 'weekly': {
      let d = addDays(base, 7);
      while (d < today) d = addDays(d, 7);
      return d;
    }
    case 'monthly': {
      const d = new Date(base);
      const dayOfMonth = d.getDate();
      d.setMonth(d.getMonth() + 1);
      // Handle month-length rollover (e.g. Jan 31 -> Feb 28).
      if (d.getDate() !== dayOfMonth) d.setDate(0);
      return d < today ? nextOccurrenceDate(rule, d, now) : d;
    }
    case 'everyNDays': {
      const n = Math.max(1, rule.n || 1);
      let d = addDays(base, n);
      while (d < today) d = addDays(d, n);
      return d;
    }
    case 'afterCompletion': {
      const n = Math.max(1, rule.n || 1);
      const span = rule.unit === 'weeks' ? n * 7 : n;
      return addDays(today, span);
    }
    default:
      return null;
  }
}

// Build the next occurrence when the current one is completed or skipped.
// Returns a fresh ActionItem or null if the series ended.
export function spawnNext(action, now, reason) {
  const rule = action.recurrenceRule;
  if (!rule || rule.paused || rule.ended) return null;

  const anchorSource = rule.freq === 'afterCompletion'
    ? now
    : (toDate(action.scheduledFor) || now);
  const nextDate = nextOccurrenceDate(rule, anchorSource, now);
  if (!nextDate) return null;

  // Keep the original time of day if one was set.
  const prevTime = toDate(action.scheduledFor);
  if (prevTime && (prevTime.getHours() || prevTime.getMinutes())) {
    nextDate.setHours(prevTime.getHours(), prevTime.getMinutes(), 0, 0);
  }

  return {
    ...JSON.parse(JSON.stringify(action)),
    id: newId(),
    status: 'scheduled',
    scheduledFor: nextDate.toISOString(),
    snoozedUntil: null,
    completedAt: null,
    blockedReason: '',
    waitingFor: '',
    waitingSince: null,
    followUpAt: null,
    lastSessionNote: reason === 'skipped' ? action.lastSessionNote : '',
    reminderRules: [],
    pinned: false,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
    lastTouchedAt: now.toISOString(),
  };
}

export function describeRule(rule) {
  if (!rule) return '';
  if (rule.paused) return `${FREQ_LABEL[rule.freq] || 'Repeats'} · paused`;
  switch (rule.freq) {
    case 'customDays': {
      const names = ['', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
      return (rule.weekdays || []).map((d) => names[d]).join(', ');
    }
    case 'everyNDays': return `Every ${rule.n} days`;
    case 'afterCompletion': return `${rule.n} ${rule.unit === 'weeks' ? 'week(s)' : 'day(s)'} after completion`;
    default: return FREQ_LABEL[rule.freq] || 'Repeats';
  }
}
