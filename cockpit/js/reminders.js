// Reminder rules and due-checking. In-app while the page is open;
// system notifications only after explicit opt-in (handled in app.js).
// Reliable closed-browser reminders would require web push or an external
// channel — the UI says so and never pretends otherwise.

import { newId } from './model.js';
import { atTime, nextWorkday, addDays, addBusinessDays, startOfDay } from './timeutil.js';

export const PRESETS = [
  { id: 'later_today', label: 'Later today' },
  { id: 'tomorrow_morning', label: 'Tomorrow morning' },
  { id: 'next_workday', label: 'Next workday' },
  { id: 'next_week', label: 'Next week' },
  { id: 'app_open', label: 'When I next open this' },
  { id: 'weekly_reset', label: 'At the weekly reset' },
  { id: 'n_business_days', label: 'After N business days' },
  { id: 'custom', label: 'Pick date & time' },
];

export function presetToDate(preset, now, settings, { n = 2, custom = null } = {}) {
  switch (preset) {
    case 'later_today': {
      const d = new Date(now.getTime() + 3 * 3600000);
      return d;
    }
    case 'tomorrow_morning':
      return atTime(addDays(startOfDay(now), 1), settings.workStart);
    case 'next_workday':
      return atTime(nextWorkday(now), settings.workStart);
    case 'next_week': {
      let d = addDays(startOfDay(now), (8 - now.getDay()) % 7 || 7); // next Monday
      return atTime(d, settings.workStart);
    }
    case 'weekly_reset': {
      let d = addDays(startOfDay(now), (8 - now.getDay()) % 7 || 7);
      return atTime(d, settings.workStart);
    }
    case 'n_business_days':
      return atTime(addBusinessDays(now, n), settings.workStart);
    case 'custom':
      return custom;
    case 'app_open':
      return null; // fires on next load, no timestamp
    default:
      return null;
  }
}

export function makeRule(preset, now, settings, opts = {}) {
  const at = presetToDate(preset, now, settings, opts);
  return {
    id: newId('r'),
    preset,
    at: at ? at.toISOString() : null, // null == "when the app next opens"
    firedAt: null,
  };
}

// Rules that should fire right now (or fired-on-open rules during load).
export function collectDue(actions, now, { includeOnOpen = false } = {}) {
  const due = [];
  for (const a of actions) {
    if (a.status === 'done' || a.status === 'dropped') continue;
    for (const r of a.reminderRules || []) {
      if (r.firedAt) continue;
      if (r.at === null) {
        if (includeOnOpen) due.push({ action: a, rule: r });
      } else if (new Date(r.at) <= now) {
        due.push({ action: a, rule: r });
      }
    }
  }
  return due;
}

// Waiting items whose follow-up moment has arrived.
export function collectFollowUpsDue(actions, now) {
  return actions.filter(
    (a) => a.status === 'waiting' && a.followUpAt && new Date(a.followUpAt) <= now
  );
}
