// Time, date and capacity utilities. Pure functions only.

export const MIN = 60 * 1000;
export const HOUR = 60 * MIN;
export const DAY = 24 * HOUR;

export function startOfDay(d) {
  const x = new Date(d);
  x.setHours(0, 0, 0, 0);
  return x;
}

export function addDays(d, n) {
  const x = new Date(d);
  x.setDate(x.getDate() + n);
  return x;
}

export function isSameDay(a, b) {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

export function dayKey(d) {
  const x = new Date(d);
  return `${x.getFullYear()}-${String(x.getMonth() + 1).padStart(2, '0')}-${String(x.getDate()).padStart(2, '0')}`;
}

// ISO week key like "2026-W33" — used for the Friday handoff note.
export function weekKey(d) {
  const x = new Date(d);
  x.setHours(0, 0, 0, 0);
  x.setDate(x.getDate() + 3 - ((x.getDay() + 6) % 7)); // Thursday of this week
  const jan4 = new Date(x.getFullYear(), 0, 4);
  const week = 1 + Math.round(((x - jan4) / DAY - 3 + ((jan4.getDay() + 6) % 7)) / 7);
  return `${x.getFullYear()}-W${String(week).padStart(2, '0')}`;
}

export function isWeekend(d) {
  const wd = d.getDay();
  return wd === 0 || wd === 6;
}

export function isWorkday(d) {
  return !isWeekend(d);
}

export function nextWorkday(d) {
  let x = addDays(startOfDay(d), 1);
  while (!isWorkday(x)) x = addDays(x, 1);
  return x;
}

export function addBusinessDays(d, n) {
  let x = startOfDay(d);
  let left = n;
  while (left > 0) {
    x = addDays(x, 1);
    if (isWorkday(x)) left--;
  }
  return x;
}

// "08:30" + a date -> Date at that time
export function atTime(d, hm) {
  const [h, m] = hm.split(':').map(Number);
  const x = new Date(d);
  x.setHours(h, m, 0, 0);
  return x;
}

export function minutesBetween(a, b) {
  return Math.round((b - a) / MIN);
}

export function fmtTime(d) {
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export function fmtWeekday(d) { return WEEKDAYS[d.getDay()]; }

export function fmtDate(d) {
  return `${WEEKDAYS[d.getDay()]}, ${MONTHS[d.getMonth()]} ${d.getDate()}`;
}

export function fmtShortDate(d) {
  return `${MONTHS[d.getMonth()]} ${d.getDate()}`;
}

export function fmtDuration(mins) {
  if (mins == null) return '';
  if (mins < 60) return `${mins} min`;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return m ? `${h} h ${m} min` : `${h} h`;
}

// "2 days", "5 hours", "just now" — coarse on purpose.
export function fmtAgo(from, now) {
  const ms = now - from;
  if (ms < 2 * MIN) return 'just now';
  if (ms < HOUR) return `${Math.round(ms / MIN)} min ago`;
  if (ms < DAY && isSameDay(from, now)) return `${Math.round(ms / HOUR)} h ago`;
  const days = Math.round((startOfDay(now) - startOfDay(from)) / DAY);
  if (days <= 1) return 'yesterday';
  return `${days} days ago`;
}

export function fmtDaysSince(from, now) {
  const days = Math.round((startOfDay(now) - startOfDay(from)) / DAY);
  if (days <= 0) return 'today';
  if (days === 1) return '1 day';
  return `${days} days`;
}

// Describes when something is scheduled, relative to now.
export function fmtWhen(d, now) {
  if (isSameDay(d, now)) return fmtTime(d);
  if (isSameDay(d, addDays(now, 1))) return `tomorrow ${d.getHours() || d.getMinutes() ? fmtTime(d) : ''}`.trim();
  const days = Math.round((startOfDay(d) - startOfDay(now)) / DAY);
  if (days > 1 && days < 7) return fmtWeekday(d);
  return fmtShortDate(d);
}

// Parse ISO string tolerant of null.
export function toDate(iso) {
  return iso ? new Date(iso) : null;
}

// ---------- capacity ----------

// Sum of estimates for actively planned actions on a given day.
// Waiting and blocked work doesn't consume your capacity.
export function plannedMinutesForDay(actions, day) {
  let total = 0;
  for (const a of actions) {
    if (['done', 'dropped', 'waiting', 'blocked'].includes(a.status)) continue;
    const when = toDate(a.scheduledFor) || toDate(a.dueAt);
    if (when && isSameDay(when, day)) total += a.estimateMinutes || 30;
  }
  return total;
}

// Free minutes between now and next hard commitment (or end of workday).
export function minutesUntilNextCommitment(commitments, now, workEnd) {
  const upcoming = commitments
    .map((c) => toDate(c.scheduledFor))
    .filter((d) => d && d > now && isSameDay(d, now))
    .sort((a, b) => a - b);
  const boundary = upcoming[0] || workEnd;
  return Math.max(0, minutesBetween(now, boundary));
}
