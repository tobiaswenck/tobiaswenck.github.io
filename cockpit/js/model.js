// ActionItem model, validation and small pure helpers.

export const SCHEMA_VERSION = 1;

export const TYPES = ['do', 'decide', 'delegate', 'followUp', 'review'];
export const STATUSES = ['inbox', 'ready', 'active', 'scheduled', 'waiting', 'blocked', 'done', 'dropped'];
export const ENERGIES = ['low', 'medium', 'high', 'any'];
export const SOURCE_TYPES = ['manual', 'linear', 'docmost', 'canny', 'calendar', 'other'];

export const TYPE_LABEL = {
  do: 'Do', decide: 'Decide', delegate: 'Delegate', followUp: 'Follow up', review: 'Review',
};

let counter = 0;
export function newId(prefix = 'a') {
  counter = (counter + 1) % 1000;
  return `${prefix}_${Date.now().toString(36)}_${counter.toString(36)}${Math.random().toString(36).slice(2, 6)}`;
}

// Only the title is required. Everything else has calm defaults.
export function createAction(partial = {}) {
  const now = new Date().toISOString();
  return {
    id: newId(),
    title: '',
    definitionOfDone: '',
    type: 'do',
    status: 'inbox',
    project: '',
    sourceRef: null,          // { type, externalId, url, label }
    scheduledFor: null,       // ISO — intended day/time to work on it
    startAfter: null,         // ISO — not before
    dueAt: null,              // ISO — hard-ish deadline
    estimateMinutes: null,
    energy: 'any',
    contexts: [],             // free strings, e.g. ['meeting'] marks hard commitments
    pinned: false,
    hard: false,              // fixed-time commitment (landmark in the day)
    blockedReason: '',
    waitingFor: '',
    waitingSince: null,
    followUpAt: null,
    snoozedUntil: null,
    recurrenceRule: null,     // see recurrence.js
    reminderRules: [],        // [{ id, at: ISO, preset, firedAt }]
    notes: '',
    lastSessionNote: '',
    demo: false,
    createdAt: now,
    updatedAt: now,
    completedAt: null,
    lastTouchedAt: now,
    ...partial,
  };
}

export function normalizeAction(a) {
  const base = createAction();
  const out = { ...base, ...a };
  if (!TYPES.includes(out.type)) out.type = 'do';
  if (!STATUSES.includes(out.status)) out.status = 'inbox';
  if (!ENERGIES.includes(out.energy)) out.energy = 'any';
  if (!Array.isArray(out.contexts)) out.contexts = [];
  if (!Array.isArray(out.reminderRules)) out.reminderRules = [];
  return out;
}

export function validateAction(a) {
  const errors = [];
  if (!a.title || !a.title.trim()) errors.push('A title is required.');
  if (a.estimateMinutes != null && (isNaN(a.estimateMinutes) || a.estimateMinutes < 0)) errors.push('Estimate must be a positive number of minutes.');
  return errors;
}

export function touch(a, now = new Date()) {
  a.updatedAt = now.toISOString();
  a.lastTouchedAt = now.toISOString();
  return a;
}

export function isOpen(a) {
  return a.status !== 'done' && a.status !== 'dropped';
}

export function isSnoozed(a, now) {
  return !!a.snoozedUntil && new Date(a.snoozedUntil) > now;
}

// Eligible for the recommendation engine.
export function isEligible(a, now) {
  if (!['ready', 'scheduled', 'active'].includes(a.status)) return false;
  if (isSnoozed(a, now)) return false;
  if (a.startAfter && new Date(a.startAfter) > now) return false;
  if (a.hard) return false; // fixed commitments are landmarks, not recommendations
  return true;
}

// Crude actionability signal: short noun-phrase titles ("KomReg rollout")
// get a gentle prompt toward a verb + object. Never blocks saving.
const VAGUE_NOUNS = /^(rollout|projec?kt|meeting|report|plan|update|status|sync|docs?|doku|wiki|misc|stuff|thema|topic)s?$/i;
export function looksVague(title) {
  const t = (title || '').trim();
  if (!t) return false;
  const words = t.split(/\s+/);
  if (words.length > 4) return false;
  return words.length === 1 || words.some((w) => VAGUE_NOUNS.test(w));
}

export function actionMinutes(a) {
  return a.estimateMinutes || 30;
}
