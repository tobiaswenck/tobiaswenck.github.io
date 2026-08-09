// Central state, mutations, undo. All persistence flows through here.
// Views subscribe and re-render; business rules live in the engines.

import * as db from './db.js';
import { createAction, normalizeAction, touch, newId } from './model.js';
import { spawnNext } from './recurrence.js';

export const DEFAULT_SETTINGS = {
  workStart: '08:30',
  workEnd: '17:30',
  dailyCapacityMinutes: 300,
  quietDays: 5,
  staleDays: 7,
  systemNotifications: false,
};

const state = {
  loaded: false,
  actions: [],
  trail: [],
  settings: { ...DEFAULT_SETTINGS },
  session: null,        // active focus session
  lastSeenAt: null,
  fridayNote: null,     // { weekKey, text, savedAt, shownWeekKey }
  onboarded: false,
};

const listeners = new Set();
const undoStack = [];

export function getState() { return state; }

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function emit(reason = '') {
  for (const fn of listeners) fn(reason);
}

// ---------- load ----------

export async function load() {
  const [actions, trail, settings, session, lastSeenAt, fridayNote, onboarded] = await Promise.all([
    db.getAll('actions'),
    db.getAll('trail'),
    db.getMeta('settings', null),
    db.getMeta('session', null),
    db.getMeta('lastSeenAt', null),
    db.getMeta('fridayNote', null),
    db.getMeta('onboarded', false),
  ]);
  state.actions = actions.map(normalizeAction);
  state.trail = trail.sort((a, b) => a.at.localeCompare(b.at));
  state.settings = { ...DEFAULT_SETTINGS, ...(settings || {}) };
  state.session = session;
  state.lastSeenAt = lastSeenAt;
  state.fridayNote = fridayNote;
  state.onboarded = !!onboarded;
  state.loaded = true;
}

export function getAction(id) {
  return state.actions.find((a) => a.id === id) || null;
}

// ---------- undo ----------

function snapshot(action) {
  return JSON.parse(JSON.stringify(action));
}

function pushUndo(label, entry) {
  undoStack.push({ label, ...entry });
  if (undoStack.length > 20) undoStack.shift();
}

export function lastUndoLabel() {
  return undoStack.length ? undoStack[undoStack.length - 1].label : null;
}

export async function undo() {
  const entry = undoStack.pop();
  if (!entry) return null;
  for (const snap of entry.restore || []) {
    const idx = state.actions.findIndex((a) => a.id === snap.id);
    if (idx >= 0) state.actions[idx] = snap; else state.actions.push(snap);
    await db.put('actions', snap);
  }
  for (const id of entry.removeActions || []) {
    state.actions = state.actions.filter((a) => a.id !== id);
    await db.remove('actions', id);
  }
  for (const id of entry.removeTrail || []) {
    state.trail = state.trail.filter((t) => t.id !== id);
    await db.remove('trail', id);
  }
  emit('undo');
  return entry.label;
}

// ---------- trail ----------

export async function addTrail(kind, { action = null, title = '', detail = '' } = {}, now = new Date()) {
  const event = {
    id: newId('t'),
    at: now.toISOString(),
    kind,                                  // completed | decision | unblocked | waiting_set | response | captured | blocked_set | dropped
    actionId: action ? action.id : null,
    title: title || (action ? action.title : ''),
    project: action ? action.project : '',
    detail,
  };
  state.trail.push(event);
  await db.put('trail', event);
  return event;
}

// ---------- mutations ----------

export async function addAction(partial, { undoable = false } = {}) {
  const action = createAction(partial);
  touch(action);
  state.actions.push(action);
  await db.put('actions', action);
  if (undoable) pushUndo('Added', { removeActions: [action.id] });
  emit('add');
  return action;
}

export async function updateAction(id, patch, { undoLabel = null, silent = false } = {}) {
  const action = getAction(id);
  if (!action) return null;
  const before = snapshot(action);
  Object.assign(action, patch);
  touch(action);
  await db.put('actions', action);
  if (undoLabel) pushUndo(undoLabel, { restore: [before] });
  if (!silent) emit('update');
  return action;
}

// Complete: records the trail event, spawns the next recurrence, returns
// everything the completion experience needs.
export async function completeAction(id, now = new Date()) {
  const action = getAction(id);
  if (!action) return null;
  const before = snapshot(action);
  action.status = 'done';
  action.completedAt = now.toISOString();
  touch(action, now);
  await db.put('actions', action);

  const kind = action.type === 'decide' ? 'decision' : 'completed';
  const event = await addTrail(kind, { action }, now);

  let spawned = null;
  const next = spawnNext(action, now, 'completed');
  if (next) {
    state.actions.push(next);
    await db.put('actions', next);
    spawned = next;
  }

  pushUndo('Completed', {
    restore: [before],
    removeTrail: [event.id],
    removeActions: spawned ? [spawned.id] : [],
  });
  emit('complete');
  return { action, spawned };
}

// Skip the current occurrence of a recurring action and create the next
// one — a single undoable step.
export async function skipRecurrence(id, now = new Date()) {
  const action = getAction(id);
  if (!action || !action.recurrenceRule) return null;
  const before = snapshot(action);
  action.status = 'dropped';
  touch(action, now);
  await db.put('actions', action);

  let spawned = null;
  const next = spawnNext(before, now, 'skipped');
  if (next) {
    state.actions.push(next);
    await db.put('actions', next);
    spawned = next;
  }
  pushUndo('Skipped occurrence', {
    restore: [before],
    removeActions: spawned ? [spawned.id] : [],
  });
  emit('skip');
  return { action, spawned };
}

export async function dropAction(id, now = new Date()) {
  const action = getAction(id);
  if (!action) return null;
  const before = snapshot(action);
  action.status = 'dropped';
  touch(action, now);
  await db.put('actions', action);
  const event = await addTrail('dropped', { action }, now);
  pushUndo('Dropped', { restore: [before], removeTrail: [event.id] });
  emit('drop');
  return action;
}

export async function snoozeAction(id, until, now = new Date()) {
  const action = getAction(id);
  if (!action) return null;
  const before = snapshot(action);
  action.snoozedUntil = until.toISOString();
  if (action.status === 'active') action.status = 'ready';
  touch(action, now);
  await db.put('actions', action);
  pushUndo('Snoozed', { restore: [before] });
  emit('snooze');
  return action;
}

export async function scheduleAction(id, when, now = new Date()) {
  const action = getAction(id);
  if (!action) return null;
  const before = snapshot(action);
  action.scheduledFor = when.toISOString();
  if (['inbox', 'ready'].includes(action.status)) action.status = 'scheduled';
  action.snoozedUntil = null;
  touch(action, now);
  await db.put('actions', action);
  pushUndo('Rescheduled', { restore: [before] });
  emit('schedule');
  return action;
}

export async function moveToWaiting(id, { waitingFor = '', followUpAt = null } = {}, now = new Date()) {
  const action = getAction(id);
  if (!action) return null;
  const before = snapshot(action);
  action.status = 'waiting';
  action.waitingFor = waitingFor;
  action.waitingSince = now.toISOString();
  action.followUpAt = followUpAt ? followUpAt.toISOString() : null;
  touch(action, now);
  await db.put('actions', action);
  const event = await addTrail('waiting_set', { action, detail: waitingFor }, now);
  pushUndo('Moved to waiting', { restore: [before], removeTrail: [event.id] });
  emit('waiting');
  return action;
}

export async function blockAction(id, reason, now = new Date()) {
  const action = getAction(id);
  if (!action) return null;
  const before = snapshot(action);
  action.status = 'blocked';
  action.blockedReason = reason;
  touch(action, now);
  await db.put('actions', action);
  const event = await addTrail('blocked_set', { action, detail: reason }, now);
  pushUndo('Blocked', { restore: [before], removeTrail: [event.id] });
  emit('block');
  return action;
}

export async function unblockAction(id, now = new Date()) {
  const action = getAction(id);
  if (!action) return null;
  const before = snapshot(action);
  action.status = 'ready';
  action.blockedReason = '';
  touch(action, now);
  await db.put('actions', action);
  const event = await addTrail('unblocked', { action }, now);
  pushUndo('Unblocked', { restore: [before], removeTrail: [event.id] });
  emit('unblock');
  return action;
}

export async function responseReceived(id, now = new Date()) {
  const action = getAction(id);
  if (!action) return null;
  const before = snapshot(action);
  action.status = 'ready';
  action.followUpAt = null;
  touch(action, now);
  await db.put('actions', action);
  const event = await addTrail('response', { action, detail: action.waitingFor }, now);
  pushUndo('Response received', { restore: [before], removeTrail: [event.id] });
  emit('response');
  return action;
}

export async function deleteAction(id) {
  const action = getAction(id);
  if (!action) return null;
  const before = snapshot(action);
  state.actions = state.actions.filter((a) => a.id !== id);
  await db.remove('actions', id);
  // Recoverable: undo restores the record fully.
  pushUndo('Deleted', { restore: [before] });
  emit('delete');
  return action;
}

// ---------- meta ----------

export async function saveSettings(patch) {
  state.settings = { ...state.settings, ...patch };
  await db.setMeta('settings', state.settings);
  emit('settings');
}

export async function saveSession(session) {
  state.session = session;
  if (session) await db.setMeta('session', session);
  else await db.removeMeta('session');
}

export async function saveLastSeen(now = new Date()) {
  state.lastSeenAt = now.toISOString();
  await db.setMeta('lastSeenAt', state.lastSeenAt);
}

export async function saveFridayNote(note) {
  state.fridayNote = note;
  if (note) await db.setMeta('fridayNote', note);
  else await db.removeMeta('fridayNote');
  emit('fridayNote');
}

export async function setOnboarded() {
  state.onboarded = true;
  await db.setMeta('onboarded', true);
  emit('onboarded');
}

export async function removeDemoData() {
  const demoIds = new Set(state.actions.filter((a) => a.demo).map((a) => a.id));
  state.actions = state.actions.filter((a) => !a.demo);
  for (const id of demoIds) await db.remove('actions', id);
  // Trail events created by interacting with demo items go too — demo data
  // never mixes into the real history.
  const demoTrail = state.trail.filter((t) => t.demo || (t.actionId && demoIds.has(t.actionId))).map((t) => t.id);
  state.trail = state.trail.filter((t) => !(t.demo || (t.actionId && demoIds.has(t.actionId))));
  for (const id of demoTrail) await db.remove('trail', id);
  emit('demo-removed');
}

export function hasDemoData() {
  return state.actions.some((a) => a.demo);
}

// ---------- import/export support ----------

export async function replaceAll({ actions, trail, settings, fridayNote }) {
  await db.clearStore('actions');
  await db.clearStore('trail');
  state.actions = actions.map(normalizeAction);
  state.trail = (trail || []).sort((a, b) => a.at.localeCompare(b.at));
  await db.bulkPut('actions', state.actions);
  await db.bulkPut('trail', state.trail);
  if (settings) await saveSettings(settings);
  if (fridayNote !== undefined) await saveFridayNote(fridayNote);
  emit('replace');
}

export async function mergeAll({ actions, trail }) {
  const byId = new Map(state.actions.map((a) => [a.id, a]));
  for (const raw of actions) {
    const a = normalizeAction(raw);
    const existing = byId.get(a.id);
    if (!existing || (a.updatedAt > existing.updatedAt)) byId.set(a.id, a);
  }
  state.actions = [...byId.values()];
  await db.bulkPut('actions', state.actions);
  const trailIds = new Set(state.trail.map((t) => t.id));
  const newTrail = (trail || []).filter((t) => !trailIds.has(t.id));
  state.trail = [...state.trail, ...newTrail].sort((a, b) => a.at.localeCompare(b.at));
  await db.bulkPut('trail', newTrail);
  emit('merge');
}
