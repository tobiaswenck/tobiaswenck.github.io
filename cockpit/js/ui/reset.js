// Reset flow: rebuild trust after a chaotic stretch. One item at a time,
// neutral language, no automatic rollover, no shame.

import * as store from '../store.js';
import { el, announce } from './dom.js';
import { scheduleFlow, waitingFlow, snoozeFlow, dropFlow } from './flows.js';
import { startOfDay, toDate, fmtDaysSince } from '../timeutil.js';
import { isOpen } from '../model.js';

// Why an item needs a new decision. Returns a label or null.
export function resetReason(a, now, settings) {
  if (!isOpen(a)) return null;
  const today = startOfDay(now);

  if (a.status === 'inbox') return 'Captured, never decided on';

  const sched = toDate(a.scheduledFor);
  if (sched && sched < today && !['waiting', 'blocked'].includes(a.status)) {
    return `Planned for ${fmtDaysSince(sched, now)} ago, didn’t happen`;
  }

  if (a.status === 'waiting' && a.followUpAt && new Date(a.followUpAt) < today) {
    return 'Follow-up came and went';
  }

  const snooze = toDate(a.snoozedUntil);
  if (snooze && snooze < today) return 'Snooze expired without a decision';

  if (a.status === 'active') {
    const touched = toDate(a.lastTouchedAt);
    if (touched && (now - touched) > 2 * 86400000) return 'Started, then left hanging';
  }

  if (['ready', 'scheduled'].includes(a.status)) {
    const touched = toDate(a.lastTouchedAt);
    if (touched && (now - touched) > (settings.staleDays || 7) * 86400000) {
      return `Untouched for ${fmtDaysSince(touched, now)}`;
    }
  }
  return null;
}

export function resetCandidates(now) {
  const { actions, settings } = store.getState();
  return actions
    .map((a) => ({ action: a, reason: resetReason(a, now, settings) }))
    .filter((x) => x.reason)
    .sort((x, y) => x.action.lastTouchedAt.localeCompare(y.action.lastTouchedAt));
}

export function renderReset(container, ctx) {
  const { now, onGotoView, onEdit } = ctx;
  const candidates = resetCandidates(now);

  container.replaceChildren();
  const frame = el('div', { class: 'reset-frame' });
  container.append(frame);

  if (!candidates.length) {
    frame.append(
      el('div', { class: 'reset-done' },
        el('p', { class: 'big', text: 'Nothing needs a new decision.' }),
        el('p', { class: 'sub', text: 'The system reflects reality. Head back to Now.' }),
        el('div', { style: 'margin-top: 18px;' },
          el('button', { class: 'act-btn', text: 'Go to Now', onclick: () => onGotoView('now') })),
      ),
    );
    return;
  }

  const total = candidates.length;
  const { action: a, reason } = candidates[0];

  frame.append(
    el('p', { class: 'reset-progress', text: `${total} item${total > 1 ? 's' : ''} need${total === 1 ? 's' : ''} a new decision · one at a time` }),
  );

  const card = el('div', { class: 'reset-card' },
    el('p', { class: 'r-kicker', text: reason }),
    el('h2', { class: 'r-title' },
      el('button', { class: 'title-btn', text: a.title, title: 'Shape', onclick: () => onEdit(a) })),
    a.project && el('p', { class: 'r-why', text: a.project }),
  );

  const decide = async (label, fn) => { await fn(); announce(label); };

  card.append(
    el('div', { class: 'r-options' },
      el('button', {
        class: 'act-btn primary', text: 'Shape',
        onclick: () => onEdit(a),
      }),
      el('button', {
        class: 'act-btn', text: 'Keep active',
        onclick: () => decide('Kept active.', () =>
          store.updateAction(a.id, { status: 'ready', snoozedUntil: null, scheduledFor: null }, { undoLabel: 'Kept active' })),
      }),
      el('button', { class: 'act-btn', text: 'Schedule…', onclick: () => scheduleFlow(a, card) }),
      el('button', {
        class: 'act-btn', text: 'Delegate…',
        onclick: async () => {
          await store.updateAction(a.id, { type: 'delegate' }, { silent: true });
          waitingFlow(store.getAction(a.id), card);
        },
      }),
      el('button', { class: 'act-btn', text: 'Move to Waiting…', onclick: () => waitingFlow(a, card) }),
      el('button', { class: 'act-btn', text: 'Defer…', onclick: () => snoozeFlow(a, card) }),
      el('button', { class: 'act-btn danger', text: 'Drop', onclick: () => dropFlow(a, card) }),
    ),
  );

  frame.append(card);
}
