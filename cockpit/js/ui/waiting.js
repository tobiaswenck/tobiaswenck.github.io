// Waiting view: work that is off your plate, owned by someone else.
// First-class — not a list of unfinished personal tasks.

import * as store from '../store.js';
import { el, announce, toast, openDialog, leaveThen } from './dom.js';
import { toLocalInput } from './flows.js';
import { fmtDaysSince, fmtWhen, toDate, atTime, addDays, addBusinessDays, startOfDay } from '../timeutil.js';

export function renderWaiting(container, ctx) {
  const { now, onBegin, onEdit } = ctx;
  const items = store.getState().actions
    .filter((a) => a.status === 'waiting')
    .sort((a, b) => (a.followUpAt || '9999').localeCompare(b.followUpAt || '9999'));

  container.replaceChildren();
  container.append(
    el('div', { class: 'waiting-head' },
      el('h2', { text: 'Waiting on others' }),
      el('p', { text: items.length ? 'These are out of your hands. Follow-ups will surface when they matter.' : '' }),
    ),
  );

  if (!items.length) {
    container.append(
      el('div', { class: 'clear-state', style: 'margin-left:0;' },
        el('p', { class: 'clear-line', text: 'Nothing is waiting on anyone.' }),
        el('p', { class: 'clear-sub', text: 'When you hand something off, it lands here instead of nagging you.' }),
      ),
    );
    return;
  }

  for (const a of items) {
    const since = toDate(a.waitingSince);
    const follow = toDate(a.followUpAt);
    const followDue = follow && follow <= now;

    const row = el('div', { class: 'waiting-row' },
      el('p', { class: 'w-title', text: a.title }),
      el('p', { class: 'w-meta' },
        el('span', { text: a.waitingFor ? `Waiting on ${a.waitingFor}` : 'Waiting for a response' }),
        since && el('span', { class: 'since', text: ` · ${fmtDaysSince(since, now)}` }),
      ),
      el('p', {
        class: `w-follow ${followDue ? 'due' : ''}`,
        text: follow
          ? (followDue ? `Follow-up is due (${fmtWhen(follow, now)}).` : `Follow-up planned: ${fmtWhen(follow, now)}.`)
          : 'No follow-up planned.',
      }),
    );

    row.append(
      el('div', { class: 'w-actions' },
        el('button', {
          class: 'act-btn primary', text: 'Response received',
          onclick: () => leaveThen(row, 'up', async () => {
            await store.responseReceived(a.id);
            const msg = `${a.waitingFor || 'The response'} came back — it’s actionable again.`;
            announce(msg);
            toast(msg, { undoText: 'Undo', onUndo: () => store.undo() });
          }),
        }),
        el('button', { class: 'act-btn', text: 'Follow up now', onclick: () => onBegin(a) }),
        el('button', { class: 'act-btn', text: 'Snooze follow-up', onclick: () => snoozeFollowUp(a) }),
        a.sourceRef?.url && el('a', { class: 'act-btn', href: a.sourceRef.url, target: '_blank', rel: 'noopener', text: 'Open source ↗', style: 'text-decoration:none;' }),
        el('button', { class: 'act-btn', text: 'Edit', onclick: () => onEdit(a) }),
      ),
    );
    container.append(row);
  }
}

function snoozeFollowUp(action) {
  const now = new Date();
  const settings = store.getState().settings;
  const options = [
    { label: 'Tomorrow', date: atTime(addDays(startOfDay(now), 1), settings.workStart) },
    { label: 'In 2 workdays', date: atTime(addBusinessDays(now, 2), settings.workStart) },
    { label: 'Next week', date: atTime(addDays(startOfDay(now), (8 - now.getDay()) % 7 || 7), settings.workStart) },
  ];
  openDialog({
    title: 'Push the follow-up',
    hint: action.title,
    build(dialog, close) {
      const wrap = el('div', { style: 'display:flex; flex-wrap:wrap; gap:8px;' });
      for (const o of options) {
        wrap.append(el('button', {
          class: 'act-btn', text: o.label,
          onclick: async () => {
            await store.updateAction(action.id, { followUpAt: o.date.toISOString() }, { undoLabel: 'Follow-up snoozed' });
            announce(`Follow-up moved to ${o.label.toLowerCase()}.`);
            close();
          },
        }));
      }
      const custom = el('input', { type: 'datetime-local', value: toLocalInput(toDate(action.followUpAt) || options[0].date), style: 'width:100%; margin-top:12px;' });
      dialog.append(
        wrap,
        el('div', { class: 'field-row', style: 'margin-top:14px;' }, el('label', { text: 'Or pick a moment' }), custom),
        el('div', { class: 'dialog-footer' },
          el('button', { class: 'act-btn', text: 'Remove follow-up', onclick: async () => { await store.updateAction(action.id, { followUpAt: null }, { undoLabel: 'Follow-up removed' }); close(); } }),
          el('span', { class: 'spacer' }),
          el('button', { class: 'act-btn', text: 'Cancel', onclick: () => close() }),
          el('button', {
            class: 'act-btn primary', text: 'Save',
            onclick: async () => {
              if (!custom.value) return;
              await store.updateAction(action.id, { followUpAt: new Date(custom.value).toISOString() }, { undoLabel: 'Follow-up moved' });
              close();
            },
          }),
        ),
      );
    },
  });
}
