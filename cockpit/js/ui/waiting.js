// Waiting view: work that is off your plate, owned by someone else.
// First-class — not a list of unfinished personal tasks.

import * as store from '../store.js';
import { el, announce, toast, openDialog, leaveThen } from './dom.js';
import { chipRow } from './pickers.js';
import { fmtDaysSince, fmtWhen, toDate, atTime, addBusinessDays } from '../timeutil.js';

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
      el('div', { class: 'clear-state waiting-empty' },
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
        a.sourceRef?.url && el('a', { class: 'act-btn as-link', href: a.sourceRef.url, target: '_blank', rel: 'noopener', text: 'Open source ↗' }),
        el('button', { class: 'act-btn', text: 'Shape', onclick: () => onEdit(a) }),
      ),
    );
    container.append(row);
  }
}

function snoozeFollowUp(action) {
  const now = new Date();
  const settings = store.getState().settings;
  openDialog({
    title: 'Push the follow-up',
    hint: action.title,
    build(dialog, close) {
      const options = [
        { id: 'tomorrow', label: 'Tomorrow', value: () => atTime(new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1), settings.workStart) },
        { id: '2bd', label: 'In 2 workdays', value: () => atTime(addBusinessDays(now, 2), settings.workStart) },
        { id: 'week', label: 'Next week', value: () => atTime(new Date(now.getFullYear(), now.getMonth(), now.getDate() + ((8 - now.getDay()) % 7 || 7)), settings.workStart) },
        { id: 'custom', label: 'Pick a moment…', value: 'custom' },
      ];
      const customWrap = el('div', { class: 'picker-custom', hidden: true });
      const customInput = el('input', { type: 'datetime-local', 'aria-label': 'Custom follow-up' });
      customWrap.append(customInput);

      const row = chipRow(options, {
        onPick: async (opt) => {
          if (opt.value === 'custom') {
            customWrap.hidden = false;
            customInput.focus();
            return;
          }
          const date = opt.value();
          await store.updateAction(action.id, { followUpAt: date.toISOString() }, { undoLabel: 'Follow-up snoozed' });
          announce(`Follow-up moved to ${opt.label.toLowerCase()}.`);
          close();
        },
      });
      customInput.addEventListener('change', async () => {
        if (!customInput.value) return;
        await store.updateAction(action.id, { followUpAt: new Date(customInput.value).toISOString() }, { undoLabel: 'Follow-up moved' });
        announce('Follow-up updated.');
        close();
      });

      dialog.append(
        row,
        customWrap,
        el('div', { class: 'dialog-footer' },
          el('button', {
            class: 'link-btn', text: 'Remove follow-up',
            onclick: async () => {
              await store.updateAction(action.id, { followUpAt: null }, { undoLabel: 'Follow-up removed' });
              close();
            },
          }),
          el('span', { class: 'spacer' }),
          el('button', { class: 'link-btn', text: 'Cancel', onclick: () => close() }),
        ),
      );
    },
  });
}
