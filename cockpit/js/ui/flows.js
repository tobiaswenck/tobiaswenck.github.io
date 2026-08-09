// Shared interaction flows: completing, snoozing, waiting, blocking,
// scheduling, reminders, dropping. Each flow explains where the item went
// (directional leave animation + undo toast + live announcement).

import * as store from '../store.js';
import { el, toast, openDialog, announce, leaveThen } from './dom.js';
import { atTime, addDays, addBusinessDays, nextWorkday, startOfDay, fmtWhen, fmtShortDate } from '../timeutil.js';
import { computeMomentum } from '../momentum.js';
import { makeRule, PRESETS } from '../reminders.js';

function undoToast(message) {
  toast(message, {
    undoText: 'Undo',
    onUndo: async () => {
      const label = await store.undo();
      if (label) announce(`${label} undone.`);
    },
  });
}

// ---------- completion ----------

function consequenceFor(action, spawned) {
  const { actions, trail } = store.getState();
  const now = new Date();
  if (spawned) {
    const when = fmtWhen(new Date(spawned.scheduledFor), now);
    return `Done. Next occurrence: ${when}.`;
  }
  if (action.type === 'decide') return 'Decision recorded.';
  if (action.type === 'delegate') return `Handed off${action.waitingFor ? ` — waiting on ${action.waitingFor} now` : ''}.`;
  if (action.project) {
    const m = computeMomentum(actions, trail, now, { quietDays: store.getState().settings.quietDays })
      .find((x) => x.project === action.project);
    if (m && m.state === 'moving') return `${action.project} is moving.`;
  }
  return 'That’s handled.';
}

// Completes the action, animates it into history, then (when appropriate)
// asks whether this creates another action.
export function completeFlow(action, node, { askFollowUp = null } = {}) {
  leaveThen(node, 'up', async () => {
    const result = await store.completeAction(action.id);
    if (!result) return;
    const consequence = consequenceFor(action, result.spawned);
    announce(consequence);
    undoToast(consequence);

    const shouldAsk = askFollowUp ?? ['decide', 'delegate', 'followUp'].includes(action.type);
    if (shouldAsk) followUpPrompt(action);
  });
}

function followUpPrompt(action) {
  openDialog({
    title: 'Does this create another action?',
    hint: action.title,
    build(dialog, close) {
      const mk = (label, fn) => el('button', { class: 'act-btn', text: label, onclick: () => { close(); fn && fn(); } });
      dialog.append(
        el('div', { class: 'reset-card' },
          el('div', { class: 'r-options' },
            mk('No follow-up', null),
            mk('Add next action', () => {
              nextActionDialog(action);
            }),
            mk('Move to Waiting', () => {
              waitingCreateDialog(action);
            }),
            mk('Add follow-up reminder', () => {
              followUpReminderDialog(action);
            }),
          ),
        ),
      );
    },
  });
}

function nextActionDialog(source) {
  openDialog({
    title: 'Next action',
    hint: 'What visible action follows? A verb and an object help.',
    build(dialog, close) {
      const input = el('input', { type: 'text', placeholder: `After “${source.title}” …`, 'data-autofocus': '' });
      input.addEventListener('keydown', async (e) => {
        if (e.key === 'Enter' && input.value.trim()) {
          await store.addAction({ title: input.value.trim(), project: source.project, status: 'ready', sourceRef: source.sourceRef });
          announce('Next action saved.');
          close();
        }
      });
      dialog.append(
        el('div', { class: 'field-row' }, input),
        el('div', { class: 'dialog-footer' },
          el('button', { class: 'act-btn', text: 'Cancel', onclick: () => close() }),
          el('button', {
            class: 'act-btn primary', text: 'Save',
            onclick: async () => {
              if (!input.value.trim()) return;
              await store.addAction({ title: input.value.trim(), project: source.project, status: 'ready', sourceRef: source.sourceRef });
              announce('Next action saved.');
              close();
            },
          }),
        ),
      );
    },
  });
}

function waitingCreateDialog(source) {
  openDialog({
    title: 'Waiting on someone now?',
    build(dialog, close) {
      const who = el('input', { type: 'text', placeholder: 'Who or what are you waiting on?', 'data-autofocus': '' });
      dialog.append(
        el('div', { class: 'field-row' }, who),
        el('div', { class: 'dialog-footer' },
          el('button', { class: 'act-btn', text: 'Cancel', onclick: () => close() }),
          el('button', {
            class: 'act-btn primary', text: 'Save',
            onclick: async () => {
              const now = new Date();
              await store.addAction({
                title: `Follow up: ${source.title}`,
                type: 'followUp',
                status: 'waiting',
                project: source.project,
                waitingFor: who.value.trim(),
                waitingSince: now.toISOString(),
                followUpAt: atTime(addBusinessDays(now, 2), store.getState().settings.workStart).toISOString(),
                sourceRef: source.sourceRef,
              });
              announce('Now waiting — follow-up suggested in two workdays.');
              close();
            },
          }),
        ),
      );
    },
  });
}

function followUpReminderDialog(source) {
  const now = new Date();
  const settings = store.getState().settings;
  openDialog({
    title: 'Remind me to follow up',
    build(dialog, close) {
      for (const p of PRESETS.filter((x) => !['n_business_days', 'custom'].includes(x.id))) {
        dialog.append(el('button', {
          class: 'act-btn', text: p.label, style: 'margin: 0 8px 8px 0;',
          onclick: async () => {
            const rule = makeRule(p.id, now, settings);
            await store.addAction({
              title: `Follow up: ${source.title}`,
              type: 'followUp',
              status: 'ready',
              project: source.project,
              reminderRules: [rule],
              sourceRef: source.sourceRef,
            });
            announce('Follow-up reminder set.');
            close();
          },
        }));
      }
      dialog.append(el('div', { class: 'dialog-footer' },
        el('button', { class: 'act-btn', text: 'Cancel', onclick: () => close() })));
    },
  });
}

// ---------- snooze / later ----------

export function snoozeFlow(action, node) {
  const now = new Date();
  const settings = store.getState().settings;
  const options = [
    { label: 'Later today', date: new Date(now.getTime() + 3 * 3600000) },
    { label: 'Tomorrow', date: atTime(addDays(startOfDay(now), 1), settings.workStart) },
    { label: 'Next workday', date: atTime(nextWorkday(now), settings.workStart) },
    { label: 'Next week', date: atTime(addDays(startOfDay(now), (8 - now.getDay()) % 7 || 7), settings.workStart) },
  ];
  openDialog({
    title: 'Move this later',
    hint: action.title,
    build(dialog, close) {
      const wrap = el('div', { class: 'r-options', style: 'display:flex; flex-wrap:wrap; gap:8px;' });
      for (const opt of options) {
        wrap.append(el('button', {
          class: 'act-btn', text: opt.label,
          onclick: () => { close(); doSnooze(opt.date, opt.label); },
        }));
      }
      const custom = el('input', { type: 'datetime-local', style: 'margin-top:12px; width:100%;' });
      dialog.append(
        wrap,
        el('div', { class: 'field-row', style: 'margin-top:14px;' },
          el('label', { text: 'Or pick a moment' }), custom),
        el('div', { class: 'dialog-footer' },
          el('button', { class: 'act-btn', text: 'Cancel', onclick: () => close() }),
          el('button', {
            class: 'act-btn primary', text: 'Snooze',
            onclick: () => {
              if (!custom.value) return;
              const d = new Date(custom.value);
              close(); doSnooze(d, fmtWhen(d, now));
            },
          }),
        ),
      );
    },
  });

  function doSnooze(date, label) {
    leaveThen(node, 'down', async () => {
      await store.snoozeAction(action.id, date);
      const msg = `Moved to ${label.toLowerCase()}.`;
      announce(msg);
      undoToast(msg);
    });
  }
}

// ---------- waiting ----------

export function waitingFlow(action, node) {
  const now = new Date();
  const settings = store.getState().settings;
  const suggested = atTime(addBusinessDays(now, 2), settings.workStart);

  openDialog({
    title: 'Hand this off mentally',
    hint: 'Waiting means someone or something else has to respond. It leaves your active stream.',
    build(dialog, close) {
      const who = el('input', { type: 'text', value: action.waitingFor || '', placeholder: 'Who or what are you waiting on?', 'data-autofocus': '' });
      const followToggle = el('input', { type: 'checkbox', checked: true, id: 'w-follow-toggle', style: 'width:auto; margin-right:8px;' });
      const followDate = el('input', { type: 'datetime-local', value: toLocalInput(suggested) });
      dialog.append(
        el('div', { class: 'field-row' }, el('label', { text: 'Waiting for' }), who),
        el('div', { class: 'field-row' },
          el('label', { for: 'w-follow-toggle', style: 'display:flex; align-items:center; cursor:pointer;' },
            followToggle, 'Follow up if nothing happens'),
          followDate,
          el('p', { class: 'field-hint', text: `Suggested: ${fmtShortDate(suggested)} (two workdays)` }),
        ),
        el('div', { class: 'dialog-footer' },
          el('button', { class: 'act-btn', text: 'Cancel', onclick: () => close() }),
          el('button', {
            class: 'act-btn primary', text: 'Move to Waiting',
            onclick: () => {
              close();
              leaveThen(node, 'side', async () => {
                await store.moveToWaiting(action.id, {
                  waitingFor: who.value.trim(),
                  followUpAt: followToggle.checked && followDate.value ? new Date(followDate.value) : null,
                });
                const msg = `Waiting on ${who.value.trim() || 'a response'} — off your plate for now.`;
                announce(msg);
                undoToast(msg);
              });
            },
          }),
        ),
      );
      followToggle.addEventListener('change', () => { followDate.disabled = !followToggle.checked; });
    },
  });
}

// ---------- blocked ----------

export function blockFlow(action, node) {
  openDialog({
    title: 'What is in the way?',
    hint: 'Blocked means a known obstacle prevents progress. It stops being recommended.',
    build(dialog, close) {
      const reason = el('input', { type: 'text', value: action.blockedReason || '', placeholder: 'e.g. Test system is down until the patch lands', 'data-autofocus': '' });
      dialog.append(
        el('div', { class: 'field-row' }, reason),
        el('div', { class: 'dialog-footer' },
          el('button', { class: 'act-btn', text: 'Cancel', onclick: () => close() }),
          el('button', {
            class: 'act-btn primary', text: 'Mark blocked',
            onclick: () => {
              close();
              leaveThen(node, 'side', async () => {
                await store.blockAction(action.id, reason.value.trim());
                const msg = 'Blocked and parked. It won’t be recommended until it’s freed.';
                announce(msg);
                undoToast(msg);
              });
            },
          }),
        ),
      );
    },
  });
}

// ---------- schedule ----------

export function scheduleFlow(action, node = null) {
  const now = new Date();
  openDialog({
    title: 'When should this happen?',
    hint: action.title,
    build(dialog, close) {
      const input = el('input', { type: 'datetime-local', value: toLocalInput(action.scheduledFor ? new Date(action.scheduledFor) : atTime(nextWorkday(now), store.getState().settings.workStart)), 'data-autofocus': '' });
      dialog.append(
        el('div', { class: 'field-row' }, input),
        el('div', { class: 'dialog-footer' },
          el('button', { class: 'act-btn', text: 'Cancel', onclick: () => close() }),
          el('button', {
            class: 'act-btn primary', text: 'Schedule',
            onclick: () => {
              if (!input.value) return;
              const d = new Date(input.value);
              close();
              const apply = async () => {
                await store.scheduleAction(action.id, d);
                const msg = `Scheduled for ${fmtWhen(d, now)}.`;
                announce(msg);
                undoToast(msg);
              };
              if (node) leaveThen(node, 'down', apply); else apply();
            },
          }),
        ),
      );
    },
  });
}

// ---------- drop ----------

export function dropFlow(action, node) {
  leaveThen(node, 'side', async () => {
    await store.dropAction(action.id);
    const msg = 'Dropped. One less open loop.';
    announce(msg);
    undoToast(msg);
  });
}

// ---------- helpers ----------

export function toLocalInput(d) {
  if (!d) return '';
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
