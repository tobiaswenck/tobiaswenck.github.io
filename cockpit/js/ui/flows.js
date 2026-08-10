// Shared interaction flows: completing, snoozing, waiting, blocking,
// scheduling, reminders, dropping. Each flow explains where the item went
// (directional leave animation + undo toast + live announcement).

import * as store from '../store.js';
import { el, toast, openDialog, announce, leaveThen } from './dom.js';
import { atTime, addBusinessDays, fmtWhen, fmtShortDate } from '../timeutil.js';
import { computeMomentum } from '../momentum.js';
import { makeRule, PRESETS } from '../reminders.js';
import { whenPicker, chipRow, toLocalInput } from './pickers.js';

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
      const options = [
        { id: 'none', label: 'No follow-up', fn: null },
        { id: 'next', label: 'Add next action', fn: () => nextActionDialog(action) },
        { id: 'wait', label: 'Move to Waiting', fn: () => waitingCreateDialog(action) },
        { id: 'remind', label: 'Add follow-up reminder', fn: () => followUpReminderDialog(action) },
      ];
      dialog.append(
        chipRow(options, {
          numbered: true,
          onPick: (opt) => { close(); opt.fn && opt.fn(); },
        }),
        el('div', { class: 'dialog-footer' },
          el('button', { class: 'link-btn', text: 'Cancel', onclick: () => close() })),
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
    hint: source.title,
    build(dialog, close) {
      const presets = PRESETS.filter((x) => !['n_business_days', 'custom'].includes(x.id));
      dialog.append(
        chipRow(presets.map((p) => ({ id: p.id, label: p.label, value: p.id })), {
          onPick: async (opt) => {
            const rule = makeRule(opt.value, now, settings);
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
        }),
        el('div', { class: 'dialog-footer' },
          el('button', { class: 'link-btn', text: 'Cancel', onclick: () => close() })),
      );
    },
  });
}

// ---------- snooze / later ----------

export function snoozeFlow(action, node) {
  const now = new Date();
  const settings = store.getState().settings;
  openDialog({
    title: 'Move this later',
    hint: action.title,
    build(dialog, close) {
      const picker = whenPicker({
        mode: 'snooze',
        settings,
        now,
        onPick: (date, opt) => {
          if (!(date instanceof Date)) return;
          close();
          doSnooze(date, opt?.label || fmtWhen(date, now));
        },
      });
      dialog.append(
        picker,
        el('div', { class: 'dialog-footer' },
          el('button', { class: 'link-btn', text: 'Cancel', onclick: () => close() })),
      );

      dialog.addEventListener('keydown', (e) => {
        if (/^[1-9]$/.test(e.key) && e.target.tagName !== 'INPUT') {
          e.preventDefault();
          picker._pickByIndex?.(Number(e.key) - 1);
        }
      });
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
      let followAt = suggested;
      let followOn = true;

      const followChips = chipRow([
        { id: 'yes', label: `Follow up ${fmtShortDate(suggested)}`, value: true },
        { id: 'no', label: 'No follow-up', value: false },
        { id: 'custom', label: 'Pick date…', value: 'custom' },
      ], {
        value: 'yes',
        onPick: (opt) => {
          if (opt.value === 'custom') {
            customWrap.hidden = false;
            customInput.focus();
            return;
          }
          customWrap.hidden = true;
          followOn = !!opt.value;
          followAt = suggested;
          for (const b of followChips.querySelectorAll('.chip')) {
            b.classList.toggle('selected', b.dataset.id === opt.id);
          }
        },
      });

      const customWrap = el('div', { class: 'picker-custom', hidden: true });
      const customInput = el('input', { type: 'datetime-local', value: toLocalInput(suggested) });
      customInput.addEventListener('change', () => {
        if (customInput.value) {
          followOn = true;
          followAt = new Date(customInput.value);
        }
      });
      customWrap.append(customInput);

      dialog.append(
        el('div', { class: 'field-row' }, el('label', { text: 'Waiting for' }), who),
        el('div', { class: 'field-row' },
          el('label', { text: 'Follow up' }),
          followChips,
          customWrap,
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
                  followUpAt: followOn ? followAt : null,
                });
                const msg = `Waiting on ${who.value.trim() || 'a response'} — off your plate for now.`;
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
  const settings = store.getState().settings;
  openDialog({
    title: 'When should this happen?',
    hint: action.title,
    build(dialog, close) {
      const picker = whenPicker({
        mode: 'schedule',
        settings,
        now,
        onPick: (date) => {
          if (!(date instanceof Date)) return;
          close();
          const apply = async () => {
            await store.scheduleAction(action.id, date);
            const msg = `Scheduled for ${fmtWhen(date, now)}.`;
            announce(msg);
            undoToast(msg);
          };
          if (node) leaveThen(node, 'down', apply); else apply();
        },
      });
      dialog.append(
        picker,
        el('div', { class: 'dialog-footer' },
          el('button', { class: 'link-btn', text: 'Cancel', onclick: () => close() })),
      );
      dialog.addEventListener('keydown', (e) => {
        if (/^[1-9]$/.test(e.key) && e.target.tagName !== 'INPUT') {
          e.preventDefault();
          picker._pickByIndex?.(Number(e.key) - 1);
        }
      });
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

export { toLocalInput };
