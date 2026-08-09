// Action editor with progressive disclosure. Only the title is required;
// the prompts encourage concrete, finishable actions without forcing a form.

import * as store from '../store.js';
import { el, openDialog, announce, confirmDialog, toast } from './dom.js';
import { toLocalInput } from './flows.js';
import { TYPES, TYPE_LABEL, STATUSES, ENERGIES, looksVague } from '../model.js';
import { FREQ_LABEL, describeRule } from '../recurrence.js';
import { PRESETS, makeRule } from '../reminders.js';
import { fmtWhen, toDate } from '../timeutil.js';

const STATUS_LABEL = {
  inbox: 'Inbox', ready: 'Ready', active: 'Active', scheduled: 'Scheduled',
  waiting: 'Waiting', blocked: 'Blocked', done: 'Done', dropped: 'Dropped',
};

export function openEditor(action) {
  const projects = [...new Set(store.getState().actions.map((a) => a.project).filter(Boolean))].sort();

  openDialog({
    title: action.title ? 'Edit action' : 'New action',
    build(dialog, close) {
      const f = {};

      f.title = el('input', { type: 'text', value: action.title, 'data-autofocus': '' });
      const vagueHint = el('p', { class: 'field-hint' });
      const checkVague = () => {
        vagueHint.textContent = looksVague(f.title.value)
          ? 'This reads like a project label. What visible action starts it?'
          : '';
      };
      f.title.addEventListener('input', checkVague);
      checkVague();

      f.dod = el('textarea', { placeholder: 'e.g. The decision is posted in Linear.' });
      f.dod.value = action.definitionOfDone;

      f.type = select(TYPES.map((t) => [t, TYPE_LABEL[t]]), action.type);
      f.status = select(STATUSES.map((s) => [s, STATUS_LABEL[s]]), action.status);
      f.energy = select(ENERGIES.map((e) => [e, e[0].toUpperCase() + e.slice(1)]), action.energy);

      f.project = el('input', { type: 'text', value: action.project, list: 'project-list' });
      const datalist = el('datalist', { id: 'project-list' }, projects.map((p) => el('option', { value: p })));

      f.estimate = el('input', { type: 'number', min: '0', step: '5', value: action.estimateMinutes ?? '', placeholder: '25' });
      f.scheduledFor = el('input', { type: 'datetime-local', value: toLocalInput(toDate(action.scheduledFor)) });
      f.dueAt = el('input', { type: 'datetime-local', value: toLocalInput(toDate(action.dueAt)) });
      f.hard = el('input', { type: 'checkbox', checked: action.hard, id: 'f-hard', style: 'width:auto; margin-right:8px;' });
      f.pinned = el('input', { type: 'checkbox', checked: action.pinned, id: 'f-pinned', style: 'width:auto; margin-right:8px;' });

      f.waitingFor = el('input', { type: 'text', value: action.waitingFor, placeholder: 'Who or what?' });
      f.followUpAt = el('input', { type: 'datetime-local', value: toLocalInput(toDate(action.followUpAt)) });

      f.sourceUrl = el('input', { type: 'url', value: action.sourceRef?.url || '', placeholder: 'https://linear.app/…' });
      f.sourceLabel = el('input', { type: 'text', value: action.sourceRef?.label || '', placeholder: 'e.g. KOM-142' });

      f.notes = el('textarea');
      f.notes.value = action.notes;

      // --- recurrence ---
      const rule = action.recurrenceRule;
      f.freq = select([['', 'Does not repeat'], ...Object.entries(FREQ_LABEL)], rule?.freq || '');
      f.freqN = el('input', { type: 'number', min: '1', value: rule?.n ?? 2, style: 'max-width: 90px;' });
      f.freqUnit = select([['days', 'days'], ['weeks', 'weeks']], rule?.unit || 'days');
      const dayBoxes = [1, 2, 3, 4, 5, 6, 7].map((d) =>
        el('label', { style: 'display:inline-flex; align-items:center; gap:4px; margin-right:10px; font-size:11px; color: var(--muted); cursor:pointer;' },
          el('input', { type: 'checkbox', value: String(d), checked: rule?.weekdays?.includes(d) || false, style: 'width:auto;' }),
          ['', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][d]));
      const freqExtra = el('div', { style: 'margin-top: 8px;' });
      const renderFreqExtra = () => {
        freqExtra.replaceChildren();
        const v = f.freq.value;
        if (v === 'customDays') freqExtra.append(...dayBoxes);
        else if (v === 'everyNDays') freqExtra.append(el('span', { style: 'font-size:12px; color:var(--muted); margin-right:8px;', text: 'Every' }), f.freqN, el('span', { style: 'font-size:12px; color:var(--muted); margin-left:8px;', text: 'days' }));
        else if (v === 'afterCompletion') freqExtra.append(f.freqN, f.freqUnit, el('span', { style: 'font-size:12px; color:var(--muted); margin-left:8px;', text: 'after completion' }));
      };
      f.freq.addEventListener('change', renderFreqExtra);
      renderFreqExtra();

      const seriesControls = el('div', { style: 'margin-top: 8px; display:flex; gap:8px; flex-wrap:wrap;' });
      if (rule) {
        seriesControls.append(
          el('button', {
            class: 'act-btn', text: rule.paused ? 'Resume series' : 'Pause series',
            onclick: async () => {
              await store.updateAction(action.id, { recurrenceRule: { ...rule, paused: !rule.paused } }, { undoLabel: 'Series changed' });
              announce(rule.paused ? 'Series resumed.' : 'Series paused.');
              close();
            },
          }),
          el('button', {
            class: 'act-btn', text: 'Skip this occurrence',
            onclick: async () => {
              const result = await store.skipRecurrence(action.id);
              if (result?.spawned) {
                toast(`Skipped. Next occurrence: ${fmtWhen(new Date(result.spawned.scheduledFor), new Date())}.`, { undoText: 'Undo', onUndo: () => store.undo() });
              } else {
                toast('Skipped. The series has no next occurrence.', { undoText: 'Undo', onUndo: () => store.undo() });
              }
              close();
            },
          }),
          el('button', {
            class: 'act-btn danger', text: 'End series',
            onclick: async () => {
              await store.updateAction(action.id, { recurrenceRule: null }, { undoLabel: 'Series ended' });
              announce('Series ended.');
              close();
            },
          }),
        );
      }

      // --- reminders ---
      const reminderList = el('div', { style: 'display:flex; flex-direction:column; gap:4px; margin-bottom:8px;' });
      let reminders = [...(action.reminderRules || [])];
      const renderReminders = () => {
        reminderList.replaceChildren();
        for (const r of reminders) {
          reminderList.append(el('div', { style: 'display:flex; gap:10px; align-items:baseline; font-size:12px; color:var(--text-2);' },
            el('span', { text: r.at ? fmtWhen(new Date(r.at), new Date()) + (r.firedAt ? ' · fired' : '') : 'when the app next opens' }),
            el('button', { class: 'link-btn', text: 'remove', onclick: () => { reminders = reminders.filter((x) => x.id !== r.id); renderReminders(); } }),
          ));
        }
      };
      renderReminders();
      const reminderPreset = select(PRESETS.map((p) => [p.id, p.label]), 'tomorrow_morning');
      const reminderCustom = el('input', { type: 'datetime-local', hidden: true, style: 'margin-top:6px;' });
      reminderPreset.addEventListener('change', () => { reminderCustom.hidden = reminderPreset.value !== 'custom'; });
      const addReminderBtn = el('button', {
        class: 'act-btn', text: 'Add reminder',
        onclick: () => {
          const now = new Date();
          const opts = reminderPreset.value === 'custom' && reminderCustom.value
            ? { custom: new Date(reminderCustom.value) } : {};
          if (reminderPreset.value === 'custom' && !reminderCustom.value) return;
          reminders.push(makeRule(reminderPreset.value, now, store.getState().settings, opts));
          renderReminders();
        },
      });

      dialog.append(
        datalist,
        field('Title', f.title, vagueHint),
        field('What will be true when this is done?', f.dod),
        el('div', { class: 'field-grid' },
          field('Do, decide, delegate, review, or follow up?', f.type),
          field('Status', f.status),
          field('Project', f.project),
          field('How long would a first session take? (min)', f.estimate),
          field('Scheduled for', f.scheduledFor),
          field('Due', f.dueAt),
          field('Energy it needs', f.energy),
          el('div', { class: 'field-row' },
            el('label', { text: 'Flags' }),
            el('label', { for: 'f-hard', style: 'display:flex; align-items:center; font-size:12px; color:var(--text-2); cursor:pointer;' }, f.hard, 'Fixed-time commitment (landmark)'),
            el('label', { for: 'f-pinned', style: 'display:flex; align-items:center; font-size:12px; color:var(--text-2); cursor:pointer; margin-top:4px;' }, f.pinned, 'Pin as the next action'),
          ),
        ),
        el('div', { class: 'field-grid' },
          field('Are you waiting on someone?', f.waitingFor),
          field('Follow up at', f.followUpAt),
          field('Source link', f.sourceUrl),
          field('Source label', f.sourceLabel),
        ),
        field('Repeats', f.freq, freqExtra, rule && el('p', { class: 'field-hint', text: `Current: ${describeRule(rule)}` }), seriesControls),
        el('div', { class: 'field-row' },
          el('label', { text: 'Reminders (in-app while open; system notifications only if enabled in Settings)' }),
          reminderList,
          el('div', { style: 'display:flex; gap:8px; flex-wrap:wrap; align-items:center;' }, reminderPreset, addReminderBtn),
          reminderCustom,
        ),
        field('Notes', f.notes),
        el('div', { class: 'dialog-footer' },
          el('button', {
            class: 'act-btn danger', text: 'Delete',
            onclick: async () => {
              if (await confirmDialog('Delete this action?', { confirmText: 'Delete', danger: true })) {
                await store.deleteAction(action.id);
                toast('Deleted.', { undoText: 'Undo', onUndo: () => store.undo() });
                close();
              }
            },
          }),
          el('span', { class: 'spacer' }),
          el('button', { class: 'act-btn', text: 'Cancel', onclick: () => close() }),
          el('button', {
            class: 'act-btn primary', text: 'Save',
            onclick: async () => {
              if (!f.title.value.trim()) { f.title.focus(); return; }
              let recurrenceRule = null;
              if (f.freq.value) {
                recurrenceRule = {
                  freq: f.freq.value,
                  weekdays: dayBoxes.filter((b) => b.querySelector('input').checked).map((b) => Number(b.querySelector('input').value)),
                  n: Number(f.freqN.value) || 1,
                  unit: f.freqUnit.value,
                  paused: rule?.paused || false,
                };
              }
              const patch = {
                title: f.title.value.trim(),
                definitionOfDone: f.dod.value.trim(),
                type: f.type.value,
                status: f.status.value,
                project: f.project.value.trim(),
                estimateMinutes: f.estimate.value ? Number(f.estimate.value) : null,
                scheduledFor: f.scheduledFor.value ? new Date(f.scheduledFor.value).toISOString() : null,
                dueAt: f.dueAt.value ? new Date(f.dueAt.value).toISOString() : null,
                energy: f.energy.value,
                hard: f.hard.checked,
                pinned: f.pinned.checked,
                waitingFor: f.waitingFor.value.trim(),
                followUpAt: f.followUpAt.value ? new Date(f.followUpAt.value).toISOString() : null,
                sourceRef: f.sourceUrl.value.trim()
                  ? { type: action.sourceRef?.type || 'manual', externalId: action.sourceRef?.externalId || null, url: f.sourceUrl.value.trim(), label: f.sourceLabel.value.trim() || null }
                  : null,
                notes: f.notes.value,
                recurrenceRule,
                reminderRules: reminders,
              };
              if (patch.status === 'waiting' && !action.waitingSince) patch.waitingSince = new Date().toISOString();
              await store.updateAction(action.id, patch, { undoLabel: 'Edited' });
              announce('Saved.');
              close();
            },
          }),
        ),
      );
    },
  });
}

function field(label, ...controls) {
  return el('div', { class: 'field-row' }, el('label', { text: label }), ...controls);
}

function select(pairs, value) {
  const s = el('select', {});
  for (const [v, label] of pairs) {
    s.append(el('option', { value: v, selected: v === value, text: label }));
  }
  return s;
}
