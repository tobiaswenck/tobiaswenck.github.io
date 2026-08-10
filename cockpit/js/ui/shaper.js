// Step-based action shaper — replaces the monolithic edit modal.
// One question at a time; answered steps compress into summary lines.
// Keyboard: 1–9 pick chips, Enter skip/advance, ↑ reopen summary, Esc save & close.

import * as store from '../store.js';
import { el, openDialog, announce, toast, confirmDialog, reducedMotion } from './dom.js';
import {
  chipRow, durationPicker, whenPicker, resolveWhenToken, settleMessage, settleDirection, toLocalInput,
} from './pickers.js';
import { TYPES, TYPE_LABEL, STATUSES, ENERGIES, looksVague } from '../model.js';
import { FREQ_LABEL, describeRule } from '../recurrence.js';
import { PRESETS, makeRule } from '../reminders.js';
import { fmtWhen } from '../timeutil.js';

const STATUS_LABEL = {
  inbox: 'Inbox', ready: 'Ready', active: 'Active', scheduled: 'Scheduled',
  waiting: 'Waiting', blocked: 'Blocked', done: 'Done', dropped: 'Dropped',
};

const STEP_IDS = ['type', 'duration', 'when', 'done', 'context', 'advanced'];

const STEP_LABEL = {
  type: 'Kind',
  duration: 'Time',
  when: 'When',
  done: 'Done when',
  context: 'Context',
  advanced: 'More',
};

export function isUnshaped(action) {
  if (!action) return false;
  if (action.hard) return false;
  if (action.status === 'done' || action.status === 'dropped') return false;
  const missingEst = action.estimateMinutes == null;
  const missingDod = !action.definitionOfDone;
  return missingEst || missingDod;
}

export function unshapedHint(action) {
  if (!isUnshaped(action)) return null;
  let n = 0;
  if (action.estimateMinutes == null) n++;
  if (!action.definitionOfDone) n++;
  return n === 1 ? 'unshaped · 1 quick question' : `unshaped · ${n} quick questions`;
}

/**
 * Full shaper dialog.
 * @param {object} action
 * @param {{ onDone?: (action) => void, startStep?: string }} opts
 */
export function openShaper(action, { onDone = null, startStep = null } = {}) {
  const live = { ...action };
  const draft = {
    type: action.type || 'do',
    estimateMinutes: action.estimateMinutes,
    whenToken: null, // set when user picks
    scheduledFor: action.scheduledFor,
    status: action.status,
    definitionOfDone: action.definitionOfDone || '',
    project: action.project || '',
    energy: action.energy || 'any',
    pinned: !!action.pinned,
    hard: !!action.hard,
    notes: action.notes || '',
    waitingFor: action.waitingFor || '',
    followUpAt: action.followUpAt,
    sourceUrl: action.sourceRef?.url || '',
    sourceLabel: action.sourceRef?.label || '',
    recurrenceRule: action.recurrenceRule ? { ...action.recurrenceRule } : null,
    reminderRules: [...(action.reminderRules || [])],
    dueAt: action.dueAt,
  };

  // Infer whenToken from existing state for summary
  if (action.status === 'ready' && !action.scheduledFor) draft.whenToken = 'now';
  else if (action.scheduledFor) draft.whenToken = 'custom';

  const answered = new Set();
  // Pre-mark steps that already have meaningful data
  if (action.type && action.type !== 'do') answered.add('type');
  if (action.estimateMinutes != null) answered.add('duration');
  if (action.scheduledFor || action.status === 'ready' || action.status === 'scheduled') answered.add('when');
  if (action.definitionOfDone) answered.add('done');
  if (action.project || action.pinned || (action.energy && action.energy !== 'any')) answered.add('context');

  let stepIndex = 0;
  if (startStep) {
    const i = STEP_IDS.indexOf(startStep);
    if (i >= 0) stepIndex = i;
  } else {
    // Jump to first unanswered core step
    const first = STEP_IDS.findIndex((id) => id !== 'advanced' && !answered.has(id));
    stepIndex = first >= 0 ? first : 0;
  }

  const projects = [...new Set(store.getState().actions.map((a) => a.project).filter(Boolean))].sort();

  let settled = false;

  openDialog({
    className: 'shaper-dialog',
    title: '',
    build(dialog, close) {
      dialog.replaceChildren(); // we'll manage title ourselves

      const titleEl = el('p', { class: 'shaper-title', text: action.title });
      const progressEl = el('p', { class: 'shaper-progress' });
      const summariesEl = el('div', { class: 'shaper-summaries', 'aria-label': 'Answered steps' });
      const stepHost = el('div', { class: 'shaper-step-host' });
      const footer = el('div', { class: 'shaper-footer' });

      dialog.append(titleEl, progressEl, summariesEl, stepHost, footer);

      let currentPicker = null;
      let keyHandler = null;

      function detachKeys() {
        if (keyHandler) {
          dialog.removeEventListener('keydown', keyHandler);
          keyHandler = null;
        }
      }

      function attachKeys(handler) {
        detachKeys();
        keyHandler = (e) => {
          const tag = e.target.tagName;
          const inField = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';

          if (e.key === 'Escape') {
            // Let document-level dialog Esc fire; onClose persists.
            return;
          }
          if (e.key === 'ArrowUp' && !inField) {
            e.preventDefault();
            if (stepIndex > 0) goTo(stepIndex - 1);
            return;
          }
          if (!inField && /^[1-9]$/.test(e.key)) {
            e.preventDefault();
            if (currentPicker && currentPicker._pickByIndex) {
              currentPicker._pickByIndex(Number(e.key) - 1);
            }
            return;
          }
          handler && handler(e, inField);
        };
        dialog.addEventListener('keydown', keyHandler);
      }

      function summaryText(id) {
        switch (id) {
          case 'type': return TYPE_LABEL[draft.type] || draft.type;
          case 'duration': return draft.estimateMinutes != null ? `≈ ${draft.estimateMinutes} min` : '—';
          case 'when': {
            if (draft.whenToken === 'now') return 'Ready now';
            if (draft.whenToken === 'someday') return 'Someday';
            if (draft.whenToken === 'today') return 'Today';
            if (draft.whenToken === 'tomorrow') return 'Tomorrow';
            if (draft.whenToken === 'this_week') return 'This week';
            if (draft.scheduledFor) return fmtWhen(new Date(draft.scheduledFor), new Date());
            return STATUS_LABEL[draft.status] || draft.status;
          }
          case 'done': return draft.definitionOfDone ? shorten(draft.definitionOfDone, 42) : '—';
          case 'context': {
            const parts = [];
            if (draft.project) parts.push(draft.project);
            if (draft.energy && draft.energy !== 'any') parts.push(draft.energy);
            if (draft.pinned) parts.push('pinned');
            return parts.join(' · ') || '—';
          }
          default: return '…';
        }
      }

      function renderSummaries() {
        summariesEl.replaceChildren();
        for (const id of STEP_IDS) {
          if (id === 'advanced') continue;
          if (!answered.has(id) && STEP_IDS.indexOf(id) >= stepIndex) continue;
          if (!answered.has(id)) continue;
          summariesEl.append(
            el('button', {
              type: 'button',
              class: 'shaper-summary',
              onclick: () => goTo(STEP_IDS.indexOf(id)),
            },
              el('span', { class: 'sum-label', text: STEP_LABEL[id] }),
              el('span', { class: 'sum-value', text: summaryText(id) }),
            ),
          );
        }
      }

      function goTo(i) {
        stepIndex = Math.max(0, Math.min(STEP_IDS.length - 1, i));
        renderStep();
      }

      function advance() {
        if (stepIndex >= STEP_IDS.length - 1) {
          finish();
          return;
        }
        stepIndex++;
        renderStep();
      }

      function skip() {
        advance();
      }

      async function finish({ animate = true } = {}) {
        if (settled) return;
        settled = true;
        detachKeys();
        const now = new Date();
        const settings = store.getState().settings;
        const patch = buildPatch(draft, action, now, settings);

        await store.updateAction(action.id, patch, { undoLabel: 'Shaped' });
        const updated = store.getAction(action.id);
        const msg = settleMessage(patch, now);
        const dir = settleDirection(patch);
        announce(msg);

        if (!animate) {
          close(updated);
          onDone && onDone(updated);
          return;
        }

        stepHost.replaceChildren();
        summariesEl.replaceChildren();
        progressEl.textContent = '';
        footer.replaceChildren();
        titleEl.hidden = true;

        const settle = el('div', {
          class: `shaper-settle settle-${dir}`,
          role: 'status',
        },
          el('p', { class: 'settle-msg', text: msg }),
          el('p', { class: 'settle-detail', text: action.title }),
        );
        stepHost.append(settle);

        const delay = reducedMotion() ? 80 : 720;
        setTimeout(() => {
          close(updated);
          onDone && onDone(updated);
        }, delay);
      }

      function renderStep() {
        const id = STEP_IDS[stepIndex];
        const coreCount = STEP_IDS.length - 1; // exclude advanced from "of N"
        const displayN = id === 'advanced' ? coreCount : Math.min(stepIndex + 1, coreCount);
        progressEl.textContent = id === 'advanced'
          ? 'Optional · everything else'
          : `Step ${displayN} of ${coreCount}`;

        renderSummaries();
        stepHost.replaceChildren();
        footer.replaceChildren();
        currentPicker = null;

        const step = el('div', { class: 'shaper-step', key: id });
        stepHost.append(step);

        if (id === 'type') renderType(step);
        else if (id === 'duration') renderDuration(step);
        else if (id === 'when') renderWhen(step);
        else if (id === 'done') renderDone(step);
        else if (id === 'context') renderContext(step);
        else renderAdvanced(step);

        footer.append(
          el('span', {},
            el('span', { class: 'kbd', text: '1–9' }), ' pick · ',
            el('span', { class: 'kbd', text: 'Enter' }), ' skip · ',
            el('span', { class: 'kbd', text: 'Esc' }), ' save',
          ),
          el('span', { class: 'spacer' }),
          el('button', {
            type: 'button',
            class: 'link-btn',
            text: id === 'advanced' ? 'Done' : 'Skip',
            onclick: () => (id === 'advanced' ? finish() : skip()),
          }),
        );
      }

      function renderType(step) {
        step.append(el('h2', { class: 'step-q', text: 'What kind of move?' }));
        const options = TYPES.map((t) => ({ id: t, label: TYPE_LABEL[t], value: t }));
        const row = chipRow(options, {
          value: draft.type,
          onPick: (opt) => {
            draft.type = opt.value;
            answered.add('type');
            advance();
          },
        });
        currentPicker = row;
        step.append(el('div', { class: 'step-body' }, row));
        attachKeys((e, inField) => {
          if (!inField && e.key === 'Enter') { e.preventDefault(); answered.add('type'); skip(); }
        });
      }

      function renderDuration(step) {
        step.append(el('h2', { class: 'step-q', text: 'How long would a first session take?' }));
        step.append(el('p', { class: 'step-hint', text: 'A rough guess is enough — activation energy, not a schedule.' }));
        const picker = durationPicker({
          value: draft.estimateMinutes,
          onPick: (mins) => {
            draft.estimateMinutes = mins;
            answered.add('duration');
            advance();
          },
        });
        currentPicker = picker;
        step.append(el('div', { class: 'step-body' }, picker));
        attachKeys((e, inField) => {
          if (!inField && e.key === 'Enter') { e.preventDefault(); skip(); }
        });
      }

      function renderWhen(step) {
        step.append(el('h2', { class: 'step-q', text: 'When?' }));
        const settings = store.getState().settings;
        const picker = whenPicker({
          mode: 'shape',
          settings,
          now: new Date(),
          onPick: (token) => {
            draft.whenToken = token instanceof Date ? 'custom' : token;
            if (token instanceof Date) {
              draft.scheduledFor = token.toISOString();
              draft.status = 'scheduled';
            } else if (token === 'someday' || token === 'now') {
              draft.scheduledFor = null;
              draft.status = 'ready';
            } else {
              const resolved = resolveWhenToken(token, new Date(), settings);
              Object.assign(draft, resolved);
            }
            answered.add('when');
            // Custom datetime: wait for change event which already called onPick with Date
            if (token === 'custom') return;
            advance();
          },
        });
        currentPicker = picker;
        step.append(el('div', { class: 'step-body' }, picker));
        attachKeys((e, inField) => {
          if (!inField && e.key === 'Enter') { e.preventDefault(); skip(); }
        });
      }

      function renderDone(step) {
        step.append(el('h2', { class: 'step-q', text: 'Done when…?' }));
        step.append(el('p', { class: 'step-hint', text: 'What will be visibly true when this is finished?' }));
        const input = el('input', {
          class: 'step-text',
          type: 'text',
          value: draft.definitionOfDone,
          placeholder: 'e.g. The decision is posted in Linear.',
          'data-autofocus': '',
          'aria-label': 'Definition of done',
        });
        const vague = el('p', { class: 'field-hint' });
        if (looksVague(action.title) && !draft.definitionOfDone) {
          vague.textContent = 'The title reads like a project label — a finish line helps.';
        }
        input.addEventListener('input', () => { draft.definitionOfDone = input.value; });
        step.append(el('div', { class: 'step-body' }, input, vague));

        attachKeys((e, inField) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            draft.definitionOfDone = input.value.trim();
            if (draft.definitionOfDone) answered.add('done');
            advance();
          }
        });
      }

      function renderContext(step) {
        step.append(el('h2', { class: 'step-q', text: 'Context' }));

        const body = el('div', { class: 'step-body' });

        // Project chips
        body.append(el('p', { class: 'step-hint', text: 'Project' }));
        const projOpts = [
          { id: '_none', label: 'None', value: '' },
          ...projects.slice(0, 8).map((p) => ({ id: p, label: p, value: p })),
          { id: '_new', label: 'Other…', value: '_new' },
        ];
        const projectInput = el('input', {
          type: 'text',
          class: 'step-text',
          placeholder: 'Project name',
          value: draft.project,
          hidden: true,
          'aria-label': 'Project name',
        });
        const projRow = chipRow(projOpts, {
          value: draft.project || '_none',
          onPick: (opt) => {
            if (opt.value === '_new') {
              projectInput.hidden = false;
              projectInput.focus();
              return;
            }
            projectInput.hidden = true;
            draft.project = opt.value;
            for (const b of projRow.querySelectorAll('.chip')) {
              const sel = b.dataset.id === opt.id;
              b.classList.toggle('selected', sel);
            }
          },
        });
        projectInput.addEventListener('change', () => { draft.project = projectInput.value.trim(); });
        body.append(projRow, projectInput);

        // Energy
        body.append(el('p', { class: 'step-hint spaced', text: 'Energy it needs' }));
        const energyOpts = ENERGIES.map((e) => ({
          id: e,
          label: e === 'any' ? 'Any' : e[0].toUpperCase() + e.slice(1),
          value: e,
        }));
        const energyRow = chipRow(energyOpts, {
          value: draft.energy,
          onPick: (opt) => {
            draft.energy = opt.value;
            for (const b of energyRow.querySelectorAll('.chip')) {
              b.classList.toggle('selected', b.dataset.id === opt.id);
            }
          },
        });
        body.append(energyRow);

        // Pin
        body.append(el('p', { class: 'step-hint spaced', text: 'Priority' }));
        const pinRow = chipRow([
          { id: 'normal', label: 'Normal', value: false },
          { id: 'pin', label: 'Pin as next', value: true },
        ], {
          value: draft.pinned ? 'pin' : 'normal',
          onPick: (opt) => {
            draft.pinned = !!opt.value;
            for (const b of pinRow.querySelectorAll('.chip')) {
              b.classList.toggle('selected', b.dataset.id === opt.id);
            }
          },
        });
        body.append(pinRow);

        step.append(body);

        currentPicker = projRow;

        const continueBtn = el('button', {
          type: 'button',
          class: 'act-btn primary',
          text: 'Continue',
          onclick: () => {
            if (!projectInput.hidden) draft.project = projectInput.value.trim();
            answered.add('context');
            advance();
          },
        });
        step.append(el('div', { class: 'shaper-continue' }, continueBtn));

        attachKeys((e, inField) => {
          if (e.key === 'Enter' && (!inField || e.target === projectInput)) {
            e.preventDefault();
            if (!projectInput.hidden) draft.project = projectInput.value.trim();
            answered.add('context');
            advance();
          }
        });
      }

      function renderAdvanced(step) {
        step.append(el('h2', { class: 'step-q', text: 'Everything else' }));
        step.append(el('p', { class: 'step-hint', text: 'Optional. Skip if you don’t need it.' }));

        const adv = el('div', { class: 'shaper-advanced' });

        // Status
        const statusSec = el('div', { class: 'adv-section' },
          el('span', { class: 'section-label', text: 'Status' }));
        const statusRow = chipRow(
          ['inbox', 'ready', 'scheduled', 'waiting', 'blocked'].map((s) => ({
            id: s, label: STATUS_LABEL[s], value: s,
          })),
          {
            value: draft.status,
            onPick: (opt) => {
              draft.status = opt.value;
              for (const b of statusRow.querySelectorAll('.chip')) {
                b.classList.toggle('selected', b.dataset.id === opt.id);
              }
            },
          },
        );
        statusSec.append(statusRow);
        adv.append(statusSec);

        // Hard commitment
        const hardSec = el('div', { class: 'adv-section' },
          el('span', { class: 'section-label', text: 'Fixed commitment' }));
        const hardRow = chipRow([
          { id: 'flex', label: 'Flexible', value: false },
          { id: 'hard', label: 'Landmark (meeting)', value: true },
        ], {
          value: draft.hard ? 'hard' : 'flex',
          onPick: (opt) => {
            draft.hard = !!opt.value;
            for (const b of hardRow.querySelectorAll('.chip')) {
              b.classList.toggle('selected', b.dataset.id === opt.id);
            }
          },
        });
        hardSec.append(hardRow);
        adv.append(hardSec);

        // Waiting for
        const waitInput = el('input', {
          type: 'text', class: 'step-text', value: draft.waitingFor,
          placeholder: 'Who or what?', 'aria-label': 'Waiting for',
        });
        waitInput.addEventListener('input', () => { draft.waitingFor = waitInput.value; });
        adv.append(el('div', { class: 'adv-section' },
          el('span', { class: 'section-label', text: 'Waiting for' }),
          waitInput,
        ));

        // Source
        const srcUrl = el('input', {
          type: 'url', class: 'step-text', value: draft.sourceUrl,
          placeholder: 'https://linear.app/…', 'aria-label': 'Source URL',
        });
        const srcLabel = el('input', {
          type: 'text', class: 'step-text', value: draft.sourceLabel,
          placeholder: 'Label (e.g. KOM-142)', 'aria-label': 'Source label',
        });
        srcLabel.classList.add('stack-gap');
        srcUrl.addEventListener('input', () => { draft.sourceUrl = srcUrl.value; });
        srcLabel.addEventListener('input', () => { draft.sourceLabel = srcLabel.value; });
        adv.append(el('div', { class: 'adv-section' },
          el('span', { class: 'section-label', text: 'Source link' }),
          srcUrl, srcLabel,
        ));

        // Notes
        const notes = el('textarea', { 'aria-label': 'Notes' });
        notes.value = draft.notes;
        notes.addEventListener('input', () => { draft.notes = notes.value; });
        adv.append(el('div', { class: 'adv-section' },
          el('span', { class: 'section-label', text: 'Notes' }),
          notes,
        ));

        // Recurrence (compact)
        const rule = draft.recurrenceRule;
        const freqRow = chipRow([
          { id: '', label: 'Doesn’t repeat', value: null },
          ...Object.entries(FREQ_LABEL).slice(0, 5).map(([k, v]) => ({ id: k, label: v, value: k })),
        ], {
          value: rule?.freq || '',
          onPick: (opt) => {
            if (!opt.value) {
              draft.recurrenceRule = null;
            } else {
              draft.recurrenceRule = {
                freq: opt.value,
                weekdays: rule?.weekdays || [],
                n: rule?.n || 1,
                unit: rule?.unit || 'days',
                paused: false,
              };
            }
            for (const b of freqRow.querySelectorAll('.chip')) {
              b.classList.toggle('selected', b.dataset.id === opt.id);
            }
          },
        });
        adv.append(el('div', { class: 'adv-section' },
          el('span', { class: 'section-label', text: 'Repeats' }),
          freqRow,
          rule && el('p', { class: 'field-hint', text: describeRule(rule) }),
        ));

        // Series controls if existing
        if (action.recurrenceRule) {
          const series = el('div', { class: 'chip-row stack-gap' });
          series.append(
            el('button', {
              type: 'button', class: 'chip',
              text: action.recurrenceRule.paused ? 'Resume series' : 'Pause series',
              onclick: async () => {
                const r = { ...action.recurrenceRule, paused: !action.recurrenceRule.paused };
                draft.recurrenceRule = r;
                await store.updateAction(action.id, { recurrenceRule: r }, { undoLabel: 'Series changed' });
                announce(r.paused ? 'Series paused.' : 'Series resumed.');
              },
            }),
            el('button', {
              type: 'button', class: 'chip',
              text: 'Skip this occurrence',
              onclick: async () => {
                const result = await store.skipRecurrence(action.id);
                if (result?.spawned) {
                  toast(`Skipped. Next: ${fmtWhen(new Date(result.spawned.scheduledFor), new Date())}.`, {
                    undoText: 'Undo', onUndo: () => store.undo(),
                  });
                }
                close(null);
              },
            }),
          );
          adv.append(series);
        }

        // Reminders
        const remList = el('div', { class: 'adv-section' });
        remList.append(el('span', { class: 'section-label', text: 'Reminders' }));
        const remItems = el('div');
        const renderRem = () => {
          remItems.replaceChildren();
          for (const r of draft.reminderRules) {
            remItems.append(el('div', { class: 'rem-item' },
              el('span', { text: r.at ? fmtWhen(new Date(r.at), new Date()) : 'when app opens' }),
              el('button', {
                type: 'button', class: 'link-btn', text: 'remove',
                onclick: () => {
                  draft.reminderRules = draft.reminderRules.filter((x) => x.id !== r.id);
                  renderRem();
                },
              }),
            ));
          }
        };
        renderRem();
        const remChips = chipRow(
          PRESETS.filter((p) => !['n_business_days'].includes(p.id)).map((p) => ({
            id: p.id, label: p.label, value: p.id,
          })),
          {
            numbered: false,
            onPick: (opt) => {
              const settings = store.getState().settings;
              draft.reminderRules.push(makeRule(opt.value, new Date(), settings));
              renderRem();
            },
          },
        );
        remList.append(remItems, remChips);
        adv.append(remList);

        // Delete
        adv.append(el('div', { class: 'adv-section' },
          el('button', {
            type: 'button',
            class: 'act-btn danger',
            text: 'Delete action',
            onclick: async () => {
              if (await confirmDialog('Delete this action?', { confirmText: 'Delete', danger: true })) {
                await store.deleteAction(action.id);
                toast('Deleted.', { undoText: 'Undo', onUndo: () => store.undo() });
                close(null);
              }
            },
          }),
        ));

        step.append(adv);
        currentPicker = statusRow;

        const doneBtn = el('button', {
          type: 'button',
          class: 'act-btn primary',
          text: 'Save',
          onclick: () => finish(),
        });
        step.append(el('div', { class: 'shaper-save' }, doneBtn));

        attachKeys((e, inField) => {
          if (!inField && e.key === 'Enter') { e.preventDefault(); finish(); }
        });
      }

      renderStep();
    },
    onClose: async () => {
      if (settled) return;
      settled = true;
      const now = new Date();
      const settings = store.getState().settings;
      const patch = buildPatch(draft, action, now, settings);
      await store.updateAction(action.id, patch, { undoLabel: 'Shaped' });
      announce(settleMessage(patch, now));
      onDone && onDone(store.getAction(action.id));
    },
  });
}

function buildPatch(draft, action, now, settings) {
  let whenPatch = {};
  if (draft.whenToken && draft.whenToken !== 'custom') {
    whenPatch = resolveWhenToken(draft.whenToken, now, settings);
  } else if (draft.whenToken === 'custom' && draft.scheduledFor) {
    whenPatch = { status: 'scheduled', scheduledFor: draft.scheduledFor, snoozedUntil: null };
  } else if (draft.status && draft.status !== action.status) {
    whenPatch = { status: draft.status };
    if (draft.scheduledFor) whenPatch.scheduledFor = draft.scheduledFor;
  }

  // If still inbox and user shaped type/duration, promote to ready
  let status = whenPatch.status || draft.status;
  if (status === 'inbox' && (draft.estimateMinutes != null || draft.definitionOfDone || answeredType(draft, action))) {
    status = whenPatch.status || 'ready';
  }

  const patch = {
    type: draft.type,
    estimateMinutes: draft.estimateMinutes,
    definitionOfDone: (draft.definitionOfDone || '').trim(),
    project: (draft.project || '').trim(),
    energy: draft.energy,
    pinned: draft.pinned,
    hard: draft.hard,
    notes: draft.notes,
    waitingFor: (draft.waitingFor || '').trim(),
    followUpAt: draft.followUpAt,
    dueAt: draft.dueAt,
    recurrenceRule: draft.recurrenceRule,
    reminderRules: draft.reminderRules,
    status,
    ...whenPatch,
  };
  if (whenPatch.scheduledFor !== undefined) patch.scheduledFor = whenPatch.scheduledFor;
  else if (draft.scheduledFor !== action.scheduledFor) patch.scheduledFor = draft.scheduledFor;

  patch.sourceRef = draft.sourceUrl.trim()
    ? {
      type: action.sourceRef?.type || 'manual',
      externalId: action.sourceRef?.externalId || null,
      url: draft.sourceUrl.trim(),
      label: draft.sourceLabel.trim() || null,
    }
    : null;

  if (patch.status === 'waiting' && !action.waitingSince) {
    patch.waitingSince = now.toISOString();
  }

  return patch;
}

function answeredType(draft, action) {
  return draft.type !== (action.type || 'do');
}

function shorten(s, n) {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/**
 * Mini begin-gate: duration + done-when only, then continue into focus.
 */
export function openBeginGate(action, { onContinue }) {
  if (!isUnshaped(action)) {
    onContinue(action);
    return;
  }

  const draft = {
    estimateMinutes: action.estimateMinutes,
    definitionOfDone: action.definitionOfDone || '',
  };

  openDialog({
    className: 'shaper-dialog begin-gate',
    title: '',
    build(dialog, close) {
      dialog.replaceChildren();
      dialog.append(
        el('p', { class: 'shaper-title', text: action.title }),
        el('p', { class: 'shaper-progress', text: 'Quick shape before focus' }),
      );

      const host = el('div', { class: 'shaper-step' });
      dialog.append(host);

      let phase = draft.estimateMinutes == null ? 'duration' : 'done';

      function render() {
        host.replaceChildren();
        if (phase === 'duration') {
          host.append(el('h2', { class: 'step-q', text: 'How long for this session?' }));
          const picker = durationPicker({
            value: draft.estimateMinutes,
            onPick: (mins) => {
              draft.estimateMinutes = mins;
              phase = !draft.definitionOfDone ? 'done' : 'finish';
              if (phase === 'finish') saveAndGo();
              else render();
            },
          });
          host.append(picker);
          host.append(el('div', { class: 'shaper-footer' },
            el('button', {
              type: 'button', class: 'link-btn', text: 'Skip',
              onclick: () => {
                phase = !draft.definitionOfDone ? 'done' : 'finish';
                if (phase === 'finish') saveAndGo();
                else render();
              },
            }),
          ));
          dialog.onkeydown = (e) => {
            if (e.key === 'Enter' && e.target.tagName !== 'INPUT') {
              e.preventDefault();
              phase = !draft.definitionOfDone ? 'done' : 'finish';
              if (phase === 'finish') saveAndGo();
              else render();
            }
            if (/^[1-9]$/.test(e.key) && e.target.tagName !== 'INPUT') {
              picker._pickByIndex?.(Number(e.key) - 1);
            }
          };
        } else {
          host.append(el('h2', { class: 'step-q', text: 'Done when…?' }));
          const input = el('input', {
            class: 'step-text', type: 'text',
            value: draft.definitionOfDone,
            placeholder: 'What will be true when this is finished?',
            'data-autofocus': '',
          });
          host.append(input);
          host.append(el('div', { class: 'shaper-footer' },
            el('button', {
              type: 'button', class: 'link-btn', text: 'Skip',
              onclick: () => saveAndGo(),
            }),
            el('span', { class: 'spacer' }),
            el('button', {
              type: 'button', class: 'act-btn primary', text: 'Begin',
              onclick: () => {
                draft.definitionOfDone = input.value.trim();
                saveAndGo();
              },
            }),
          ));
          input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              draft.definitionOfDone = input.value.trim();
              saveAndGo();
            }
          });
          dialog.onkeydown = null;
        }
      }

      async function saveAndGo() {
        const patch = {};
        if (draft.estimateMinutes != null) patch.estimateMinutes = draft.estimateMinutes;
        if (draft.definitionOfDone) patch.definitionOfDone = draft.definitionOfDone;
        if (Object.keys(patch).length) {
          await store.updateAction(action.id, patch, { undoLabel: 'Shaped' });
        }
        const updated = store.getAction(action.id);
        close(updated);
        onContinue(updated);
      }

      render();
    },
  });
}
