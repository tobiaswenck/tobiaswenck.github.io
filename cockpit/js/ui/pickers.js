// Shared chip / duration / when pickers — one vocabulary for all quick
// dialogs and the shaper. Keyboard: number keys 1–9 pick a chip.

import { el } from './dom.js';
import {
  atTime, addDays, nextWorkday, startOfDay,
} from '../timeutil.js';

export function toLocalInput(d) {
  if (!d) return '';
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/**
 * @param {Array<{ id: string, label: string, value?: any }>} options
 * @param {{ value?: string, onPick: (opt) => void, numbered?: boolean, className?: string }} opts
 */
export function chipRow(options, { value = null, onPick, numbered = true, className = '' } = {}) {
  const row = el('div', {
    class: `chip-row ${className}`.trim(),
    role: 'listbox',
    'aria-label': 'Choices',
  });

  const buttons = [];
  options.forEach((opt, i) => {
    const selected = value != null && (opt.id === value || opt.value === value);
    const btn = el('button', {
      type: 'button',
      class: `chip${selected ? ' selected' : ''}`,
      role: 'option',
      'aria-selected': String(!!selected),
      dataset: { id: opt.id, index: String(i) },
      onclick: () => onPick(opt),
    },
      numbered && i < 9 ? el('span', { class: 'chip-num', 'aria-hidden': 'true', text: String(i + 1) }) : null,
      el('span', { class: 'chip-label', text: opt.label }),
    );
    buttons.push(btn);
    row.append(btn);
  });

  row._pickByIndex = (idx) => {
    if (idx >= 0 && idx < options.length) onPick(options[idx]);
  };
  row._options = options;
  return row;
}

/** Duration chips: 5 · 15 · 25 · 45 · 90 · custom */
export function durationPicker({ value = null, onPick, allowCustom = true } = {}) {
  const wrap = el('div', { class: 'picker-block' });
  const options = [
    { id: '5', label: '5 min', value: 5 },
    { id: '15', label: '15 min', value: 15 },
    { id: '25', label: '25 min', value: 25 },
    { id: '45', label: '45 min', value: 45 },
    { id: '90', label: '90 min', value: 90 },
  ];
  if (allowCustom) options.push({ id: 'custom', label: 'Custom…', value: 'custom' });

  const customWrap = el('div', { class: 'picker-custom', hidden: true });
  const customInput = el('input', {
    type: 'number',
    min: '1',
    step: '5',
    placeholder: 'Minutes',
    'aria-label': 'Custom minutes',
  });
  customWrap.append(customInput);

  let selectedId = value != null ? String(value) : null;
  if (value != null && ![5, 15, 25, 45, 90].includes(value)) selectedId = 'custom';

  const row = chipRow(options, {
    value: selectedId,
    onPick: (opt) => {
      if (opt.id === 'custom') {
        customWrap.hidden = false;
        customInput.focus();
        customInput.select();
        return;
      }
      customWrap.hidden = true;
      onPick(opt.value);
      // Refresh selection styling
      for (const b of row.querySelectorAll('.chip')) {
        const sel = b.dataset.id === opt.id;
        b.classList.toggle('selected', sel);
        b.setAttribute('aria-selected', String(sel));
      }
    },
  });

  customInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      const n = Number(customInput.value);
      if (n > 0) onPick(n);
    }
  });

  wrap.append(row, customWrap);
  wrap._pickByIndex = row._pickByIndex;
  wrap._focusCustom = () => { customWrap.hidden = false; customInput.focus(); };
  return wrap;
}

/**
 * When picker — resolves to a Date or a semantic token.
 * Tokens: 'now' | 'today' | 'tomorrow' | 'this_week' | 'someday' | Date
 * For snooze-style: later_today | tomorrow | next_workday | next_week | Date
 */
export function whenPicker({
  mode = 'shape', // 'shape' | 'snooze' | 'schedule'
  settings,
  now = new Date(),
  onPick,
  includeSomeday = true,
} = {}) {
  const wrap = el('div', { class: 'picker-block' });
  let options;

  if (mode === 'snooze') {
    options = [
      { id: 'later_today', label: 'Later today', value: () => new Date(now.getTime() + 3 * 3600000) },
      { id: 'tomorrow', label: 'Tomorrow', value: () => atTime(addDays(startOfDay(now), 1), settings.workStart) },
      { id: 'next_workday', label: 'Next workday', value: () => atTime(nextWorkday(now), settings.workStart) },
      { id: 'next_week', label: 'Next week', value: () => atTime(addDays(startOfDay(now), (8 - now.getDay()) % 7 || 7), settings.workStart) },
      { id: 'custom', label: 'Pick a moment…', value: 'custom' },
    ];
  } else if (mode === 'schedule') {
    options = [
      { id: 'today', label: 'Today', value: () => atTime(now, settings.workStart) },
      { id: 'tomorrow', label: 'Tomorrow', value: () => atTime(addDays(startOfDay(now), 1), settings.workStart) },
      { id: 'next_workday', label: 'Next workday', value: () => atTime(nextWorkday(now), settings.workStart) },
      { id: 'next_week', label: 'Next week', value: () => atTime(addDays(startOfDay(now), (8 - now.getDay()) % 7 || 7), settings.workStart) },
      { id: 'custom', label: 'Pick a moment…', value: 'custom' },
    ];
  } else {
    // shape
    options = [
      { id: 'now', label: 'Now (ready)', value: 'now' },
      { id: 'today', label: 'Today', value: 'today' },
      { id: 'tomorrow', label: 'Tomorrow', value: 'tomorrow' },
      { id: 'this_week', label: 'This week', value: 'this_week' },
    ];
    if (includeSomeday) options.push({ id: 'someday', label: 'Someday', value: 'someday' });
    options.push({ id: 'custom', label: 'Pick a moment…', value: 'custom' });
  }

  const customWrap = el('div', { class: 'picker-custom', hidden: true });
  const customInput = el('input', {
    type: 'datetime-local',
    'aria-label': 'Custom date and time',
  });
  customWrap.append(customInput);

  const row = chipRow(options, {
    onPick: (opt) => {
      if (opt.id === 'custom' || opt.value === 'custom') {
        customWrap.hidden = false;
        customInput.focus();
        return;
      }
      customWrap.hidden = true;
      const resolved = typeof opt.value === 'function' ? opt.value() : opt.value;
      onPick(resolved, opt);
      for (const b of row.querySelectorAll('.chip')) {
        const sel = b.dataset.id === opt.id;
        b.classList.toggle('selected', sel);
        b.setAttribute('aria-selected', String(sel));
      }
    },
  });

  customInput.addEventListener('change', () => {
    if (!customInput.value) return;
    onPick(new Date(customInput.value), { id: 'custom', label: 'Custom' });
  });
  customInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && customInput.value) {
      e.preventDefault();
      onPick(new Date(customInput.value), { id: 'custom', label: 'Custom' });
    }
  });

  wrap.append(row, customWrap);
  wrap._pickByIndex = row._pickByIndex;
  return wrap;
}

/** Reminder preset chips */
export function reminderPicker({ presets, onPick } = {}) {
  const options = presets.map((p) => ({ id: p.id, label: p.label, value: p.id }));
  return chipRow(options, {
    onPick: (opt) => onPick(opt.id),
  });
}

/** Resolve shape "when" tokens into status + scheduledFor */
export function resolveWhenToken(token, now, settings) {
  if (token instanceof Date) {
    return { status: 'scheduled', scheduledFor: token.toISOString(), snoozedUntil: null };
  }
  switch (token) {
    case 'now':
      return { status: 'ready', scheduledFor: null, snoozedUntil: null };
    case 'today':
      return {
        status: 'scheduled',
        scheduledFor: atTime(now, settings.workStart).toISOString(),
        snoozedUntil: null,
      };
    case 'tomorrow':
      return {
        status: 'scheduled',
        scheduledFor: atTime(addDays(startOfDay(now), 1), settings.workStart).toISOString(),
        snoozedUntil: null,
      };
    case 'this_week': {
      // Next free workday afternoon-ish, or Friday if midweek
      const wd = now.getDay();
      const daysAhead = wd === 5 ? 0 : Math.min(4, Math.max(1, 5 - wd));
      const d = addDays(startOfDay(now), daysAhead || 1);
      return {
        status: 'scheduled',
        scheduledFor: atTime(d, settings.workStart).toISOString(),
        snoozedUntil: null,
      };
    }
    case 'someday':
      return { status: 'ready', scheduledFor: null, snoozedUntil: null };
    default:
      return {};
  }
}

export function settleMessage(patch, now) {
  const mins = patch.estimateMinutes;
  if (patch.status === 'scheduled' && patch.scheduledFor) {
    const d = new Date(patch.scheduledFor);
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    if (d.toDateString() === now.toDateString()) {
      return mins ? `Shaped. Ready today — about ${mins} minutes.` : 'Shaped. Fits today.';
    }
    return `Shaped. It fits your ${days[d.getDay()]}.`;
  }
  if (mins) return `Ready — ${mins} focused minutes.`;
  return 'Shaped. Ready when you are.';
}

export function settleDirection(patch) {
  if (patch.status === 'scheduled' || patch.snoozedUntil) return 'down';
  return 'inplace';
}
