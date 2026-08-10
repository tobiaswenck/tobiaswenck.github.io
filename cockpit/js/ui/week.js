// Week view: management attention across the week — not a Kanban board.
// Past days compress into summaries; today and the future get the space.

import * as store from '../store.js';
import { el } from './dom.js';
import { scheduleFlow } from './flows.js';
import {
  startOfDay, addDays, isSameDay, fmtTime, fmtShortDate, fmtDuration,
  plannedMinutesForDay, toDate, weekKey,
} from '../timeutil.js';
import { isOpen } from '../model.js';
import { MOMENTUM_LABEL } from '../momentum.js';

const MOVE_KINDS = ['completed', 'decision', 'unblocked', 'response'];
const DAY_NAMES = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'];

export function renderWeek(container, ctx) {
  const { now, momentum, onEdit, onGotoView } = ctx;
  const { actions, trail, settings } = store.getState();

  container.replaceChildren();
  container.append(renderHead(now));

  // ---------- the five days ----------
  const monday = mondayOf(now);
  const days = el('section', { 'aria-label': 'Days of the week' });

  for (let i = 0; i < 5; i++) {
    const day = addDays(monday, i);
    const isPast = startOfDay(day) < startOfDay(now) && !isSameDay(day, now);
    const isToday = isSameDay(day, now);

    const dayEl = el('div', { class: `week-day ${isPast ? 'past' : ''} ${isToday ? 'today' : ''}` },
      el('div', { class: 'day-label' },
        `${DAY_NAMES[i]}${isToday ? ' · now' : ''}`,
        el('span', { class: 'dnum', text: fmtShortDate(day) }),
      ),
    );

    const body = el('div', { class: 'day-items' });

    if (isPast) {
      body.append(el('p', { class: 'day-summary', text: summarizeDay(trail, day) }));
    } else {
      const items = itemsForDay(actions, day)
        .sort((a, b) => (a.scheduledFor || a.dueAt || '').localeCompare(b.scheduledFor || b.dueAt || ''));
      if (!items.length) {
        body.append(el('p', { class: 'day-empty', text: isToday ? 'Nothing more planned today.' : 'Open.' }));
      }
      for (const a of items.slice(0, 7)) {
        const d = toDate(a.scheduledFor);
        const rowEl = el('div', { class: `day-item ${a.hard ? 'hard' : ''}` },
          el('span', { class: 't', text: d && (d.getHours() || d.getMinutes()) ? fmtTime(d) : '·' }),
          el('span', { text: a.title }),
        );
        if (!a.hard) {
          rowEl.append(el('span', { class: 'row-actions' },
            el('button', { text: 'Move', onclick: () => scheduleFlow(a) }),
            el('button', { text: 'Shape', onclick: () => onEdit(a) }),
          ));
          rowEl.classList.add('spine-row');
        }
        body.append(rowEl);
      }

      // Soft capacity — restrained, not alarming.
      const planned = plannedMinutesForDay(actions, day);
      const cap = settings.dailyCapacityMinutes;
      if (planned > 0) {
        const pct = Math.min(130, Math.round((planned / cap) * 100));
        const over = planned > cap;
        body.append(
          el('div', { class: 'capacity-line' },
            el('div', { class: 'capacity-bar', role: 'img', 'aria-label': `${fmtDuration(planned)} planned of ${fmtDuration(cap)} capacity` },
              el('div', { class: `fill ${over ? 'over' : ''}`, style: `width:${Math.min(100, pct)}%;` })),
            el('span', { text: `${fmtDuration(planned)} planned` }),
            over && el('span', { class: 'capacity-note', text: `${fullDayName(i)} looks overloaded — more planned than realistically fits.` }),
          ),
        );
      }
    }

    dayEl.append(body);
    days.append(dayEl);
  }
  container.append(days);

  // ---------- management attention ----------
  const decisions = actions.filter((a) => isOpen(a) && a.type === 'decide' && !['waiting', 'blocked'].includes(a.status));
  if (decisions.length) {
    const sec = el('section', { class: 'week-section' },
      el('span', { class: 'section-label', text: `${decisions.length === 1 ? 'One decision needs making' : `${decisions.length} decisions need making`}` }));
    for (const a of decisions.slice(0, 6)) {
      sec.append(el('div', { class: 'ws-row' },
        el('button', { class: 'link-btn', text: a.title, onclick: () => onEdit(a) }),
        a.project && el('span', { class: 'why', text: a.project }),
      ));
    }
    container.append(sec);
  }

  const blockedOrWaiting = momentum.filter((m) => ['blocked', 'waiting', 'quiet'].includes(m.state));
  if (blockedOrWaiting.length) {
    const sec = el('section', { class: 'week-section' },
      el('span', { class: 'section-label', text: 'Not moving on its own' }));
    for (const m of blockedOrWaiting.slice(0, 6)) {
      sec.append(el('div', { class: 'ws-row' },
        el('span', { text: m.project }),
        el('span', { class: `mstate ${m.state}`, text: MOMENTUM_LABEL[m.state] }),
        el('span', { class: 'why', text: m.detail }),
      ));
    }
    container.append(sec);
  }

  const waitingCount = actions.filter((a) => a.status === 'waiting').length;
  if (waitingCount) {
    container.append(el('p', { class: 'week-link' },
      el('button', { class: 'link-btn', text: `${waitingCount} item${waitingCount > 1 ? 's' : ''} waiting on others →`, onclick: () => onGotoView('waiting') })));
  }

  // ---------- Friday handoff ----------
  const wd = now.getDay();
  if (wd === 5 || wd === 6 || wd === 0) {
    container.append(renderHandoff(now));
  }
}

function renderHead(now) {
  const wd = now.getDay();
  let q, sub;
  if (wd === 1) { q = 'What needs to be true by Friday?'; sub = 'Set the shape of the week: outcomes, risks, and what carries over.'; }
  else if (wd === 2 || wd === 3) { q = 'What is moving — and what has gone quiet?'; sub = 'Midweek is about momentum: keep what moves, notice what stalls.'; }
  else if (wd === 4) { q = 'What still genuinely needs to happen this week?'; sub = 'The week is narrowing. Optional work can wait; unresolved decisions can’t.'; }
  else if (wd === 5) { q = 'Close the week.'; sub = 'Close loops, hand off, defer deliberately — and leave a note for Monday-you.'; }
  else { q = 'The week is closed.'; sub = 'Anything here can wait until Monday.'; }
  return el('div', { class: 'week-head' },
    el('h2', { class: 'week-question', text: q }),
    el('p', { class: 'week-sub', text: sub }),
  );
}

function renderHandoff(now) {
  const state = store.getState();
  const wk = weekKey(now);
  const existing = state.fridayNote && state.fridayNote.weekKey === wk ? state.fridayNote.text : '';

  const area = el('textarea', { placeholder: 'e.g. The rollout decision is made — start with the customer reply. Ignore the DocSync noise.', 'aria-label': 'Note for Monday' });
  area.value = existing;
  const saved = el('p', { class: 'handoff-saved', text: existing ? 'Saved. Monday-you will see this.' : '' });

  let timer = null;
  area.addEventListener('input', () => {
    clearTimeout(timer);
    saved.textContent = '…';
    timer = setTimeout(async () => {
      await store.saveFridayNote({ weekKey: wk, text: area.value.trim(), savedAt: new Date().toISOString(), shownWeekKey: null });
      saved.textContent = area.value.trim() ? 'Saved. Monday-you will see this.' : '';
    }, 500);
  });

  return el('section', { class: 'handoff' },
    el('span', { class: 'section-label', text: 'What should Monday-you know?' }),
    area,
    saved,
  );
}

// ---------- helpers ----------

function mondayOf(d) {
  const x = startOfDay(d);
  const shift = (x.getDay() + 6) % 7; // Mon=0
  return addDays(x, -shift);
}

function summarizeDay(trail, day) {
  const events = trail.filter((t) => MOVE_KINDS.includes(t.kind) && isSameDay(new Date(t.at), day));
  if (!events.length) return 'No recorded movement.';
  const decisions = events.filter((t) => t.kind === 'decision').length;
  const cleared = events.filter((t) => t.kind === 'unblocked').length;
  const parts = [`${events.length} move${events.length > 1 ? 's' : ''}`];
  if (decisions) parts.push(`${decisions} decision${decisions > 1 ? 's' : ''}`);
  if (cleared) parts.push(`${cleared} blocker${cleared > 1 ? 's' : ''} cleared`);
  return parts.join(' · ');
}

function itemsForDay(actions, day) {
  return actions.filter((a) => {
    if (!isOpen(a) || ['waiting', 'blocked'].includes(a.status)) return false;
    const d = toDate(a.scheduledFor) || toDate(a.dueAt);
    return d && isSameDay(d, day);
  });
}

function fullDayName(i) {
  return ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'][i];
}
