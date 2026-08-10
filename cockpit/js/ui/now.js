// The Now view: a temporal spine anchored on the current moment.
// Past above (fading), NOW in the middle, future below. Composition and
// copy change with the time-state — not just the heading.

import * as store from '../store.js';
import { el } from './dom.js';
import { completeFlow, snoozeFlow, waitingFlow } from './flows.js';
import {
  fmtTime, fmtDate, fmtWhen, fmtDuration, isSameDay, startOfDay, addDays,
  toDate, minutesBetween,
} from '../timeutil.js';
import { TYPE_LABEL, actionMinutes, isOpen } from '../model.js';
import { MOMENTUM_LABEL } from '../momentum.js';
import { unshapedHint } from './shaper.js';

const MOVE_KINDS = ['completed', 'decision', 'unblocked', 'response'];

function row(cls, time, text) {
  return el('div', { class: `spine-row ${cls}` },
    el('div', { class: 'spine-time', text: time }),
    el('div', { class: 'spine-body', text }),
  );
}

export function renderNow(container, ctx) {
  const { now, timeState: ts, momentum, recommendation: rec, onBegin, onEdit, onCapture, onGotoView } = ctx;
  const { actions, trail } = store.getState();

  container.replaceChildren();

  container.append(renderNarrative(now, ts, rec, actions, trail, onGotoView));
  if (!ts.isWeekend) container.append(renderDayGeometry(now, ts));

  const spine = el('section', { class: 'spine', 'aria-label': 'Timeline of the day' });

  // The recommendation lives at NOW; don't repeat it in the future lists.
  const recIds = new Set(
    [rec.primary?.action.id, ...rec.alternatives.map((x) => x.action.id)].filter(Boolean),
  );

  // ---------- past ----------
  const earlier = summarizeEarlierWeek(trail, now);
  if (earlier) {
    spine.append(row('compressed', 'earlier', earlier));
  }
  const yesterday = summarizeYesterday(trail, now);
  if (yesterday) {
    spine.append(row('compressed', 'yesterday', yesterday));
  }

  const todayEvents = trail.filter((t) => MOVE_KINDS.includes(t.kind) && isSameDay(new Date(t.at), now));
  todayEvents.forEach((t, i) => {
    const age = Math.min(3, todayEvents.length - 1 - i);
    const r = el('div', { class: `spine-row past age-${age}` },
      el('div', { class: 'spine-time', text: fmtTime(new Date(t.at)) }),
      el('div', { class: 'spine-body' },
        el('span', { class: 'tick', 'aria-hidden': 'true', text: '✓' }),
        el('span', { text: trailLabel(t) }),
      ),
    );
    spine.append(r);
  });

  // ---------- NOW ----------
  spine.append(
    el('div', { class: 'now-marker', role: 'separator', 'aria-label': `Now, ${fmtTime(now)}` },
      el('div', { class: 'line', 'aria-hidden': 'true' }),
      el('span', { class: 'label', text: `Now · ${fmtTime(now)}` }),
      el('div', { class: 'line right', 'aria-hidden': 'true' }),
    ),
  );

  if (rec.primary) {
    spine.append(renderRecommendation(rec.primary, ts, { onBegin, onEdit }));
    if (rec.alternatives.length) {
      spine.append(renderAlternatives(rec.alternatives, onBegin));
    }
  } else {
    spine.append(renderClearState(ts, { onCapture, onGotoView }));
  }

  // ---------- future ----------
  for (const item of upcomingToday(actions, now, recIds)) {
    spine.append(renderUpcomingRow(item, now, { onBegin, onEdit }));
  }
  for (const item of laterItems(actions, now, recIds)) {
    spine.append(renderLaterRow(item, now, { onBegin, onEdit }));
  }

  container.append(spine);

  // ---------- context strips ----------
  const waitingCount = actions.filter((a) => a.status === 'waiting').length;
  if (waitingCount) {
    container.append(
      el('p', { class: 'week-link' },
        el('button', {
          class: 'link-btn',
          text: `${waitingCount} thing${waitingCount > 1 ? 's are' : ' is'} waiting on others →`,
          onclick: () => onGotoView('waiting'),
        }),
      ),
    );
  }

  const attention = momentum.filter((m) => m.needsAttention).slice(0, 6);
  if (attention.length) {
    const section = el('section', { class: 'momentum', 'aria-label': 'Project momentum' },
      el('span', { class: 'section-label', text: 'Where projects stand' }));
    for (const m of attention) {
      section.append(
        el('div', { class: 'momentum-row' },
          el('span', { class: 'proj', text: m.project }),
          el('span', { class: `mstate ${m.state}`, text: MOMENTUM_LABEL[m.state] }),
          el('span', { class: 'mdetail', text: m.detail }),
        ),
      );
    }
    container.append(section);
  }
}

// ================= narrative =================

function renderNarrative(now, ts, rec, actions, trail, onGotoView) {
  const { greeting, lines } = narrativeCopy(now, ts, rec, actions, trail);
  const nar = el('section', { class: 'narrative', 'aria-label': 'Current situation' },
    el('p', { class: 'datemark', text: fmtDate(now) }),
    el('h1', { class: 'greeting', text: greeting }),
  );
  for (const line of lines) {
    nar.append(el('p', { class: 'situation', text: line }));
  }

  const carry = carryOverCount(actions, now);
  if (carry >= 3 && ['week_opening', 'morning_orientation', 'midday_recalibration'].includes(ts.id)) {
    nar.append(el('p', { class: 'situation' },
      el('button', {
        class: 'link-btn',
        text: `${carry} items need a new decision → run a reset`,
        onclick: () => onGotoView('reset'),
      })));
  }
  return nar;
}

function narrativeCopy(now, ts, rec, actions, trail) {
  const moved = ts.completedToday;
  const lines = [];
  const next = ts.nextCommitment;
  const gap = next ? minutesBetween(now, toDate(next.scheduledFor)) : null;

  const windowLine = () => {
    if (next && gap <= 120 && gap > 0) lines.push(`You have ${gap} minutes before ${next.title}.`);
  };

  switch (ts.id) {
    case 'week_opening': {
      const windows = focusWindows(ts, now);
      lines.push('What needs to be true by Friday?');
      if (windows >= 1) lines.push(`Today has ${windows} useful focus window${windows > 1 ? 's' : ''}.`);
      return { greeting: 'Monday. A fresh week.', lines };
    }
    case 'morning_orientation': {
      const windows = focusWindows(ts, now);
      if (ts.commitmentsToday.length === 0) lines.push('No fixed commitments today — a long runway.');
      else if (windows >= 1) lines.push(`Today has ${windows} useful focus window${windows > 1 ? 's' : ''}.`);
      if (next) lines.push(`First commitment: ${fmtTime(toDate(next.scheduledFor))} ${next.title}.`);
      return { greeting: 'Good morning.', lines };
    }
    case 'midday_recalibration': {
      if (moved >= 2) lines.push(`The morning moved ${moved} things forward.`);
      else if (moved === 1) lines.push('The morning moved one thing forward.');
      else lines.push('A quiet morning so far. The afternoon is still open.');
      windowLine();
      return { greeting: 'Midday.', lines };
    }
    case 'afternoon_compression': {
      if (rec.primary) lines.push('One important move still fits today.');
      if (ts.minutesRemaining > 0) lines.push(`About ${fmtDuration(Math.round(ts.minutesRemaining / 15) * 15)} of the workday remain.`);
      windowLine();
      return { greeting: 'The day is narrowing.', lines };
    }
    case 'day_shutdown': {
      if (moved > 0) lines.push(`Today: ${moved} meaningful move${moved > 1 ? 's' : ''}.`);
      if (rec.primary) lines.push('One open loop deserves a decision before stopping.');
      else lines.push('Nothing else needs to be started today.');
      return { greeting: 'Winding down.', lines };
    }
    case 'week_convergence': {
      lines.push('What still genuinely needs to happen this week?');
      const decisions = actions.filter((a) => isOpen(a) && a.type === 'decide' && !['waiting', 'blocked'].includes(a.status)).length;
      if (decisions) lines.push(`${decisions === 1 ? 'One decision is' : `${decisions} decisions are`} still open.`);
      windowLine();
      return { greeting: 'The week is converging.', lines };
    }
    case 'week_closure': {
      if (ts.isWeekend) {
        return { greeting: 'It’s the weekend.', lines: ['Nothing here needs you.'] };
      }
      lines.push('Close loops, hand things off, and leave a note for Monday-you.');
      if (moved > 0) lines.push(`Today: ${moved} meaningful move${moved > 1 ? 's' : ''}.`);
      return { greeting: 'Friday. Closing the week.', lines };
    }
    default: { // active_work
      if (moved >= 1) lines.push(`${moved} thing${moved > 1 ? 's have' : ' has'} moved today.`);
      windowLine();
      return { greeting: 'In motion.', lines };
    }
  }
}

function focusWindows(ts, now) {
  // Count gaps ≥ 45 min between now, today's commitments, and end of day.
  const marks = [
    now < ts.workStart ? ts.workStart : now,
    ...ts.commitmentsToday.map((c) => toDate(c.scheduledFor)).filter((d) => d > now),
    ts.workEnd,
  ].sort((a, b) => a - b);
  let windows = 0;
  for (let i = 0; i < marks.length - 1; i++) {
    if (minutesBetween(marks[i], marks[i + 1]) >= 45) windows++;
  }
  return windows;
}

function carryOverCount(actions, now) {
  const today = startOfDay(now);
  return actions.filter((a) => {
    if (!isOpen(a) || ['waiting', 'blocked'].includes(a.status)) return false;
    const s = toDate(a.scheduledFor);
    return (s && s < today) || a.status === 'inbox';
  }).length;
}

// ================= day geometry =================

function renderDayGeometry(now, ts) {
  const elapsed = Math.max(0.04, ts.fractionElapsed);
  const remaining = Math.max(0.04, 1 - ts.fractionElapsed);
  // Elapsed time compresses: it never takes more than 40% of the track.
  const elapsedGrow = Math.min(elapsed, 0.4) * 10;
  const remainingGrow = remaining * 10 + (elapsed > 0.4 ? (elapsed - 0.4) * 4 : 0);

  const elapsedEl = el('div', { class: 'geo-elapsed', style: `flex-grow:${elapsedGrow};` });
  const remainingEl = el('div', { class: 'geo-remaining', style: `flex-grow:${remainingGrow};` });

  // Landmarks: hard commitments still ahead of now.
  const total = minutesBetween(now, ts.workEnd) || 1;
  for (const c of ts.commitmentsToday) {
    const d = toDate(c.scheduledFor);
    if (d <= now) continue;
    const pos = Math.min(0.97, minutesBetween(now, d) / total);
    remainingEl.append(el('span', {
      class: 'geo-landmark',
      style: `left:${(pos * 100).toFixed(1)}%;`,
      title: `${fmtTime(d)} ${c.title}`,
    }));
  }

  return el('div', { class: 'day-geometry', 'aria-hidden': 'true' },
    el('div', { class: 'geo-track' }, elapsedEl, el('div', { class: 'geo-now' }), remainingEl),
    el('div', { class: 'geo-labels' },
      el('span', { text: 'earlier today' }),
      el('span', { text: now >= ts.workEnd ? 'day over' : `until ${fmtTime(ts.workEnd)}` }),
    ),
  );
}

// ================= past helpers =================

function trailLabel(t) {
  switch (t.kind) {
    case 'decision': return `Decided: ${t.title}`;
    case 'unblocked': return `Unblocked: ${t.title}`;
    case 'response': return `Reply received: ${t.title}`;
    default: return t.title;
  }
}

function summarizeYesterday(trail, now) {
  const y = addDays(startOfDay(now), -1);
  const events = trail.filter((t) => MOVE_KINDS.includes(t.kind) && isSameDay(new Date(t.at), y));
  if (!events.length) return null;
  const decisions = events.filter((t) => t.kind === 'decision').length;
  const unblocked = events.filter((t) => t.kind === 'unblocked').length;
  const parts = [`${events.length} meaningful move${events.length > 1 ? 's' : ''}`];
  if (decisions) parts.push(`${decisions} decision${decisions > 1 ? 's' : ''}`);
  if (unblocked) parts.push(`${unblocked} blocker${unblocked > 1 ? 's' : ''} cleared`);
  return parts.join(' · ');
}

function summarizeEarlierWeek(trail, now) {
  const from = addDays(startOfDay(now), -6);
  const to = addDays(startOfDay(now), -1);
  const events = trail.filter((t) => {
    const d = new Date(t.at);
    return MOVE_KINDS.includes(t.kind) && d >= from && d < to;
  });
  if (events.length < 2) return null;
  const projects = new Set(events.map((e) => e.project).filter(Boolean)).size;
  return `${events.length} moves${projects > 1 ? ` across ${projects} projects` : ''}`;
}

// ================= recommendation =================

const KICKER = {
  week_opening: 'First move of the week',
  morning_orientation: 'First useful move',
  active_work: 'What needs you now',
  midday_recalibration: 'Best next move',
  afternoon_compression: 'One more move fits',
  day_shutdown: 'One open loop',
  week_convergence: 'Still needs to happen this week',
  week_closure: 'Before the week closes',
};

function renderRecommendation(primary, ts, { onBegin, onEdit }) {
  const a = primary.action;
  const mins = actionMinutes(a);
  const hint = unshapedHint(a);
  const block = el('div', { class: 'now-block' },
    el('p', { class: 'rec-kicker', text: KICKER[ts.id] || 'What needs you now' }),
    el('h2', { class: 'rec-title' },
      el('button', {
        class: 'title-btn',
        text: a.title,
        title: 'Shape this action',
        onclick: () => onEdit(a),
      }),
    ),
    el('p', { class: 'rec-meta' },
      el('span', { text: a.estimateMinutes != null ? `≈ ${fmtDuration(mins)}` : 'duration?' }),
      a.project && el('span', { text: a.project }),
      el('span', { text: TYPE_LABEL[a.type] }),
      a.sourceRef?.url && el('a', { href: a.sourceRef.url, target: '_blank', rel: 'noopener', text: a.sourceRef.label || a.sourceRef.type }),
      hint && el('span', { class: 'unshaped-cue', text: hint }),
    ),
    el('p', { class: 'rec-why', text: primary.reasons.join(' ') }),
    a.definitionOfDone && el('p', { class: 'rec-dod', text: `Done when: ${a.definitionOfDone}` }),
  );

  const actionsRow = el('div', { class: 'rec-actions' },
    el('button', { class: 'begin-btn', text: 'Begin', onclick: () => onBegin(a) }),
    el('button', { class: 'act-btn', text: 'Done', title: 'Already handled', onclick: () => completeFlow(a, block) }),
    el('button', { class: 'act-btn', text: 'Later', onclick: () => snoozeFlow(a, block) }),
    el('button', { class: 'act-btn', text: 'Waiting…', onclick: () => waitingFlow(a, block) }),
    el('button', { class: 'link-btn', text: 'Shape', onclick: () => onEdit(a) }),
  );
  block.append(actionsRow);
  return block;
}

function renderAlternatives(alternatives, onBegin) {
  const wrap = el('div', { class: 'alternatives' },
    el('p', { class: 'alt-label', text: 'Also reasonable' }));
  for (const alt of alternatives) {
    wrap.append(
      el('div', { class: 'alt-row' },
        el('button', { class: 'alt-pick', text: alt.action.title, onclick: () => onBegin(alt.action) }),
        alt.reasons[0] && el('span', { class: 'alt-why', text: alt.reasons[0] }),
      ),
    );
  }
  return wrap;
}

function renderClearState(ts, { onCapture, onGotoView }) {
  let line = 'Nothing needs you right now.';
  let sub = '';
  if (ts.nextCommitment) {
    sub = `You’re clear until ${fmtTime(toDate(ts.nextCommitment.scheduledFor))} — ${ts.nextCommitment.title}.`;
  } else if (ts.id === 'day_shutdown') {
    line = 'Nothing else needs to be started today.';
  } else if (ts.isWeekend) {
    line = 'Nothing here needs you.';
    sub = 'Enjoy the weekend.';
  } else {
    sub = 'No follow-ups are currently due.';
  }
  return el('div', { class: 'clear-state' },
    el('p', { class: 'clear-line', text: line }),
    sub && el('p', { class: 'clear-sub', text: sub }),
    el('div', { class: 'clear-actions' },
      el('button', { class: 'link-btn', text: 'Capture something', onclick: onCapture }),
      el('button', { class: 'link-btn', text: 'Look at the week', onclick: () => onGotoView('week') }),
    ),
  );
}

// ================= future =================

function upcomingToday(actions, now, excludeIds) {
  return actions
    .filter((a) => isOpen(a) && !['waiting', 'blocked'].includes(a.status))
    .filter((a) => a.hard || !excludeIds.has(a.id))
    .filter((a) => {
      const d = toDate(a.scheduledFor);
      return d && isSameDay(d, now) && d > now;
    })
    .sort((a, b) => a.scheduledFor.localeCompare(b.scheduledFor))
    .slice(0, 6);
}

function laterItems(actions, now, excludeIds) {
  const tomorrow = startOfDay(addDays(now, 1));
  const horizon = addDays(tomorrow, 7);
  return actions
    .filter((a) => isOpen(a) && !['waiting', 'blocked'].includes(a.status) && !excludeIds.has(a.id))
    .filter((a) => {
      const d = toDate(a.scheduledFor) || toDate(a.dueAt);
      return d && d >= tomorrow && d < horizon;
    })
    .sort((a, b) => (a.scheduledFor || a.dueAt).localeCompare(b.scheduledFor || b.dueAt))
    .slice(0, 3);
}

function renderUpcomingRow(a, now, { onBegin, onEdit }) {
  const d = toDate(a.scheduledFor);
  const r = el('div', { class: 'spine-row upcoming' },
    el('div', { class: 'spine-time', text: fmtTime(d) }),
    el('div', { class: 'spine-body' },
      a.hard && el('span', { class: 'commit-mark', 'aria-hidden': 'true' }),
      el('span', { text: a.title }),
    ),
  );
  if (!a.hard) {
    r.querySelector('.spine-body').append(rowActions(a, r, { onBegin, onEdit }));
  } else {
    r.querySelector('.spine-body').append(
      el('span', { class: 'row-actions' },
        el('button', { text: 'Shape', onclick: () => onEdit(a) })),
    );
  }
  return r;
}

function renderLaterRow(a, now, { onBegin, onEdit }) {
  const d = toDate(a.scheduledFor) || toDate(a.dueAt);
  const r = el('div', { class: 'spine-row later' },
    el('div', { class: 'spine-time', text: fmtWhen(d, now) }),
    el('div', { class: 'spine-body' }, el('span', { text: a.title })),
  );
  r.querySelector('.spine-body').append(rowActions(a, r, { onBegin, onEdit }));
  return r;
}

function rowActions(a, rowNode, { onBegin, onEdit }) {
  const hint = unshapedHint(a);
  return el('span', { class: 'row-actions' },
    hint && el('span', { class: 'unshaped-cue', text: hint }),
    el('button', { text: 'Begin', onclick: () => onBegin(a) }),
    el('button', { text: 'Done', onclick: () => completeFlow(a, rowNode) }),
    el('button', { text: 'Later', onclick: () => snoozeFlow(a, rowNode) }),
    el('button', { text: 'Shape', onclick: () => onEdit(a) }),
  );
}
