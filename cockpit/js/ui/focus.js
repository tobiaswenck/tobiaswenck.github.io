// Focus mode: the chosen action expands into a quiet workspace while the
// rest of the app recedes. State survives reloads (resumption cue included).

import * as store from '../store.js';
import { el, announce, toast } from './dom.js';
import { completeFlow, blockFlow } from './flows.js';
import { fmtTime, fmtDuration, fmtAgo } from '../timeutil.js';

let layer = null;
let tickInterval = null;
let clockInterval = null;

function newSession(action) {
  return {
    actionId: action.id,
    startedAt: new Date().toISOString(),
    note: action.lastSessionNote || '',
    parked: [],
    timer: null, // { durationSec, startedAt, pausedRemaining, running }
    savedAt: new Date().toISOString(),
  };
}

async function persist(session) {
  session.savedAt = new Date().toISOString();
  await store.saveSession(session);
}

export function isFocusing() {
  return !!layer;
}

// Returns true if there is a saved session to resume.
export function hasSavedSession() {
  const s = store.getState().session;
  if (!s) return false;
  const a = store.getAction(s.actionId);
  return !!(a && a.status !== 'done' && a.status !== 'dropped');
}

export async function restoreFocus({ onClose }) {
  const s = store.getState().session;
  if (!hasSavedSession()) { if (s) await store.saveSession(null); return false; }
  const action = store.getAction(s.actionId);
  openFocus(action, { onClose, resume: true, session: s });
  return true;
}

export async function openFocus(action, { onClose, resume = false, session = null }) {
  closeFocusLayer();

  const sess = session || newSession(action);
  if (!resume) {
    if (action.status !== 'active') {
      await store.updateAction(action.id, { status: 'active' }, { silent: true });
    }
    await persist(sess);
  }

  document.body.classList.add('focusing');

  const clock = el('span', { class: 'fclock', text: fmtTime(new Date()) });
  const timeLeft = el('span', { class: 'time-left', text: '—' });
  const timerControls = el('span', { class: 'timer-controls' });

  const noteArea = el('textarea', {
    placeholder: 'Session note — where are you, what did you find?',
    'aria-label': 'Session note',
  });
  noteArea.value = sess.note || '';
  let noteTimer = null;
  noteArea.addEventListener('input', () => {
    sess.note = noteArea.value;
    clearTimeout(noteTimer);
    noteTimer = setTimeout(() => persist(sess), 400);
  });

  const parkedList = el('div', { class: 'parked-list' });
  const renderParked = () => {
    parkedList.replaceChildren();
    for (const p of sess.parked) {
      parkedList.append(el('div', { class: 'parked-item' },
        el('span', { class: 'tick', 'aria-hidden': 'true', text: '→' }),
        el('span', { text: `${p.text} · captured` })));
    }
  };
  renderParked();

  const parkInput = el('input', {
    type: 'text',
    placeholder: 'Something else came up? Park it here and stay on task.',
    'aria-label': 'Interruption parking lot',
  });
  parkInput.addEventListener('keydown', async (e) => {
    if (e.key === 'Enter' && parkInput.value.trim()) {
      const text = parkInput.value.trim();
      parkInput.value = '';
      await store.addAction({ title: text, status: 'inbox' });
      sess.parked.push({ text, at: new Date().toISOString() });
      await persist(sess);
      renderParked();
      announce('Parked in the inbox. Back to work.');
    }
  });

  // ---------- timer ----------

  function timerRemaining() {
    const t = sess.timer;
    if (!t) return null;
    if (!t.running) return t.pausedRemaining ?? t.durationSec;
    return Math.round(t.durationSec - (Date.now() - new Date(t.startedAt)) / 1000);
  }

  function renderTimer() {
    const t = sess.timer;
    timerControls.replaceChildren();
    if (!t) {
      timeLeft.textContent = '';
      timeLeft.classList.remove('overtime');
      const mins = action.estimateMinutes;
      timerControls.append(
        el('button', { class: 'act-btn', text: 'Start for 5 minutes', onclick: () => startTimer(5) }),
        el('button', { class: 'act-btn', text: '25 min', onclick: () => startTimer(25) }),
        mins && mins !== 25 && el('button', { class: 'act-btn', text: `≈ ${fmtDuration(mins)}`, onclick: () => startTimer(mins) }),
        el('span', { class: 'field-hint', style: 'align-self:center;', text: 'Timer is optional.' }),
      );
      return;
    }
    const rem = timerRemaining();
    const abs = Math.abs(rem);
    const mm = String(Math.floor(abs / 60)).padStart(2, '0');
    const ss = String(abs % 60).padStart(2, '0');
    timeLeft.textContent = `${rem < 0 ? '+' : ''}${mm}:${ss}`;
    timeLeft.classList.toggle('overtime', rem < 0);
    timerControls.append(
      t.running
        ? el('button', { class: 'act-btn', text: 'Pause', onclick: pauseTimer })
        : el('button', { class: 'act-btn', text: 'Resume', onclick: resumeTimer }),
      el('button', { class: 'act-btn', text: 'Clear', onclick: clearTimer }),
    );
  }

  async function startTimer(mins) {
    sess.timer = { durationSec: mins * 60, startedAt: new Date().toISOString(), pausedRemaining: null, running: true };
    await persist(sess);
    renderTimer();
  }
  async function pauseTimer() {
    if (!sess.timer) return;
    sess.timer.pausedRemaining = timerRemaining();
    sess.timer.running = false;
    await persist(sess);
    renderTimer();
  }
  async function resumeTimer() {
    if (!sess.timer) return;
    sess.timer.durationSec = sess.timer.pausedRemaining ?? sess.timer.durationSec;
    sess.timer.startedAt = new Date().toISOString();
    sess.timer.pausedRemaining = null;
    sess.timer.running = true;
    await persist(sess);
    renderTimer();
  }
  async function clearTimer() {
    sess.timer = null;
    await persist(sess);
    renderTimer();
  }

  // ---------- resumption cue ----------

  let resumeCue = null;
  if (resume) {
    const parts = ['Picking up where you left off'];
    const saved = new Date(sess.savedAt);
    parts[0] += ` (${fmtAgo(saved, new Date())}).`;
    if (sess.note) parts.push(`Last note: ${sess.note.length > 80 ? sess.note.slice(0, 80) + '…' : sess.note}`);
    const rem = sess.timer ? timerRemaining() : null;
    if (rem && rem > 0) parts.push(`${Math.round(rem / 60)} minutes remained on the timer.`);
    resumeCue = el('p', { class: 'focus-resume-cue', text: parts.join(' ') });
    if (sess.timer && sess.timer.running) {
      // A timer can't really run while the page is closed — pause it honestly.
      sess.timer.pausedRemaining = Math.max(0, timerRemaining());
      sess.timer.running = false;
    }
  }

  // ---------- exit paths ----------

  async function exitPreserving() {
    sess.note = noteArea.value;
    await persist(sess);
    await store.updateAction(action.id, { lastSessionNote: sess.note }, { silent: true });
    close(false);
    toast('Paused. This will be here when you come back.');
  }

  async function completeFromFocus() {
    await store.updateAction(action.id, { lastSessionNote: noteArea.value }, { silent: true });
    await store.saveSession(null);
    close(true);
    completeFlow(store.getAction(action.id), null, { askFollowUp: ['decide', 'delegate', 'followUp'].includes(action.type) });
  }

  async function blockFromFocus() {
    await store.updateAction(action.id, { lastSessionNote: noteArea.value }, { silent: true });
    await store.saveSession(null);
    close(true);
    blockFlow(store.getAction(action.id), null);
  }

  function close(clearSession) {
    closeFocusLayer();
    onClose && onClose(clearSession);
  }

  // ---------- layout ----------

  const stage = el('div', { class: 'focus-stage', role: 'dialog', 'aria-modal': 'true', 'aria-label': `Focus: ${action.title}` },
    el('div', { class: 'focus-topline' },
      el('span', { text: 'In focus' }),
      clock,
    ),
    resumeCue,
    el('h2', { class: 'focus-title', text: action.title }),
    el('div', { class: 'focus-meta' },
      action.project && el('span', { text: action.project }),
      action.estimateMinutes && el('span', { text: `≈ ${fmtDuration(action.estimateMinutes)}` }),
      action.sourceRef?.url && el('a', { href: action.sourceRef.url, target: '_blank', rel: 'noopener', text: `Open ${action.sourceRef.label || action.sourceRef.type} ↗` }),
    ),
    action.definitionOfDone && el('div', { class: 'focus-dod' },
      el('span', { class: 'dod-label', text: 'Done when' }),
      action.definitionOfDone,
    ),
    el('div', { class: 'focus-timer' }, timeLeft, timerControls),
    el('div', { class: 'focus-note' }, noteArea),
    el('div', { class: 'parking' }, parkInput, parkedList),
    el('div', { class: 'focus-actions' },
      el('button', { class: 'act-btn primary', text: 'Complete', onclick: completeFromFocus }),
      el('button', { class: 'act-btn', text: 'Blocked…', onclick: blockFromFocus }),
      el('span', { class: 'spacer' }),
      el('button', { class: 'act-btn', text: 'Step away', title: 'Exit and keep this session for later', onclick: exitPreserving }),
    ),
  );

  layer = el('div', { class: 'focus-layer' }, stage);
  layer.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { e.stopPropagation(); exitPreserving(); }
  });
  document.getElementById('overlays').append(layer);
  noteArea.focus();

  renderTimer();
  clockInterval = setInterval(() => { clock.textContent = fmtTime(new Date()); }, 15000);
  tickInterval = setInterval(() => { if (sess.timer) renderTimer(); }, 1000);
}

function closeFocusLayer() {
  if (layer) { layer.remove(); layer = null; }
  clearInterval(tickInterval);
  clearInterval(clockInterval);
  document.body.classList.remove('focusing');
}
