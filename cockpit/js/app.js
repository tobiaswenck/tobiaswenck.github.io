// Application orchestrator: routing, chrome, banners, reminder scheduling,
// resumption, onboarding. Business rules live in the engines; rendering in
// the view modules.

import * as store from './store.js';
import { deriveTimeState } from './timestate.js';
import { computeMomentum } from './momentum.js';
import { recommend } from './recommend.js';
import { collectDue, collectFollowUpsDue } from './reminders.js';
import { exportJSON, importJSON } from './importexport.js';
import { buildDemoData } from './data.js';
import { el, announce, toast, openDialog } from './ui/dom.js';
import { renderNow } from './ui/now.js';
import { renderWeek } from './ui/week.js';
import { renderWaiting } from './ui/waiting.js';
import { renderReset, resetCandidates } from './ui/reset.js';
import { openCapture, openInboxReview } from './ui/capture.js';
import { openShaper, openBeginGate } from './ui/shaper.js';
import { openFocus, restoreFocus, isFocusing } from './ui/focus.js';
import { isSameDay, weekKey, toDate, HOUR } from './timeutil.js';

let currentView = 'now';
const viewEl = document.getElementById('view');
const bannersEl = document.getElementById('banners');

// ---------- context ----------

function buildCtx() {
  const now = new Date();
  const state = store.getState();
  const timeState = deriveTimeState({
    now,
    actions: state.actions,
    trail: state.trail,
    session: state.session,
    settings: state.settings,
  });
  const momentum = computeMomentum(state.actions, state.trail, now, { quietDays: state.settings.quietDays });

  const todayMoves = state.trail.filter((t) => ['completed', 'decision', 'unblocked', 'response'].includes(t.kind) && isSameDay(new Date(t.at), now) && t.project);
  const lastCompletedProject = todayMoves.length ? todayMoves[todayMoves.length - 1].project : null;

  const recommendation = recommend({
    actions: state.actions,
    now,
    timeState,
    momentum,
    lastCompletedProject,
    activeSessionActionId: state.session?.actionId || null,
  });

  return {
    now, timeState, momentum, recommendation,
    onBegin: beginAction,
    onEdit: (a) => openShaper(a),
    onCapture: () => openCapture({ onEdit: openShaper }),
    onGotoView: gotoView,
  };
}

function beginAction(action) {
  openBeginGate(action, {
    onContinue: (shaped) => openFocus(shaped || action, { onClose: () => render() }),
  });
}

// ---------- rendering ----------

function render() {
  if (!store.getState().loaded) return;
  updateCounts();
  if (isFocusing()) return;

  if (!store.getState().onboarded && store.getState().actions.length === 0) {
    renderOnboarding();
    return;
  }

  const ctx = buildCtx();
  if (currentView === 'now') renderNow(viewEl, ctx);
  else if (currentView === 'week') renderWeek(viewEl, ctx);
  else if (currentView === 'waiting') renderWaiting(viewEl, ctx);
  else if (currentView === 'reset') renderReset(viewEl, ctx);
}

function gotoView(view) {
  currentView = view;
  for (const btn of document.querySelectorAll('.view-nav button')) {
    if (btn.dataset.view === view) btn.setAttribute('aria-current', 'page');
    else btn.removeAttribute('aria-current');
  }
  render();
  viewEl.focus({ preventScroll: true });
}

function updateCounts() {
  const { actions } = store.getState();
  const now = new Date();
  setCount('waiting-count', actions.filter((a) => a.status === 'waiting').length);
  setCount('reset-count', resetCandidates(now).length);
  setCount('inbox-count', actions.filter((a) => a.status === 'inbox').length);
  document.querySelector('[data-menu="remove-demo"]').hidden = !store.hasDemoData();
}

function setCount(id, n) {
  const node = document.getElementById(id);
  node.hidden = n === 0;
  node.textContent = n > 9 ? '9+' : String(n);
}

// ---------- onboarding ----------

function renderOnboarding() {
  viewEl.replaceChildren(
    el('div', { class: 'onboard' },
      el('h2', { text: 'This is not another task list.' }),
      el('p', { text: 'Linear, Docmost and Canny stay the systems of record. This page sits above them and answers one question: what deserves your attention right now?' }),
      el('p', { text: 'It follows the day with you — mornings orient, middays recalibrate, evenings close. Completed work leaves a trail instead of disappearing.' }),
      el('p', { text: 'Capture with Ctrl+K. Only a title is needed; everything else can come later.' }),
      el('div', { class: 'onboard-actions' },
        el('button', {
          class: 'act-btn primary', text: 'Start empty',
          onclick: async () => { await store.setOnboarded(); announce('Ready.'); render(); },
        }),
        el('button', {
          class: 'act-btn', text: 'Look around with example data',
          onclick: async () => {
            const { actions, trail } = buildDemoData(new Date());
            for (const a of actions) await store.addAction(a);
            for (const t of trail) { store.getState().trail.push(t); await import('./db.js').then((db) => db.put('trail', t)); }
            store.getState().trail.sort((a, b) => a.at.localeCompare(b.at));
            await store.setOnboarded();
            announce('Example data loaded. Remove it any time from the menu.');
            render();
          },
        }),
      ),
    ),
  );
}

// ---------- banners ----------

function addBanner(kind, title, bodyNode, actions = [], { dismissible = true, onDismiss = null } = {}) {
  const banner = el('div', { class: `banner ${kind}` },
    el('div', { class: 'banner-title' },
      el('span', { text: title }),
      dismissible && el('button', {
        class: 'link-btn', text: 'dismiss',
        onclick: () => {
          banner.classList.add('leaving');
          setTimeout(() => banner.remove(), 260);
          onDismiss && onDismiss();
        },
      }),
    ),
    el('div', { class: 'banner-body' }, bodyNode),
    actions.length ? el('div', { class: 'banner-actions' }, actions) : null,
  );
  bannersEl.append(banner);
  return banner;
}

function showFridayNoteBanner() {
  const note = store.getState().fridayNote;
  const now = new Date();
  if (!note || !note.text || note.dismissed) return;
  if (note.weekKey === weekKey(now)) return; // still the same week — visible in Week view
  addBanner('friday', 'Message from Friday-you', el('p', { text: note.text }), [], {
    onDismiss: () => store.saveFridayNote({ ...note, dismissed: true }),
  });
}

function showSinceBanner() {
  const state = store.getState();
  const now = new Date();
  const last = toDate(state.lastSeenAt);
  if (!last || (now - last) < 3 * HOUR) return;

  const lines = [];
  for (const a of state.actions) {
    if (a.status === 'done' || a.status === 'dropped') continue;
    const follow = toDate(a.followUpAt);
    if (a.status === 'waiting' && follow && follow > last && follow <= now) {
      lines.push(`Follow-up on “${a.title}” is now relevant${a.waitingFor ? ` (${a.waitingFor})` : ''}.`);
    }
    const snooze = toDate(a.snoozedUntil);
    if (snooze && snooze > last && snooze <= now) {
      lines.push(`“${a.title}” is back from snooze.`);
    }
    const sched = toDate(a.scheduledFor);
    if (!a.hard && sched && sched > last && sched <= now) {
      lines.push(`“${a.title}” was planned for this window.`);
    }
  }
  if (!lines.length) return;
  addBanner('since', 'Since you were last here',
    el('ul', {}, lines.slice(0, 4).map((t) => el('li', { text: t }))));
}

function showDemoBanner() {
  if (!store.hasDemoData()) return;
  const banner = addBanner('demo', 'Example data',
    el('p', { text: 'Everything below is illustrative — nothing here is yours yet.' }),
    [el('button', {
      class: 'act-btn', text: 'Remove example data',
      onclick: async () => {
        await store.removeDemoData();
        banner.remove();
        announce('Example data removed.');
      },
    })], { dismissible: true });
}

// ---------- reminders ----------

const shownReminders = new Set();

function checkReminders({ includeOnOpen = false } = {}) {
  const now = new Date();
  const state = store.getState();
  const due = collectDue(state.actions, now, { includeOnOpen });

  for (const { action, rule } of due) {
    if (shownReminders.has(rule.id)) continue;
    shownReminders.add(rule.id);
    fireReminder(action, rule, now);
  }

  // Follow-ups that just became due surface once per session too.
  for (const a of collectFollowUpsDue(state.actions, now)) {
    const key = `fu_${a.id}_${a.followUpAt}`;
    if (shownReminders.has(key)) continue;
    shownReminders.add(key);
    fireFollowUpReminder(a);
  }
}

async function fireReminder(action, rule, now) {
  rule.firedAt = now.toISOString();
  await store.updateAction(action.id, { reminderRules: action.reminderRules }, { silent: true });

  const settings = store.getState().settings;
  if (settings.systemNotifications && 'Notification' in window && Notification.permission === 'granted') {
    try { new Notification('Cockpit', { body: action.title }); } catch { /* tab-only context */ }
  }

  const banner = addBanner('reminder', 'This wanted your attention',
    el('p', { text: action.title }),
    [
      el('button', { class: 'act-btn primary', text: 'Start', onclick: () => { banner.remove(); beginAction(action); } }),
      el('button', {
        class: 'act-btn', text: 'Snooze 1 h',
        onclick: async () => {
          action.reminderRules.push({ id: `${rule.id}_s`, preset: 'later_today', at: new Date(Date.now() + HOUR).toISOString(), firedAt: null });
          await store.updateAction(action.id, { reminderRules: action.reminderRules }, { silent: true });
          banner.remove();
          announce('Snoozed for an hour.');
        },
      }),
      el('button', {
        class: 'act-btn', text: 'Complete',
        onclick: async () => { banner.remove(); await store.completeAction(action.id); announce('That’s handled.'); },
      }),
      action.sourceRef?.url && el('a', { class: 'act-btn', style: 'text-decoration:none;', href: action.sourceRef.url, target: '_blank', rel: 'noopener', text: 'Open source ↗' }),
    ].filter(Boolean),
  );
  announce(`Reminder: ${action.title}`);
}

function fireFollowUpReminder(action) {
  const banner = addBanner('reminder', 'Follow-up is due',
    el('p', { text: `${action.title}${action.waitingFor ? ` — waiting on ${action.waitingFor}` : ''}` }),
    [
      el('button', { class: 'act-btn primary', text: 'Follow up now', onclick: () => { banner.remove(); beginAction(action); } }),
      el('button', {
        class: 'act-btn', text: 'Response received',
        onclick: async () => { banner.remove(); await store.responseReceived(action.id); },
      }),
      el('button', { class: 'act-btn', text: 'See Waiting', onclick: () => { banner.remove(); gotoView('waiting'); } }),
    ],
  );
}

// ---------- settings ----------

function openSettings() {
  const s = store.getState().settings;
  openDialog({
    title: 'Settings',
    build(dialog, close) {
      const workStart = el('input', { type: 'time', value: s.workStart });
      const workEnd = el('input', { type: 'time', value: s.workEnd });
      const capacity = el('input', { type: 'number', min: '30', step: '30', value: s.dailyCapacityMinutes });
      const quiet = el('input', { type: 'number', min: '1', value: s.quietDays });
      const stale = el('input', { type: 'number', min: '1', value: s.staleDays });
      const notif = el('input', { type: 'checkbox', checked: s.systemNotifications, id: 'set-notif', style: 'width:auto; margin-right:8px;' });

      dialog.append(
        el('div', { class: 'field-grid' },
          fieldRow('Workday starts', workStart),
          fieldRow('Workday ends', workEnd),
          fieldRow('Realistic focus capacity per day (min)', capacity),
          fieldRow('A project is “quiet” after (days)', quiet),
          fieldRow('An action is stale after (days)', stale),
        ),
        el('div', { class: 'field-row' },
          el('label', { for: 'set-notif', style: 'display:flex; align-items:center; cursor:pointer; color: var(--text-2); font-size: 13px;' },
            notif, 'System notifications while this page is open'),
          el('p', { class: 'field-hint', text: 'Honest limitation: browser reminders cannot fire reliably while this page is closed. That would need server-backed push, a calendar entry, or a desktop runtime.' }),
        ),
        el('div', { class: 'dialog-footer' },
          el('button', { class: 'act-btn', text: 'Cancel', onclick: () => close() }),
          el('button', {
            class: 'act-btn primary', text: 'Save',
            onclick: async () => {
              if (notif.checked && 'Notification' in window && Notification.permission === 'default') {
                await Notification.requestPermission();
              }
              await store.saveSettings({
                workStart: workStart.value || '08:30',
                workEnd: workEnd.value || '17:30',
                dailyCapacityMinutes: Number(capacity.value) || 300,
                quietDays: Number(quiet.value) || 5,
                staleDays: Number(stale.value) || 7,
                systemNotifications: notif.checked && (!('Notification' in window) || Notification.permission === 'granted'),
              });
              announce('Settings saved.');
              close();
            },
          }),
        ),
      );
    },
  });

  function fieldRow(label, control) {
    return el('div', { class: 'field-row' }, el('label', { text: label }), control);
  }
}

// ---------- chrome wiring ----------

function wireChrome() {
  for (const btn of document.querySelectorAll('.view-nav button')) {
    btn.addEventListener('click', () => gotoView(btn.dataset.view));
  }

  document.getElementById('capture-btn').addEventListener('click', () => openCapture({ onEdit: openShaper }));

  const menuBtn = document.getElementById('menu-btn');
  const menu = document.getElementById('menu');
  menuBtn.addEventListener('click', () => {
    const open = menu.hidden;
    menu.hidden = !open;
    menuBtn.setAttribute('aria-expanded', String(open));
    if (open) menu.querySelector('button').focus();
  });
  document.addEventListener('click', (e) => {
    if (!menu.hidden && !menu.contains(e.target) && e.target !== menuBtn && !menuBtn.contains(e.target)) {
      menu.hidden = true;
      menuBtn.setAttribute('aria-expanded', 'false');
    }
  });
  menu.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { menu.hidden = true; menuBtn.setAttribute('aria-expanded', 'false'); menuBtn.focus(); }
  });

  menu.addEventListener('click', async (e) => {
    const item = e.target.closest('[data-menu]');
    if (!item) return;
    menu.hidden = true;
    menuBtn.setAttribute('aria-expanded', 'false');
    switch (item.dataset.menu) {
      case 'inbox': openInboxReview({ onEdit: openShaper }); break;
      case 'export': exportJSON(); announce('Export downloaded.'); break;
      case 'import': document.getElementById('import-file').click(); break;
      case 'settings': openSettings(); break;
      case 'remove-demo':
        await store.removeDemoData();
        document.querySelector('.banner.demo')?.remove();
        announce('Example data removed.');
        break;
    }
  });

  document.getElementById('import-file').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    e.target.value = '';
    if (!file) return;
    openDialog({
      title: 'Import data',
      hint: `Import “${file.name}” — merge with what’s here, or replace everything?`,
      build(dialog, close) {
        dialog.append(el('div', { class: 'dialog-footer' },
          el('button', { class: 'act-btn', text: 'Cancel', onclick: () => close() }),
          el('button', { class: 'act-btn', text: 'Merge', onclick: () => close('merge') }),
          el('button', { class: 'act-btn danger', text: 'Replace everything', onclick: () => close('replace') }),
        ));
      },
      onClose: async (mode) => {
        if (!mode) return;
        try {
          const { count } = await importJSON(file, mode);
          toast(`Imported ${count} actions (${mode}).`);
          announce('Import complete.');
        } catch (err) {
          toast(err.message || 'Import failed.');
        }
      },
    });
  });

  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      openCapture({ onEdit: openShaper });
    }
  });
}

// ---------- boot ----------

async function boot() {
  await store.load();
  wireChrome();

  store.subscribe((reason) => {
    // Typing flows persist quietly; re-rendering mid-keystroke would eat the field.
    if (reason === 'fridayNote') return;
    render();
  });

  showDemoBanner();
  showFridayNoteBanner();
  showSinceBanner();

  render();

  // Restore an interrupted focus session — the app resumes, it doesn't reset.
  const resumed = await restoreFocus({ onClose: () => render() });
  if (resumed) announce('Resuming your focus session.');

  checkReminders({ includeOnOpen: true });
  setInterval(() => checkReminders(), 30 * 1000);

  // The composition follows the clock.
  setInterval(() => {
    if (isFocusing()) return;
    if (document.querySelector('.dialog-backdrop')) return;
    const ae = document.activeElement;
    if (ae && viewEl.contains(ae) && ['INPUT', 'TEXTAREA', 'SELECT'].includes(ae.tagName)) return;
    render();
  }, 60 * 1000);

  await store.saveLastSeen();
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') store.saveLastSeen();
  });
  setInterval(() => store.saveLastSeen(), 2 * 60 * 1000);
}

boot();
