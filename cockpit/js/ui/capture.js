// Quick capture (Ctrl/Cmd+K): raw text in, inbox item out. Nothing else
// is required — a thought is not automatically a commitment.

import * as store from '../store.js';
import { el, openDialog, announce } from './dom.js';
import { scheduleFlow, dropFlow } from './flows.js';

let captureOpen = false;

export function openCapture({ onEdit } = {}) {
  if (captureOpen) return;
  captureOpen = true;

  openDialog({
    className: 'capture-dialog',
    labelledBy: null,
    build(dialog, close) {
      const input = el('input', {
        class: 'capture-input',
        type: 'text',
        placeholder: 'What came up?',
        'aria-label': 'Capture a thought',
        'data-autofocus': '',
      });
      const url = el('input', { type: 'url', placeholder: 'Link (optional — Linear, Docmost, Canny…)', 'aria-label': 'Source link' });
      const confirm = el('p', { class: 'capture-confirm', role: 'status' });

      async function save() {
        const title = input.value.trim();
        if (!title) return;
        const sourceRef = url.value.trim()
          ? { type: guessSource(url.value), externalId: null, url: url.value.trim(), label: guessSource(url.value) }
          : null;
        await store.addAction({ title, status: 'inbox', sourceRef });
        input.value = '';
        url.value = '';
        confirm.textContent = `“${shorten(title)}” landed in the inbox.`;
        announce('Captured to inbox.');
        input.focus();
      }

      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); save(); }
      });
      url.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); save(); }
      });

      dialog.append(
        input,
        el('div', { class: 'capture-extra' }, url),
        confirm,
        el('div', { class: 'capture-footer' },
          el('span', {}, el('span', { class: 'kbd', text: 'Enter' }), ' saves · ', el('span', { class: 'kbd', text: 'Esc' }), ' closes'),
          el('span', { text: 'Inbox, not obligation.' }),
        ),
      );
    },
    onClose: () => { captureOpen = false; },
  });
}

function guessSource(u) {
  try {
    const host = new URL(u).hostname;
    if (host.includes('linear')) return 'linear';
    if (host.includes('docmost')) return 'docmost';
    if (host.includes('canny')) return 'canny';
    return 'other';
  } catch { return 'other'; }
}

function shorten(s) {
  return s.length > 48 ? `${s.slice(0, 48)}…` : s;
}

// ---------- inbox review (from the menu) ----------

export function openInboxReview({ onEdit }) {
  openDialog({
    title: 'Inbox',
    hint: 'Raw thoughts. Decide what each one becomes — or let Reset walk you through them.',
    build(dialog, close) {
      const items = store.getState().actions.filter((a) => a.status === 'inbox');
      if (!items.length) {
        dialog.append(el('p', { style: 'color: var(--muted); font-size: 13px;', text: 'Inbox is empty.' }));
      }
      for (const a of items) {
        const row = el('div', { class: 'inbox-row' },
          el('span', { class: 'title', text: a.title }),
          el('span', { class: 'actions' },
            el('button', {
              class: 'act-btn', text: 'Ready',
              title: 'Make it an actionable item',
              onclick: async () => { await store.updateAction(a.id, { status: 'ready' }, { undoLabel: 'Made ready' }); row.remove(); },
            }),
            el('button', { class: 'act-btn', text: 'Schedule…', onclick: () => { close(); scheduleFlow(a); } }),
            el('button', { class: 'act-btn', text: 'Edit', onclick: () => { close(); onEdit(a); } }),
            el('button', { class: 'act-btn danger', text: 'Drop', onclick: () => dropFlow(a, row) }),
          ),
        );
        dialog.append(row);
      }
      dialog.append(el('div', { class: 'dialog-footer' },
        el('button', { class: 'act-btn', text: 'Close', onclick: () => close() })));
    },
  });
}
