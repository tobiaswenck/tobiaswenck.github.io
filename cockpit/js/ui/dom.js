// Shared DOM utilities: element builder, dialogs, toasts with undo,
// screen-reader announcements, leave animations.

export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k === 'html') node.innerHTML = v;
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (k in node && typeof v === 'boolean') node[k] = v;
    else node.setAttribute(k, v);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    node.append(child.nodeType ? child : document.createTextNode(child));
  }
  return node;
}

export function esc(s) {
  const d = document.createElement('div');
  d.textContent = s ?? '';
  return d.innerHTML;
}

export function announce(text) {
  const region = document.getElementById('live-region');
  if (!region) return;
  region.textContent = '';
  requestAnimationFrame(() => { region.textContent = text; });
}

export function reducedMotion() {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

// Animate a row out of the composition in a direction that explains where
// it went (up = into the past, down = into the future, side = out of the
// active stream), then run the state change.
export function leaveThen(node, direction, done) {
  if (!node || reducedMotion()) { done(); return; }
  node.classList.add(`leaving-${direction}`);
  let called = false;
  const finish = () => { if (!called) { called = true; done(); } };
  node.addEventListener('transitionend', finish, { once: true });
  setTimeout(finish, 420);
}

// ---------- toasts / undo ----------

let toastRegion = null;
function ensureToastRegion() {
  if (!toastRegion) {
    toastRegion = el('div', { id: 'toast-region' });
    document.body.append(toastRegion);
  }
  return toastRegion;
}

export function toast(message, { undoText = null, onUndo = null, duration = 6000 } = {}) {
  const region = ensureToastRegion();
  const node = el('div', { class: 'toast', role: 'status' },
    el('span', { text: message }),
    undoText && el('button', {
      class: 'undo',
      text: undoText,
      onclick: () => { dismiss(); onUndo && onUndo(); },
    }),
  );
  region.append(node);
  let timer = setTimeout(dismiss, duration);
  function dismiss() {
    clearTimeout(timer);
    node.classList.add('leaving');
    setTimeout(() => node.remove(), 300);
  }
  return dismiss;
}

// ---------- dialogs ----------

const openDialogs = [];

export function openDialog({ title = '', hint = '', className = '', build, onClose = null, labelledBy = null }) {
  const previousFocus = document.activeElement;
  const backdrop = el('div', { class: 'dialog-backdrop' });
  const titleId = `dlg_${Math.random().toString(36).slice(2, 8)}`;
  const dialog = el('div', {
    class: `dialog ${className}`,
    role: 'dialog',
    'aria-modal': 'true',
    'aria-labelledby': labelledBy || (title ? titleId : null),
  });

  if (title) dialog.append(el('h2', { id: titleId, text: title }));
  if (hint) dialog.append(el('p', { class: 'dialog-hint', text: hint }));

  function close(result) {
    const idx = openDialogs.indexOf(entry);
    if (idx >= 0) openDialogs.splice(idx, 1);
    backdrop.remove();
    document.removeEventListener('keydown', onKey, true);
    if (previousFocus && previousFocus.focus) previousFocus.focus();
    onClose && onClose(result);
  }

  const entry = { close };
  openDialogs.push(entry);

  function onKey(e) {
    if (openDialogs[openDialogs.length - 1] !== entry) return;
    if (e.key === 'Escape') {
      e.stopPropagation();
      close(null);
    } else if (e.key === 'Tab') {
      // Keep focus inside the dialog.
      const focusables = dialog.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      if (!focusables.length) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  }

  document.addEventListener('keydown', onKey, true);
  backdrop.addEventListener('mousedown', (e) => { if (e.target === backdrop) close(null); });

  build(dialog, close);
  backdrop.append(dialog);
  document.getElementById('overlays').append(backdrop);

  const auto = dialog.querySelector('[data-autofocus]') || dialog.querySelector('input, textarea, select, button');
  if (auto) auto.focus();

  return close;
}

export function confirmDialog(message, { confirmText = 'Confirm', danger = false } = {}) {
  return new Promise((resolve) => {
    openDialog({
      title: message,
      build(dialog, close) {
        dialog.append(
          el('div', { class: 'dialog-footer' },
            el('button', { class: 'act-btn', text: 'Cancel', onclick: () => close(false) }),
            el('button', {
              class: `act-btn ${danger ? 'danger' : 'primary'}`,
              text: confirmText,
              'data-autofocus': '',
              onclick: () => close(true),
            }),
          ),
        );
      },
      onClose: (result) => resolve(!!result),
    });
  });
}
