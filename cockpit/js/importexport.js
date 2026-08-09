// JSON export and import with schema versioning.

import { SCHEMA_VERSION } from './model.js';
import * as store from './store.js';

export function exportJSON() {
  const state = store.getState();
  const payload = {
    app: 'execution-cockpit',
    schemaVersion: SCHEMA_VERSION,
    exportedAt: new Date().toISOString(),
    settings: state.settings,
    fridayNote: state.fridayNote,
    actions: state.actions,
    trail: state.trail,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `cockpit-export-${payload.exportedAt.slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// mode: 'replace' | 'merge'
export async function importJSON(file, mode) {
  const text = await file.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error('That file is not valid JSON.');
  }
  if (data.app !== 'execution-cockpit' || !Array.isArray(data.actions)) {
    throw new Error('That file does not look like a Cockpit export.');
  }
  if (data.schemaVersion > SCHEMA_VERSION) {
    throw new Error(`This export uses schema v${data.schemaVersion}; this app understands up to v${SCHEMA_VERSION}.`);
  }
  // Future migrations would run here, keyed on data.schemaVersion.
  if (mode === 'replace') {
    await store.replaceAll({
      actions: data.actions,
      trail: data.trail || [],
      settings: data.settings || null,
      fridayNote: data.fridayNote ?? null,
    });
  } else {
    await store.mergeAll({ actions: data.actions, trail: data.trail || [] });
  }
  return { count: data.actions.length };
}
