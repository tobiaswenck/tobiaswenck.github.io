// IndexedDB persistence with a versioned schema.
// Stores:
//   actions — ActionItem records, keyPath id
//   trail   — meaningful events (completions, decisions, blockers cleared...), keyPath id
//   meta    — settings, focus session, handoff notes, flags; keyPath key

const DB_NAME = 'execution-cockpit';
const DB_VERSION = 1;

let dbPromise = null;

export function openDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = req.result;
      // Migration switch — extend per-version when the schema grows.
      if (e.oldVersion < 1) {
        const actions = db.createObjectStore('actions', { keyPath: 'id' });
        actions.createIndex('status', 'status');
        actions.createIndex('project', 'project');
        actions.createIndex('updatedAt', 'updatedAt');
        const trail = db.createObjectStore('trail', { keyPath: 'id' });
        trail.createIndex('at', 'at');
        db.createObjectStore('meta', { keyPath: 'key' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}

function tx(db, store, mode = 'readonly') {
  return db.transaction(store, mode).objectStore(store);
}

function request(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function getAll(store) {
  const db = await openDB();
  return request(tx(db, store).getAll());
}

export async function put(store, value) {
  const db = await openDB();
  return request(tx(db, store, 'readwrite').put(value));
}

export async function bulkPut(store, values) {
  if (!values.length) return;
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(store, 'readwrite');
    const os = t.objectStore(store);
    for (const v of values) os.put(v);
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}

export async function remove(store, key) {
  const db = await openDB();
  return request(tx(db, store, 'readwrite').delete(key));
}

export async function clearStore(store) {
  const db = await openDB();
  return request(tx(db, store, 'readwrite').clear());
}

export async function getMeta(key, fallback = null) {
  const db = await openDB();
  const row = await request(tx(db, 'meta').get(key));
  return row ? row.value : fallback;
}

export async function setMeta(key, value) {
  const db = await openDB();
  return request(tx(db, 'meta', 'readwrite').put({ key, value }));
}

export async function removeMeta(key) {
  return remove('meta', key);
}
