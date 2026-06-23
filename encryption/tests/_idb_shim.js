/**
 * MINIMAL in-memory IndexedDB shim for node (S4 gate ONLY).
 *
 * This is a deliberately tiny fake — NOT a spec-complete IndexedDB and NOT a
 * dependency (we do not add fake-indexeddb). It implements exactly the surface
 * KeyStorageService touches:
 *   indexedDB.open(name, version) with onupgradeneeded/onsuccess/onerror
 *   db.objectStoreNames.contains(name)
 *   db.createObjectStore(name, { keyPath })  (single string OR array keyPath)
 *   store.createIndex(name, keyPath, opts)
 *   db.transaction(name|names, mode) -> tx.objectStore(name)
 *   store.get/put/delete/clear  (async-ish: onsuccess/onerror microtasks)
 *   store.index(name).getAll(value) / .count(IDBKeyRange.only(value))
 *   IDBKeyRange.only(value)
 *   db.close()
 *
 * Keys: a single-string keyPath stores under record[keyPath]; an array keyPath
 * builds a composite string key from the joined field values (JSON-encoded so
 * distinct tuples never collide). Stored values are kept by reference, which is
 * fine for a single-process test (no structured-clone needed); ArrayBuffers and
 * Uint8Arrays round-trip by identity, which is STRICTER than real IndexedDB and
 * still proves serialize/wrap correctness.
 *
 * The shim is intentionally not exhaustive; if KeyStorageService grows new IDB
 * surface, extend here.
 */

'use strict';

function defer(fn) {
    // Mimic the async IDBRequest callback timing.
    Promise.resolve().then(fn);
}

function compositeKey(keyPath, record) {
    if (Array.isArray(keyPath)) {
        return JSON.stringify(keyPath.map((p) => record[p]));
    }
    return JSON.stringify(record[keyPath]);
}

function compositeKeyFromValue(keyPath, valueOrArray) {
    if (Array.isArray(keyPath)) {
        return JSON.stringify(valueOrArray);
    }
    return JSON.stringify(valueOrArray);
}

class FakeRequest {
    constructor() {
        this.onsuccess = null;
        this.onerror = null;
        this.result = undefined;
        this.error = null;
    }
    _succeed(result) {
        this.result = result;
        defer(() => { if (this.onsuccess) this.onsuccess({ target: this }); });
    }
    _fail(err) {
        this.error = err;
        defer(() => { if (this.onerror) this.onerror({ target: this }); });
    }
}

class FakeIndex {
    constructor(store, keyPath) {
        this.store = store;
        this.keyPath = keyPath;
    }
    // Extract a record's value for THIS index's keyPath. Mirrors real IndexedDB:
    // a compound (array) keyPath yields the array of the named fields' values, so
    // an index on ['userId','kind'] matches a query value of [userId, kind].
    _recordIndexValue(rec) {
        if (Array.isArray(this.keyPath)) {
            return JSON.stringify(this.keyPath.map((p) => rec[p]));
        }
        return JSON.stringify(rec[this.keyPath]);
    }
    getAll(value) {
        const req = new FakeRequest();
        const wanted = JSON.stringify(value);
        const out = [];
        for (const rec of this.store._data.values()) {
            if (this._recordIndexValue(rec) === wanted) out.push(rec);
        }
        req._succeed(out);
        return req;
    }
    count(range) {
        const req = new FakeRequest();
        const wanted = range == null ? null : range._only;
        let n = 0;
        for (const rec of this.store._data.values()) {
            if (wanted == null || this._recordIndexValue(rec) === JSON.stringify(wanted)) n++;
        }
        req._succeed(n);
        return req;
    }
}

class FakeObjectStore {
    constructor(name, keyPath) {
        this.name = name;
        this.keyPath = keyPath;
        this._data = new Map();     // compositeKey string -> record
        this._indexes = new Map();  // indexName -> FakeIndex
    }
    createIndex(name, keyPath /*, opts */) {
        const idx = new FakeIndex(this, keyPath);
        this._indexes.set(name, idx);
        return idx;
    }
    index(name) {
        const idx = this._indexes.get(name);
        if (!idx) throw new Error('No such index: ' + name);
        return idx;
    }
    get(key) {
        const req = new FakeRequest();
        req._succeed(this._data.get(compositeKeyFromValue(this.keyPath, key)));
        return req;
    }
    getAll() {
        const req = new FakeRequest();
        req._succeed(Array.from(this._data.values()));
        return req;
    }
    put(record) {
        const req = new FakeRequest();
        this._data.set(compositeKey(this.keyPath, record), record);
        req._succeed(undefined);
        return req;
    }
    delete(key) {
        const req = new FakeRequest();
        this._data.delete(compositeKeyFromValue(this.keyPath, key));
        req._succeed(undefined);
        return req;
    }
    clear() {
        const req = new FakeRequest();
        this._data.clear();
        req._succeed(undefined);
        return req;
    }
}

class FakeTransaction {
    constructor(db, names /*, mode */) {
        this.db = db;
        this.names = Array.isArray(names) ? names : [names];
        this.onerror = null;
        this.error = null;
    }
    objectStore(name) {
        const store = this.db._stores.get(name);
        if (!store) throw new Error('NotFoundError: object store not found: ' + name);
        return store;
    }
}

// A FakeDatabase is a single CONNECTION. The persistent state (object stores +
// data + version) lives in a shared `backing` object that survives across
// open()/close() cycles -- exactly like a real IndexedDB where closing one
// connection does not destroy the database. close() only closes THIS connection.
class FakeDatabase {
    constructor(backing) {
        this._backing = backing;
        this._closed = false;
    }
    get name() { return this._backing.name; }
    get version() { return this._backing.version; }
    set version(v) { this._backing.version = v; }
    get _stores() { return this._backing.stores; }
    get objectStoreNames() {
        const names = Array.from(this._backing.stores.keys());
        return { contains: (n) => names.includes(n) };
    }
    createObjectStore(name, opts) {
        const store = new FakeObjectStore(name, opts.keyPath);
        this._backing.stores.set(name, store);
        return store;
    }
    transaction(names /*, mode */) {
        if (this._closed) throw new Error('InvalidStateError: database is closed');
        return new FakeTransaction(this, names);
    }
    close() { this._closed = true; }
}

function makeFakeIndexedDB() {
    // Persist backing state by name across open() calls so a version bump triggers
    // onupgradeneeded against the EXISTING stores (proves additive upgrade). Each
    // open() returns a FRESH connection over the same backing.
    const _dbs = new Map(); // name -> backing { name, version, stores:Map }

    const indexedDB = {
        open(name, version) {
            const req = new FakeRequest();
            defer(() => {
                let backing = _dbs.get(name);
                const oldVersion = backing ? backing.version : 0;
                if (!backing) {
                    backing = { name, version: version || 1, stores: new Map() };
                    _dbs.set(name, backing);
                } else {
                    backing.version = version || backing.version;
                }
                const db = new FakeDatabase(backing);
                if ((version || 1) > oldVersion) {
                    // fire onupgradeneeded with a connection over the (pre-existing) stores
                    if (req.onupgradeneeded) {
                        req.onupgradeneeded({ target: { result: db }, oldVersion, newVersion: version });
                    }
                }
                req._succeed(db);
            });
            return req;
        },
        deleteDatabase(name) {
            const req = new FakeRequest();
            _dbs.delete(name);
            req._succeed(undefined);
            return req;
        },
        _dbs
    };

    const IDBKeyRange = {
        only(value) { return { _only: value }; }
    };

    return { indexedDB, IDBKeyRange };
}

module.exports = { makeFakeIndexedDB };
