import { describe, expect, it, beforeEach } from "bun:test";

describe("State Persistence Across Page Refresh (localStorage)", () => {
  const STORAGE_KEY = "substitution_cipher_solver_state_v1";

  function createStorageMock() {
    let store = {};
    return {
      getItem(key) {
        return Object.prototype.hasOwnProperty.call(store, key) ? store[key] : null;
      },
      setItem(key, val) {
        store[key] = String(val);
      },
      removeItem(key) {
        delete store[key];
      },
      clear() {
        store = {};
      },
      get store() {
        return store;
      }
    };
  }

  function createSolverInstance(storage) {
    const state = {
      tokens: [],
      cipherToPlain: {},
      appliedMappings: [],
      focusedIndex: null,
      highlightedChar: null,
      highlightedNgram: null,
      sortMode: "freq",
      wrapLength: 60
    };

    const history = {
      past: [],
      future: []
    };

    function syncCipherToPlain() {
      state.cipherToPlain = {};
      for (let i = state.appliedMappings.length - 1; i >= 0; i--) {
        const m = state.appliedMappings[i];
        if (m && m.cipher && m.plain) {
          state.cipherToPlain[m.cipher] = m.plain;
        }
      }
    }

    function loadSample() {
      state.tokens = "NLBNURTFSA".split("");
      state.appliedMappings = [
        { cipher: "T", plain: "T" },
        { cipher: "F", plain: "H" },
        { cipher: "A", plain: "E" }
      ];
      syncCipherToPlain();
      state.focusedIndex = null;
      state.highlightedChar = null;
      state.highlightedNgram = null;
      state.sortMode = "freq";
      state.wrapLength = 60;
    }

    function saveStateToStorage() {
      try {
        if (!storage) return;
        const payload = {
          tokens: state.tokens,
          appliedMappings: state.appliedMappings,
          wrapLength: state.wrapLength,
          sortMode: state.sortMode,
          historyPast: history.past,
          historyFuture: history.future
        };
        storage.setItem(STORAGE_KEY, JSON.stringify(payload));
      } catch (err) {
        // ignore
      }
    }

    function loadStateFromStorage() {
      try {
        if (!storage) return false;
        const raw = storage.getItem(STORAGE_KEY);
        if (!raw) return false;
        const data = JSON.parse(raw);
        if (!data || !Array.isArray(data.tokens) || data.tokens.length === 0) {
          return false;
        }

        state.tokens = [...data.tokens];
        state.appliedMappings = Array.isArray(data.appliedMappings)
          ? data.appliedMappings.filter(m => m && m.cipher && m.plain).map(m => ({
              cipher: String(m.cipher).toUpperCase(),
              plain: String(m.plain).toUpperCase()
            }))
          : [];
        syncCipherToPlain();

        if (data.wrapLength) {
          state.wrapLength = data.wrapLength;
        }
        if (data.sortMode === "freq" || data.sortMode === "az") {
          state.sortMode = data.sortMode;
        }

        if (Array.isArray(data.historyPast)) {
          history.past = data.historyPast;
        }
        if (Array.isArray(data.historyFuture)) {
          history.future = data.historyFuture;
        }

        state.focusedIndex = null;
        state.highlightedChar = null;
        state.highlightedNgram = null;
        return true;
      } catch (err) {
        return false;
      }
    }

    function init() {
      const restored = loadStateFromStorage();
      if (!restored) {
        loadSample();
      }
      saveStateToStorage();
    }

    function setMapping(cipher, plain) {
      const c = cipher.toUpperCase();
      const p = plain ? plain.toUpperCase() : null;
      history.past.push({
        tokens: [...state.tokens],
        appliedMappings: state.appliedMappings.map(m => ({ ...m }))
      });
      state.appliedMappings = state.appliedMappings.filter(m => m.cipher !== c);
      if (p) {
        state.appliedMappings.unshift({ cipher: c, plain: p });
      }
      syncCipherToPlain();
      saveStateToStorage();
    }

    function insertSpace(index) {
      history.past.push({
        tokens: [...state.tokens],
        appliedMappings: state.appliedMappings.map(m => ({ ...m }))
      });
      state.tokens.splice(index + 1, 0, " ");
      saveStateToStorage();
    }

    return {
      state,
      history,
      init,
      loadSample,
      setMapping,
      insertSpace,
      saveStateToStorage,
      loadStateFromStorage
    };
  }

  it("loads default sample on first visit when localStorage is empty", () => {
    const storage = createStorageMock();
    const solver = createSolverInstance(storage);
    solver.init();

    expect(solver.state.tokens.join("")).toBe("NLBNURTFSA");
    expect(solver.state.cipherToPlain["A"]).toBe("E");
    expect(solver.state.cipherToPlain["F"]).toBe("H");
    expect(solver.state.cipherToPlain["T"]).toBe("T");
    expect(storage.getItem(STORAGE_KEY)).not.toBeNull();
  });

  it("preserves applied substitutions and manual spaces across simulated page refresh", () => {
    const storage = createStorageMock();
    
    // Session 1: User works on cipher
    const session1 = createSolverInstance(storage);
    session1.init();

    // User applies a new substitution B -> O
    session1.setMapping("B", "O");
    // User inserts space after 3rd token: 'NLB' + ' ' + 'NURTFSA'
    session1.insertSpace(2);

    expect(session1.state.tokens[3]).toBe(" ");
    expect(session1.state.cipherToPlain["B"]).toBe("O");

    // Session 2: User refreshes page (new solver instance loads from same storage)
    const session2 = createSolverInstance(storage);
    session2.init();

    // Verify all progress is restored exactly!
    expect(session2.state.tokens[3]).toBe(" ");
    expect(session2.state.tokens.join("")).toBe("NLB NURTFSA");
    expect(session2.state.cipherToPlain["B"]).toBe("O");
    expect(session2.state.cipherToPlain["A"]).toBe("E");
    expect(session2.state.appliedMappings[0]).toEqual({ cipher: "B", plain: "O" });
  });

  it("preserves duplicate mappings across page refresh", () => {
    const storage = createStorageMock();

    const session1 = createSolverInstance(storage);
    session1.init();

    // User creates duplicate: maps B -> E (while A -> E already exists)
    session1.state.appliedMappings.unshift({ cipher: "B", plain: "E" });
    session1.saveStateToStorage();

    // Reload (Session 2)
    const session2 = createSolverInstance(storage);
    session2.init();

    expect(session2.state.appliedMappings.some(m => m.cipher === "B" && m.plain === "E")).toBe(true);
    expect(session2.state.appliedMappings.some(m => m.cipher === "A" && m.plain === "E")).toBe(true);
  });

  it("preserves history stack so undo works after refresh", () => {
    const storage = createStorageMock();

    const session1 = createSolverInstance(storage);
    session1.init();
    session1.setMapping("B", "O");
    expect(session1.history.past.length).toBe(1);

    // Reload (Session 2)
    const session2 = createSolverInstance(storage);
    session2.init();

    expect(session2.history.past.length).toBe(1);
    expect(session2.state.cipherToPlain["B"]).toBe("O");
  });

  it("gracefully recovers from corrupt or invalid JSON in localStorage", () => {
    const storage = createStorageMock();
    storage.setItem(STORAGE_KEY, "invalid-json{{[}");

    const solver = createSolverInstance(storage);
    solver.init();

    // Should fall back to sample without throwing error
    expect(solver.state.tokens.join("")).toBe("NLBNURTFSA");
    expect(solver.state.cipherToPlain["A"]).toBe("E");
  });
});
