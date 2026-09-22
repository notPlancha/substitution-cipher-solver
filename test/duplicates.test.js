import { describe, expect, it } from "bun:test";

describe("Duplicate Mapping and Conflict Highlighting System", () => {
  function createMappingManager(initialPairs = [
    { cipher: "T", plain: "T" },
    { cipher: "F", plain: "H" },
    { cipher: "A", plain: "E" }
  ]) {
    let mappings = initialPairs.map(p => ({ cipher: p.cipher.toUpperCase(), plain: p.plain.toUpperCase() }));
    let historyPast = [];
    let historyFuture = [];

    function pushHistory() {
      historyPast.push(mappings.map(m => ({ ...m })));
      historyFuture = [];
    }

    function undo() {
      if (historyPast.length === 0) return;
      historyFuture.push(mappings.map(m => ({ ...m })));
      mappings = historyPast.pop();
    }

    function redo() {
      if (historyFuture.length === 0) return;
      historyPast.push(mappings.map(m => ({ ...m })));
      mappings = historyFuture.pop();
    }

    function getPlainsForCipher(cipher) {
      if (!cipher) return [];
      const c = cipher.toUpperCase();
      const plains = [];
      for (const m of mappings) {
        if (m.cipher === c && m.plain && !plains.includes(m.plain)) {
          plains.push(m.plain);
        }
      }
      return plains;
    }

    function getCiphersForPlain(plain) {
      if (!plain) return [];
      const p = plain.toUpperCase();
      const ciphers = [];
      for (const m of mappings) {
        if (m.plain === p && m.cipher && !ciphers.includes(m.cipher)) {
          ciphers.push(m.cipher);
        }
      }
      return ciphers;
    }

    function getConflicts() {
      const duplicatePlains = {}; // plain -> [cipher1, cipher2, ...]
      const duplicateCiphers = {}; // cipher -> [plain1, plain2, ...]
      const plainToCiphers = {};
      const cipherToPlains = {};

      for (const m of mappings) {
        if (!m.cipher || !m.plain) continue;
        const c = m.cipher.toUpperCase();
        const p = m.plain.toUpperCase();

        if (!plainToCiphers[p]) plainToCiphers[p] = [];
        if (!plainToCiphers[p].includes(c)) plainToCiphers[p].push(c);

        if (!cipherToPlains[c]) cipherToPlains[c] = [];
        if (!cipherToPlains[c].includes(p)) cipherToPlains[c].push(p);
      }

      for (const [p, ciphers] of Object.entries(plainToCiphers)) {
        if (ciphers.length > 1) {
          duplicatePlains[p] = ciphers;
        }
      }

      for (const [c, plains] of Object.entries(cipherToPlains)) {
        if (plains.length > 1) {
          duplicateCiphers[c] = plains;
        }
      }

      return { duplicatePlains, duplicateCiphers, plainToCiphers, cipherToPlains };
    }

    // Set mapping from Encrypted Alphabet (Cipher -> Plain)
    function setEncryptedMapping(cipher, plain) {
      const c = cipher.toUpperCase();
      const p = plain ? plain.toUpperCase() : null;
      pushHistory();
      // Remove any existing mapping for this cipher letter
      mappings = mappings.filter(m => m.cipher !== c);
      if (p) {
        // Add new mapping without erasing other ciphers mapped to p
        mappings.unshift({ cipher: c, plain: p });
      }
    }

    // Set mapping from Plain Alphabet (Plain -> Cipher)
    function setPlainMapping(plain, cipher) {
      const p = plain.toUpperCase();
      const c = cipher ? cipher.toUpperCase() : null;
      pushHistory();
      // Remove any existing mapping for this plain letter
      mappings = mappings.filter(m => m.plain !== p);
      if (c) {
        // Add new mapping without erasing other plains mapped to c
        mappings.unshift({ cipher: c, plain: p });
      }
    }

    function removeMappingPair(cipher, plain) {
      const c = cipher.toUpperCase();
      const p = plain.toUpperCase();
      pushHistory();
      mappings = mappings.filter(m => !(m.cipher === c && m.plain === p));
    }

    // Simulate table representation for Plain Alphabet
    function getPlainTableState() {
      const { duplicatePlains, duplicateCiphers } = getConflicts();
      const assignedCipherLetters = new Set(mappings.map(m => m.cipher.toUpperCase()));
      const table = {};

      for (let i = 65; i <= 90; i++) {
        const letter = String.fromCharCode(i);
        const isLabelConflict = !!duplicatePlains[letter] || !!duplicateCiphers[letter];
        const isUsed = assignedCipherLetters.has(letter);
        const ciphersForPlain = getCiphersForPlain(letter);
        const value = ciphersForPlain.join("");
        const isInputConflict = ciphersForPlain.length > 1 || ciphersForPlain.some(c => !!duplicateCiphers[c]);

        table[letter] = {
          labelConflict: isLabelConflict,
          isUsed,
          value,
          inputConflict: isInputConflict
        };
      }
      return table;
    }

    // Simulate table representation for Encrypted Alphabet
    function getEncryptedTableState() {
      const { duplicatePlains, duplicateCiphers } = getConflicts();
      const assignedPlainLetters = new Set(mappings.map(m => m.plain.toUpperCase()));
      const table = {};

      for (let i = 65; i <= 90; i++) {
        const letter = String.fromCharCode(i);
        const isLabelConflict = !!duplicatePlains[letter] || !!duplicateCiphers[letter];
        const isUsed = assignedPlainLetters.has(letter);
        const plainsForCipher = getPlainsForCipher(letter);
        const value = plainsForCipher.join("");
        const isInputConflict = plainsForCipher.length > 1 || plainsForCipher.some(p => !!duplicatePlains[p]);

        table[letter] = {
          labelConflict: isLabelConflict,
          isUsed,
          value,
          inputConflict: isInputConflict
        };
      }
      return table;
    }

    return {
      get mappings() { return mappings; },
      getPlainsForCipher,
      getCiphersForPlain,
      getConflicts,
      setEncryptedMapping,
      setPlainMapping,
      removeMappingPair,
      getPlainTableState,
      getEncryptedTableState,
      undo,
      redo
    };
  }

  it("does not replace an already assigned letter when adding a duplicate in Encrypted Alphabet", () => {
    const mgr = createMappingManager();
    // A -> E already exists
    expect(mgr.getPlainsForCipher("A")).toEqual(["E"]);

    // User types 'E' above cipher 'B' in Encrypted Alphabet
    mgr.setEncryptedMapping("B", "E");

    // Both A and B must be mapped to E without A being replaced!
    expect(mgr.getPlainsForCipher("A")).toEqual(["E"]);
    expect(mgr.getPlainsForCipher("B")).toEqual(["E"]);
    expect(mgr.getCiphersForPlain("E")).toEqual(["B", "A"]);

    // Conflict detection must flag plain E as duplicate with [B, A]
    const { duplicatePlains, duplicateCiphers } = mgr.getConflicts();
    expect(duplicatePlains["E"]).toEqual(["B", "A"]);
    expect(Object.keys(duplicateCiphers).length).toBe(0);

    // Verify Plain Alphabet table UI state
    const plainTable = mgr.getPlainTableState();
    // Plain E input should show "BA", and have inputConflict = true
    expect(plainTable["E"].value).toBe("BA");
    expect(plainTable["E"].inputConflict).toBe(true);
    // Plain E label should have labelConflict = true
    expect(plainTable["E"].labelConflict).toBe(true);

    // Verify Encrypted Alphabet table UI state
    const encTable = mgr.getEncryptedTableState();
    // Enc A input should show "E", and have inputConflict = true
    expect(encTable["A"].value).toBe("E");
    expect(encTable["A"].inputConflict).toBe(true);
    // Enc B input should show "E", and have inputConflict = true
    expect(encTable["B"].value).toBe("E");
    expect(encTable["B"].inputConflict).toBe(true);
    // Enc E label (tracking used plain letters) should have labelConflict = true
    expect(encTable["E"].labelConflict).toBe(true);
  });

  it("does not replace an already assigned letter when adding a duplicate in Plain Alphabet", () => {
    const mgr = createMappingManager();
    // E -> A already exists
    expect(mgr.getCiphersForPlain("E")).toEqual(["A"]);

    // User types 'A' under plain 'H' in Plain Alphabet
    mgr.setPlainMapping("H", "A");

    // Both E and H must have cipher 'A' without E being replaced!
    expect(mgr.getCiphersForPlain("E")).toEqual(["A"]);
    expect(mgr.getCiphersForPlain("H")).toEqual(["A"]);
    expect(mgr.getPlainsForCipher("A")).toEqual(["H", "E"]);

    // Conflict detection must flag cipher A as duplicate with [H, E]
    const { duplicateCiphers, duplicatePlains } = mgr.getConflicts();
    expect(duplicateCiphers["A"]).toEqual(["H", "E"]);
    expect(Object.keys(duplicatePlains).length).toBe(0);

    // Verify Plain Alphabet table UI state
    const plainTable = mgr.getPlainTableState();
    // Both Plain E and Plain H should have input value "A" with inputConflict = true
    expect(plainTable["E"].value).toBe("A");
    expect(plainTable["E"].inputConflict).toBe(true);
    expect(plainTable["H"].value).toBe("A");
    expect(plainTable["H"].inputConflict).toBe(true);
    // Label A in Plain Alphabet should have labelConflict = true
    expect(plainTable["A"].labelConflict).toBe(true);

    // Verify Encrypted Alphabet table UI state
    const encTable = mgr.getEncryptedTableState();
    // Enc A input should show "HE" (both plains) and have inputConflict = true
    expect(encTable["A"].value).toBe("HE");
    expect(encTable["A"].inputConflict).toBe(true);
    // Enc A label should have labelConflict = true
    expect(encTable["A"].labelConflict).toBe(true);
  });

  it("resolves conflict cleanly when a duplicate mapping is removed", () => {
    const mgr = createMappingManager();
    mgr.setEncryptedMapping("B", "E"); // Creates duplicate on E: [B, A]
    expect(mgr.getConflicts().duplicatePlains["E"]).toEqual(["B", "A"]);

    // Remove B -> E mapping pair
    mgr.removeMappingPair("B", "E");

    // A -> E remains, conflict is gone!
    expect(mgr.getPlainsForCipher("A")).toEqual(["E"]);
    expect(mgr.getPlainsForCipher("B")).toEqual([]);
    expect(mgr.getCiphersForPlain("E")).toEqual(["A"]);

    const { duplicatePlains, duplicateCiphers } = mgr.getConflicts();
    expect(duplicatePlains["E"]).toBeUndefined();
    expect(Object.keys(duplicatePlains).length).toBe(0);
    expect(Object.keys(duplicateCiphers).length).toBe(0);

    const plainTable = mgr.getPlainTableState();
    expect(plainTable["E"].value).toBe("A");
    expect(plainTable["E"].inputConflict).toBe(false);
    expect(plainTable["E"].labelConflict).toBe(false);
  });

  it("supports undo and redo without replacing duplicate mappings", () => {
    const mgr = createMappingManager();
    mgr.setPlainMapping("H", "A"); // Duplicate cipher A on E and H
    expect(mgr.getConflicts().duplicateCiphers["A"]).toEqual(["H", "E"]);

    // Undo should revert to before H->A was added
    mgr.undo();
    expect(mgr.getCiphersForPlain("H")).toEqual(["F"]);
    expect(mgr.getCiphersForPlain("E")).toEqual(["A"]);
    expect(Object.keys(mgr.getConflicts().duplicateCiphers).length).toBe(0);

    // Redo should restore duplicate
    mgr.redo();
    expect(mgr.getCiphersForPlain("H")).toEqual(["A"]);
    expect(mgr.getCiphersForPlain("E")).toEqual(["A"]);
    expect(mgr.getConflicts().duplicateCiphers["A"]).toEqual(["H", "E"]);
  });
});
