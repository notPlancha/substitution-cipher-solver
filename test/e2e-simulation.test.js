import { describe, expect, it } from "bun:test";

describe("Substitution Cipher Solver Logic Simulation", () => {
  const SAMPLE_CIPHERTEXT = 
    "NLBNURTFSAPTAKOARLGLATAALTFGRTYLGLATFAECYCBTARTFAUIEAMJCRAEW" +
    "CRNLDARKCLYTURGLDRAPNRTAETNOJATMFJAYPCRITFAWCRTGKASTCTGNLNBD" +
    "MMSJGIACJJNTFARSWFNMCKATNOJATMFJAYFAWCSRAQUGRAETNSGDLTFANBBG" +
    "MGCJSAMRATSCMTGLWFGMFFACDRAAELNTTNEGSMJNSACLYTFGLDCONUTFGSWN" +
    "RICTOJATMFJAYWGTFSAVARAJADCJPALCJTGASBNRVGNJCTGLDTFACMT";

  function createSimulator() {
    const state = {
      tokens: SAMPLE_CIPHERTEXT.split(""),
      cipherToPlain: { A: "E", F: "H", T: "T" },
      appliedMappings: [
        { cipher: "T", plain: "T" },
        { cipher: "F", plain: "H" },
        { cipher: "A", plain: "E" }
      ]
    };

    function setMapping(c, p) {
      const cu = c.toUpperCase();
      const pu = p ? p.toUpperCase() : null;
      state.appliedMappings = state.appliedMappings.filter(m => m.cipher !== cu);
      if (!pu) {
        delete state.cipherToPlain[cu];
      } else {
        state.cipherToPlain[cu] = pu;
        state.appliedMappings.unshift({ cipher: cu, plain: pu });
      }
    }

    function getPlainToCipher() {
      const inverted = {};
      for (const [c, p] of Object.entries(state.cipherToPlain)) {
        if (p && !inverted[p.toUpperCase()]) {
          inverted[p.toUpperCase()] = c.toUpperCase();
        }
      }
      return inverted;
    }

    function detectDuplicates() {
      const plainToCiphers = {};
      const duplicatePlains = new Set();
      for (const [c, p] of Object.entries(state.cipherToPlain)) {
        if (!p) continue;
        const pu = p.toUpperCase();
        if (!plainToCiphers[pu]) plainToCiphers[pu] = [];
        plainToCiphers[pu].push(c.toUpperCase());
        if (plainToCiphers[pu].length > 1) duplicatePlains.add(pu);
      }
      return { plainToCiphers, duplicatePlains };
    }

    function insertSpaceAt(index) {
      state.tokens.splice(index + 1, 0, " ");
      return index + 2;
    }

    function removeSpaceAt(index) {
      if (state.tokens[index] === " ") {
        state.tokens.splice(index, 1);
        return Math.max(0, index - 1);
      }
      return index;
    }

    function getDecryptedText() {
      return state.tokens.map(t => {
        if (t === " ") return " ";
        if (/[A-Z]/i.test(t)) return state.cipherToPlain[t.toUpperCase()] || "_";
        return t;
      }).join("");
    }

    let historyPast = [];
    let historyFuture = [];

    function pushHistory() {
      historyPast.push({
        tokens: [...state.tokens],
        cipherToPlain: { ...state.cipherToPlain },
        appliedMappings: state.appliedMappings.map(m => ({ ...m }))
      });
      historyFuture = [];
    }

    function undo() {
      if (historyPast.length === 0) return false;
      historyFuture.push({
        tokens: [...state.tokens],
        cipherToPlain: { ...state.cipherToPlain },
        appliedMappings: state.appliedMappings.map(m => ({ ...m }))
      });
      const prev = historyPast.pop();
      state.tokens = [...prev.tokens];
      state.cipherToPlain = { ...prev.cipherToPlain };
      state.appliedMappings = prev.appliedMappings ? prev.appliedMappings.map(m => ({ ...m })) : [];
      return true;
    }

    function redo() {
      if (historyFuture.length === 0) return false;
      historyPast.push({
        tokens: [...state.tokens],
        cipherToPlain: { ...state.cipherToPlain },
        appliedMappings: state.appliedMappings.map(m => ({ ...m }))
      });
      const next = historyFuture.pop();
      state.tokens = [...next.tokens];
      state.cipherToPlain = { ...next.cipherToPlain };
      state.appliedMappings = next.appliedMappings ? next.appliedMappings.map(m => ({ ...m })) : [];
      return true;
    }

    function setMappingWithHistory(c, p) {
      pushHistory();
      setMapping(c, p);
    }

    function insertSpaceWithHistory(idx) {
      pushHistory();
      return insertSpaceAt(idx);
    }

    return {
      state,
      get tokens() { return state.tokens; },
      get cipherToPlain() { return state.cipherToPlain; },
      setMapping,
      setMappingWithHistory,
      insertSpaceWithHistory,
      undo,
      redo,
      getPlainToCipher,
      detectDuplicates,
      insertSpaceAt,
      removeSpaceAt,
      getDecryptedText,
      getHistoryCount: () => ({ past: historyPast.length, future: historyFuture.length })
    };
  }

  it("renders decrypted text with initial A->E, F->H, T->T matching Image 2", () => {
    const sim = createSimulator();
    const decrypted = sim.getDecryptedText();
    // In line 1: TFA at pos 6-8 should be THE
    expect(decrypted.slice(6, 10)).toBe("TH_E");
    // At pos 26-28: TFA should be THE
    expect(decrypted.includes("ETHE")).toBe(true);
  });

  it("autofills all occurrences across text when user types a letter", () => {
    const sim = createSimulator();
    // Map S -> R
    sim.setMapping("S", "R");
    expect(sim.cipherToPlain["S"]).toBe("R");
    const decrypted = sim.getDecryptedText();
    // Under 'TFS', since T=T, F=H, S=R -> 'THR'
    expect(decrypted.slice(6, 9)).toBe("THR");
  });

  it("detects duplicate conflicts when two cipher letters map to same plain letter", () => {
    const sim = createSimulator();
    sim.setMapping("B", "E"); // A is already mapped to E
    const { duplicatePlains, plainToCiphers } = sim.detectDuplicates();
    expect(duplicatePlains.has("E")).toBe(true);
    expect(plainToCiphers["E"]).toEqual(["A", "B"]);
  });

  it("synchronizes manual spaces in both ciphertext and decrypted output", () => {
    const sim = createSimulator();
    // Insert space after token 8 ('S' in 'NLBNURTFSA...')
    sim.insertSpaceAt(8);
    expect(sim.tokens[9]).toBe(" ");
    const decrypted = sim.getDecryptedText();
    expect(decrypted[9]).toBe(" ");
    expect(sim.tokens.length).toBe(296);

    // Remove space
    sim.removeSpaceAt(9);
    expect(sim.tokens[9]).not.toBe(" ");
    expect(sim.tokens.length).toBe(295);
  });

  it("performs undo (go back) and redo (go forward) for substitutions and spaces", () => {
    const sim = createSimulator();
    expect(sim.getHistoryCount().past).toBe(0);

    // 1. Make a substitution
    sim.setMappingWithHistory("O", "N");
    expect(sim.getDecryptedText().includes("N")).toBe(true);
    expect(sim.getHistoryCount().past).toBe(1);

    // 2. Undo
    const undone = sim.undo();
    expect(undone).toBe(true);
    expect(sim.getDecryptedText().includes("N")).toBe(false);
    expect(sim.getHistoryCount().future).toBe(1);

    // 3. Redo
    const redone = sim.redo();
    expect(redone).toBe(true);
    expect(sim.getDecryptedText().includes("N")).toBe(true);
    expect(sim.getHistoryCount().future).toBe(0);

    // 4. Undo space insertion
    sim.insertSpaceWithHistory(5);
    expect(sim.getHistoryCount().past).toBe(2);
    expect(sim.tokens[6]).toBe(" ");
    sim.undo();
    expect(sim.tokens[6]).not.toBe(" ");
  });

  it("tracks last mappings applied with initial snapshot T->T, F->H, A->E", () => {
    const sim = createSimulator();
    // 1. Initial snapshot has T->T, F->H, A->E
    expect(sim.state.appliedMappings).toEqual([
      { cipher: "T", plain: "T" },
      { cipher: "F", plain: "H" },
      { cipher: "A", plain: "E" }
    ]);

    // 2. Applying a new mapping (e.g. T -> V) moves T -> V to the top
    sim.setMappingWithHistory("T", "V");
    expect(sim.state.appliedMappings[0]).toEqual({ cipher: "T", plain: "V" });
    expect(sim.state.appliedMappings.length).toBe(3);

    // 3. Applying an unmapped letter (e.g. C -> V) prepends to top
    sim.setMappingWithHistory("C", "V");
    expect(sim.state.appliedMappings[0]).toEqual({ cipher: "C", plain: "V" });
    expect(sim.state.appliedMappings[1]).toEqual({ cipher: "T", plain: "V" });
    expect(sim.state.appliedMappings.length).toBe(4);

    // 4. Undo restores previous applied mappings order
    sim.undo();
    expect(sim.state.appliedMappings[0]).toEqual({ cipher: "T", plain: "V" });
    expect(sim.state.appliedMappings.length).toBe(3);

    // 5. Removing a mapping removes it from the list
    sim.setMapping("T", "");
    expect(sim.state.appliedMappings.find(m => m.cipher === "T")).toBeUndefined();
    expect(sim.state.appliedMappings.length).toBe(2);
  });
});
