import { describe, expect, it } from "bun:test";

export function analyzeCipher(text) {
  const letters = text.toUpperCase().replace(/[^A-Z]/g, "");
  const total = letters.length;
  const counts = {};
  for (let i = 65; i <= 90; i++) {
    counts[String.fromCharCode(i)] = 0;
  }
  for (const ch of letters) {
    counts[ch] = (counts[ch] || 0) + 1;
  }

  const bigrams = {};
  for (let i = 0; i < letters.length - 1; i++) {
    const bg = letters.slice(i, i + 2);
    bigrams[bg] = (bigrams[bg] || 0) + 1;
  }

  const trigrams = {};
  for (let i = 0; i < letters.length - 2; i++) {
    const tg = letters.slice(i, i + 3);
    trigrams[tg] = (trigrams[tg] || 0) + 1;
  }

  return { total, counts, bigrams, trigrams };
}

export function detectDuplicates(mapping) {
  const plainToCiphers = {};
  const duplicatePlains = new Set();

  for (const [cipher, plain] of Object.entries(mapping)) {
    if (!plain) continue;
    const p = plain.toUpperCase();
    if (!plainToCiphers[p]) {
      plainToCiphers[p] = [];
    }
    plainToCiphers[p].push(cipher.toUpperCase());
    if (plainToCiphers[p].length > 1) {
      duplicatePlains.add(p);
    }
  }

  return { plainToCiphers, duplicatePlains };
}

export function buildInvertedMapping(mapping) {
  const inverted = {};
  for (const [c, p] of Object.entries(mapping)) {
    if (p && !inverted[p.toUpperCase()]) {
      inverted[p.toUpperCase()] = c.toUpperCase();
    }
  }
  return inverted;
}

export function insertSpace(textArray, index) {
  const newArr = [...textArray];
  newArr.splice(index, 0, " ");
  return newArr;
}

export function removeSpace(textArray, index) {
  const newArr = [...textArray];
  if (newArr[index] === " ") {
    newArr.splice(index, 1);
  }
  return newArr;
}

describe("Cipher Analysis and Mapping", () => {
  const sampleText = `NLBNURTFSAPTAKOARLGLATAALTFGRTYLGLATFAECYCBTARTFAUIEAMJCRAEW` +
    `CRNLDARKCLYTURGLDRAPNRTAETNOJATMFJAYPCRITFAWCRTGKASTCTGNLNBD` +
    `MMSJGIACJJNTFARSWFNMCKATNOJATMFJAYFAWCSRAQUGRAETNSGDLTFANBBG` +
    `MGCJSAMRATSCMTGLWFGMFFACDRAAELNTTNEGSMJNSACLYTFGLDCONUTFGSWN` +
    `RICTOJATMFJAYWGTFSAVARAJADCJPALCJTGASBNRVGNJCTGLDTFACMT`;

  it("calculates accurate letter counts and frequencies", () => {
    const analysis = analyzeCipher(sampleText);
    expect(analysis.total).toBe(295);
    expect(analysis.counts["A"]).toBe(43);
    expect(analysis.counts["T"]).toBe(34);
    expect(analysis.counts["F"]).toBe(19);
    expect(analysis.bigrams["TF"]).toBe(11);
    expect(analysis.bigrams["FA"]).toBe(8);
    expect(analysis.trigrams["TFA"]).toBe(6);
  });

  it("detects duplicate mappings", () => {
    const mapping = { A: "E", B: "E", F: "H", T: "T" };
    const { duplicatePlains, plainToCiphers } = detectDuplicates(mapping);
    expect(duplicatePlains.has("E")).toBe(true);
    expect(duplicatePlains.has("H")).toBe(false);
    expect(plainToCiphers["E"]).toEqual(["A", "B"]);
  });

  it("builds correct inverted mapping for plain alphabet table", () => {
    const mapping = { A: "E", F: "H", T: "T" };
    const inverted = buildInvertedMapping(mapping);
    expect(inverted["E"]).toBe("A");
    expect(inverted["H"]).toBe("F");
    expect(inverted["T"]).toBe("T");
    expect(inverted["A"]).toBeUndefined();
  });

  it("supports manual space insertion and deletion syncing", () => {
    const tokens = ["N", "L", "B", "N"];
    const withSpace = insertSpace(tokens, 2);
    expect(withSpace).toEqual(["N", "L", " ", "B", "N"]);
    const removed = removeSpace(withSpace, 2);
    expect(removed).toEqual(["N", "L", "B", "N"]);
  });
});
