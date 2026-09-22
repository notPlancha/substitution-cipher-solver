/**
 * Substitution Cipher Solver
 * Core interactive engine and cryptanalysis toolkit.
 */

// Standard English Letter Frequencies (percentages)
const ENGLISH_FREQS = {
  E: 12.70, T: 9.06, A: 8.17, O: 7.51, I: 6.97, N: 6.75, S: 6.33, H: 6.09,
  R: 5.99,  D: 4.25, L: 4.03, C: 2.78, U: 2.76, M: 2.41, W: 2.36, F: 2.23,
  G: 2.02,  Y: 1.97, P: 1.93, B: 1.49, V: 0.98, K: 0.77, J: 0.15, X: 0.15,
  Q: 0.10,  Z: 0.07
};

// English Reference Top N-grams
const ENGLISH_TOP_BIGRAMS = [
  "TH", "HE", "IN", "ER", "AN", "RE", "ED", "ON", "ES", "ST",
  "EN", "AT", "TO", "NT", "HA", "ND", "OU", "EA", "NG", "AS"
];

const ENGLISH_TOP_TRIGRAMS = [
  "THE", "AND", "THA", "ENT", "ION", "TIO", "FOR", "NDE", "HAS", "NCE",
  "TIS", "OFT", "MEN", "VER", "ALL", "WIT", "THI", "ING"
];

// Screenshot Reference Sample
const SAMPLE_CIPHERTEXT = 
  "NLBNURTFSAPTAKOARLGLATAALTFGRTYLGLATFAECYCBTARTFAUIEAMJCRAEW" +
  "CRNLDARKCLYTURGLDRAPNRTAETNOJATMFJAYPCRITFAWCRTGKASTCTGNLNBD" +
  "MMSJGIACJJNTFARSWFNMCKATNOJATMFJAYFAWCSRAQUGRAETNSGDLTFANBBG" +
  "MGCJSAMRATSCMTGLWFGMFFACDRAAELNTTNEGSMJNSACLYTFGLDCONUTFGSWN" +
  "RICTOJATMFJAYWGTFSAVARAJADCJPALCJTGASBNRVGNJCTGLDTFACMT";

// Initial mappings from Image 1
const SAMPLE_INITIAL_MAPPINGS = {
  A: "E",
  F: "H",
  T: "T"
};

// Initial snapshot order of applied mappings
const SAMPLE_INITIAL_APPLIED = [
  { cipher: "T", plain: "T" },
  { cipher: "F", plain: "H" },
  { cipher: "A", plain: "E" }
];

// ---------------------------------------------------------------------------
// Application State
// ---------------------------------------------------------------------------
const state = {
  // Array of characters including spaces: ['N', 'L', 'B', ' ', 'N', ...]
  tokens: [],
  // Cipher letter -> Plain letter mapping: { A: 'E', F: 'H', T: 'T' }
  cipherToPlain: {},
  // Chronological list of applied mappings (most recent first): [{ cipher: 'T', plain: 'T' }, ...]
  appliedMappings: [],
  // Currently focused token index in the typable text
  focusedIndex: null,
  // Currently highlighted cipher letter (for all matching characters)
  highlightedChar: null,
  // Currently highlighted n-gram (e.g. 'TFA' or 'TF')
  highlightedNgram: null,
  // Frequency sort mode: 'freq' or 'az'
  sortMode: "freq",
  // Wrap characters per line
  wrapLength: 60
};

// ---------------------------------------------------------------------------
// History Stack for Go Back (Undo) / Go Forward (Redo)
// ---------------------------------------------------------------------------
const history = {
  past: [],
  future: []
};

function pushHistory() {
  history.past.push({
    tokens: [...state.tokens],
    cipherToPlain: { ...state.cipherToPlain },
    appliedMappings: state.appliedMappings.map(m => ({ ...m })),
    focusedIndex: state.focusedIndex
  });
  if (history.past.length > 100) {
    history.past.shift();
  }
  history.future = [];
  updateHistoryButtons();
}

function undo() {
  if (history.past.length === 0) return;
  history.future.push({
    tokens: [...state.tokens],
    cipherToPlain: { ...state.cipherToPlain },
    appliedMappings: state.appliedMappings.map(m => ({ ...m })),
    focusedIndex: state.focusedIndex
  });
  const prev = history.past.pop();
  state.tokens = [...prev.tokens];
  state.cipherToPlain = { ...prev.cipherToPlain };
  state.appliedMappings = prev.appliedMappings ? prev.appliedMappings.map(m => ({ ...m })) : [];
  state.focusedIndex = prev.focusedIndex;
  updateHistoryButtons();
  renderAll();
  showToast("↩️ Undo (went back)");
}

function redo() {
  if (history.future.length === 0) return;
  history.past.push({
    tokens: [...state.tokens],
    cipherToPlain: { ...state.cipherToPlain },
    appliedMappings: state.appliedMappings.map(m => ({ ...m })),
    focusedIndex: state.focusedIndex
  });
  const next = history.future.pop();
  state.tokens = [...next.tokens];
  state.cipherToPlain = { ...next.cipherToPlain };
  state.appliedMappings = next.appliedMappings ? next.appliedMappings.map(m => ({ ...m })) : [];
  state.focusedIndex = next.focusedIndex;
  updateHistoryButtons();
  renderAll();
  showToast("↪️ Redo (went forward)");
}

function updateHistoryButtons() {
  const btnUndo = document.getElementById("btn-undo");
  const btnRedo = document.getElementById("btn-redo");
  if (btnUndo) btnUndo.disabled = history.past.length === 0;
  if (btnRedo) btnRedo.disabled = history.future.length === 0;
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  loadSample();
  setupEventListeners();
  updateHistoryButtons();
  renderAll();
});

function loadSample() {
  state.tokens = SAMPLE_CIPHERTEXT.split("");
  state.cipherToPlain = { ...SAMPLE_INITIAL_MAPPINGS };
  state.appliedMappings = SAMPLE_INITIAL_APPLIED.map(m => ({ ...m }));
  state.focusedIndex = null;
  state.highlightedChar = null;
  state.highlightedNgram = null;
}

// ---------------------------------------------------------------------------
// Core Computations & Analysis
// ---------------------------------------------------------------------------

/**
 * Get all alphabetic letters from tokens
 */
function getLettersOnly() {
  return state.tokens.filter(ch => /[A-Z]/i.test(ch)).map(ch => ch.toUpperCase());
}

/**
 * Compute letter counts and percentages
 */
function computeLetterStats() {
  const letters = getLettersOnly();
  const total = letters.length || 1;
  const counts = {};

  for (let i = 65; i <= 90; i++) {
    counts[String.fromCharCode(i)] = 0;
  }

  for (const ch of letters) {
    counts[ch] = (counts[ch] || 0) + 1;
  }

  const stats = Object.entries(counts).map(([char, count]) => ({
    char,
    count,
    percentage: (count / total) * 100,
    mappedTo: state.cipherToPlain[char] || null,
    englishFreq: ENGLISH_FREQS[char] || 0
  }));

  if (state.sortMode === "freq") {
    stats.sort((a, b) => b.count - a.count || a.char.localeCompare(b.char));
  } else {
    stats.sort((a, b) => a.char.localeCompare(b.char));
  }

  return { stats, totalLetters: letters.length };
}

/**
 * Compute n-gram occurrences (bigrams or trigrams)
 */
function computeNgrams(n) {
  const letters = getLettersOnly().join("");
  const counts = {};
  
  for (let i = 0; i <= letters.length - n; i++) {
    const gram = letters.slice(i, i + n);
    counts[gram] = (counts[gram] || 0) + 1;
  }

  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .filter(([_, count]) => count > 1) // only repeated n-grams
    .slice(0, 15)
    .map(([gram, count]) => {
      // Decode preview using current key
      const decoded = gram
        .split("")
        .map(c => state.cipherToPlain[c] || "_")
        .join(" ");
      return { gram, count, decoded };
    });
}

/**
 * Compute double letters (repeats)
 */
function computeDoubleLetters() {
  const letters = getLettersOnly().join("");
  const counts = {};

  for (let i = 0; i < letters.length - 1; i++) {
    if (letters[i] === letters[i + 1]) {
      const doubleGram = letters.slice(i, i + 2);
      counts[doubleGram] = (counts[doubleGram] || 0) + 1;
    }
  }

  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([gram, count]) => {
      const decoded = gram
        .split("")
        .map(c => state.cipherToPlain[c] || "_")
        .join("");
      return { gram, count, decoded };
    });
}

/**
 * Inverted mapping: Plain -> Cipher
 */
function getPlainToCipher() {
  const inverted = {};
  for (const [c, p] of Object.entries(state.cipherToPlain)) {
    if (p) {
      const pUpper = p.toUpperCase();
      if (!inverted[pUpper]) {
        inverted[pUpper] = c.toUpperCase();
      }
    }
  }
  return inverted;
}

/**
 * Detect duplicates / collisions in mappings
 */
function getDuplicatePlainMappings() {
  const plainToCiphers = {};
  const duplicatePlains = new Set();

  for (const [cipher, plain] of Object.entries(state.cipherToPlain)) {
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

// ---------------------------------------------------------------------------
// Mapping Operations & Autofill Synchronization
// ---------------------------------------------------------------------------

function setMapping(cipherChar, plainChar) {
  const c = cipherChar.toUpperCase();
  const p = plainChar ? plainChar.toUpperCase() : null;
  if (p && state.cipherToPlain[c] === p) return;
  if (!p && !state.cipherToPlain[c]) return;

  pushHistory();
  state.appliedMappings = state.appliedMappings.filter(m => m.cipher !== c);
  if (!p) {
    delete state.cipherToPlain[c];
  } else {
    state.cipherToPlain[c] = p;
    state.appliedMappings.unshift({ cipher: c, plain: p });
  }
  renderAll();
}

function removeMapping(cipherChar) {
  const c = cipherChar.toUpperCase();
  if (!state.cipherToPlain[c]) return;

  pushHistory();
  delete state.cipherToPlain[c];
  state.appliedMappings = state.appliedMappings.filter(m => m.cipher !== c);
  renderAll();
}

function clearAllMappings() {
  if (Object.keys(state.cipherToPlain).length === 0) return;
  pushHistory();
  state.cipherToPlain = {};
  state.appliedMappings = [];
  renderAll();
}

// ---------------------------------------------------------------------------
// Space Insertion / Deletion Sync
// ---------------------------------------------------------------------------

function insertSpaceAt(index) {
  pushHistory();
  state.tokens.splice(index + 1, 0, " ");
  state.focusedIndex = index + 2 < state.tokens.length ? index + 2 : index + 1;
  renderAll();
  focusBlank(state.focusedIndex);
}

function removeSpaceAt(index) {
  if (index >= 0 && index < state.tokens.length && state.tokens[index] === " ") {
    pushHistory();
    state.tokens.splice(index, 1);
    state.focusedIndex = Math.max(0, index - 1);
    renderAll();
    focusBlank(state.focusedIndex);
  }
}

function resetAllSpaces() {
  if (!state.tokens.includes(" ")) return;
  pushHistory();
  state.tokens = state.tokens.filter(token => token !== " ");
  state.focusedIndex = null;
  renderAll();
}

// ---------------------------------------------------------------------------
// Rendering Functions
// ---------------------------------------------------------------------------

function renderAll() {
  renderConflictBanner();
  renderAlphabetTables();
  renderCipherWorkspace();
  renderStatistics();
}

/**
 * Render duplicate mapping warning banner
 */
function renderConflictBanner() {
  const banner = document.getElementById("conflict-banner");
  const msgEl = document.getElementById("conflict-message");
  const { duplicatePlains, plainToCiphers } = getDuplicatePlainMappings();

  if (duplicatePlains.size > 0) {
    const details = Array.from(duplicatePlains).map(p => {
      return `Plain '${p}' assigned to [${plainToCiphers[p].join(", ")}]`;
    });
    msgEl.textContent = `Duplicate mapping conflict: ${details.join(" | ")}`;
    banner.classList.remove("hidden");
  } else {
    banner.classList.add("hidden");
  }
}

/**
 * Render Plain alphabet and Encrypted alphabet tables (Image 1 Style)
 * Updates in-place when inputs already exist to preserve keyboard focus.
 */
function renderAlphabetTables() {
  const plainLabelsEl = document.getElementById("plain-alphabet-labels");
  const plainInputsEl = document.getElementById("plain-alphabet-inputs");
  const encryptedInputsEl = document.getElementById("encrypted-alphabet-inputs");
  const encryptedLabelsEl = document.getElementById("encrypted-alphabet-labels");

  const plainToCipher = getPlainToCipher();
  const { duplicatePlains, plainToCiphers } = getDuplicatePlainMappings();

  const assignedCipherLetters = new Set(Object.keys(state.cipherToPlain).map(c => c.toUpperCase()));
  const assignedPlainLetters = new Set(Object.values(state.cipherToPlain).map(p => p.toUpperCase()));

  const inputsAlreadyExist = plainInputsEl.children.length === 26;

  for (let i = 65; i <= 90; i++) {
    const idx = i - 65;
    const letter = String.fromCharCode(i);

    // 1. Plain alphabet Table
    const isCipherAssigned = assignedCipherLetters.has(letter);
    let plainLabelCell = plainLabelsEl.children[idx];
    if (!plainLabelCell) {
      plainLabelCell = document.createElement("div");
      plainLabelCell.textContent = letter;
      plainLabelsEl.appendChild(plainLabelCell);
    }
    plainLabelCell.className = `cell-label ${isCipherAssigned ? "used" : ""}`;
    plainLabelCell.title = isCipherAssigned ? `Cipher letter '${letter}' has been used` : `Cipher letter '${letter}' is available`;

    const cipherMapped = plainToCipher[letter] || "";
    const isConflictPlain = duplicatePlains.has(letter);
    let plainInput = plainInputsEl.children[idx];

    if (!plainInput) {
      plainInput = document.createElement("input");
      plainInput.type = "text";
      plainInput.maxLength = 1;
      plainInput.dataset.plain = letter;
      plainInput.dataset.idx = idx;
      plainInput.title = `Cipher letter that encrypts to plain '${letter}'`;

      plainInput.addEventListener("input", (e) => {
        const val = e.target.value.toUpperCase().replace(/[^A-Z]/g, "");
        e.target.value = val;
        if (val) {
          setMapping(val, letter);
          // Advance to next plain input
          if (idx < 25) {
            plainInputsEl.children[idx + 1].focus();
          }
        } else {
          if (cipherMapped) {
            removeMapping(cipherMapped);
          }
        }
      });

      plainInput.addEventListener("keydown", (e) => {
        if (e.key === "Backspace" || e.key === "Delete") {
          if (cipherMapped) {
            removeMapping(cipherMapped);
          }
        } else if (e.key === "ArrowRight" && idx < 25) {
          plainInputsEl.children[idx + 1].focus();
        } else if (e.key === "ArrowLeft" && idx > 0) {
          plainInputsEl.children[idx - 1].focus();
        }
      });

      plainInputsEl.appendChild(plainInput);
    }

    if (document.activeElement !== plainInput) {
      plainInput.value = cipherMapped;
    }
    plainInput.className = `cell-input ${isConflictPlain ? "conflict" : ""}`;

    // 2. Encrypted alphabet Table
    const plainMapped = state.cipherToPlain[letter] || "";
    const isConflictCipher = plainMapped && duplicatePlains.has(plainMapped.toUpperCase());
    let encInput = encryptedInputsEl.children[idx];

    if (!encInput) {
      encInput = document.createElement("input");
      encInput.type = "text";
      encInput.maxLength = 1;
      encInput.dataset.cipher = letter;
      encInput.dataset.idx = idx;
      encInput.title = `Plain letter decrypted from cipher '${letter}'`;

      encInput.addEventListener("input", (e) => {
        const val = e.target.value.toUpperCase().replace(/[^A-Z]/g, "");
        e.target.value = val;
        if (val) {
          setMapping(letter, val);
          // Advance to next enc input
          if (idx < 25) {
            encryptedInputsEl.children[idx + 1].focus();
          }
        } else {
          removeMapping(letter);
        }
      });

      encInput.addEventListener("keydown", (e) => {
        if (e.key === "Backspace" || e.key === "Delete") {
          removeMapping(letter);
        } else if (e.key === "ArrowRight" && idx < 25) {
          encryptedInputsEl.children[idx + 1].focus();
        } else if (e.key === "ArrowLeft" && idx > 0) {
          encryptedInputsEl.children[idx - 1].focus();
        }
      });

      encryptedInputsEl.appendChild(encInput);
    }

    if (document.activeElement !== encInput) {
      encInput.value = plainMapped;
    }
    encInput.className = `cell-input ${isConflictCipher ? "conflict" : ""}`;

    const isPlainAssigned = assignedPlainLetters.has(letter);
    let encLabelCell = encryptedLabelsEl.children[idx];
    if (!encLabelCell) {
      encLabelCell = document.createElement("div");
      encLabelCell.textContent = letter;
      encryptedLabelsEl.appendChild(encLabelCell);
    }
    encLabelCell.className = `cell-label ${isPlainAssigned ? "used" : ""}`;
    encLabelCell.title = isPlainAssigned ? `Plain letter '${letter}' has been used` : `Plain letter '${letter}' is available`;
  }
}

/**
 * Render Interactive Ciphertext Workspace (Image 2 Style)
 */
function renderCipherWorkspace() {
  const container = document.getElementById("cipher-interactive-container");
  container.innerHTML = "";

  const { duplicatePlains } = getDuplicatePlainMappings();
  const lettersOnly = getLettersOnly();
  const assignedCount = Object.keys(state.cipherToPlain).length;

  document.getElementById("stats-total-chars").textContent = `${lettersOnly.length} letters`;
  document.getElementById("stats-solved-chars").textContent = `${assignedCount}/26 mapped`;

  // Break tokens into lines based on wrapLength
  const wrap = state.wrapLength === "auto" ? 60 : parseInt(state.wrapLength, 10);
  const lines = [];
  for (let i = 0; i < state.tokens.length; i += wrap) {
    lines.push(state.tokens.slice(i, i + wrap));
  }

  let globalTokenIndex = 0;

  lines.forEach((lineTokens, lineIdx) => {
    const lineBlock = document.createElement("div");
    lineBlock.className = "cipher-line-block";

    // Ciphertext Row (Upper)
    const cipherRow = document.createElement("div");
    cipherRow.className = "line-letters-row line-cipher-row";

    // Decrypted Typable Row (Lower)
    const plainRow = document.createElement("div");
    plainRow.className = "line-letters-row line-plain-row";

    lineTokens.forEach((token) => {
      const currentIndex = globalTokenIndex++;
      const isSpace = token === " ";
      const isLetter = /[A-Z]/i.test(token);
      const cipherChar = isLetter ? token.toUpperCase() : token;
      const plainChar = isLetter ? (state.cipherToPlain[cipherChar] || "") : "";
      const isConflict = plainChar && duplicatePlains.has(plainChar.toUpperCase());

      // Check if matches active highlight
      const isMatch = state.highlightedChar && state.highlightedChar === cipherChar;
      const isNgramMatch = isTokenInHighlightedNgram(currentIndex);

      // Cipher slot
      const cipherSlot = document.createElement("span");
      cipherSlot.className = `char-slot ${isSpace ? "space-slot" : ""} ${isMatch ? "highlight-match" : ""} ${isNgramMatch ? "highlight-ngram" : ""}`;
      cipherSlot.textContent = isSpace ? "" : cipherChar;
      cipherRow.appendChild(cipherSlot);

      // Plain typable blank slot
      const plainSlot = document.createElement("span");
      plainSlot.className = `char-slot char-slot-blank ${isSpace ? "space-slot" : ""} ${currentIndex === state.focusedIndex ? "focused" : ""} ${isMatch ? "highlight-match" : ""} ${isNgramMatch ? "highlight-ngram" : ""}`;
      plainSlot.tabIndex = 0;
      plainSlot.dataset.index = currentIndex;
      plainSlot.dataset.cipher = cipherChar;

      if (isSpace) {
        const marker = document.createElement("span");
        marker.className = "space-gap-marker";
        marker.title = "Space (Click or press Backspace to remove)";
        plainSlot.appendChild(marker);
      } else {
        const charSpan = document.createElement("span");
        charSpan.className = `blank-char ${!plainChar ? "empty" : ""} ${isConflict ? "conflict" : ""}`;
        charSpan.textContent = plainChar || "_";
        plainSlot.appendChild(charSpan);
      }

      // Slot interactions
      plainSlot.addEventListener("focus", () => {
        state.focusedIndex = currentIndex;
        state.highlightedChar = isLetter ? cipherChar : null;
        updateSlotHighlights();
      });

      plainSlot.addEventListener("mouseenter", () => {
        if (isLetter && !state.focusedIndex) {
          state.highlightedChar = cipherChar;
          updateSlotHighlights();
        }
      });

      plainSlot.addEventListener("mouseleave", () => {
        if (!state.focusedIndex) {
          state.highlightedChar = null;
          updateSlotHighlights();
        }
      });

      // Click to focus and select slot
      plainSlot.addEventListener("click", () => {
        state.focusedIndex = currentIndex;
        state.highlightedChar = isLetter ? cipherChar : null;
        plainSlot.focus();
        updateSlotHighlights();
      });

      // Typing handler in typable blanks
      plainSlot.addEventListener("keydown", (e) => {
        handleBlankKeyDown(e, currentIndex, cipherChar, isSpace);
      });

      plainRow.appendChild(plainSlot);
    });

    lineBlock.appendChild(cipherRow);
    lineBlock.appendChild(plainRow);
    container.appendChild(lineBlock);
  });

  // Restore keyboard focus if a slot was previously focused
  if (state.focusedIndex !== null) {
    const target = container.querySelector(`.char-slot-blank[data-index="${state.focusedIndex}"]`);
    if (target && document.activeElement !== target) {
      target.focus();
    }
  }
}

/**
 * Check if a token index is part of the highlighted n-gram
 */
function isTokenInHighlightedNgram(tokenIndex) {
  if (!state.highlightedNgram) return false;
  const gram = state.highlightedNgram;
  const n = gram.length;

  // Check window around tokenIndex
  const startIndex = Math.max(0, tokenIndex - n + 1);
  const endIndex = Math.min(state.tokens.length - n, tokenIndex);

  for (let i = startIndex; i <= endIndex; i++) {
    const slice = state.tokens.slice(i, i + n).join("").toUpperCase();
    if (slice === gram) {
      return true;
    }
  }
  return false;
}

/**
 * Fast highlight updater without re-rendering the full DOM
 */
function updateSlotHighlights() {
  const blanks = document.querySelectorAll(".char-slot-blank");
  const cipherSlots = document.querySelectorAll(".line-cipher-row .char-slot");

  blanks.forEach((blank, idx) => {
    const cipher = blank.dataset.cipher;
    const isFocused = parseInt(blank.dataset.index, 10) === state.focusedIndex;
    const isMatch = state.highlightedChar && state.highlightedChar === cipher;
    const isNgram = isTokenInHighlightedNgram(idx);

    blank.classList.toggle("focused", isFocused);
    blank.classList.toggle("highlight-match", !!isMatch);
    blank.classList.toggle("highlight-ngram", !!isNgram);

    if (cipherSlots[idx]) {
      cipherSlots[idx].classList.toggle("highlight-match", !!isMatch);
      cipherSlots[idx].classList.toggle("highlight-ngram", !!isNgram);
    }
  });
}

/**
 * Handle keyboard events in the typable plaintext blanks
 */
function handleBlankKeyDown(e, index, cipherChar, isSpace) {
  // 1. Manual Space Insertion: Spacebar
  if (e.key === " " || e.code === "Space") {
    e.preventDefault();
    insertSpaceAt(index);
    return;
  }

  // 2. Letter input A-Z: Autofill mapping!
  if (/^[a-zA-Z]$/.test(e.key) && !e.ctrlKey && !e.altKey && !e.metaKey) {
    e.preventDefault();
    if (/[A-Z]/i.test(cipherChar)) {
      setMapping(cipherChar, e.key.toUpperCase());
      // Advance to next slot
      moveToNextBlank(index);
    }
    return;
  }

  // 3. Backspace: Clear mapping or remove space
  if (e.key === "Backspace") {
    e.preventDefault();
    if (isSpace) {
      removeSpaceAt(index);
      return;
    }

    // Check if current slot has a mapping
    if (state.cipherToPlain[cipherChar]) {
      removeMapping(cipherChar);
      return;
    }

    // If blank was already empty, move left and delete previous space if any
    if (index > 0) {
      if (state.tokens[index - 1] === " ") {
        removeSpaceAt(index - 1);
      } else {
        moveToPrevBlank(index);
      }
    }
    return;
  }

  // 4. Delete key: Clear mapping or remove current space
  if (e.key === "Delete") {
    e.preventDefault();
    if (isSpace) {
      removeSpaceAt(index);
    } else {
      removeMapping(cipherChar);
    }
    return;
  }

  // 5. Arrow Keys Navigation
  const wrap = state.wrapLength === "auto" ? 60 : parseInt(state.wrapLength, 10);

  if (e.key === "ArrowRight") {
    e.preventDefault();
    moveToNextBlank(index);
  } else if (e.key === "ArrowLeft") {
    e.preventDefault();
    moveToPrevBlank(index);
  } else if (e.key === "ArrowDown") {
    e.preventDefault();
    const target = Math.min(state.tokens.length - 1, index + wrap);
    focusBlank(target);
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    const target = Math.max(0, index - wrap);
    focusBlank(target);
  } else if (e.key === "Tab") {
    // Normal Tab behavior or next blank
    if (!e.shiftKey) {
      e.preventDefault();
      moveToNextBlank(index);
    } else {
      e.preventDefault();
      moveToPrevBlank(index);
    }
  }
}

function moveToNextBlank(currentIndex) {
  let next = currentIndex + 1;
  while (next < state.tokens.length && state.tokens[next] === " ") {
    next++;
  }
  if (next < state.tokens.length) {
    focusBlank(next);
  }
}

function moveToPrevBlank(currentIndex) {
  let prev = currentIndex - 1;
  while (prev >= 0 && state.tokens[prev] === " ") {
    prev--;
  }
  if (prev >= 0) {
    focusBlank(prev);
  }
}

function focusBlank(index) {
  state.focusedIndex = index;
  const target = document.querySelector(`.char-slot-blank[data-index="${index}"]`);
  if (target) {
    target.focus();
  }
}

// ---------------------------------------------------------------------------
// Right Sidebar Cryptanalysis Rendering
// ---------------------------------------------------------------------------

function renderStatistics() {
  renderAppliedMappings();
  renderLetterChart();
  renderBigrams();
  renderTrigrams();
  renderDoubles();
}

/**
 * Render Last Mappings Applied List (Snapshot Feed)
 */
function renderAppliedMappings() {
  const container = document.getElementById("applied-mappings-list");
  const countEl = document.getElementById("applied-mappings-count");
  if (!container) return;

  const count = state.appliedMappings.length;
  if (countEl) {
    countEl.textContent = `${count} applied`;
  }

  if (count === 0) {
    container.innerHTML = `<div class="applied-mappings-empty">No mappings applied yet. Type in any blank to begin.</div>`;
    return;
  }

  const { duplicatePlains } = getDuplicatePlainMappings();

  container.innerHTML = state.appliedMappings.map((m, index) => {
    const isLatest = index === 0;
    const isConflict = duplicatePlains.has(m.plain);
    return `
      <div class="mapping-chip ${isLatest ? "latest" : ""} ${isConflict ? "conflict" : ""}" data-cipher="${m.cipher}" title="Click to highlight '${m.cipher}' in text">
        <span class="chip-cipher">${m.cipher}</span>
        <span class="chip-arrow">→</span>
        <span class="chip-plain">${m.plain}</span>
        <span class="chip-delete" data-delete-cipher="${m.cipher}" title="Remove mapping ${m.cipher} → ${m.plain}">&times;</span>
      </div>
    `;
  }).join("");

  container.querySelectorAll(".mapping-chip").forEach(chip => {
    chip.addEventListener("click", (e) => {
      const deleteBtn = e.target.closest("[data-delete-cipher]");
      if (deleteBtn) {
        e.stopPropagation();
        removeMapping(deleteBtn.dataset.deleteCipher);
        return;
      }

      const cipher = chip.dataset.cipher;
      state.highlightedChar = (state.highlightedChar === cipher) ? null : cipher;
      state.highlightedNgram = null;
      renderCipherWorkspace();
      renderLetterChart();
    });
  });
}

/**
 * Render comparative SVG Bar Chart: Ciphertext % vs English Standard %
 */
function renderLetterChart() {
  const container = document.getElementById("letter-chart-container");
  const { stats, totalLetters } = computeLetterStats();

  const rowHeight = 22;
  const chartHeight = stats.length * rowHeight + 10;
  const svgWidth = 320;
  const labelWidth = 55;
  const barMaxWidth = 180;
  const maxPercent = 16; // scaling max

  let rowsSvg = "";

  stats.forEach((item, idx) => {
    const y = idx * rowHeight + 6;
    const cipherWidth = Math.min(barMaxWidth, (item.percentage / maxPercent) * barMaxWidth);
    const englishWidth = Math.min(barMaxWidth, (item.englishFreq / maxPercent) * barMaxWidth);
    const mapped = item.mappedTo ? `→ ${item.mappedTo}` : "";
    const isSelected = state.highlightedChar === item.char;

    rowsSvg += `
      <g class="chart-bar-group ${isSelected ? "active" : ""}" data-char="${item.char}">
        <!-- Letter & mapping text -->
        <text x="2" y="${y + 12}" font-family="var(--font-mono)" font-size="11" font-weight="700" fill="#0f172a">
          ${item.char} ${mapped ? `<tspan fill="#1d72b8">${mapped}</tspan>` : ""}
        </text>
        
        <!-- English reference bar (amber outline) -->
        <rect x="${labelWidth}" y="${y}" width="${englishWidth}" height="7" rx="2" fill="#f59e0b" opacity="0.75" />
        
        <!-- Ciphertext bar (solid blue) -->
        <rect class="bar-cipher" x="${labelWidth}" y="${y + 8}" width="${cipherWidth}" height="7" rx="2" fill="#2563eb" />
        
        <!-- Count & % text -->
        <text x="${labelWidth + Math.max(cipherWidth, englishWidth) + 8}" y="${y + 11}" font-size="10" fill="#64748b">
          ${item.count} (${item.percentage.toFixed(1)}%)
        </text>
      </g>
    `;
  });

  container.innerHTML = `
    <svg class="freq-chart-svg" viewBox="0 0 ${svgWidth} ${chartHeight}" height="${chartHeight}">
      ${rowsSvg}
    </svg>
  `;

  // Attach click listener on bar groups
  container.querySelectorAll(".chart-bar-group").forEach(group => {
    group.addEventListener("click", () => {
      const char = group.dataset.char;
      state.highlightedChar = (state.highlightedChar === char) ? null : char;
      state.highlightedNgram = null;
      renderCipherWorkspace();
      renderLetterChart();
    });
  });
}

/**
 * Render Bigrams List
 */
function renderBigrams() {
  const cipherListEl = document.getElementById("cipher-bigrams-list");
  const englishListEl = document.getElementById("english-bigrams-list");

  const bigrams = computeNgrams(2);

  cipherListEl.innerHTML = bigrams.map(b => `
    <div class="ngram-row ${state.highlightedNgram === b.gram ? "active" : ""}" data-ngram="${b.gram}">
      <span class="ngram-label">${b.gram}</span>
      <span class="ngram-decrypted">${b.decoded}</span>
      <span class="ngram-count">${b.count}</span>
    </div>
  `).join("");

  englishListEl.innerHTML = ENGLISH_TOP_BIGRAMS.slice(0, 15).map(bg => `
    <div class="ngram-row">
      <span class="ngram-label">${bg}</span>
    </div>
  `).join("");

  // Attach click handler to highlight n-gram in ciphertext
  cipherListEl.querySelectorAll(".ngram-row").forEach(row => {
    row.addEventListener("click", () => {
      const ngram = row.dataset.ngram;
      state.highlightedNgram = (state.highlightedNgram === ngram) ? null : ngram;
      state.highlightedChar = null;
      renderCipherWorkspace();
      renderBigrams();
    });
  });
}

/**
 * Render Trigrams List
 */
function renderTrigrams() {
  const cipherListEl = document.getElementById("cipher-trigrams-list");
  const englishListEl = document.getElementById("english-trigrams-list");

  const trigrams = computeNgrams(3);

  cipherListEl.innerHTML = trigrams.map(t => `
    <div class="ngram-row ${state.highlightedNgram === t.gram ? "active" : ""}" data-ngram="${t.gram}">
      <span class="ngram-label">${t.gram}</span>
      <span class="ngram-decrypted">${t.decoded}</span>
      <span class="ngram-count">${t.count}</span>
    </div>
  `).join("");

  englishListEl.innerHTML = ENGLISH_TOP_TRIGRAMS.slice(0, 15).map(tg => `
    <div class="ngram-row">
      <span class="ngram-label">${tg}</span>
    </div>
  `).join("");

  cipherListEl.querySelectorAll(".ngram-row").forEach(row => {
    row.addEventListener("click", () => {
      const ngram = row.dataset.ngram;
      state.highlightedNgram = (state.highlightedNgram === ngram) ? null : ngram;
      state.highlightedChar = null;
      renderCipherWorkspace();
      renderTrigrams();
    });
  });
}

/**
 * Render Double Letters (Repeats)
 */
function renderDoubles() {
  const container = document.getElementById("cipher-doubles-list");
  const doubles = computeDoubleLetters();

  if (doubles.length === 0) {
    container.innerHTML = `<span style="font-size:12px; color:#64748b;">No double letters detected</span>`;
    return;
  }

  container.innerHTML = doubles.map(d => `
    <div class="double-chip ${state.highlightedNgram === d.gram ? "active" : ""}" data-ngram="${d.gram}">
      <span class="double-label">${d.gram}</span>
      <span class="double-decrypted">(${d.decoded})</span>
      <span class="double-count">×${d.count}</span>
    </div>
  `).join("");

  container.querySelectorAll(".double-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const ngram = chip.dataset.ngram;
      state.highlightedNgram = (state.highlightedNgram === ngram) ? null : ngram;
      state.highlightedChar = null;
      renderCipherWorkspace();
      renderDoubles();
    });
  });
}

// ---------------------------------------------------------------------------
// Event Listeners & UI Controls
// ---------------------------------------------------------------------------

function setupEventListeners() {
  // Undo & Redo Buttons
  const btnUndo = document.getElementById("btn-undo");
  const btnRedo = document.getElementById("btn-redo");
  if (btnUndo) btnUndo.addEventListener("click", undo);
  if (btnRedo) btnRedo.addEventListener("click", redo);

  // Global Keyboard Shortcuts: Ctrl+Z (Undo) and Ctrl+Y / Ctrl+Shift+Z (Redo)
  window.addEventListener("keydown", (e) => {
    // If typing in the custom ciphertext textarea, allow standard text undo
    if (e.target && e.target.tagName === "TEXTAREA") {
      return;
    }

    const isCtrlOrCmd = e.ctrlKey || e.metaKey;
    if (!isCtrlOrCmd) return;

    // Ctrl+Z (without Shift) -> Undo
    if ((e.key === "z" || e.key === "Z") && !e.shiftKey) {
      e.preventDefault();
      undo();
      return;
    }

    // Ctrl+Y or Ctrl+Shift+Z -> Redo
    if ((e.key === "y" || e.key === "Y") || (e.shiftKey && (e.key === "z" || e.key === "Z"))) {
      e.preventDefault();
      redo();
      return;
    }
  });

  // Load Sample Button
  document.getElementById("btn-load-sample").addEventListener("click", () => {
    pushHistory();
    loadSample();
    renderAll();
    showToast("Loaded sample ciphertext from screenshot");
  });

  // Reset Spaces Button
  document.getElementById("btn-clear-spaces").addEventListener("click", () => {
    resetAllSpaces();
    showToast("Removed all manually inserted spaces");
  });

  // Clear Key Button
  document.getElementById("btn-clear-mappings").addEventListener("click", () => {
    if (confirm("Clear all letter substitutions?")) {
      clearAllMappings();
      showToast("Cleared all substitutions");
    }
  });

  // Copy Plaintext Button
  document.getElementById("btn-copy-solution").addEventListener("click", () => {
    const plainText = state.tokens.map(token => {
      if (token === " ") return " ";
      if (/[A-Z]/i.test(token)) {
        return state.cipherToPlain[token.toUpperCase()] || "_";
      }
      return token;
    }).join("");

    navigator.clipboard.writeText(plainText).then(() => {
      showToast("Plaintext copied to clipboard!");
    }).catch(() => {
      showToast("Could not copy to clipboard");
    });
  });

  // Frequency Sorting Toggles
  const btnFreq = document.getElementById("btn-sort-freq");
  const btnAz = document.getElementById("btn-sort-az");

  btnFreq.addEventListener("click", () => {
    state.sortMode = "freq";
    btnFreq.classList.add("active");
    btnAz.classList.remove("active");
    renderStatistics();
  });

  btnAz.addEventListener("click", () => {
    state.sortMode = "az";
    btnAz.classList.add("active");
    btnFreq.classList.remove("active");
    renderStatistics();
  });

  // Wrap length selector
  document.getElementById("line-width-select").addEventListener("change", (e) => {
    state.wrapLength = e.target.value;
    renderCipherWorkspace();
  });

  // Custom Ciphertext Modal
  const modal = document.getElementById("paste-modal");
  const btnOpenModal = document.getElementById("btn-open-paste-modal");
  const btnCloseModal = document.getElementById("btn-close-modal");
  const btnCancelModal = document.getElementById("btn-modal-cancel");
  const btnApplyModal = document.getElementById("btn-modal-apply");
  const textareaInput = document.getElementById("custom-ciphertext-input");

  btnOpenModal.addEventListener("click", () => {
    textareaInput.value = state.tokens.join("");
    modal.classList.remove("hidden");
    textareaInput.focus();
  });

  const closeModal = () => modal.classList.add("hidden");
  btnCloseModal.addEventListener("click", closeModal);
  btnCancelModal.addEventListener("click", closeModal);

  btnApplyModal.addEventListener("click", () => {
    let text = textareaInput.value;
    const isUppercase = document.getElementById("opt-uppercase").checked;
    const isStripPunct = document.getElementById("opt-strip-punct").checked;

    if (isUppercase) {
      text = text.toUpperCase();
    }
    if (isStripPunct) {
      text = text.replace(/[^A-Za-z\s]/g, "");
    }

    if (text.trim().length === 0) {
      alert("Please enter some text!");
      return;
    }

    pushHistory();
    state.tokens = text.split("");
    state.focusedIndex = null;
    state.highlightedChar = null;
    state.highlightedNgram = null;
    closeModal();
    renderAll();
    showToast("Loaded custom ciphertext");
  });
}

function showToast(message) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.classList.remove("hidden");
  setTimeout(() => {
    toast.classList.add("hidden");
  }, 2400);
}
