# Substitution Cipher Solver 🔤

A responsive, interactive WebUI tool for cryptanalyzing and solving monoalphabetic substitution ciphers. Features bidirectional autofill, duplicate mapping conflict detection, synchronized manual space management, undo/redo history, and a cryptanalysis sidebar with letter frequency comparison graphs, bigrams, and trigrams.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-ready--to--publish-success.svg)

---

## 🚀 Live Demo on GitHub Pages

Once published to your repository, your site will be live at:
```
https://<your-username>.github.io/<your-repo-name>/
```

---

## ✨ Features

- **Dual Alphabet Mapping Tables**:
  - **Plain Alphabet**: Plain A–Z row over 26 typable cipher inputs (used ciphertext letters are grayed out).
  - **Encrypted Alphabet**: 26 typable plaintext inputs over encrypted A–Z row (used plaintext letters are grayed out).
  - Both tables are synchronized bi-directionally with each other and the text.
- **Interactive Ciphertext Workspace**:
  - Monospaced column alignment where each ciphertext character sits directly above its typable blank.
  - **Autofill**: Typing a letter under any character instantly fills all occurrences of that character across the entire text.
  - **Arrow Key Navigation**: Move seamlessly with <kbd>←</kbd>, <kbd>→</kbd>, <kbd>↑</kbd>, <kbd>↓</kbd>, and auto-advance.
  - **Matching Character Highlights**: Focus or hover on any character to highlight all identical cipher characters.
- **Manual Space Insertion & Deletion**:
  - Press <kbd>Space</kbd> on any blank to insert a space into **both** the ciphertext row and the plaintext row, keeping columns perfectly aligned.
  - Press <kbd>Backspace</kbd> on a space to remove it from both rows.
  - One-click **Reset Spaces** button.
- **Go Back (Undo) & Go Forward (Redo)**:
  - Toolbar buttons: **Undo** (`↩️`) and **Redo** (`↪️`).
  - Keyboard shortcuts: <kbd>Ctrl+Z</kbd> / <kbd>Cmd+Z</kbd> (Undo) and <kbd>Ctrl+Y</kbd> / <kbd>Ctrl+Shift+Z</kbd> (Redo).
  - Tracks all substitution edits, spaces, sample loads, and key clears.
- **Duplicate Conflict Highlighting**:
  - Instantly detects if two ciphertext letters map to the same plaintext letter, highlighting the inputs and blanks in red with an alert banner.
- **Cryptanalysis Sidebar**:
  - **Letter Frequency Analysis**: Interactive SVG chart comparing ciphertext letter percentages against standard English letter frequencies (sortable by frequency or alphabetically A–Z, with click-to-highlight).
  - **Bigrams Analysis**: Top 2-letter sequences with counts, percentages, live decoded previews, and standard English reference list.
  - **Trigrams Analysis**: Top 3-letter sequences with counts, percentages, live decoded previews, and standard English reference list.
  - **Double Letters (Repeats)**: Chips for repeated letters (`FF`, `AA`, `TT`...).

---

## 📦 How to Publish to GitHub Pages

This repository is ready to publish to GitHub Pages out-of-the-box with pure static HTML, CSS, and JavaScript.

### Method 1: GitHub Actions (Recommended)

1. Push your repository to GitHub:
   ```bash
   git add .
   git commit -m "Initial commit for Substitution Cipher Solver"
   git remote add origin https://github.com/<your-username>/<your-repo-name>.git
   git push -u origin master
   ```
2. In your GitHub repository, navigate to **Settings** > **Pages**.
3. Under **Build and deployment** > **Source**, select **GitHub Actions**.
4. The workflow in `.github/workflows/deploy.yml` will automatically trigger and deploy your site within 1–2 minutes!

### Method 2: Classic Branch Deploy

1. In your GitHub repository, navigate to **Settings** > **Pages**.
2. Under **Build and deployment** > **Source**, select **Deploy from a branch**.
3. Choose branch: **master** (or **main**), folder: **/ (root)**, and click **Save**.
4. GitHub Pages will build and publish your site directly from the root directory.

---

## 💻 Local Development

No complex build steps or heavy dependencies required.

### With Bun (Recommended)
```bash
# Run the local server
bun dev

# Run automated tests
bun test
```
Visit `http://localhost:3000` in your browser.

### Direct File Open
You can also directly open `index.html` in any modern web browser.

---

## 🧪 Tests

Automated tests are included to verify frequency calculation, n-gram extraction, duplicate conflict detection, space synchronization, and undo/redo history:

```bash
bun test
```

---

## 📄 License

MIT
