# Class 4 — JavaScript Functions in Phishing Detection

The `static/` folder has 4 JavaScript files. **Important:** only `script.js` is actually loaded by every page
(via `base.html`). The other three (`analyzer.js`, `dashboard.js`, `history.js`) are **not currently linked**
with `<script src="...">` tags in their matching templates — each page instead has its own inline `<script>`
block at the bottom of the HTML file that does the real work. These `.js` files represent the *original,
cleaner design intent* for the app, so they're still great to study even though they aren't the code actually
running today.

---

## 1. `script.js` — Shared Utilities (loaded on every page)

This is the only file loaded globally, via `base.html`, at the very bottom of `<body>`. It holds small
reusable helper functions so every page doesn't have to repeat the same logic.

| Function | What it does |
|---|---|
| `showLoading(elementId)` / `hideLoading(elementId)` | Toggles the `hidden` CSS class on a spinner element, to show/hide a loading indicator during API calls. |
| `showError(message, elementId='errorSection')` / `hideError(elementId)` | Writes an error message into `#errorMessage` and reveals the container with id `elementId`. Defaults to an element called `errorSection`. |
| `formatDate(dateString)` | Wraps `new Date(dateString)` and returns a human-readable `"date time"` string using `toLocaleDateString()` + `toLocaleTimeString()`. |
| `getRiskLevelClass(riskLevel)` | Maps a risk level string (`Low`/`Moderate`/`High`/`Critical`) to a CSS class name for coloring badges. |
| `getRiskBadge(riskLevel)` | Maps a risk level to an emoji (✅ ⚠️ ❌ 🚨) for quick visual scanning. |
| `apiCall(url, options)` | A `fetch()` wrapper: sets JSON headers, checks `response.ok`, throws on failure, and returns parsed JSON. Centralizes error handling for every API request. |
| `setupTabs()` | Wires up click handlers for `.tab-button` elements to switch between `.tab-content` panels (e.g. "paste email" vs "upload file" tabs). |
| `setupFileInput()` | Listens for a file being chosen in an `#emailFile` input and logs the filename. |
| `resetAnalyzer()` | Resets the analyzer form and hides errors/results — used by a "Analyze Another" button. |
| `closeModal(modalId)` | Hides a modal dialog by id. |

**Key teaching point:** because this file is loaded *after* every page's own inline script, any function name
it defines (like `showError`) will silently overwrite a same-named function defined earlier in a page's own
`<script>` block. This caused a real bug earlier in this project — always avoid name collisions with `script.js`.

---

## 2. `analyzer.js` — Email Analyzer Page Logic (currently unused by analyzer.html)

Intended to run on the `/analyzer` page and handle the "paste email → get results" flow.

| Function | What it does |
|---|---|
| `handleAnalyze(event)` | The form's `submit` handler. Prevents the default page reload, validates that either pasted text or an uploaded file was provided, builds a `FormData` object, and `POST`s it to `/api/analyze`. On success it calls `displayResults()`; on failure it calls `showError()`. |
| `displayResults(analysis)` | Takes the JSON response and paints it into the DOM: risk score/percentage, risk level badge and color, the list of detected indicators, the AI explanation text, parsed email details (sender/subject/links/emails found), and the recommendations list. Then scrolls smoothly to the results section. |
| `setupResultActions()` | Wires up "Analyze Another" (resets the form) and "View History" (navigates to `/history`) buttons. |
| `loadSampleEmail()` | Fills the textarea with a canned phishing example so users can try the tool without writing their own email. |

**Teaching point:** notice the validation pattern — always check user input *before* making a network request
(`if (!emailText && !emailFile) { showError(...); return; }`), and always wrap the `fetch()` call in
`try/catch/finally` so the loading spinner reliably turns off even if the request fails.

---

## 3. `history.js` — Analysis History Page Logic (currently unused by history.html)

Intended to run on the `/history` page and show a table of every past analysis.

| Function | What it does |
|---|---|
| `loadHistory()` | Fetches the analysis list and stats, then calls `displayHistory()` and `updateStatistics()`. |
| `displayHistory(analyses)` | Builds one `<tr>` per analysis: formatted date, type, risk score/level (with emoji badge), a truncated content preview, and "View"/"Delete" buttons wired to `viewDetail()` / `deleteAnalysis()`. |
| `updateStatistics(stats)` | Fills in summary numbers at the top of the page: total analyses, average risk score, and counts of Critical/High risk emails. |
| `viewDetail(analysisId)` | Fetches one analysis by id and opens a modal with the full details via `displayDetailModal()`. |
| `displayDetailModal(analysis)` | Renders a detailed modal: date, type, risk score, all detected indicators, the full AI explanation, all recommendations, and the first 500 characters of the original email (HTML-escaped for safety). |
| `deleteAnalysis(analysisId)` | Confirms with the user, then `POST`s to the delete endpoint and refreshes the list. |
| `setupFilters()` / `applyFilters()` | Wires up the search box and risk-level dropdown to filter the visible table rows live as you type. |

**Teaching point:** `escapeHtml()` is used before injecting raw email content into `innerHTML` — this prevents
a **stored XSS vulnerability**, since a malicious email could otherwise contain `<script>` tags that execute
when displayed. Always escape untrusted content before rendering it as HTML.

---

## 4. `dashboard.js` — Dashboard Page Logic (currently unused by dashboard.html)

Intended to run on the `/dashboard` page and show a summary + chart.

| Function | What it does |
|---|---|
| `loadDashboardData()` | Fetches history/stats data and calls `updateMetrics()`, `updateRecentAnalyses()`, and `renderRiskChart()`. |
| `updateMetrics(stats)` | Updates the small stat boxes: total analyses, average risk %, and counts of Critical/High risk emails. |
| `updateRecentAnalyses(analyses)` | Renders the last analyses into a table, similar to `history.js`'s table but simpler (no filters/delete). |
| `renderRiskChart(riskDistribution)` | Uses the **Chart.js** library to draw a doughnut chart of how many emails fall into each risk level (Low/Moderate/High/Critical), with a custom color per level and a tooltip showing the count. |

**Teaching point:** `if (riskChart) { riskChart.destroy(); }` before creating a new chart — this prevents memory
leaks and duplicate/overlapping charts if the dashboard data reloads more than once.

---

## Common Patterns Across All Files

1. **`DOMContentLoaded` listener** at the top of each file — ensures the script only touches the DOM once the
   HTML has fully loaded, avoiding "cannot read property of null" errors.
2. **`async`/`await` with `try/catch`** for every network call — keeps error handling consistent and readable.
3. **Separation of concerns** — one function fetches data, a different function renders it. This makes each
   function easier to test and reuse.
4. **Template literals** (`` `${...}` ``) to build HTML strings for table rows instead of string concatenation.
