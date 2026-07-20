#!/usr/bin/env node
// VERIFY THE BUILT BUNDLE AGAINST THE CSP. Do not assume Vite's output complies.
//
// vite.config.ts asks for output that runs under
//
//   default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'
//
// This script checks what we GOT. The difference matters: the config records an
// intention, and a Vite minor release can change a default without changing a
// line of it. Every failure below is a real thing that a default build does.
//
// WHAT THIS CANNOT DO, stated so nobody reads a pass as more than it is: it is
// a static scan of emitted files. It cannot see a URL assembled at runtime from
// string fragments, and it does not execute the page. The live proof is the
// network counter in the running app, which counts what the browser actually
// fetched; this script is the cheap check that runs before you get there.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, extname } from "node:path";

const root = process.argv[2] ?? "dist";
const failures = [];
const notes = [];

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...walk(path));
    else out.push(path);
  }
  return out;
}

let files;
try {
  files = walk(root);
} catch {
  console.error(`check-csp: '${root}' does not exist. Run 'npm run build' first.`);
  process.exit(1);
}

const html = files.filter((f) => extname(f) === ".html");
const js = files.filter((f) => extname(f) === ".js");
const css = files.filter((f) => extname(f) === ".css");

if (html.length === 0) failures.push("no HTML in the build output");

/**
 * HTML comments, removed before scanning.
 *
 * WHY THIS IS NOT A DETAIL: index.html's own comment explains that Vite's
 * module-preload polyfill emits an inline `<script>`. The literal text
 * "<script>" inside that prose made the inline-script check match the comment
 * and run to the NEXT real `</script>`, so the first run of this script failed
 * on the sentence describing the thing it was checking for. A checker that
 * reports a violation the build does not have is worse than no checker: the
 * next person silences it, and then it is not watching when it matters.
 */
function stripComments(source) {
  return source.replace(/<!--[\s\S]*?-->/g, "");
}

for (const file of html) {
  const source = stripComments(readFileSync(file, "utf8"));

  // 1. INLINE SCRIPT. `script-src 'self'` refuses it, silently. This is what
  //    Vite's modulePreload polyfill emits by default.
  for (const match of source.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
    const [, attrs, body] = match;
    if (body.trim().length > 0 && !/\bsrc=/.test(attrs)) {
      failures.push(`${file}: inline <script> body (script-src 'self' blocks it)`);
    }
  }

  // 2. INLINE STYLE ELEMENT. `style-src 'self'` refuses it.
  for (const match of source.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/g)) {
    if (match[1].trim().length > 0) {
      failures.push(`${file}: inline <style> element (style-src 'self' blocks it)`);
    }
  }

  // 3. STYLE ATTRIBUTE IN MARKUP. Governed by style-src-attr, which falls back
  //    to style-src. NOTE the asymmetry that makes this app work at all:
  //    React's `style={{...}}` prop is NOT this -- it writes through
  //    `node.style.setProperty` (CSSOM), which CSP does not govern. Only a
  //    style attribute parsed out of HTML is blocked, which is why the check is
  //    on the HTML files and not on the JS.
  if (/<[^>]+\sstyle=["']/.test(source)) {
    failures.push(`${file}: style="" attribute in markup (style-src 'self' blocks it)`);
  }

  // 4. THE POLICY ITSELF has to be present and has to be the strict one. A
  //    build that dropped the meta tag would pass every other check here while
  //    enforcing nothing at all.
  // `[^"]+` for the content, NOT `[^"']+`. A CSP is full of single quotes --
  // 'none', 'self' -- so a character class excluding them captures only
  // "default-src " and then reports every directive as missing. That was the
  // second false positive on this script's first run, and it failed in the
  // direction that looks like a real problem, which is the expensive direction.
  const csp = /http-equiv=["']Content-Security-Policy["'][^>]*content=["']([^"]+)["']/i.exec(
    source,
  );
  if (!csp) {
    failures.push(`${file}: no Content-Security-Policy meta tag`);
  } else {
    const policy = csp[1];
    for (const required of [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "connect-src 'self'",
    ]) {
      if (!policy.includes(required)) {
        failures.push(`${file}: CSP is missing "${required}"`);
      }
    }
    // 'unsafe-inline' and 'unsafe-eval' are the two escapes that would make
    // every check above vacuous. If a dependency needs either, the rule is that
    // the dependency does not ship.
    for (const banned of ["'unsafe-inline'", "'unsafe-eval'"]) {
      if (policy.includes(banned)) {
        failures.push(`${file}: CSP contains ${banned}`);
      }
    }
  }
}

// 5. REMOTE ORIGINS. `default-src 'none'` means every one of these is a request
//    the browser refuses -- so the symptom is a missing font or a dead image,
//    not an error anyone reads.
//
//    HTML AND CSS ARE DECIDABLE and are checked as such: a remote URL in a
//    `src`/`href` attribute or in a `url()` is a load, full stop.
//
//    MINIFIED JS IS NOT DECIDABLE BY REGEX, and pretending otherwise is how a
//    checker becomes noise. React embeds "http://www.w3.org/1999/xlink" as an
//    SVG namespace and "https://reactjs.org" in an error message; neither is
//    ever fetched. The first version of this script tried to tell a load from a
//    mention by looking for `src=`/`href=` within twenty characters, and
//    flagged `xlinkHref","http://www.w3.org/1999/xlink"` as a CDN load. A
//    heuristic that cries wolf on React's own namespace table gets muted, and a
//    muted check is not a check.
//
//    So JS is handled by REVIEW instead of by inference: every distinct origin
//    in the bundle must be on the list below, each with the reason it is inert.
//    A new origin -- which is what adding a CDN dependency looks like -- fails,
//    and the fix is for a human to look at it and either remove it or write
//    down why it is harmless. That is a smaller claim than "we proved nothing
//    is loaded", and it is one this script can actually keep.
const KNOWN_INERT_ORIGINS = {
  "http://www.w3.org":
    "XML/SVG/MathML namespace URIs in React DOM's attribute tables. Namespace " +
    "identifiers, never dereferenced.",
  "https://reactjs.org":
    "The docs link in React's minified-error message. Text in a string, only " +
    "ever printed.",
  "https://react.dev":
    "As above; React moved the docs domain and both spellings appear across " +
    "versions.",
  "https://tailwindcss.com":
    "The attribution comment at the top of Tailwind's emitted stylesheet.",
};

const remote = /\bhttps?:\/\/(?!localhost|127\.0\.0\.1)[a-z0-9.-]+/gi;

// HTML and CSS: decidable, so failures.
for (const file of [...html, ...css]) {
  const source = stripComments(readFileSync(file, "utf8"));
  const loads = [
    ...source.matchAll(/(?:src|href|action)\s*=\s*["'](https?:\/\/[^"']+)["']/gi),
    ...source.matchAll(/url\(\s*["']?(https?:\/\/[^"')]+)/gi),
    ...source.matchAll(/@import\s+["'](https?:\/\/[^"']+)["']/gi),
  ];
  for (const [, url] of loads) {
    if (/^https?:\/\/(localhost|127\.0\.0\.1)/.test(url)) continue;
    failures.push(`${file}: loads from a remote origin: ${url}`);
  }
}

// JS: not decidable, so reviewed.
for (const file of js) {
  const source = readFileSync(file, "utf8");
  const origins = [...new Set(source.match(remote) ?? [])];
  for (const origin of origins) {
    if (origin in KNOWN_INERT_ORIGINS) {
      notes.push(`${file}: ${origin} - ${KNOWN_INERT_ORIGINS[origin]}`);
    } else {
      failures.push(
        `${file}: unreviewed remote origin ${origin}. If it is never fetched, ` +
          `add it to KNOWN_INERT_ORIGINS in this script with the reason. If it ` +
          `is fetched, the dependency does not ship.`,
      );
    }
  }
}

// 6. data: URIs. `default-src 'none'` has no `data:` source, so an inlined
//    asset is a resource the page requests and the policy denies. This is what
//    `assetsInlineLimit: 0` prevents; the check is that it still does.
for (const file of [...css, ...html]) {
  const source = readFileSync(file, "utf8");
  if (/url\(\s*["']?data:/.test(source)) {
    failures.push(`${file}: data: URI in a url() (default-src 'none' blocks it)`);
  }
}

const total = { html: html.length, js: js.length, css: css.length };
console.log(
  `check-csp: scanned ${total.html} HTML, ${total.js} JS, ${total.css} CSS in ${root}/`,
);
for (const note of notes) console.log(`  note: ${note}`);

if (failures.length > 0) {
  console.error("\ncheck-csp: FAIL");
  for (const failure of failures) console.error(`  - ${failure}`);
  console.error(
    "\nThe built bundle would not run under the panel's CSP. Fix the build,\n" +
      "not the policy: if a dependency needs 'unsafe-inline', it does not ship.",
  );
  process.exit(1);
}

console.log(
  "check-csp: PASS - the bundle runs under\n" +
    "  default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'",
);
