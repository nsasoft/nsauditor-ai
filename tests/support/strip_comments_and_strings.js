// tests/support/strip_comments_and_strings.js
// ─────────────────────────────────────────────────────────────────────────────
// THE JS LEXER THAT BLANKS COMMENTS AND LITERAL TEXT, for this repository's source censuses (EE board B158's Community
// half: the fetch redirect-policy census and the status-class vocabulary census). The function below is copied byte for
// byte from Enterprise's tests/support/strip_comments_and_strings.js at EE 3d6a0b6; no Community test imports anything from
// the Enterprise checkout, so a census here can never pass vacuously the day that checkout is absent.
//
// Removes /* */ and // comments and the text of string and template literals — keeping the CODE inside a template's
// `${...}` — so a word in prose, a comment or a string never reads as code. Conservative: over-stripping is acceptable,
// because a real call is bare code, never inside a string or a comment.
// A `.js` file: the suite globs tests/**/*.test.mjs, and this is a helper, not a test.
// ─────────────────────────────────────────────────────────────────────────────
export function stripCommentsAndStrings(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  // states: code | line-comment | block-comment | single | double | template | regex
  let state = "code";
  let lastSig;          // last significant code char emitted (regex-vs-division disambiguation)
  let inClass = false;  // inside a [...] char class within a regex literal
  // Stack of brace-depths, one frame per open `${` expression we are inside.
  // Entering `${` pushes a 0-depth frame and switches to "code" (expression code
  // is preserved); a `}` at frame-depth 0 pops back to the enclosing "template".
  const templateExprDepth = [];
  // After a value (identifier / number / ) / ] / string / regex) a `/` is DIVISION;
  // otherwise it begins a regex literal. Strings/template/regex close by setting lastSig
  // to a value-end (`)`) so a following `/` is correctly read as division.
  const isValueEnd = (ch) => ch !== undefined && /[A-Za-z0-9_$)\]]/.test(ch);
  while (i < n) {
    const c = src[i];
    const c2 = i + 1 < n ? src[i + 1] : "";
    if (state === "code") {
      if (c === "/" && c2 === "/") { state = "line-comment"; i += 2; continue; }
      if (c === "/" && c2 === "*") { state = "block-comment"; i += 2; continue; }
      // A regex literal (NOT division). Drop its contents so a method-name inside a
      // pattern can't leak as code AND a quote inside it can't desync the string scanner
      // (e.g. `.replace(/'/g, "")` at plugins/1130:5746 would otherwise mask a later
      // mutating call — a read-only-guarantee false-negative).
      if (c === "/" && !isValueEnd(lastSig)) { state = "regex"; inClass = false; out += " "; i += 1; continue; }
      if (c === "'") { state = "single"; out += " "; i += 1; continue; }
      if (c === '"') { state = "double"; out += " "; i += 1; continue; }
      if (c === "`") { state = "template"; out += " "; i += 1; continue; }
      // Brace tracking only matters while we are inside a template `${...}` expr.
      if (templateExprDepth.length) {
        if (c === "{") { templateExprDepth[templateExprDepth.length - 1] += 1; out += c; lastSig = c; i += 1; continue; }
        if (c === "}") {
          if (templateExprDepth[templateExprDepth.length - 1] === 0) {
            // matching close of `${ … }` → resume blanking template literal text
            templateExprDepth.pop();
            state = "template";
            out += " ";
            i += 1; continue;
          }
          templateExprDepth[templateExprDepth.length - 1] -= 1; out += c; lastSig = c; i += 1; continue;
        }
      }
      if (!/\s/.test(c)) lastSig = c;
      out += c; i += 1; continue;
    }
    if (state === "regex") {
      if (c === "\\") { i += 2; continue; }                   // escape — skip the escaped char
      if (c === "\n") { state = "code"; out += "\n"; i += 1; continue; } // unterminated — bail to code
      if (c === "[") { inClass = true; i += 1; continue; }    // enter [...] char class (/ is literal inside)
      if (c === "]") { inClass = false; i += 1; continue; }
      if (c === "/" && !inClass) { state = "code"; lastSig = ")"; i += 1; continue; } // close
      i += 1; continue;                                       // drop regex-body chars
    }
    if (state === "line-comment") {
      if (c === "\n") { state = "code"; out += "\n"; }
      i += 1; continue;
    }
    if (state === "block-comment") {
      if (c === "*" && c2 === "/") { state = "code"; i += 2; continue; }
      if (c === "\n") out += "\n"; // preserve line count
      i += 1; continue;
    }
    if (state === "single") {
      if (c === "\\") { i += 2; continue; } // skip escaped char
      if (c === "'") { state = "code"; lastSig = ")"; }
      i += 1; continue;
    }
    if (state === "double") {
      if (c === "\\") { i += 2; continue; }
      if (c === '"') { state = "code"; lastSig = ")"; }
      i += 1; continue;
    }
    if (state === "template") {
      if (c === "\\") { i += 2; continue; } // escape (e.g. \` \$) — stays literal
      if (c === "$" && c2 === "{") {
        // enter an interpolation expression: preserve its CODE
        templateExprDepth.push(0);
        state = "code";
        out += "  "; // blank the `${` markers, preserve length
        i += 2; continue;
      }
      if (c === "`") { state = "code"; lastSig = ")"; }
      if (c === "\n") out += "\n"; // preserve line count
      i += 1; continue;
    }
  }
  return out;
}
