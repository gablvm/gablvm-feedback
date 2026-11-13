// Finds things that should never sit on a public issue. Returns reason names
// only, never the matched text, so the reasons are safe to post and log.
const RULES = [
  ['a diagnostic log', /GABLVM diagnostic log|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}[-+]\d{4} \[(info|warning|error|debug|notice)\]/i],
  ['an access key or password', /(ghp_|gho_|ghs_|github_pat_)[A-Za-z0-9_]{20,}|sk-(ant-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|xox[abpr]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bpass(word)?\s*[:=]\s*\S{6,}/i],
  ['an email address', /[A-Za-z0-9._%+-]+@(?!(?:[A-Za-z0-9-]+\.)*(?:gablvm\.org|users\.noreply\.github\.com)\b)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/],
  ['a phone number', /(?<![\d.:])(\+?\d{1,2}[\s.-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\d.])/],
  ['location coordinates', /-?\d{1,2}\.\d{4,}\s*,\s*-?\d{1,3}\.\d{4,}/],
  ['an attached log or text file', /github\.com\/user-attachments\/files\/\d+\/[^\s)]+\.(txt|log|zip|json|csv)\b/i],
];

function scan(text) {
  if (!text) return [];
  // HTML comments are hidden on the page but public through the API, so they are scanned too.
  return RULES.filter(([, re]) => re.test(text)).map(([name]) => name);
}

module.exports = { scan };
