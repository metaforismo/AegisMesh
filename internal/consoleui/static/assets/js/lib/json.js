// JSON → token list for the envelope viewer. Works on the parsed value, so
// there is no string parsing of attacker-controlled bytes and every token is
// later rendered as a Text node.

const MAX_TOKENS = 200000;

export function jsonTokens(value, { indent = 2 } = {}) {
  const out = [];
  const pad = (depth) => ' '.repeat(depth * indent);
  let truncated = false;

  function push(type, text) {
    if (out.length >= MAX_TOKENS) {
      truncated = true;
      return false;
    }
    out.push({ type, text });
    return true;
  }

  function walk(v, depth) {
    if (truncated) return;
    if (v === null) return void push('lit', 'null');
    if (typeof v === 'boolean') return void push('lit', String(v));
    if (typeof v === 'number') return void push('num', Number.isFinite(v) ? String(v) : 'null');
    if (typeof v === 'string') return void push('str', JSON.stringify(v));
    if (Array.isArray(v)) {
      if (v.length === 0) return void push('punct', '[]');
      push('punct', '[');
      v.forEach((item, i) => {
        push('ws', `\n${pad(depth + 1)}`);
        walk(item, depth + 1);
        if (i < v.length - 1) push('punct', ',');
      });
      push('ws', `\n${pad(depth)}`);
      push('punct', ']');
      return;
    }
    if (typeof v === 'object') {
      const keys = Object.keys(v);
      if (keys.length === 0) return void push('punct', '{}');
      push('punct', '{');
      keys.forEach((k, i) => {
        push('ws', `\n${pad(depth + 1)}`);
        push('key', JSON.stringify(k));
        push('punct', ': ');
        walk(v[k], depth + 1);
        if (i < keys.length - 1) push('punct', ',');
      });
      push('ws', `\n${pad(depth)}`);
      push('punct', '}');
      return;
    }
    push('lit', 'null');
  }

  walk(value, 0);
  return { tokens: out, truncated };
}

// Concatenated text; equals JSON.stringify(value, null, indent) when not truncated.
export function tokensToText(tokens) {
  return tokens.map((t) => t.text).join('');
}
