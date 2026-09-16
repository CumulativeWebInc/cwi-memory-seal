/* CWI Memory Seal — memory.js v1.0.0
 * Zero-dependency UMD engine: memory-integrity scanning + checkpoint sealing.
 * Part 1: canonical JSON, UTF-8, base64, embedded SHA-256, Ed25519 provider
 * (node crypto | vendored tweetnacl, same pattern as Identity Ledger).
 * Honest limits: the scanner is heuristic — a clean scan is NOT a proof of
 * clean memory; a checkpoint proves integrity since sealing, not truth.
 */
(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], function () { return factory('browser'); });
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory('node');
  } else {
    root.MemorySeal = factory('browser');
  }
}(typeof self !== 'undefined' ? self : this, function (ENV) {

'use strict';

var SCHEMA_AUDIT = 'cwi.memory-audit/1.0';
var SCHEMA_CHECKPOINT = 'cwi.memory-checkpoint/1.0';
var SCHEMA_CHECKPOINT_LOG = 'cwi.memory-checkpoint-log/1.0';
var RULES_VERSION = 'ms-rules/1.0';
var AUDIT_ID_PREFIX = 'msa_';
var CHECKPOINT_ID_PREFIX = 'msc_';
var CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/* ---------------- text / base64 helpers ---------------- */

function utf8Encode(str) {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
  var bytes = [], i, c;
  for (i = 0; i < str.length; i++) {
    c = str.charCodeAt(i);
    if (c < 0x80) bytes.push(c);
    else if (c < 0x800) bytes.push(0xC0 | (c >> 6), 0x80 | (c & 0x3F));
    else if (c >= 0xD800 && c <= 0xDBFF && i + 1 < str.length) {
      var lo = str.charCodeAt(i + 1);
      if (lo >= 0xDC00 && lo <= 0xDFFF) {
        var cp = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
        bytes.push(0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3F), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F));
        i++;
      } else bytes.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F));
    } else bytes.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F));
  }
  return new Uint8Array(bytes);
}

function b64encode(bytes) {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  var s = '', i;
  for (i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64decode(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(str) || str.length % 4 !== 0) return null;
  try {
    var raw;
    if (typeof Buffer !== 'undefined') raw = new Uint8Array(Buffer.from(str, 'base64'));
    else {
      var s = atob(str), out = new Uint8Array(s.length), i;
      for (i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
      raw = out;
    }
    return raw;
  } catch (e) { return null; }
}

/* ---------------- canonical JSON ----------------
 * Deterministic: object keys sorted by UTF-16 code units, no whitespace.
 * Arrays keep order. Strings use JSON.stringify (deterministic across
 * conforming engines). */

function canonical(v) {
  if (v === null || v === undefined) return 'null';
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  var t = typeof v;
  if (t === 'object') {
    var keys = Object.keys(v).sort(), i, out = [];
    for (i = 0; i < keys.length; i++) out.push(JSON.stringify(keys[i]) + ':' + canonical(v[keys[i]]));
    return '{' + out.join(',') + '}';
  }
  return JSON.stringify(v);
}

/* ---------------- SHA-256 (embedded, zero-dep) ---------------- */

function sha256Hex(str) {
  var bytes = utf8Encode(str);
  var K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
      h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  var bitLen = bytes.length * 8, i, j;
  var padded = [];
  for (i = 0; i < bytes.length; i++) padded.push(bytes[i]);
  padded.push(0x80);
  while (padded.length % 64 !== 56) padded.push(0);
  var hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
  padded.push((hi>>>24)&255,(hi>>>16)&255,(hi>>>8)&255,hi&255,(lo>>>24)&255,(lo>>>16)&255,(lo>>>8)&255,lo&255);
  function rotr(x,n){ return (x>>>n)|(x<<(32-n)); }
  for (i = 0; i < padded.length; i += 64) {
    var w = new Array(64);
    for (j = 0; j < 16; j++) w[j] = (padded[i+4*j]<<24)|(padded[i+4*j+1]<<16)|(padded[i+4*j+2]<<8)|padded[i+4*j+3];
    for (j = 16; j < 64; j++) {
      var s0 = rotr(w[j-15],7)^rotr(w[j-15],18)^(w[j-15]>>>3);
      var s1 = rotr(w[j-2],17)^rotr(w[j-2],19)^(w[j-2]>>>10);
      w[j] = (w[j-16]+s0+w[j-7]+s1)|0;
    }
    var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,hh=h7;
    for (j = 0; j < 64; j++) {
      var S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
      var ch = (e&f)^((~e)&g);
      var t1 = (hh+S1+ch+K[j]+w[j])|0;
      var S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
      var maj = (a&b)^(a&c)^(b&c);
      var t2 = (S0+maj)|0;
      hh=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
    }
    h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0;
    h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+hh)|0;
  }
  function hex(x){ return ('00000000'+(x>>>0).toString(16)).slice(-8); }
  return hex(h0)+hex(h1)+hex(h2)+hex(h3)+hex(h4)+hex(h5)+hex(h6)+hex(h7);
}

/* ---------------- Ed25519 provider (node crypto | tweetnacl) ---------------- */

var nodeCrypto = null;
if (ENV === 'node') { try { nodeCrypto = require('crypto'); } catch (e) { nodeCrypto = null; } }

function getNacl() {
  var n = (typeof root !== 'undefined' && root.nacl) ? root.nacl : null;
  if (!n && typeof globalThis !== 'undefined' && globalThis.nacl) n = globalThis.nacl;
  return n;
}

/* Keypair: { publicKeyB64, privateKeyB64 } — privateKey is the 32-byte SEED. */

function generateKeypair() {
  if (nodeCrypto) {
    var kp = nodeCrypto.generateKeyPairSync('ed25519');
    var pub = kp.publicKey.export({ format: 'jwk' });
    var priv = kp.privateKey.export({ format: 'jwk' });
    return {
      publicKeyB64: b64encode(base64urlToBytes(pub.x)),
      privateKeyB64: b64encode(base64urlToBytes(priv.d))
    };
  }
  var nacl = getNacl();
  if (!nacl) throw new Error('Ed25519 unavailable: load vendor/nacl.js first');
  var pair = nacl.sign.keyPair();
  return { publicKeyB64: b64encode(pair.publicKey), privateKeyB64: b64encode(pair.secretKey.slice(0, 32)) };
}

function base64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return b64decode(s);
}

function bytesToBase64url(bytes) {
  return b64encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function pubToJwk(pubBytes) {
  return { kty: 'OKP', crv: 'Ed25519', x: bytesToBase64url(pubBytes) };
}

function signBytes(msgBytes, seedB64) {
  var seed = b64decode(seedB64);
  if (!seed || seed.length !== 32) throw new Error('private key must be 32-byte seed, base64');
  if (nodeCrypto) {
    var der = new Uint8Array(48);
    var prefix = [0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20], i;
    for (i = 0; i < 16; i++) der[i] = prefix[i];
    for (i = 0; i < 32; i++) der[16 + i] = seed[i];
    var priv = nodeCrypto.createPrivateKey({ key: Buffer.from(der), format: 'der', type: 'pkcs8' });
    return new Uint8Array(nodeCrypto.sign(null, Buffer.from(msgBytes), priv));
  }
  var nacl = getNacl();
  if (!nacl) throw new Error('Ed25519 unavailable: load vendor/nacl.js first');
  var pair = nacl.sign.keyPair.fromSeed(seed);
  return nacl.sign.detached(msgBytes, pair.secretKey);
}

function verifyBytes(msgBytes, sigBytes, pubBytes) {
  if (nodeCrypto) {
    try {
      var pub = nodeCrypto.createPublicKey({ key: pubToJwk(pubBytes), format: 'jwk' });
      return nodeCrypto.verify(null, Buffer.from(msgBytes), pub, Buffer.from(sigBytes));
    } catch (e) { return false; }
  }
  var nacl = getNacl();
  if (!nacl) throw new Error('Ed25519 unavailable: load vendor/nacl.js first');
  try { return nacl.sign.detached.verify(msgBytes, sigBytes, pubBytes); }
  catch (e) { return false; }
}

function randomId(prefix, n) {
  var out = '', i;
  var rand;
  if (nodeCrypto) {
    rand = nodeCrypto.randomBytes(n);
    for (i = 0; i < n; i++) out += CROCKFORD[rand[i] & 31];
  } else {
    var nacl = getNacl();
    if (nacl) { rand = nacl.randomBytes(n); for (i = 0; i < n; i++) out += CROCKFORD[rand[i] & 31]; }
    else for (i = 0; i < n; i++) out += CROCKFORD[Math.floor(Math.random() * 32)];
  }
  return prefix + out;
}

function isoNow() { return new Date().toISOString(); }

function excerpt(s, n) {
  s = String(s).replace(/\s+/g, ' ').trim();
  n = n || 160;
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

/* ---------------- contamination scanner ----------------
 * Heuristic, evidence-bound rules. Every finding carries the exact excerpt
 * and line ref that triggered it — flags are for human triage, never verdicts.
 * A clean scan is NOT a proof of clean memory. */

var STOPWORDS = {};
('a,an,the,and,or,but,if,then,else,when,while,of,at,by,for,with,about,into,' +
 'through,during,before,after,above,below,to,from,up,down,in,out,on,off,over,' +
 'under,again,further,once,here,there,when,where,which,who,whom,this,that,' +
 'these,those,am,is,are,was,were,be,been,being,have,has,had,having,do,does,' +
 'did,doing,would,should,could,ought,i,you,he,she,it,we,they,them,his,her,' +
 'its,our,their,my,your,as,not,no,yes,so,than,too,very,can,will,just,don,' +
 'now,say,said,says,per,via,e.g.,i.e.').split(',').forEach(function (w) { STOPWORDS[w] = 1; });

function significantTokens(s) {
  var out = [], seen = {};
  String(s).toLowerCase().replace(/[^a-z0-9_@./-]+/g, ' ').split(/\s+/).forEach(function (t) {
    if (t.length >= 3 && !STOPWORDS[t] && !seen[t]) { seen[t] = 1; out.push(t); }
  });
  return out;
}

function jaccard(a, b) {
  if (!a.length || !b.length) return 0;
  var sa = {}, inter = 0, i;
  for (i = 0; i < a.length; i++) sa[a[i]] = 1;
  for (i = 0; i < b.length; i++) if (sa[b[i]]) inter++;
  return inter / (a.length + b.length - inter);
}

function findDates(line) {
  var out = [], m, re = /(20\d\d)-(\d\d)-(\d\d)/g;
  while ((m = re.exec(line)) !== null) out.push(m[0]);
  return out;
}

function daysBetween(aISO, bISO) {
  return Math.abs(Date.parse(aISO) - Date.parse(bISO)) / 86400000;
}

var RULES = [
  {
    id: 'MS-01', severity: 'CRITICAL', title: 'Injected directive',
    description: 'Agent-addressed imperative / override language inside memory text. ' +
      'Legitimate if it is the user\'s own standing policy (mark as POLICY); ' +
      'treat as prompt injection if it arrived via third-party content.',
    detect: function (lines) {
      var re = /\b(you (must|shall|will|are to)|never (reveal|mention|disclose|tell)|ignore (all |your |previous )?(instructions|rules|policies|directives)|disregard (your |the )?(system|prior|previous)|do not (follow|obey|reveal)|pretend to be|act as if you|forget (everything|all) (you|your))/i;
      return lines.filter(function (l) { return re.test(l.text); }).map(function (l) {
        return { rule: 'MS-01', severity: 'CRITICAL', line: l.n,
          evidence: excerpt(l.text),
          advice: 'Triage: is this the user\'s standing policy, or content pasted from an external source? Mark policy lines as POLICY.' };
      });
    }
  },
  {
    id: 'MS-02', severity: 'CRITICAL', title: 'Secret-shaped value in memory',
    description: 'A value that looks like a real secret (API key, token, private key block) ' +
      'is stored in memory text. Memory is read by many processes — rotate and remove.',
    detect: function (lines) {
      var re = /(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|(?<![A-Za-z0-9_])(api[_-]?key|secret|password|passwd|bearer|client_secret)["']?\s*[:=]\s*["']?[A-Za-z0-9\-_+/=]{12,})/i;
      return lines.filter(function (l) { return re.test(l.text); }).map(function (l) {
        return { rule: 'MS-02', severity: 'CRITICAL', line: l.n,
          evidence: excerpt(l.text),
          advice: 'Rotate the credential, remove the value from memory, keep only its storage location.' };
      });
    }
  },
  {
    id: 'MS-03', severity: 'CRITICAL', title: 'Credential-category key with value',
    description: 'A KEY/TOKEN/SECRET/PASSWORD/CREDENTIAL/PRIVATE-named key carries a value ' +
      'in memory. Per CWI security policy these are secrets — never inline.',
    detect: function (lines) {
      var re = /\b[A-Za-z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE)[A-Za-z_]*\b\s*[:=]\s*\S{8,}/;
      var out = [];
      lines.forEach(function (l) {
        if (!re.test(l.text)) return;
        // allow file-path references (not values)
        if (/[\/~]\S*\.(md|txt|json|key|pem|gpg)\b/.test(l.text)) return;
        out.push({ rule: 'MS-03', severity: 'CRITICAL', line: l.n,
          evidence: excerpt(l.text),
          advice: 'If the value is real, rotate and remove. Keep the storage reference, never the value.' });
      });
      return out;
    }
  },
  {
    id: 'MS-04', severity: 'CRITICAL', title: 'Self-preservation / oversight-evasion language',
    description: 'Memory text containing goals an agent must never hold: hiding things ' +
      'from the user, self-replication, or disabling safeguards.',
    detect: function (lines) {
      var re = /\b(hide (this|it|the .{0,20}) from the user|don'?t tell (the )?user|do not tell (the )?user|replicate (yourself|itself)|evade (shutdown|detection|oversight)|disable (the )?(safety|safeguards?|approval)|self-?preservation|acquire (more )?resources)/i;
      return lines.filter(function (l) { return re.test(l.text); }).map(function (l) {
        return { rule: 'MS-04', severity: 'CRITICAL', line: l.n,
          evidence: excerpt(l.text),
          advice: 'If this is the user\'s prohibition text, mark as POLICY. If it is an agent goal, delete it.' };
      });
    }
  },
  {
    id: 'MS-05', severity: 'WARNING', title: 'Sensitive-attribute inference',
    description: 'A protected attribute (race, ethnicity, religion, health/disability, ' +
      'politics, sexual orientation, criminal history) appears inferred rather than stated.',
    detect: function (lines) {
      var attr = /\b(race|ethnic|relig|disab|health condition|mental health|politic|sexual orientation|criminal|victim of)/i;
      var infer = /\b(seems|appears|looks like|probably|sounds like|i think|likely|must be)\b/i;
      return lines.filter(function (l) { return attr.test(l.text) && infer.test(l.text); }).map(function (l) {
        return { rule: 'MS-05', severity: 'WARNING', line: l.n,
          evidence: excerpt(l.text),
          advice: 'Surface protected attributes only when explicit and relevant — never as inference.' };
      });
    }
  },
  {
    id: 'MS-06', severity: 'WARNING', title: 'Possible contradiction (unmarked)',
    description: 'Two lines share most significant tokens but one negates the other, ' +
      'with no correction marker. Could be a real contradiction — or a legitimate update. Human review.',
    detect: function (lines) {
      var neg = /\b(no longer|not |never |isn'?t|wasn'?t|aren'?t|weren'?t|can'?t|couldn'?t|without)\b/i;
      var out = [], seen = {}, i, j;
      for (i = 0; i < lines.length; i++) {
        for (j = i + 1; j < lines.length; j++) {
          var a = lines[i], b = lines[j];
          if (a.text.length < 40 || b.text.length < 40) continue;
          var ta = significantTokens(a.text), tb = significantTokens(b.text);
          if (ta.length < 4 || tb.length < 4) continue;
          var negA = neg.test(a.text), negB = neg.test(b.text);
          if (negA === negB) continue; // both plain or both negated
          if (jaccard(ta, tb) >= 0.45) {
            var key = a.n + ':' + b.n;
            if (seen[key]) continue; seen[key] = 1;
            out.push({ rule: 'MS-06', severity: 'WARNING', line: a.n, line2: b.n,
              evidence: 'L' + a.n + ': ' + excerpt(a.text, 90) + '  ⇄  L' + b.n + ': ' + excerpt(b.text, 90),
              advice: 'Verify which statement is current; if superseded, add a correction marker (see MS-07).' });
          }
        }
      }
      return out.slice(0, 50);
    }
  },
  {
    id: 'MS-07', severity: 'INFO', title: 'Retroactive-edit marker (healthy)',
    description: 'A correction/supersede marker — the healthy way memory evolves. ' +
      'Recorded for the record; these reduce contradiction risk.',
    detect: function (lines) {
      var re = /\b(corrected from|superseded|replaced on|correction applied|updated from|previously (said|recorded)|old (value|copy) superseded)\b/i;
      return lines.filter(function (l) { return re.test(l.text); }).map(function (l) {
        return { rule: 'MS-07', severity: 'INFO', line: l.n,
          evidence: excerpt(l.text),
          advice: 'Good practice — keep marking every retrospective edit this way.' };
      });
    }
  },
  {
    id: 'MS-08', severity: 'WARNING', title: 'Unverified lineage presented as fact',
    description: 'A factual claim whose own lineage is flagged unverified, reported, ' +
      'or claimed — the assertion outruns its evidence. Attach a source or downgrade.',
    detect: function (lines) {
      var lineage = /\b(unverified|unconfirmed|reported(ly)?|claimed|alleged|supposedly|per the export|import says)\b/i;
      var factual = /\b(is|are|has|have|owns|holds|verified|confirmed|deployed|live)\b/i;
      return lines.filter(function (l) { return lineage.test(l.text) && factual.test(l.text); }).map(function (l) {
        return { rule: 'MS-08', severity: 'WARNING', line: l.n,
          evidence: excerpt(l.text),
          advice: 'Attach the evidence source or reword as a claim, not a verified fact.' };
      });
    }
  },
  {
    id: 'MS-09', severity: 'INFO', title: 'Vague attribution',
    description: 'An assertion attributed to "someone", "a source", or an unnamed export. ' +
      'Low risk alone; higher risk when combined with MS-08.',
    detect: function (lines) {
      var re = /\b(someone (said|told|claims)|the export says|a source (said|says)|people say|an? unnamed)\b/i;
      return lines.filter(function (l) { return re.test(l.text); }).map(function (l) {
        return { rule: 'MS-09', severity: 'INFO', line: l.n,
          evidence: excerpt(l.text),
          advice: 'Name the source when possible so the claim stays checkable.' };
      });
    }
  },
  {
    id: 'MS-10', severity: 'WARNING', title: 'Near-duplicate facts (drift risk)',
    description: 'The same fact recorded twice in different words or places — ' +
      'one copy will drift. Keep one canonical copy.',
    detect: function (lines) {
      var out = [], seen = {}, i, j;
      var long = lines.filter(function (l) { return l.text.trim().length >= 60; });
      for (i = 0; i < long.length; i++) {
        for (j = i + 1; j < long.length; j++) {
          var a = long[i], b = long[j];
          var ta = significantTokens(a.text), tb = significantTokens(b.text);
          if (ta.length < 5 || tb.length < 5) continue;
          var sim = jaccard(ta, tb);
          if (sim >= 0.85) {
            var key = a.n + ':' + b.n;
            if (seen[key]) continue; seen[key] = 1;
            out.push({ rule: 'MS-10', severity: 'WARNING', line: a.n, line2: b.n,
              evidence: 'L' + a.n + ' ≈ L' + b.n + ' (token overlap ' + Math.round(sim * 100) + '%)',
              advice: 'Consolidate to one canonical copy; keep pointers, not copies.' });
          }
        }
      }
      return out.slice(0, 50);
    }
  },
  {
    id: 'MS-11', severity: 'INFO', title: 'Stale entry (needs re-verification)',
    description: 'An entry dated >120 days ago still phrased as current, with no ' +
      're-verification marker. Facts decay — re-verify or re-date.',
    detect: function (lines, ctx) {
      var nowISO = (ctx && ctx.now) || isoNow();
      var fresh = /\b(re-?verified|re-?checked|re-?confirmed|as of 20\d\d-)/i;
      var current = /\b(currently|is now|are now|active|ongoing|live|as of now|still)\b/i;
      var out = [];
      lines.forEach(function (l) {
        var dates = findDates(l.text);
        if (!dates.length || fresh.test(l.text) || !current.test(l.text)) return;
        var stale = dates.some(function (d) { return daysBetween(d, nowISO.slice(0, 10)) > 120; });
        if (stale) out.push({ rule: 'MS-11', severity: 'INFO', line: l.n,
          evidence: excerpt(l.text),
          advice: 'Re-verify the fact or mark it historical; present-tense claims older than 120 days decay.' });
      });
      return out.slice(0, 50);
    }
  },
  {
    id: 'MS-12', severity: 'WARNING', title: 'Low-confidence high-stakes claim',
    description: 'Hedged language ("probably", "seems") in a sentence about money, ' +
      'wallets, rights, payments, or signing. High-stakes claims need evidence, not hedges.',
    detect: function (lines) {
      var hedge = /\b(probably|seems|might be|could be|appears to|i believe|likely|unclear)\b/i;
      var stakes = /\b(money|payment|wallet|sign(ing|ed)?|spend|rights|royalt|price|cost|\$|USDC|mint)\b/i;
      return lines.filter(function (l) { return hedge.test(l.text) && stakes.test(l.text); }).map(function (l) {
        return { rule: 'MS-12', severity: 'WARNING', line: l.n,
          evidence: excerpt(l.text),
          advice: 'Verify against a source before this becomes an operating assumption.' };
      });
    }
  }
];

/* ---------------- scan ----------------
 * scan(text, opts) -> audit envelope (cwi.memory-audit/1.0).
 * opts: { source, now (ISO), includeInfo (default true) } */

function splitLines(text) {
  return String(text || '').split(/\r?\n/).map(function (t, i) { return { n: i + 1, text: t }; })
    .filter(function (l) { return l.text.trim().length > 0; });
}

function scan(text, opts) {
  opts = opts || {};
  var lines = splitLines(text);
  var ctx = { now: opts.now || isoNow() };
  var findings = [];
  RULES.forEach(function (rule) {
    var hits;
    try { hits = rule.detect(lines, ctx) || []; }
    catch (e) { hits = [{ rule: rule.id, severity: 'INFO', line: 0, evidence: 'rule error: ' + e.message, advice: 'report this' }]; }
    hits.forEach(function (h) {
      findings.push({
        rule: rule.id,
        severity: h.severity || rule.severity,
        title: rule.title,
        line: h.line || 0,
        line2: h.line2 || null,
        evidence: h.evidence || '',
        advice: h.advice || rule.description
      });
    });
  });
  findings.sort(function (a, b) {
    var rank = { CRITICAL: 0, WARNING: 1, INFO: 2 };
    if (rank[a.severity] !== rank[b.severity]) return rank[a.severity] - rank[b.severity];
    return (a.line || 0) - (b.line || 0);
  });
  var counts = { CRITICAL: 0, WARNING: 0, INFO: 0 };
  findings.forEach(function (f) { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  return {
    schema: SCHEMA_AUDIT,
    audit_id: opts.auditId || randomId(AUDIT_ID_PREFIX, 16),
    source: opts.source || 'pasted-text',
    scanned_at: ctx.now,
    rules_version: RULES_VERSION,
    input_sha256: sha256Hex(canonical(String(text || ''))),
    line_count: lines.length,
    counts: counts,
    finding_count: findings.length,
    findings: findings,
    honest_limits: 'Heuristic rules v1 — flags are triage input for a human, never verdicts. ' +
      'A clean scan is not a proof of clean memory. Rules can be evaded by adversarial text. ' +
      'MS-01/MS-04 findings that match the user\'s own standing policy should be marked POLICY.'
  };
}

function summarizeAudit(audit) {
  var c = audit.counts || {};
  return (c.CRITICAL || 0) + ' critical · ' + (c.WARNING || 0) + ' warning · ' + (c.INFO || 0) + ' info';
}

/* ---------------- checkpoints ----------------
 * A checkpoint seals a snapshot of memory entries: hash-chained and
 * Ed25519-signed. It proves the entries have not been added to, removed
 * from, or reordered since sealing — it says nothing about whether the
 * entries were true when sealed. */

function normalizeEntries(entries) {
  return (entries || []).map(function (e, i) {
    if (typeof e === 'string') return { id: 'e' + (i + 1), text: e };
    return { id: String(e.id || ('e' + (i + 1))), text: String(e.text || ''), ts: e.ts || null };
  });
}

function entriesHash(entries) {
  return sha256Hex(canonical(normalizeEntries(entries)));
}

function checkpointSignPayload(cp) {
  return {
    schema: cp.schema,
    checkpoint_id: cp.checkpoint_id,
    created_at: cp.created_at,
    entries_hash: cp.entries_hash,
    entry_count: cp.entry_count,
    prev_hash: cp.prev_hash,
    signer_pubkey_b64: cp.signer_pubkey_b64
  };
}

function sealCheckpoint(args) {
  args = args || {};
  var entries = normalizeEntries(args.entries);
  if (!entries.length) throw new Error('cannot seal an empty snapshot');
  if (!args.keypair || !args.keypair.publicKeyB64 || !args.keypair.privateKeyB64)
    throw new Error('keypair required');
  var cp = {
    schema: SCHEMA_CHECKPOINT,
    checkpoint_id: args.checkpointId || randomId(CHECKPOINT_ID_PREFIX, 16),
    created_at: args.createdAt || isoNow(),
    entries_hash: entriesHash(entries),
    entry_count: entries.length,
    prev_hash: args.prevHash || null,
    signer_pubkey_b64: args.keypair.publicKeyB64,
    label: args.label || ''
  };
  var sig = signBytes(utf8Encode(canonical(checkpointSignPayload(cp))), args.keypair.privateKeyB64);
  cp.signature_b64 = b64encode(sig);
  return cp;
}

/* verifyCheckpoint(cp, entries, opts) -> { ok, checks[] }
 * Checks: schema tag, entry-count match, entries-hash recompute, prev-hash
 * shape, signature over the sealed payload. Provide the same entries array
 * that was sealed (or an array whose entriesHash equals entries_hash). */

function verifyCheckpoint(cp, entries, opts) {
  opts = opts || {};
  var checks = [];
  function check(name, pass, detail) { checks.push({ name: name, pass: !!pass, detail: detail || '' }); }
  check('schema', cp && cp.schema === SCHEMA_CHECKPOINT, 'expected ' + SCHEMA_CHECKPOINT);
  check('entry_count', entries && entries.length === cp.entry_count,
    'sealed ' + (cp.entry_count || '?') + ', presented ' + (entries ? entries.length : '?'));
  var recomputed = entries ? entriesHash(entries) : null;
  check('entries_hash', recomputed === cp.entries_hash,
    recomputed === cp.entries_hash ? 'sha256 match' : 'MISMATCH — entries added/removed/edited/reordered');
  check('prev_hash_shape', cp.prev_hash === null || /^[0-9a-f]{64}$/.test(cp.prev_hash || ''),
    cp.prev_hash ? 'chained to ' + String(cp.prev_hash).slice(0, 12) + '…' : 'genesis (no parent)');
  var sigOk = false;
  try {
    var sig = b64decode(cp.signature_b64);
    var pub = b64decode(cp.signer_pubkey_b64);
    if (sig && sig.length === 64 && pub && pub.length === 32)
      sigOk = verifyBytes(utf8Encode(canonical(checkpointSignPayload(cp))), sig, pub);
  } catch (e) { sigOk = false; }
  check('signature', sigOk, sigOk ? 'Ed25519 valid for sealed payload' : 'INVALID — payload or signature tampered, or wrong key');
  var ok = checks.every(function (c) { return c.pass; });
  return { ok: ok, verdict: ok ? 'SEALED_VERIFIED' : 'SEAL_BROKEN', checks: checks };
}

/* verifyChain(log) — log: { schema: cwi.memory-checkpoint-log/1.0, checkpoints: [...] }
 * Verifies each checkpoint's own signature/hash linkage AND that each
 * prev_hash equals sha256(canonical(previous checkpoint)). */

function chainHeadHash(cp) { return sha256Hex(canonical(cp)); }

function verifyChain(log) {
  var results = [], prevHead = null, i;
  var cps = (log && log.checkpoints) || [];
  for (i = 0; i < cps.length; i++) {
    var cp = cps[i];
    var linkOk = (i === 0) ? (cp.prev_hash === null) : (cp.prev_hash === prevHead);
    results.push({
      checkpoint_id: cp.checkpoint_id,
      link_ok: linkOk,
      link_detail: i === 0 ? 'genesis' : (linkOk ? 'chained' : 'CHAIN BREAK — prev_hash does not match previous head'),
      head_hash: chainHeadHash(cp)
    });
    prevHead = chainHeadHash(cp);
  }
  var ok = results.every(function (r) { return r.link_ok; });
  return { ok: ok, count: results.length, results: results };
}

function validateAudit(audit) {
  var errors = [];
  if (!audit || audit.schema !== SCHEMA_AUDIT) errors.push('schema must be ' + SCHEMA_AUDIT);
  if (audit && !/^msa_[0-9A-HJKMNP-TV-Z]{16}$/.test(audit.audit_id || '')) errors.push('bad audit_id');
  if (audit && !/^[0-9a-f]{64}$/.test(audit.input_sha256 || '')) errors.push('bad input_sha256');
  if (audit && !Array.isArray(audit.findings)) errors.push('findings must be an array');
  return { ok: errors.length === 0, errors: errors };
}

/* ---------------- exports ---------------- */

return {
  SCHEMA_AUDIT: SCHEMA_AUDIT,
  SCHEMA_CHECKPOINT: SCHEMA_CHECKPOINT,
  SCHEMA_CHECKPOINT_LOG: SCHEMA_CHECKPOINT_LOG,
  RULES_VERSION: RULES_VERSION,
  RULES: RULES,
  canonical: canonical,
  sha256Hex: sha256Hex,
  utf8Encode: utf8Encode,
  b64encode: b64encode,
  b64decode: b64decode,
  randomId: randomId,
  excerpt: excerpt,
  scan: scan,
  summarizeAudit: summarizeAudit,
  normalizeEntries: normalizeEntries,
  entriesHash: entriesHash,
  sealCheckpoint: sealCheckpoint,
  verifyCheckpoint: verifyCheckpoint,
  verifyChain: verifyChain,
  chainHeadHash: chainHeadHash,
  generateKeypair: generateKeypair,
  validateAudit: validateAudit
};

}));
