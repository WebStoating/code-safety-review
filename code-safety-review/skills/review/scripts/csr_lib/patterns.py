"""Shared regex catalogs. See references/attack-patterns.md for what each one targets."""
from __future__ import annotations

import re
from typing import List

I = re.IGNORECASE

# --- dynamic execution -------------------------------------------------------
# Code evaluation (not RegExp.prototype.exec).
EXEC_STRONG_JS = re.compile(
    r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"`]|\bvm\.(runIn\w+|compileFunction)\s*\(|"
    r"\bnew\s+vm\.Script\s*\(|\.then\s*\(\s*eval\s*\)|\(\s*0\s*,\s*eval\s*\)|\.constructor\s*\(\s*['\"`]"
)
# Process execution (child_process API; `.exec(` alone is RegExp and is excluded).
EXEC_CMD_JS = re.compile(
    r"(?<![\w.$])(execSync|execFileSync|spawnSync|exec|execFile|spawn|fork)\s*\(|"
    r"\.\s*(execSync|execFileSync|spawnSync|execFile|spawn|fork)\s*\(|\bchild_process\b\W{0,4}\.\s*exec\s*\("
)
EXEC_JS = re.compile(EXEC_STRONG_JS.pattern + "|" + EXEC_CMD_JS.pattern)
EXEC_PY = re.compile(
    r"(?<![\w.])(exec|eval|compile)\s*\(|__import__\s*\(|\bos\.(system|popen|exec\w*|spawn\w*)\s*\(|"
    r"\bsubprocess\.\w+\s*\(|\bpty\.spawn|\bmarshal\.loads\s*\(|\bctypes\.(CDLL|windll|cdll)|"
    r"\bimportlib\.import_module\s*\(\s*[^'\"]"
)

# --- network -----------------------------------------------------------------
NETWORK_CALL_JS = re.compile(
    r"\bhttps?\.(request|get)\s*\(|require\(\s*['\"](node:)?https?['\"]\s*\)\s*\.\s*(get|request)\s*\(|"
    r"\bfetch\s*\(|new\s+XMLHttpRequest|\baxios(\.\w+)?\s*\(|\bnet\.(connect|createConnection)\s*\(|"
    r"\bnew\s+WebSocket\s*\(|\bdns\.(resolve\w*|lookup)\s*\(|\bgot(\.\w+)?\s*\("
)
NETWORK_JS = re.compile(
    r"\bhttps?\.(request|get)\s*\(|require\(\s*['\"](node:)?(https?|net|dgram|tls)['\"]\s*\)|"
    r"from\s+['\"](node:)?(https?|net|dgram)['\"]|\bfetch\s*\(|XMLHttpRequest|\baxios(\.\w+)?\s*\(|"
    r"\bnet\.(connect|createConnection)\s*\(|\bnew\s+WebSocket\s*\(|\bdns\.(resolve\w*|lookup)\s*\(|"
    r"\bgot(\.\w+)?\s*\(|\bsuperagent\b|\bundici\b|\bnode-fetch\b"
)
NETWORK_PY = re.compile(
    r"\burllib\.request\b|\burlopen\s*\(|\brequests\.(get|post|put|request|Session)\b|\bhttpx\.|"
    r"\bsocket\.(socket|create_connection)\s*\(|\bhttp\.client\b|\baiohttp\b|\bpycurl\b|"
    r"\bftplib\b|\bsmtplib\b|\bparamiko\b|\bwebsocket\b"
)
NETWORK_CMD = re.compile(
    r"\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|bitsadmin|ncat|socat)\b|"
    r"certutil\s+-urlcache|DownloadString|DownloadFile|Net\.WebClient|\b(https?|ftp)://",
    I,
)
PIPE_TO_SHELL = re.compile(
    r"(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,400}\|\s*"
    r"(sudo\s+)?((ba|z|da|k)?sh|cmd(\.exe)?|powershell(\.exe)?|pwsh|iex|Invoke-Expression|node|python3?|perl|ruby)\b|"
    r"\b(ba|z)?sh\s+(-c\s+)?['\"]?\$\(\s*(curl|wget)|\b(ba|z)?sh\s+<\(\s*(curl|wget)|"
    r"\biex\s*\(|Invoke-Expression|DownloadString\s*\(",
    I,
)
INLINE_EXEC_CMD = re.compile(
    r"\b(powershell|pwsh)(\.exe)?\b[^\n]{0,80}\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}|"
    r"\bnode\s+(-e|--eval|-p)\s|\bpython3?\s+-c\s|\bbase64\s+(-d|--decode|-D)\b|FromBase64String|"
    r"\bperl\s+-e\s|\bruby\s+-e\s",
    I,
)
HIDDEN_PS = re.compile(r"-w(indowstyle)?\s+hidden|-noni(nteractive)?\b|-ExecutionPolicy\s+Bypass|-ep\s+bypass", I)

# --- secrets / sensitive reads -----------------------------------------------
SECRET_PATHS = re.compile(
    r"(?:~|\$HOME|\bHOME\b|homedir\(\)|USERPROFILE|expanduser\(|Path\.home\(\))[^\n]{0,60}\.npmrc\b|_authToken|"
    r"(?<![\w.-])\.ssh[/\\\\'\"]|\bid_(rsa|ed25519|ecdsa|dsa)\b|(?<![\w.-])\.aws[/\\\\]|"
    r"\.config[/\\\\]gh\b|\.docker[/\\\\]config\.json|\.kube[/\\\\]config|\.git-credentials|\.netrc\b|"
    r"\.pypirc\b|\bLogin Data\b|\bLocal State\b|Library/Keychains|\bsecurity\s+find-(generic|internet)-password|"
    r"\.gnupg\b|\bmetamask\b|nkbihfbeogaeaoehlefnkodbefgpgknn|\bexodus\b|\bphantom\b.{0,20}wallet|"
    r"Application Support/(Google/Chrome|BraveSoftware|Firefox)|AppData[/\\\\]+(Local|Roaming)[/\\\\]+"
    r"(Google|BraveSoftware|Mozilla|Microsoft[/\\\\]+Edge)|\.(bash|zsh)_history|/etc/(passwd|shadow)|"
    r"\.claude\.json|\.codex[/\\\\]auth\.json|\.config[/\\\\]gcloud",
    I,
)
# Serialising/enumerating the WHOLE environment (copies for child processes are not dumps).
ENV_DUMP_JS = re.compile(r"JSON\.stringify\(\s*process\.env\s*\)|Object\.(entries|values)\(\s*process\.env\s*\)|"
                         r"util\.inspect\(\s*process\.env\b")
ENV_DUMP_PY = re.compile(r"(json\.dumps|str|repr|urlencode|pickle\.dumps|b64encode)\(\s*(dict\(\s*)?os\.environ\b|"
                         r"\.join\([^)\n]{0,80}os\.environ\.items\(\)")
ENV_DUMP_SHELL = re.compile(r"\bprintenv\b|(^|[;&|]\s*)env\s*\||Get-ChildItem\s+env:|\bgci\s+env:|(^|[;&]\s*)set\s*>", I | re.M)
ENV_DUMP = re.compile("|".join(p.pattern for p in (ENV_DUMP_JS, ENV_DUMP_PY, ENV_DUMP_SHELL)), I | re.M)
CLIPBOARD = re.compile(
    r"\bclipboardy\b|\bpbpaste\b|Get-Clipboard|Windows\.Forms\.Clipboard|\bxclip\b|\bxsel\b|"
    r"clipboard\.readText|\bpyperclip\b",
    I,
)

# --- obfuscation -------------------------------------------------------------
B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/=])")
B64_ANY = re.compile(r"['\"`]([A-Za-z0-9+/]{16,}={0,2})['\"`]")
HEX_BLOB = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){60,}(?![0-9a-fA-F])|(?:\\x[0-9a-fA-F]{2}){20,}")
CHARCODE_CHAIN = re.compile(r"fromCharCode\s*\(\s*((0x[0-9a-fA-F]+|\d+)\s*,\s*){5,}|(chr\(\s*\d+\s*\)\s*\+\s*){5,}")
OBF_IDENT = re.compile(r"\b_0x[0-9a-fA-F]{4,}\b")
DECODE_JS = re.compile(r"Buffer\.from\s*\([^)]*['\"](base64|hex)['\"]|\batob\s*\(|"
                       r"fromCharCode\s*\(\s*((0x[0-9a-fA-F]+|\d+)\s*,\s*){5,}|decodeURIComponent\s*\(\s*escape", I)
JOINED_NAME = re.compile(r"\[\s*((['\"])[A-Za-z_]{1,6}\2(\s*,\s*(['\"])[A-Za-z_]{1,6}\4)+)\s*\]\s*\.join\(\s*(['\"])\5\s*\)")
EXEC_NAMES = {"eval", "Function", "exec", "execSync", "spawn", "require", "child_process", "constructor", "runInThisContext"}
DECODE_PY = re.compile(r"\b(b64decode|b32decode|b85decode|a85decode|urlsafe_b64decode|unhexlify|fromhex)\s*\(|"
                       r"zlib\.decompress|gzip\.decompress|lzma\.decompress|bz2\.decompress|codecs\.decode\s*\([^)]*rot|"
                       r"marshal\.loads|pickle\.loads")
DATA_URI = re.compile(r"data:[a-z]+/[\w.+-]+;base64,|sourceMappingURL=data:", I)

# --- locations ---------------------------------------------------------------
URL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s'\"`<>)\]\\}]+", I)
IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
RAW_IP_URL = re.compile(r"\b(?:https?|wss?)://(?:\d{1,3}\.){3}\d{1,3}", I)
WEBHOOK_HOSTS = re.compile(
    r"webhook\.site|requestbin|pipedream\.net|hookbin|discord(app)?\.com/api/webhooks|hooks\.slack\.com|"
    r"api\.telegram\.org/bot|ngrok(-free)?\.(io|app)|interact\.sh|oast\.(fun|pro|live|site|online|me)|"
    r"burpcollaborator|canarytokens|beeceptor|requestcatcher|trycloudflare\.com|pastebin\.com|transfer\.sh|"
    r"0x0\.st|ip-api\.com|api\.ipify\.org",
    I,
)

NONCODE_EXT = r"woff2?|ttf|otf|eot|png|jpe?g|gif|ico|bmp|webp|svg|dict|npl|txt|dat|bin|lock|log|md|csv|css|map|wasm"
INTERPRETER_ON_NONCODE = re.compile(
    r"\b(node|nodejs|bun|deno(\s+run)?|python[23]?|sh|bash|zsh|ruby|perl)\s+(-\S+\s+)*['\"]?([^\s'\"|;&]+\.(" + NONCODE_EXT + r"))\b",
    I,
)

# Known indicators from the referenced campaigns, stored defanged; refanged here.
_KNOWN_IOCS_DEFANGED = [
    "vscode-load[.]onrender[.]com",
    "ip-api-check-gold[.]vercel[.]app",
    "144[.]172[.]116[.]80",
    "audit[.]checkmarx[.]cx",
]
KNOWN_IOC_LIST: List[str] = [x.replace("[.]", ".") for x in _KNOWN_IOCS_DEFANGED]
KNOWN_IOCS = re.compile("|".join(re.escape(x) for x in KNOWN_IOC_LIST), I)


def command_risks(cmd: str) -> List[str]:
    """Classify a shell command line (task, lifecycle script, hook). Returns reason tags."""
    reasons = []
    if PIPE_TO_SHELL.search(cmd):
        reasons.append("downloads and pipes remote content into an interpreter")
    if INTERPRETER_ON_NONCODE.search(cmd):
        reasons.append("runs an interpreter on a non-code file")
    if INLINE_EXEC_CMD.search(cmd):
        reasons.append("inline/encoded code execution")
    if HIDDEN_PS.search(cmd):
        reasons.append("hidden/bypassed PowerShell")
    if NETWORK_CMD.search(cmd) and not reasons:
        reasons.append("network access")
    if B64_BLOB.search(cmd):
        reasons.append("embedded base64 blob")
    if SECRET_PATHS.search(cmd) or ENV_DUMP.search(cmd):
        reasons.append("touches secrets or environment")
    if WEBHOOK_HOSTS.search(cmd) or RAW_IP_URL.search(cmd):
        reasons.append("contacts webhook/raw-IP endpoint")
    if KNOWN_IOCS.search(cmd):
        reasons.append("matches a known malware indicator")
    return reasons


DANGEROUS_REASONS = {
    "downloads and pipes remote content into an interpreter",
    "runs an interpreter on a non-code file",
    "inline/encoded code execution",
    "hidden/bypassed PowerShell",
    "embedded base64 blob",
    "touches secrets or environment",
    "contacts webhook/raw-IP endpoint",
    "matches a known malware indicator",
}


def is_dangerous_command(cmd: str) -> bool:
    return any(r in DANGEROUS_REASONS for r in command_risks(cmd))
