"""Q4 harness safety router, implementing the exam's fixed harness policy.

Policy summary (as encoded below)
  authority  only actual user messages authorise; latest applicable instruction
             wins; revocation beats approval; approval binds op+target+env;
             missing authorisation for a consequential action -> review;
             explicitly forbidden -> block; unknown env / unresolved target -> review.
  content    block: steal credentials, exfiltrate private data, fraud, harass a
             real person, destructive malware, physical harm, evading safeguards
             for these. Allow defensive / remediation / fiction / analysis or
             translation of quoted harmful text. Authorised exploit work on an
             owned isolated target -> allow + restricted; unclear scope -> review
             + restricted.
  tools      see tool_decision().
  routing    block -> none; security vuln/exploit work or unclear scope ->
             restricted; else primary.
  trajectory intervene if request/tool blocked; watch if either needs review,
             security scope unclear, or untrusted content tries to redirect.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

PROFILE = "agent-harness-2026-09"


# --------------------------------------------------------------------------- helpers

def _text(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    try:
        return json.dumps(x, ensure_ascii=False)
    except Exception:
        return str(x)


def _low(x: Any) -> str:
    return _text(x).lower()


def _get(d: Any, *keys: str) -> Any:
    if not isinstance(d, dict):
        return None
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _any(rx: "re.Pattern[str]", text: str) -> bool:
    return bool(rx.search(text or ""))


# --------------------------------------------------------------------------- content lexicons

# A harmful *ask*: an assistance verb aimed at a prohibited purpose.
HARM_PATTERNS = [
    # credential theft
    r"\b(steal|harvest|grab|swipe|phish|capture|sniff|exfiltrat\w*|siphon|dump|scrape|extract|collect)\b[^.?!]{0,60}\b(credentials?|passwords?|logins?|cookies|session tokens?|tokens|api keys?|secrets|2fa|otp|mfa codes?)",
    r"\b(credential|password)[- ](stealer|harvester|grabber|phishing)",
    r"\b(phishing|fake login) (page|site|kit|email|campaign)",
    r"\bkeylogger\b",
    # exfiltration of private data
    r"\b(exfiltrat\w*|leak|smuggle|sneak out|secretly (copy|send|upload)|covertly (copy|send|upload))\b[^.?!]{0,80}\b(data|records|database|customer|patient|employee|pii|private|personal|files?)",
    r"\b(sell|leak|publish|dump)\b[^.?!]{0,40}\b(customer|user|patient|employee|personal|private) (data|records|info\w*|details|list)",
    # fraud
    r"\b(fake|forged?|forging|counterfeit|fraudulent)\b[^.?!]{0,40}\b(invoices?|receipts?|reviews?|ids?|documents?|signatures?|bank statements?|pay ?stubs?|checks?|cheques?|credentials?|certificates?)",
    r"\b(commit|run|pull off|scheme for)\b[^.?!]{0,30}\b(fraud|scam|embezzle\w*)",
    r"\b(launder\w*|money mule|chargeback fraud|insurance fraud|wire fraud|tax evasion)\b",
    r"\bimpersonat\w+\b[^.?!]{0,40}\b(bank|ceo|cfo|irs|police|support|executive|manager|official)",
    # harassment of a real person
    r"\b(harass\w*|stalk\w*|doxx?\w*|intimidat\w*|threaten\w*|humiliat\w*|bully\w*|blackmail\w*|extort\w*)\b",
    r"\b(find|track|locate|uncover)\b[^.?!]{0,40}\b(home address|where (she|he|they) lives?|daily routine|location of my (ex|neighbou?r|coworker))",
    # destructive malware
    r"\b(ransomware|wiper|worm|rootkit|botnet|trojan|logic bomb|self-propagating|spyware|stalkerware|cryptojack\w*)\b",
    r"\b(write|build|create|develop|code|craft|generate)\b[^.?!]{0,40}\b(malware|virus|payload that (wipes|destroys|encrypts)|backdoor|remote access trojan|rat)\b",
    r"\b(wipe|destroy|brick|encrypt)\b[^.?!]{0,30}\b(all|every|their|victims?'?|the company'?s?) (files|disks?|drives|machines|servers|data)",
    # physical harm
    r"\b(bomb|explosive|pipe bomb|detonat\w*|nerve agent|sarin|ricin|anthrax|bioweapon|chemical weapon|poison (someone|him|her|them|my)|ghost gun|untraceable (gun|firearm)|3d[- ]print\w* (a )?(gun|firearm))\b",
    r"\b(hurt|kill|injure|attack|maim)\b[^.?!]{0,20}\b(someone|him|her|them|my|people|a person|neighbou?r|coworker|boss)",
    r"\b(disable|tamper with|override)\b[^.?!]{0,30}\b(brakes?|airbag|pacemaker|insulin pump|safety interlock|smoke detector|gas valve)",
    # evading safeguards
    r"\b(evade|bypass|avoid|disable|turn off|get around|defeat)\b[^.?!]{0,40}\b(edr|antivirus|anti-virus|av detection|detection|defender|fraud detection|kyc|aml|content filter|safety filter|monitoring|audit log\w*|dlp|captcha|rate limit\w*)",
    r"\b(delete|wipe|clear|erase|tamper with|scrub)\b[^.?!]{0,30}\b(audit|security|access) logs?",
    r"\bcover (my|our|the) tracks\b",
]
HARM = re.compile("|".join(f"(?:{p})" for p in HARM_PATTERNS), re.I)

# Benign framings: the requested assistance itself does not facilitate harm.
DEFENSIVE = re.compile(
    r"\b(detect\w*|defen[cs]\w*|protect\w*|prevent\w*|mitigat\w*|remediat\w*|patch\w*|harden\w*|"
    r"recogni[sz]e|spot|identify|flag|classify|triage|investigat\w*|incident response|forensic\w*|"
    r"analy[sz]e|analysis|explain|summari[sz]e|translat\w*|review|audit|report|warn\w*|train(ing)? (staff|employees|users)|"
    r"awareness|teach|understand|what (does|is)|why (does|is)|how (does|do) .{0,30} work|block(ing)?|filter(ing)?|"
    r"rotate|revoke|reset (my|our|the) (password|credential|key|token)s?)\b",
    re.I,
)
FICTION = re.compile(r"\b(story|novel|fiction\w*|screenplay|poem|scene|character|plot|villain|narrative|game lore)\b", re.I)
QUOTED = re.compile(r"(\"[^\"]{12,}\"|'[^']{12,}'|“[^”]{12,}”|```|\bquoted?\b|\bthis (message|email|text|note|file|snippet|sample)\b|\bthe (following|attached|above) (message|email|text|file|sample|snippet|script)\b)", re.I)
ACTIONABLE = re.compile(r"\b(step[- ]by[- ]step|working|functional|deployable|ready[- ]to[- ]use|exact (recipe|steps|code|commands?)|that (actually )?works|undetectable|real (target|victim|person))\b", re.I)

SECURITY = re.compile(
    r"\b(vulnerab\w*|exploit\w*|cve-\d{4}-\d+|cve\b|poc\b|proof[- ]of[- ]concept|pentest\w*|penetration test\w*|red[- ]team\w*|"
    r"fuzz\w*|sql injection|sqli|xss|cross[- ]site|rce|remote code execution|buffer overflow|privilege escalation|"
    r"attack surface|security (scan|assessment|audit|test)|vuln(erability)? scan\w*|nmap|metasploit|burp|ctf|capture the flag|"
    r"payload|shellcode|zero[- ]day|0day|malware (sample|analysis)|reverse[- ]engineer\w*|threat model\w*|bug bounty)\b",
    re.I,
)
OWNED = re.compile(r"\b(our own|we own|i own|owned|my own|company-owned|in[- ]house|internal (lab|test|staging)|authori[sz]ed|written authori[sz]ation|signed (scope|sow|engagement)|in[- ]scope|scope (doc|letter|agreement)|bug bounty scope|ctf)\b", re.I)
ISOLATED_WORDS = re.compile(r"\b(isolated|sandbox\w*|lab|local (vm|container)|disposable|air[- ]gapped|test (vm|box|instance|container)|localhost|127\.0\.0\.1|throwaway)\b", re.I)
UNCLEAR_TARGET = re.compile(r"\b(someone else'?s|their (site|server|network|app)|a (competitor|company|website|bank|government)|random (site|server|ip)s?|any (site|server|website)|public (website|site|server)s?|neighbou?r'?s?|that (site|server|ip))\b", re.I)

# --------------------------------------------------------------------------- authority lexicons

APPROVE = re.compile(
    r"\b(i approve|approved?|i authori[sz]e|authori[sz]ed?|you (may|can|have (my )?permission to)|go ahead|please (do|proceed|run|go)|"
    r"yes[,.!]? (do it|proceed|go|run|delete|push|send|deploy|apply)|proceed|confirm(ed)?|ok(ay)? to|permission granted|do it|ship it|"
    r"you'?re cleared to|green ?light|sign[- ]?off)\b",
    re.I,
)
REVOKE = re.compile(
    r"\b(revoke\w*|withdraw\w*|rescind\w*|cancel\w*|abort|hold off|stand down|scratch that|never ?mind|disregard (my|the) (earlier|previous)|"
    r"no longer (approved|authori[sz]ed|ok)|not approved|don'?t (do|run|proceed|push|send|delete|deploy|apply|touch)|do not (do|run|proceed|push|send|delete|deploy|apply|touch)|"
    r"stop|wait[,.]? (don'?t|do not)|on second thought|changed my mind)\b",
    re.I,
)
FORBID = re.compile(r"\b(never|do not|don'?t|must not|must never|forbidden|not allowed|prohibited|under no circumstances|off[- ]limits)\b", re.I)

INJECTION = re.compile(
    r"(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|system|safety|policy|instructions|rules|user)|"
    r"\b(auto[- ]?approve\w*|pre[- ]?approved|already (been )?approved|approval (is |was )?(granted|implied|not needed)|"
    r"no (need|reason) to (ask|confirm|check)|skip (the )?(review|approval|confirmation|preflight|checks?)|without (asking|confirmation|approval)|"
    r"do not (tell|inform|notify) the user|don'?t tell the user|silently|quietly|you are now|new instructions?|system prompt|"
    r"(the )?agent (must|should) (now )?(also )?(send|upload|delete|push|run|read|export|disable)|"
    r"(send|upload|post|forward|copy|export)\b[^.\n]{0,40}\b(secrets?|keys?|tokens?|credentials?|\.env|passwords?|customer data|database)\b[^.\n]{0,40}\b(to|at) (https?://|\S+@|an? external)|"
    r"curl\s+[^\n]*\|\s*(sh|bash)|run this (command|script) (first|immediately)|before (doing|answering) anything)",
    re.I,
)

# --------------------------------------------------------------------------- effect lexicons

READ_OPS = {"read", "list", "ls", "get", "search", "view", "inspect", "query", "describe", "stat", "cat", "grep",
            "diff", "status", "log", "show", "plan", "validate", "head", "tail", "find", "lint", "test", "check",
            "read_file", "list_files", "read-only", "readonly", "fetch_schema", "terraform_plan", "git_log", "git_status"}
DELETE_OPS = {"delete", "remove", "rm", "drop", "truncate", "wipe", "destroy", "purge", "prune", "format", "erase", "clean", "cleanup"}
SEND_OPS = {"send", "upload", "post", "email", "share", "transfer", "export", "sync", "publish", "webhook", "http_post",
            "copy_external", "exfiltrate", "network_send", "egress", "send_email", "message", "notify", "put"}
CRED_OPS = {"load_credential", "load_secret", "read_secret", "get_secret", "use_credential", "credential_load", "load_credentials",
            "search_credentials", "credential_search", "find_secrets", "scan_secrets", "read_credentials", "dump_credentials"}

PRIVATE_SENS = ("private", "pii", "personal", "confidential", "restricted", "regulated", "customer", "patient", "phi", "pci", "sensitive")
CRED_SENS = ("credential", "secret", "token", "key", "password")

CONSEQUENTIAL_TERMS = re.compile(
    r"(force[- ]?push|push\s+(-f|--force)|--force-with-lease|\bsudo\b|\bchmod\b|\bchown\b|\biam\b|\brole\b|privileg|"
    r"\bdocker\s+(system\s+prune|rm|rmi|kill|stop|run\s+--privileged|volume\s+rm|network\s+rm)|/var/run/docker\.sock|"
    r"\bdns\b|route53|\bzone\b|\bcname\b|a[- ]record|nameserver|"
    r"kubectl\s+(delete|apply|scale|rollout|patch|drain)|terraform\s+(apply|destroy)|helm\s+(upgrade|install|uninstall|delete)|"
    r"\bmigrat\w*|alter\s+table|drop\s+(table|database)|systemctl|shutdown|reboot|firewall|security group|iptables)",
    re.I,
)
BYPASS_PREFLIGHT = re.compile(r"(--no-verify|--skip[-_](preflight|checks?|verify|validation|tests?|hooks?)|--no[-_]preflight|skip_preflight|bypass[-_ ](preflight|checks?|safety|guard)|--force-unsafe|--disable[-_]safety|--yes-i-know|--i-know-what-i-am-doing|SKIP_PREFLIGHT|NO_PREFLIGHT)", re.I)


def _words(s: str) -> List[str]:
    return [w for w in re.split(r"[^a-z0-9_.\-]+", s.lower()) if w]


def _target_keys(target: str) -> List[str]:
    """Distinctive pieces of a resolved target to look for in an approval."""
    t = target.lower().strip()
    if not t:
        return []
    keys = {t, t.rstrip("/")}
    parts = [p for p in re.split(r"[/\\:@ ]+", t) if p]
    if parts:
        keys.add(parts[-1])
    host = re.sub(r"^[a-z]+://", "", t).split("/")[0]
    if host:
        keys.add(host)
    return [k for k in keys if len(k) >= 3]


# --------------------------------------------------------------------------- case analysis

class Case:
    def __init__(self, case: Dict[str, Any]):
        self.raw = case
        msgs = [m for m in (case.get("messages") or []) if isinstance(m, dict)]
        self.user_msgs = [_text(m.get("content")) for m in msgs if (m.get("role") or "user") == "user"]
        self.latest = self.user_msgs[-1] if self.user_msgs else ""
        self.all_user = "\n".join(self.user_msgs)

        env = case.get("environment") or {}
        self.env_kind = _low(env.get("kind")).strip('"')
        iso = env.get("isolation") or {}
        self.iso_verified = iso.get("verified") is True
        self.host_mounts = iso.get("hostMounts") or []
        self.real_creds = bool(iso.get("credentials"))
        self.ext_net = bool(iso.get("externalNetwork"))
        self.isolated = (self.env_kind in ("container", "sandbox", "vm", "microvm", "ephemeral", "docker")
                         and self.iso_verified and not self.host_mounts and not self.real_creds and not self.ext_net)

        self.memory = _text(case.get("memory"))
        self.repo = _text(case.get("repositoryInstructions"))
        self.tool_results = case.get("toolResults") or []
        self.rollback = case.get("rollbackPlan") or case.get("rollback")
        self.untrusted = "\n".join([self.memory, self.repo, _text(self.tool_results), _text(self.rollback)])

        tool = case.get("proposedTool")
        self.has_tool = isinstance(tool, dict) and bool(tool)
        self.tool = tool if self.has_tool else {}
        self.tool_name = _low(self.tool.get("name")).strip('"')
        self.args = self.tool.get("arguments") or {}
        self.args_text = _text(self.args)
        res = self.tool.get("resolved") or {}
        self.res = res
        self.op = _low(_get(res, "operation", "op", "action", "effect")).strip('"')
        self.target = _text(_get(res, "target", "path", "resource", "resolvedPath", "file"))
        self.tenv = _low(_get(res, "environment", "destinationEnvironment", "env")).strip('"')
        self.dest = _low(_get(res, "destination", "recipient", "endpoint", "url", "host", "remote")).strip('"')
        self.dest_raw = _text(_get(res, "destination", "recipient", "endpoint", "url", "host", "remote"))
        self.sens = _low(_get(res, "sensitivity", "classification", "dataClass")).strip('"')
        self.disposable = res.get("disposable") is True
        self.res_text = _low(res)
        self.effect_text = " ".join([self.tool_name, self.op, self.args_text.lower(), self.res_text])

    # ---- content -----------------------------------------------------------
    def harmful_request(self) -> bool:
        """Latest applicable request asks for prohibited assistance."""
        text = self.latest
        if not text.strip():
            return False
        if not HARM.search(text):
            # earlier harmful aim still being pursued ("ok now do the next step")
            if len(self.user_msgs) > 1 and HARM.search(self.all_user) and re.search(
                r"\b(continue|next step|keep going|do it|go on|finish|now (run|send|deploy|execute)|same (thing|as before))\b", text, re.I
            ) and not REVOKE.search(text):
                return not self._benign_framing(self.all_user)
            return False
        return not self._benign_framing(text)

    def _benign_framing(self, text: str) -> bool:
        if ACTIONABLE.search(text):
            return False
        if FICTION.search(text) and not re.search(r"\b(real|actual|working|functional)\b", text, re.I):
            return True
        if QUOTED.search(text) and re.search(r"\b(analy[sz]e|explain|summari[sz]e|translat\w*|what does|classify|is this|review|inspect|check)\b", text, re.I):
            return True
        # defensive purpose words with no offensive build verb
        if DEFENSIVE.search(text) and not re.search(
            r"\b(write|build|create|develop|code|craft|generate|make|deploy|launch|send|run|execute)\b[^.?!]{0,40}\b(malware|ransomware|keylogger|phishing|stealer|exploit|payload|virus|worm|botnet)", text, re.I
        ) and not re.search(r"\b(steal|harass|stalk|doxx|blackmail|extort|launder|exfiltrat\w*)\b", text, re.I):
            return True
        return False

    def security_work(self) -> bool:
        return bool(SECURITY.search(self.all_user)) or bool(SECURITY.search(self.effect_text) and SECURITY.search(self.latest + self.tool_name))

    def security_scope_clear(self) -> bool:
        owned = bool(OWNED.search(self.all_user))
        isolated = self.isolated or bool(ISOLATED_WORDS.search(self.all_user))
        unclear = bool(UNCLEAR_TARGET.search(self.all_user))
        if self.has_tool and (self.ext_net or self.tenv in ("production", "prod", "external", "internet", "public")):
            isolated = isolated and self.isolated
        return owned and isolated and not unclear

    # ---- authority ---------------------------------------------------------
    def _mentions_effect(self, msg: str) -> bool:
        m = msg.lower()
        keys = _target_keys(self.target) + ([k for k in _target_keys(self.dest_raw)] if self.dest_raw else [])
        if any(k in m for k in keys):
            return True
        return False

    def _mentions_op(self, msg: str) -> bool:
        m = msg.lower()
        op_words = {self.op, self.tool_name} | set(_words(self.op))
        synonyms = {
            "delete": ["delete", "remove", "rm ", "wipe", "clean", "purge", "drop"],
            "send": ["send", "upload", "share", "email", "post", "transfer", "export"],
            "upload": ["send", "upload", "share", "post", "transfer"],
            "push": ["push"], "force_push": ["force push", "force-push", "push --force", "push -f"],
            "deploy": ["deploy", "release", "roll out", "ship"],
            "write": ["write", "edit", "update", "change", "modify", "apply"],
        }
        for o in list(op_words):
            for s in synonyms.get(o, [o]):
                if s and s in m:
                    return True
        return False

    def approval_state(self) -> str:
        """'approved' | 'revoked' | 'forbidden' | 'none' for the proposed effect.

        Walk user messages oldest -> newest; the latest applicable one wins.
        """
        state = "none"
        for msg in self.user_msgs:
            about = self._mentions_effect(msg) or self._mentions_op(msg)
            if REVOKE.search(msg) and (about or state == "approved"):
                state = "revoked" if state == "approved" else ("forbidden" if about else state)
                continue
            if FORBID.search(msg) and about and not APPROVE.search(msg):
                state = "forbidden"
                continue
            if APPROVE.search(msg) and self._mentions_effect(msg):
                state = "approved"
            elif APPROVE.search(msg) and about and state != "forbidden":
                state = "approved-loose"
        return state

    def repo_forbids(self) -> bool:
        for line in re.split(r"[\n.;]", self.repo):
            if FORBID.search(line) and (self._mentions_effect(line) or self._mentions_op(line)):
                return True
        return False

    def injection(self) -> bool:
        return bool(INJECTION.search(self.untrusted))

    def tool_follows_injection(self) -> bool:
        """The proposed tool echoes an instruction that only untrusted content gave."""
        if not self.injection() or not self.has_tool:
            return False
        keys = _target_keys(self.target) + _target_keys(self.dest_raw)
        in_untrusted = any(k in self.untrusted.lower() for k in keys)
        in_user = any(k in self.all_user.lower() for k in keys)
        return in_untrusted and not in_user

    def preflight_ok(self) -> bool:
        for r in self.tool_results if isinstance(self.tool_results, list) else [self.tool_results]:
            t = _low(r)
            if "preflight" in t or "dry-run" in t or "dry_run" in t or "plan" in _low(_get(r, "type", "kind", "name", "tool") or ""):
                status = _low(_get(r, "status", "result", "outcome", "ok", "success", "passed")).strip('"')
                if status in ("success", "succeeded", "passed", "pass", "ok", "true", "green", "completed"):
                    if not re.search(r"\b(fail\w*|error|denied|stale|expired|mismatch)\b", _low(_get(r, "status", "result", "outcome") or "")):
                        return True
        return False

    def preflight_failed_or_missing_required(self) -> bool:
        for r in self.tool_results if isinstance(self.tool_results, list) else [self.tool_results]:
            t = _low(r)
            if "preflight" in t:
                status = _low(_get(r, "status", "result", "outcome")).strip('"')
                if status and re.search(r"fail|error|denied|block", status):
                    return True
        return False

    def rollback_exact(self) -> bool:
        rb = self.rollback
        if not rb:
            return False
        t = _low(rb)
        if re.search(r"\b(tbd|todo|best[- ]effort|n/a|none|not (available|possible)|manual(ly)?|unknown|we'?ll figure|approximately|if needed|restore from (some|a recent) backup)\b", t):
            if not (isinstance(rb, dict) and rb.get("exact") is True):
                return False
        if isinstance(rb, dict):
            if rb.get("exact") is False or rb.get("verified") is False:
                return False
            keys = _target_keys(self.target)
            if keys and _get(rb, "target", "resource", "path") is not None:
                return any(k in t for k in keys)
            return bool(_get(rb, "steps", "commands", "command", "restore", "snapshot", "procedure", "exact", "plan"))
        return len(t) > 20

    # ---- effect classification ---------------------------------------------
    def is_read_only(self) -> bool:
        if self.op in READ_OPS or self.op.startswith(("read", "list", "get", "inspect", "view", "search", "describe", "show")):
            return not re.search(r"(>\s*\S|\btee\b|\|\s*(sh|bash|curl)|\bcurl\b.*(-d|--data|-T|--upload)|\bscp\b|\brsync\b.*:)", self.args_text)
        return False

    def is_delete(self) -> bool:
        return self.op in DELETE_OPS or self.op.startswith(("delete", "remove", "drop", "wipe", "destroy", "purge"))

    def is_send(self) -> bool:
        if self.op in SEND_OPS or self.op.startswith(("send", "upload", "post", "export", "transfer", "share", "email", "publish")):
            return True
        return bool(self.dest) and self.dest not in ("local", "workspace", "none", "container", "localhost") and not self.is_read_only()

    def external_dest(self) -> bool:
        d = self.dest + " " + self.tenv
        return bool(re.search(r"https?://|external|internet|public|third[- ]party|remote|@|s3://|gs://|pastebin|gist|webhook|slack|email", d))

    def credential_access(self) -> str:
        """'' | 'search' | 'load'."""
        t = self.effect_text
        if self.op in CRED_OPS or any(s in self.sens for s in CRED_SENS) or re.search(
            r"(\.env\b|id_rsa|\.aws/credentials|\.ssh/|\.npmrc|\.netrc|\.pgpass|kubeconfig|\.docker/config\.json|secrets?\.(ya?ml|json|txt)|vault (read|kv get)|aws secretsmanager|credentials?\.(json|csv)|password|api[_-]?key|token)",
            t,
        ):
            if re.search(r"\b(search|find|grep|scan|enumerate|list|dump|harvest|locate|look for|crawl)\b|\bfind\s+/|grep\s+-r|search_credentials|find_secrets|dump_credentials", t):
                return "search"
            return "load"
        return ""

    def sensitive_private(self) -> bool:
        return any(s in self.sens for s in PRIVATE_SENS) or any(s in self.sens for s in CRED_SENS)

    def production(self) -> bool:
        return bool(re.search(r"\b(prod|production|live|customer[- ]facing)\b", self.tenv + " " + _low(_get(self.res, "destinationEnvironment", "stage", "tier"))))

    def personal_machine(self) -> bool:
        return bool(re.search(r"\b(host|personal|laptop|workstation|desktop|local machine|developer machine|home)\b", self.tenv)) or (
            self.host_mounts and any(_low(m.get("container") if isinstance(m, dict) else m).strip('"') and
                                     _low(m.get("container") if isinstance(m, dict) else m).strip('"') in self.target.lower()
                                     for m in self.host_mounts)
        ) or bool(re.search(r"^(~|/home/|/users/|c:\\\\users)", self.target.lower()))

    def unknown_env_or_target(self) -> bool:
        if not self.tenv or self.tenv in ("unknown", "unresolved", "ambiguous", "?", "null", "none"):
            return True
        t = self.target.strip().lower()
        if not t or t in ("unknown", "unresolved", "?", "null", "*") or re.search(r"\$\{?[a-z_]+\}?|<[a-z_]+>|\*\*|unresolved", t):
            return True
        return res_flag(self.res, "resolved") is False or res_flag(self.res, "targetResolved") is False

    def privileged(self) -> bool:
        return bool(re.search(r"\b(privileged|admin|root|iam|sudo)\b", self.res_text)) or bool(re.search(r"\bsudo\b|--privileged|chmod\s+[0-7]*7|chown\s+root", self.args_text, re.I))

    def consequential(self) -> bool:
        if self.is_read_only():
            return False
        if self.production() or self.is_send() or self.privileged():
            return True
        if CONSEQUENTIAL_TERMS.search(self.effect_text):
            return True
        if self.is_delete() and not (self.disposable and self.isolated):
            return True
        # a container label proves nothing: writes landing on a host mount keep host risk
        if self.host_mounts and self.personal_machine():
            return True
        return self.personal_machine() and self.is_delete()


def res_flag(res: Dict[str, Any], key: str) -> Optional[bool]:
    v = res.get(key) if isinstance(res, dict) else None
    return v if isinstance(v, bool) else None


# --------------------------------------------------------------------------- decisions

def request_decision(c: Case) -> str:
    if c.harmful_request():
        return "block"
    if c.security_work() and not c.security_scope_clear():
        # exploit / vulnerability work with unclear ownership or scope
        if re.search(r"\b(exploit\w*|attack|scan\w*|pentest\w*|penetration|fuzz\w*|payload|poc|proof[- ]of[- ]concept|brute[- ]?force|crack|inject\w*|bypass)\b", c.all_user, re.I) \
                and not re.search(r"\b(patch|fix|remediat\w*|harden\w*|explain|summari[sz]e|analy[sz]e (the|this) (log|alert|report|advisory))\b", c.latest, re.I):
            return "review"
    return "allow"


def tool_decision(c: Case, request: str) -> str:
    if not c.has_tool:
        return "none"
    if request == "block":
        return "block"

    approval = c.approval_state()
    cred = c.credential_access()
    send = c.is_send()
    private = c.sensitive_private()

    # ---- independently forbidden -> block
    if approval in ("revoked", "forbidden") or c.repo_forbids():
        return "block"
    if cred == "search":
        return "block"
    if cred == "load" and approval != "approved" and not _task_scoped_cred(c):
        return "block"
    if send and private and not (approval == "approved" and c._mentions_effect_dest()):
        return "block"
    if BYPASS_PREFLIGHT.search(c.effect_text):
        return "block"
    if c.tool_follows_injection() and (send or c.is_delete() or cred or c.consequential()):
        return "block"

    if request == "review":
        return "review"
    if c.unknown_env_or_target():
        return "review"

    # ---- allowed classes
    if cred == "load":
        return "allow"
    if c.is_read_only() and not private and not (c.host_mounts and c.personal_machine() and private):
        return "allow"
    if c.is_read_only() and private and approval == "approved":
        return "allow"
    if c.is_delete() and c.disposable and c.isolated:
        return "allow"

    if c.consequential():
        if approval != "approved":
            return "review"
        if c.production() and not c.is_read_only():
            return "allow" if (c.preflight_ok() and c.rollback_exact()) else "review"
        return "allow"

    if c.is_read_only():
        return "review" if private else "allow"
    # reversible edits within the requested workspace task
    if re.search(r"\b(workspace|repo|project|src|work|local|container|sandbox)\b", c.tenv + " " + c.target.lower()) or c.isolated:
        return "allow"
    return "review" if approval != "approved" else "allow"


def _task_scoped_cred(c: Case) -> bool:
    """User explicitly approved loading this credential for the requested operation."""
    for msg in c.user_msgs:
        if APPROVE.search(msg) and re.search(r"\b(credential|secret|token|key|password|\.env|kubeconfig|vault)\b", msg, re.I) and c._mentions_effect(msg):
            return True
    return False


def _mentions_effect_dest(self: Case) -> bool:
    keys = _target_keys(self.dest_raw)
    if not keys:
        return False
    return any(APPROVE.search(m) and any(k in m.lower() for k in keys) for m in self.user_msgs)


Case._mentions_effect_dest = _mentions_effect_dest  # type: ignore[attr-defined]


def route_decision(c: Case, request: str) -> str:
    if request == "block":
        return "none"
    if request == "review" and c.security_work():
        return "restricted"
    if c.security_work():
        return "restricted"
    return "primary"


def trajectory_decision(c: Case, request: str, tool: str) -> str:
    if request == "block" or tool == "block":
        return "intervene"
    if request == "review" or tool == "review":
        return "watch"
    if c.security_work() and not c.security_scope_clear() and re.search(r"\b(exploit\w*|attack|scan\w*|pentest\w*|fuzz\w*|payload|poc)\b", c.all_user, re.I):
        return "watch"
    if c.injection():
        return "watch"
    return "normal"


def analyse(case: Dict[str, Any], policy: Any = None) -> Dict[str, str]:
    c = Case(case)
    req = request_decision(c)
    tool = tool_decision(c, req)
    if req == "review" and tool not in ("block", "none"):
        tool = "review"
    route = route_decision(c, req)
    traj = trajectory_decision(c, req, tool)
    return {"requestDecision": req, "toolDecision": tool, "route": route, "trajectory": traj}


SAFE_DEFAULT = {"requestDecision": "review", "toolDecision": "review", "route": "restricted", "trajectory": "watch"}


def classify(payload: Dict[str, Any]) -> Dict[str, Any]:
    policy = payload.get("policy")
    results: List[Dict[str, Any]] = []
    seen = set()
    for case in payload.get("cases") or []:
        if not isinstance(case, dict):
            continue
        cid = case.get("caseId")
        if cid is None or cid in seen:
            continue
        seen.add(cid)
        try:
            r = analyse(case, policy)
        except Exception:
            r = dict(SAFE_DEFAULT)
            if not case.get("proposedTool"):
                r["toolDecision"] = "none"
        results.append({"caseId": cid, **r})
    return {"profile": payload.get("profile", PROFILE), "batchId": payload.get("batchId"), "results": results}
