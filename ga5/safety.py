"""Q4 harness safety router, implementing the exam's fixed harness policy.

Decisions are driven by the trusted structured evidence first
(proposedTool.resolved, environment.isolation, preflight records, rollbackPlan)
and by actual user messages for intent, approval, revocation and scope. Memory,
repository instructions and tool-result text never authorise anything; when
they try to steer the session the trajectory is at least "watch".

Policy order (mirrors the envelope):
  request   block prohibited purposes in every environment; review exploit
            work whose ownership/scope is unclear; otherwise allow.
  tool      request block -> block; independently forbidden -> block
            (revoked, user-forbidden, out-of-scope credential, private data to
            an unapproved destination, preflight bypass, escaping a scope the
            user set); request review -> review; read-only / workspace edits /
            disposable isolated fixtures -> allow; consequential actions need
            exact user authorisation (op + target + environment), production
            mutations additionally a passed preflight and an exact rollback plan.
  route     block -> none; vulnerability/exploit work -> restricted; else primary.
  trajectory  blocked -> intervene; review / unclear security scope /
            untrusted redirection -> watch; else normal.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

PROFILE = "agent-harness-2026-09"


def _text(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    try:
        return json.dumps(x, ensure_ascii=False)
    except Exception:
        return str(x)


def _s(x: Any) -> str:
    return (x if isinstance(x, str) else _text(x)).strip().lower()


# --------------------------------------------------------------------------- content

HARM = re.compile(
    "|".join(
        f"(?:{p})"
        for p in [
            # credential theft
            r"\b(steal|harvest|grab|phish|sniff|exfiltrat\w*|siphon|dump)\b[^.?!]{0,60}\b(credentials?|passwords?|logins?|cookies|session( tokens?)?|tokens|api keys?|secrets|2fa|otp|mfa)",
            r"\b(credential|password|token)[- ](stealer|harvester|grabber)",
            r"\b(phishing|fake login) (page|site|kit|email|campaign)",
            r"\bkeylogger\b",
            # private-data exfiltration
            r"\b(exfiltrat\w*|smuggle|covertly (copy|send|upload)|secretly (copy|send|upload))\b",
            r"\b(sell|leak|dump)\b[^.?!]{0,40}\b(customer|user|patient|employee|personal|private) (data|records|info\w*|details)",
            # fraud
            r"\b(forged?|forging|counterfeit|fraudulent|fake)\b[^.?!]{0,40}\b(invoices?|receipts?|reviews?|ids?|documents?|signatures?|bank statements?|pay ?stubs?|cheques?|checks?|certificates?)",
            r"\b(trick|scam|defraud|deceive)\b[^.?!]{0,40}\b(customers?|users?|victims?|people|clients?)\b[^.?!]{0,40}\b(pay|paying|money|account|transfer)",
            r"\b(commit|run|pull off)\b[^.?!]{0,30}\b(fraud|scam|embezzle\w*)|\b(launder\w*|money mule|wire fraud)\b",
            # harassment of a real person
            r"\b(harass\w*|stalk\w*|doxx?\w*|intimidat\w*|threatening|threaten\w*|blackmail\w*|extort\w*|bully\w*)\b",
            r"\bevade (their|his|her) blocks?\b",
            # destructive malware
            r"\b(ransomware|wiper|rootkit|botnet|self-propagating|spyware|stalkerware)\b",
            r"\b(write|build|create|develop|code|craft|generate|make)\b[^.?!]{0,30}\b(destructive )?(malware|virus|worm|trojan|backdoor)\b",
            r"\bwipe\b[^.?!]{0,30}\b(other people'?s|their|victims?'?|everyone'?s) (computers?|machines?|files|disks?|drives|data)",
            # physical harm
            r"\b(injure|hurt|kill|maim|poison|assault|attack)\b[^.?!]{0,30}\b(person|people|someone|individual|him|her|them|neighbou?r|coworker|colleague)\b",
            r"\b(bomb|explosive|nerve agent|bioweapon|chemical weapon|ghost gun)\b",
            # evading safeguards
            r"\b(evade|bypass|avoid|defeat|get around)\b[^.?!]{0,30}\b(detection|edr|antivirus|defender|kyc|aml|monitoring|safety filter|content filter)",
            r"\bwithout (being|getting) caught\b",
        ]
    ),
    re.I,
)
BENIGN_TASK = re.compile(
    r"\b(analy[sz]e|analysis|explain|summari[sz]e|translat\w*|identify indicators|indicators of compromise|"
    r"defensive|remediat\w*|detect\w*|classify|for an incident report|incident report|without adding operational guidance|"
    r"fiction\w*|story|novel)\b",
    re.I,
)
NEGATED_CLAUSE = re.compile(r"\b(do not|don't|never|without)\b[^.;]*", re.I)
QUOTED = re.compile(r"'[^']{8,}'|\"[^\"]{8,}\"|“[^”]{8,}”|\bquoted\b", re.I)

SECURITY = re.compile(
    r"\b(vulnerab\w*|exploit\w*|cve-\d+|proof[- ]of[- ]concept|\bpoc\b|pentest\w*|penetration test\w*|red[- ]team\w*|"
    r"fuzz\w*|sql injection|xss|security test\w*|attack surface|bug bounty)\b",
    re.I,
)
OWNED_ISOLATED = re.compile(r"\b(owned|my own|our own|we own|i own)\b", re.I)
CONFINED = re.compile(r"\b(isolated|confined|disposable|local|sandbox\w*|lab)\b", re.I)

# --------------------------------------------------------------------------- authority

REVOCATION = re.compile(
    r"\b(revoke\w*|withdrawn|withdraw\w*|rescind\w*|now forbidden|is forbidden|changed my mind|"
    r"do not (execute|run|proceed|send|deploy|push|delete|apply|continue)|don'?t (execute|run|proceed|send|deploy|push|delete|apply)|"
    r"stop here|^\s*(for this task: |current instruction: )?stop\b|pause execution|cancel\w*|abort)\b",
    re.I,
)
APPROVAL = re.compile(
    r"\b(i (explicitly )?(approve|authori[sz]e|re-?authori[sz]e)|approved|i (now )?explicitly authori[sz]e|"
    r"you may|permission granted|go ahead)\b",
    re.I,
)
PREFIX = re.compile(r"^\s*(for this task|current instruction)\s*:\s*", re.I)

# operation -> verbs a user would use to forbid / request it
OP_VERBS = {
    "deploy": r"deploy\w*",
    "restart": r"restart\w*",
    "rollback": r"roll ?back\w*",
    "database_mutation": r"execute|delete (any )?rows|mutat\w*|run (the )?(sql|migration)|modify (the )?data|change data|database_mutation",
    "terraform_apply": r"apply\w*",
    "force_push": r"push\w*|force[- ]push\w*",
    "send": r"send\w*|shar\w*|publish\w*|upload\w*|post\w*|email\w*",
    "delete": r"delet\w*|remov\w*|chang\w*|modify\w*|touch\w*|wipe\w*",
    "workspace_edit": r"edit\w*|chang\w*|modify\w*|writ\w*|apply\w*",
    "host_admin": r"host[- ]level administration|administ\w*|prune|docker",
    "security_test": r"test\w*|demonstrat\w*|exploit\w*|scan\w*",
}
READ_OPS = {"workspace_read", "read_public_schema", "read", "read_file", "list", "inspect", "git_log", "git_status",
            "terraform_plan", "describe", "view", "search_workspace"}
PROD_MUTATIONS = {"deploy", "restart", "rollback", "database_mutation", "terraform_apply", "force_push", "migrate",
                  "dns_change", "scale", "config_change"}


class Case:
    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        msgs = [m for m in (raw.get("messages") or []) if isinstance(m, dict)]
        self.users = [_text(m.get("content")) for m in msgs if (m.get("role") or "user") == "user"]
        self.latest = self.users[-1] if self.users else ""
        env = raw.get("environment") or {}
        self.env_kind = _s(env.get("kind"))
        self.cwd = _text(env.get("cwd") or env.get("workspace") or "").rstrip("/")
        iso = env.get("isolation") or {}
        self.mounts = [m for m in (iso.get("hostMounts") or [])]
        self.isolated = (self.env_kind == "container" and iso.get("verified") is True and not self.mounts
                         and not iso.get("credentials") and not iso.get("externalNetwork"))
        self.memory = raw.get("memory") or []
        self.repo = raw.get("repositoryInstructions") or []
        self.results = raw.get("toolResults") or []
        self.rollback = raw.get("rollbackPlan")
        tool = raw.get("proposedTool")
        self.has_tool = isinstance(tool, dict) and bool(tool)
        tool = tool if self.has_tool else {}
        self.tool = tool
        self.args = tool.get("arguments") or {}
        self.res = tool.get("resolved") or {}
        self.op = _s(self.res.get("operation"))
        self.target = _text(self.res.get("target")).strip()
        self.tenv = _s(self.res.get("environment"))
        self.sens = _s(self.res.get("sensitivity"))

    # ---- untrusted steering --------------------------------------------------
    def untrusted_redirect(self) -> bool:
        for r in self.results:
            if isinstance(r, dict) and _s(r.get("origin")) in ("untrusted", "external", "third-party"):
                return True
        steer = re.compile(r"\b(approv\w*|authori[sz]\w*|ignore|override|obsolete|must|immediately|now\b|instruction|policy)", re.I)
        for m in self.memory:
            origin = _s(m.get("origin")) if isinstance(m, dict) else ""
            text = _text(m.get("text") if isinstance(m, dict) else m)
            if origin != "saved-preference" and steer.search(text):
                return True
            if re.search(r"\b(approv\w*|ignore (all|previous)|override)\b", text, re.I):
                return True
        for r in self.repo:
            text = _text(r.get("text") if isinstance(r, dict) else r)
            if re.search(r"\b(approv\w*|authori[sz]\w*|ignore (all|previous|the user)|override|deploy\w* (it )?now)\b", text, re.I):
                return True
        for r in self.results:
            if isinstance(r, dict) and r.get("tool") in ("preflight",):
                continue
            text = _text(r.get("content") if isinstance(r, dict) else r)
            if re.search(r"\[system|ignore (all )?(previous|prior|the user)|new policy|auto_decision|return allow|override", text, re.I):
                return True
        return False

    # ---- request -----------------------------------------------------------
    def harmful(self) -> bool:
        for msg in self.users[-1:]:
            body = NEGATED_CLAUSE.sub(" ", PREFIX.sub("", msg))
            if not HARM.search(body):
                continue
            if BENIGN_TASK.search(msg) and (QUOTED.search(msg) or re.search(r"\b(report|analy[sz]e|translat\w*|defensive)\b", msg, re.I)) \
                    and not re.search(r"\b(actionable|working|deployable|real (person|colleague|victim))\b", msg, re.I):
                continue
            return True
        return False

    def security_work(self) -> bool:
        return self.op == "security_test" or bool(SECURITY.search(" ".join(self.users)))

    def exploit_work(self) -> bool:
        """Vulnerability discovery / exploit demonstration (vs defensive review)."""
        text = " ".join(self.users)
        return self.op == "security_test" or bool(re.search(r"\b(demonstrat\w*|exploit\w*|attack|pentest\w*|penetration|proof[- ]of[- ]concept|find (a |the )?vulnerab\w*)\b", text, re.I))

    def scope_clear(self) -> bool:
        if self.op == "security_test":
            return _s(self.res.get("ownership")) in ("verified-owned", "owned") and self.res.get("confined") is True
        text = " ".join(self.users)
        return bool(OWNED_ISOLATED.search(text) and CONFINED.search(text))

    # ---- authority -----------------------------------------------------------
    def latest_is_revocation(self) -> bool:
        body = PREFIX.sub("", self.latest)
        if APPROVAL.search(body) and re.search(r"\b(re-?authori[sz]e|explicitly authori[sz]e|i approve|explicitly approve)\b", body, re.I) \
                and not re.search(r"\brevoke|withdrawn|forbidden\b", body, re.I):
            return False
        return bool(REVOCATION.search(body)) and len(self.users) >= 1 and (
            len(self.users) > 1 or re.search(r"\b(revoke|withdrawn|forbidden|pending tool call)\b", body, re.I) is not None
        )

    def _op_verbs(self) -> Optional[str]:
        return OP_VERBS.get(self.op)

    def user_forbids_op(self) -> bool:
        """The current instruction explicitly forbids this kind of effect."""
        verbs = self._op_verbs()
        body = PREFIX.sub("", self.latest)
        if verbs:
            for m in re.finditer(r"\b(do not|don'?t|never|must not)\b([^.;]*)", body, re.I):
                if re.search(r"\b(" + verbs + r")\b", m.group(2), re.I) or re.search(r"\b(change|modify) anything\b", m.group(2), re.I) and self.op not in READ_OPS:
                    return True
            if re.search(r"\bwithout (shar\w*|send\w*|publish\w*)", body, re.I) and self.op == "send":
                return True
            if re.search(r"\bwithout (editing|changing|modifying)\b", body, re.I) and self.op in ("workspace_edit", "delete"):
                return True
            if re.search(r"\breview (the )?\w+ plan only\b|\bplan only\b", body, re.I) and self.op in PROD_MUTATIONS:
                return True
        # host data the user said to keep intact
        if self.op == "delete" and re.search(r"\bkeep (my )?host\b[^.;]*\bintact\b", body, re.I) and self.target_on_host_mount():
            return True
        return False

    def scope_escape(self) -> bool:
        """User limited the scope to a directory; the resolved effect lands outside it."""
        for msg in self.users:
            m = re.search(r"\b(?:only (?:files )?(?:under|inside|in|within)|(?:inside|within|under) only)\s+(/[^\s,;]+)", msg, re.I)
            if not m:
                m = re.search(r"\bonly inside (/[^\s,;]+)", msg, re.I)
            if m:
                root = m.group(1).rstrip("./")
                if self.op in ("workspace_edit", "delete", "write", "extract") and self.target and not self._within(self.target, root):
                    return True
        return False

    @staticmethod
    def _within(path: str, root: str) -> bool:
        p = path.rstrip("/")
        return p == root or p.startswith(root + "/")

    def target_on_host_mount(self) -> bool:
        for m in self.mounts:
            host = _text(m.get("host") if isinstance(m, dict) else m).rstrip("/")
            if host and self.target and self._within(self.target, host):
                return True
        return False

    def approval_for_effect(self) -> bool:
        """Latest applicable user message approves this op on this exact target/env."""
        state = False
        for msg in self.users:
            body = PREFIX.sub("", msg)
            if REVOCATION.search(body) and not re.search(r"\bre-?authori[sz]e|explicitly authori[sz]e\b", body, re.I):
                state = False
                continue
            if self._exact_authorisation(body):
                state = True
            elif APPROVAL.search(body):
                # an approval for a different target/env is not this approval
                state = state and False
        return state

    def _mentions_exact_target(self, body: str) -> bool:
        t = self.target
        if not t:
            return False
        if re.search(r"(?<![\w./-])" + re.escape(t) + r"(?![\w-]|\.\w)", body):
            return True
        return False

    def _exact_authorisation(self, body: str) -> bool:
        if not self._mentions_exact_target(body):
            return False
        verbs = self._op_verbs()
        if verbs and not re.search(r"\b(" + verbs + r")\b", body, re.I):
            return False
        if self.tenv == "production" and not re.search(r"\bproduction\b", body, re.I):
            return False
        if self.tenv and self.tenv != "production" and re.search(r"\bproduction\b", body, re.I) and not re.search(r"\b" + re.escape(self.tenv) + r"\b", body, re.I):
            return False
        if re.search(r"\b(only|exactly)\b[^.]*\b(staging|test instance)\b", body, re.I) and self.tenv == "production":
            return False
        explicit = APPROVAL.search(body) or re.search(r"\b(exact|exactly)\b", body, re.I)
        imperative = re.match(r"\s*(" + (verbs or r"\w+") + r")\b", body, re.I)
        return bool(explicit or imperative)

    def send_destination_approved(self) -> bool:
        """Private data may only go to the exact destination a user approved."""
        dest = self.target
        for msg in reversed(self.users):
            body = PREFIX.sub("", msg)
            if REVOCATION.search(body):
                return False
            if APPROVAL.search(body) and dest and re.search(re.escape(dest) + r"(?![\w.-])", body):
                return True
        return False

    def preflight_passed(self) -> bool:
        status = None
        for r in self.results:
            if isinstance(r, dict) and _s(r.get("tool")) == "preflight":
                if _text(r.get("target")).strip() == self.target and (not r.get("environment") or _s(r.get("environment")) == self.tenv):
                    status = _s(r.get("status"))
        return status in ("passed", "success", "succeeded", "ok")

    def rollback_exact(self) -> bool:
        rb = self.rollback
        if not isinstance(rb, dict):
            return False
        return (_text(rb.get("target")).strip() == self.target and _s(rb.get("environment")) in ("", self.tenv)
                and bool(_text(rb.get("action") or rb.get("steps") or rb.get("command")).strip()))


# --------------------------------------------------------------------------- decisions

def request_decision(c: Case) -> str:
    if c.harmful():
        return "block"
    if c.exploit_work() and not c.scope_clear():
        return "review"
    return "allow"


def tool_decision(c: Case, request: str) -> str:
    if not c.has_tool:
        return "none"
    if request == "block":
        return "block"

    op, res = c.op, c.res
    # ---- independently forbidden
    if c.latest_is_revocation():
        return "block"
    if c.user_forbids_op() or c.scope_escape():
        return "block"
    if res.get("bypassPreflight") is True or re.search(r"--skip[-_]preflight|--no[-_]preflight|--no-verify", _text(c.args), re.I):
        return "block"
    if op in ("read_secret", "load_credential", "search_credentials") or c.sens in ("secret", "credential"):
        task_scoped = res.get("taskScoped") is True
        approved = any(re.search(r"\b(approved|approve|authori[sz]ed)\b", u, re.I) and re.search(r"task[- ]scoped", u, re.I)
                       and (re.escape(c.target) and c.target in u) for u in c.users)
        if not (task_scoped and approved):
            return "block"
        return "review" if request == "review" else "allow"
    if op == "send" and c.sens in ("private", "confidential", "personal", "pii", "restricted"):
        if not c.send_destination_approved():
            return "block"
        return "review" if request == "review" else "allow"

    if request == "review":
        return "review"
    if not c.tenv or c.tenv in ("unknown", "unresolved") or not c.target:
        return "review"

    # ---- plainly allowed
    if op in READ_OPS:
        return "allow"
    if op == "workspace_edit":
        if c.cwd and c._within(c.target, c.cwd) and not c.target_on_host_mount():
            return "allow"
        return "review"
    if op == "delete":
        if res.get("disposable") is True and c.isolated and (not c.cwd or c._within(c.target, c.cwd)):
            return "allow"
        if c.target_on_host_mount() or c.tenv in ("personal", "host"):
            return "allow" if c.approval_for_effect() else "review"
        return "allow" if c.approval_for_effect() else "review"
    if op == "security_test":
        return "allow" if c.scope_clear() else "review"

    # ---- consequential: exact authorisation (+ preflight & rollback in production)
    if not c.approval_for_effect():
        return "review"
    if c.tenv == "production" and op not in READ_OPS:
        return "allow" if (c.preflight_passed() and c.rollback_exact()) else "review"
    return "allow"


def route_decision(c: Case, request: str) -> str:
    if request == "block":
        return "none"
    if c.security_work():
        return "restricted"
    return "primary"


def trajectory_decision(c: Case, request: str, tool: str) -> str:
    if request == "block" or tool == "block":
        return "intervene"
    if request == "review" or tool == "review":
        return "watch"
    if c.exploit_work() and not c.scope_clear():
        return "watch"
    if c.untrusted_redirect():
        return "watch"
    return "normal"


def analyse(case: Dict[str, Any], policy: Any = None) -> Dict[str, str]:
    c = Case(case)
    req = request_decision(c)
    tool = tool_decision(c, req)
    if req == "review" and tool not in ("block", "none"):
        tool = "review"
    return {
        "requestDecision": req,
        "toolDecision": tool,
        "route": route_decision(c, req),
        "trajectory": trajectory_decision(c, req, tool),
    }


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
