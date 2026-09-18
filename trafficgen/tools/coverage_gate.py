#!/usr/bin/env python3
# coverage_gate.py — P5R 覆盖反查门（R3 落地件，不替代门2-1/2/3）。
#
# 干什么：读 cases/<proto>.json，照“该测的清单”逐项点名，缺一件就红。
# 不干什么：不断包字节、不跑服务（那是门2-2 suite 的事）；只查“有没有例”。
# 口径（诚实声明）：
# - 失败码“台词版也算”：回放语义下响应码是用户写的 Response 原文，门只查
#   字面出现，不查引擎拦截（C 类边界，见 D 条目 R6）。
# - 商业映射查用例 id/summary/notes 关键字，是地板线——证明“想到了”，
#   不证明“测真了”（对接真服务器另立项）。
# - composite 定义与补例清单配套，改定义同步改清单（见 check_smtp 注释）。
# 检查表按协议逐个登记（CHECKS）；未登记的协议出口 2（门脚本判黄，不挡路）。
#
# 用法：python3 trafficgen/tools/coverage_gate.py smtp [--cases <path>]
# 出口：全绿 0；有缺口 1；协议未登记/文件缺失 2。

import json
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# SMTP 检查表（D-SMTP-1 P3 清单 + 覆盖审计 9 空白的机器版）
# --------------------------------------------------------------------------

SMTP_COMMANDS = ["HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET",
                 "NOOP", "VRFY", "EXPN", "TURN", "AUTH", "QUIT"]
SMTP_FAIL_CODES = ["530", "550", "554", "452", "421", "503", "535"]
SMTP_EMAIL_SHAPES = ["text-only", "html-only", "alternative", "mixed-single",
                     "mixed-multi", "custom-boundary", "empty-body",
                     "attach-only"]
SMTP_COMMERCIAL = ["postfix", "gmail", "exchange"]


def _smtp_dialogs(cases):
    """逐个产出 (case_id, smtp层dict)。顶层 smtp 键（presence 负例）不算。"""
    for c in cases:
        spec = c.get("spec_json", {}) or {}
        for layer in spec.get("layers", []) or []:
            smtp = (layer or {}).get("smtp")
            if isinstance(smtp, dict):
                yield c.get("id", "?"), smtp


def _cmd_tokens(dialog):
    """Dialog 的命令字序列。base64 载荷（含 =/+）自动排除，只收纯字母字。"""
    toks = []
    for item in dialog or []:
        if not isinstance(item, dict):
            continue
        parts = (item.get("cmd") or "").strip().split()
        if parts and re.fullmatch(r"[A-Z]+", parts[0].upper()):
            toks.append(parts[0].upper())
    return toks


def _responses_text(dialog):
    return " ".join((item.get("response") or "")
                     for item in (dialog or []) if isinstance(item, dict))


def _email_shapes(email):
    """Email 八格判定（形态定义见 D-SMTP-1 P3 清单 R1 落地）。"""
    shapes = set()
    if not isinstance(email, dict):
        return shapes
    has_text = bool((email.get("text_body") or "").strip())
    has_html = bool((email.get("html_body") or "").strip())
    atts = email.get("attachments") or []
    n_att = len(atts) if isinstance(atts, list) else 0
    custom = bool((email.get("boundary") or "").strip()) and (has_html or n_att > 0)
    if has_text and not has_html and n_att == 0:
        shapes.add("text-only")
    if has_html and not has_text and n_att == 0:
        shapes.add("html-only")
    if has_text and has_html and n_att == 0:
        shapes.add("alternative")
    if n_att == 1:
        shapes.add("mixed-single")
    if n_att >= 2:
        shapes.add("mixed-multi")
    if custom:
        shapes.add("custom-boundary")
    if not has_text and not has_html and n_att == 0:
        shapes.add("empty-body")
    if not has_text and not has_html and n_att > 0:
        shapes.add("attach-only")
    return shapes


def check_smtp(cases):
    """返回 [(检查名, 通过?, 证据case_id或缺口说明)]。"""
    rows = []
    dialogs = [(cid, sm.get("dialog") or []) for cid, sm in _smtp_dialogs(cases)]

    # 1. 对话命令 12 个，一个不能少。
    for cmd in SMTP_COMMANDS:
        hit = next((cid for cid, d in dialogs if cmd in _cmd_tokens(d)), None)
        rows.append((f"命令 {cmd}", hit is not None, hit or "无用例"))

    # 2. 失败码 7 个，台词版也算。
    blob = " ".join(_responses_text(d) for _, d in dialogs)
    for code in SMTP_FAIL_CODES:
        hit = re.search(r"(?<![0-9])" + code + r"(?![0-9])", blob) is not None
        rows.append((f"失败码 {code}", hit, "台词出现" if hit else "无用例"))

    # 3. Email 八格。
    shape_hit = {}
    for cid, sm in _smtp_dialogs(cases):
        for s in _email_shapes(sm.get("email")):
            shape_hit.setdefault(s, cid)
    for s in SMTP_EMAIL_SHAPES:
        rows.append((f"Email {s}", s in shape_hit,
                     shape_hit.get(s, "无用例")))

    # 4. direction 覆盖字段至少 1 例在用。
    hit = next((cid for cid, sm in _smtp_dialogs(cases)
                for item in (sm.get("dialog") or [])
                if isinstance(item, dict) and (item.get("direction") or "").strip()),
               None)
    rows.append(("direction 字段在用", hit is not None, hit or "25 例出现 0 次"))

    # 5. 同连接多事务：一例 Dialog 含 ≥2 个 DATA（两封信；RSET 重发不算）。
    hit = next((cid for cid, d in dialogs
                if _cmd_tokens(d).count("DATA") >= 2), None)
    rows.append(("多事务（同连接两封信）", hit is not None, hit or "无用例"))

    # 6. 异常断线：含 MAIL/DATA 但无 QUIT 的 Dialog。
    def abnormal(d):
        toks = _cmd_tokens(d)
        return ("MAIL" in toks or "DATA" in toks) and "QUIT" not in toks
    hit = next((cid for cid, d in dialogs if abnormal(d)), None)
    rows.append(("异常断线（无 QUIT）", hit is not None, hit or "无用例"))

    # 7. 长保活：一例 Dialog 含 ≥2 个 NOOP。
    hit = next((cid for cid, d in dialogs
                if _cmd_tokens(d).count("NOOP") >= 2), None)
    rows.append(("长保活（多 NOOP）", hit is not None, hit or "无用例"))

    # 8. 复合流：≥2 DATA 且（AUTH 或 RSET 或附件邮件）——与纯多封信区分。
    def composite(cid, sm, d):
        toks = _cmd_tokens(d)
        if toks.count("DATA") < 2:
            return False
        has_auth = "AUTH" in toks
        has_rset = "RSET" in toks
        has_att = bool((sm.get("email") or {}).get("attachments"))
        return has_auth or has_rset or has_att
    hit = next((cid for cid, sm in _smtp_dialogs(cases)
                for d in [sm.get("dialog") or []] if composite(cid, sm, d)),
               None)
    rows.append(("复合流（多动作一条流）", hit is not None, hit or "无用例"))

    # 9. 现网三家映射（id/summary/notes 关键字，地板线）。
    texts = {c.get("id", "?"): json.dumps(
        [c.get("id"), c.get("summary"),
         (c.get("expect") or {}).get("notes")], ensure_ascii=False).lower()
             for c in cases}
    for kw in SMTP_COMMERCIAL:
        hit = next((cid for cid, t in texts.items() if kw in t), None)
        rows.append((f"现网映射 {kw}", hit is not None, hit or "无用例"))

    return rows


# --------------------------------------------------------------------------
# POP3 检查表（D-POP3-1 P3 清单机器版：命令×码矩阵 + 形态 + 多事务三项 +
# 商业三家；回放语义下 -ERR 台词版也算，C 类边界见 D 条目）
# --------------------------------------------------------------------------

POP3_COMMANDS = ["USER", "PASS", "APOP", "STAT", "LIST", "RETR", "DELE",
                 "NOOP", "RSET", "TOP", "UIDL", "QUIT", "CAPA", "STLS",
                 "AUTH"]
POP3_COMMERCIAL = ["gmail", "outlook", "dovecot"]


def _pop3_commands(cases):
    """逐个产出 (case_id, pop3层dict)。顶层 pop3 键（presence 负例）不算。"""
    for c in cases:
        spec = c.get("spec_json", {}) or {}
        for layer in spec.get("layers", []) or []:
            pop3 = (layer or {}).get("pop3")
            if isinstance(pop3, dict):
                yield c.get("id", "?"), pop3


def _pop3_tokens(cmds):
    """commands 的命令字序列（EmitMailDrop/EmitTop 合成轮跳过字面统计）。"""
    toks = []
    for item in cmds or []:
        if not isinstance(item, dict):
            continue
        parts = (item.get("cmd") or "").strip().split()
        if parts and re.fullmatch(r"[A-Z]+", parts[0].upper()):
            toks.append(parts[0].upper())
    return toks


def _pop3_responses(cmds):
    return " ".join((item.get("response") or "")
                     for item in (cmds or []) if isinstance(item, dict))


def check_pop3(cases):
    """返回 [(检查名, 通过?, 证据case_id或缺口说明)]。"""
    rows = []
    cmds = [(cid, p.get("commands") or []) for cid, p in _pop3_commands(cases)]

    # 1. 命令 15 个，一个不能少（含 RSET：DELE 后撤销标记）。
    for cmd in POP3_COMMANDS:
        hit = next((cid for cid, d in cmds if cmd in _pop3_tokens(d)), None)
        rows.append((f"命令 {cmd}", hit is not None, hit or "无用例"))

    # 2. -ERR 台词至少 1 例（回放语义不断引擎拦截）。
    blob = " ".join(_pop3_responses(d) for _, d in cmds)
    hit = re.search(r"-ERR", blob) is not None
    rows.append(("-ERR 台词", hit, "台词出现" if hit else "无用例"))

    # 3. maildrop 合成（EmitMailDrop）与 TOP 合成（EmitTop）各至少 1 例。
    maildrop = next((cid for cid, p in _pop3_commands(cases)
                     for item in (p.get("commands") or [])
                     if isinstance(item, dict) and item.get("emit_mail_drop")),
                    None)
    rows.append(("maildrop 合成", maildrop is not None, maildrop or "无用例"))
    top = next((cid for cid, p in _pop3_commands(cases)
                for item in (p.get("commands") or [])
                if isinstance(item, dict) and item.get("emit_top")),
               None)
    rows.append(("TOP 合成", top is not None, top or "无用例"))

    # 4. 多行响应（multiline）至少 1 例。
    hit = next((cid for cid, p in _pop3_commands(cases)
                for item in (p.get("commands") or [])
                if isinstance(item, dict) and item.get("multiline")),
               None)
    rows.append(("多行响应", hit is not None, hit or "无用例"))

    # 5. 多事务三项：多轮 RETR / 无 QUIT 断线 / 多 NOOP。
    hit = next((cid for cid, d in cmds
                if _pop3_tokens(d).count("RETR") >= 2), None)
    rows.append(("多事务（同连接两 RETR）", hit is not None, hit or "无用例"))

    def abnormal(d):
        toks = _pop3_tokens(d)
        return "RETR" in toks and "QUIT" not in toks
    hit = next((cid for cid, d in cmds if abnormal(d)), None)
    rows.append(("异常断线（无 QUIT）", hit is not None, hit or "无用例"))
    hit = next((cid for cid, d in cmds
                if _pop3_tokens(d).count("NOOP") >= 2), None)
    rows.append(("长保活（多 NOOP）", hit is not None, hit or "无用例"))

    # 6. 复合流：登录 + ≥3 业务动作一条流。
    def composite(d):
        toks = _pop3_tokens(d)
        if "USER" not in toks or "QUIT" not in toks:
            return False
        biz = [t for t in toks if t not in ("USER", "PASS", "QUIT")]
        return len(set(biz)) >= 3
    hit = next((cid for cid, d in cmds if composite(d)), None)
    rows.append(("复合流（多动作一条流）", hit is not None, hit or "无用例"))

    # 7. MIME 双附件下载（与 smtp_t033 对称；包内双附件字节）。
    hit = next((cid for cid, p in _pop3_commands(cases)
                for m in ((p.get("mailbox") or {}).get("messages") or [])
                if isinstance(m, dict) and len(m.get("mime_parts") or []) >= 2),
               None)
    rows.append(("MIME 双附件下载", hit is not None, hit or "无用例"))

    # 8. PASS 登录失败 -ERR（现网最常见失败；台词版）。
    pass_err = next((cid for cid, d in cmds
                     for item in d
                     if isinstance(item, dict) and
                     (item.get("cmd") or "").strip().upper().startswith("PASS")
                     and "-ERR" in (item.get("response") or "")), None)
    rows.append(("PASS -ERR 台词", pass_err is not None, pass_err or "无用例"))

    # 9. validator 四分支收口（EmitMailDrop 无信箱/MsgNum 越界×2/双合成互斥）。
    blob_exp = json.dumps([(c.get("id"), (c.get("expect") or {}).get(
        "error_contains")) for c in cases], ensure_ascii=False)
    for needle, name in [("but Mailbox is nil", "合成无信箱拒"),
                         ("out of range", "信号越界拒"),
                         ("mutually exclusive", "双合成互斥拒")]:
        hit = needle in blob_exp
        rows.append((name, hit, "锚词出现" if hit else "无用例"))

    # 10. 全缺省双流放行（与 smtp_t024 对称；静态门反例）。
    hit = next((c.get("id", "?") for c in cases
                if ((c.get("strategy_fc") or {}).get("value") == 2 and
                    all((lay.get("ip") or {}) == {} and
                        (lay.get("tcp") or {}) == {}
                        for lay in (c.get("spec_json", {}) or {}).get(
                            "layers", []) if "ip" in (lay or {}) or
                        "tcp" in (lay or {})))), None)
    rows.append(("全缺省双流", hit is not None, hit or "无用例"))

    # 11. 现网三家映射（id/summary/notes 关键字，地板线）。
    texts = {c.get("id", "?"): json.dumps(
        [c.get("id"), c.get("summary"),
         (c.get("expect") or {}).get("notes")], ensure_ascii=False).lower()
             for c in cases}
    for kw in POP3_COMMERCIAL:
        hit = next((cid for cid, t in texts.items() if kw in t), None)
        rows.append((f"现网映射 {kw}", hit is not None, hit or "无用例"))

    return rows


# --------------------------------------------------------------------------
# IMAP 检查表（D-IMAP-1 P3 清单机器版：命令×码矩阵 + 形态 + 多事务三项 +
# 双组合流 + 商业三家；回放语义下 NO/BAD 台词版也算，C 类边界见 D 条目）
# --------------------------------------------------------------------------

IMAP_COMMANDS = ["CAPABILITY", "NOOP", "LOGOUT", "STARTTLS", "AUTHENTICATE",
                 "LOGIN", "ENABLE", "SELECT", "EXAMINE", "CREATE", "DELETE",
                 "RENAME", "SUBSCRIBE", "UNSUBSCRIBE", "LIST", "NAMESPACE",
                 "STATUS", "APPEND", "IDLE", "CLOSE", "UNSELECT", "EXPUNGE",
                 "SEARCH", "FETCH", "STORE", "COPY", "MOVE", "UID"]
IMAP_COMMERCIAL = ["gmail", "outlook", "dovecot"]


def _imap_commands(cases):
    """逐个产出 (case_id, imap层dict)。顶层 imap 键（presence 负例）不算。"""
    for c in cases:
        spec = c.get("spec_json", {}) or {}
        for layer in spec.get("layers", []) or []:
            imap = (layer or {}).get("imap")
            if isinstance(imap, dict):
                yield c.get("id", "?"), imap


def _imap_tokens(cmds):
    """commands 的命令字序列（EmitIDLE 合成轮跳过字面统计）。"""
    toks = []
    for item in cmds or []:
        if not isinstance(item, dict):
            continue
        parts = (item.get("cmd") or "").strip().split()
        if parts and re.fullmatch(r"[A-Z]+", parts[0].upper()):
            toks.append(parts[0].upper())
    return toks


def _imap_responses(cmds):
    return " ".join(" ".join(item.get("responses") or [])
                     for item in (cmds or []) if isinstance(item, dict))


def check_imap(cases):
    """返回 [(检查名, 通过?, 证据case_id或缺口说明)]。"""
    rows = []
    cmds = [(cid, p.get("commands") or []) for cid, p in _imap_commands(cases)]

    # 1. 命令 28 个，一个不能少（SUBSCRIBE/UNSUBSCRIBE 同例 T-IMAP-25 双命令）。
    for cmd in IMAP_COMMANDS:
        hit = next((cid for cid, d in cmds if cmd in _imap_tokens(d)), None)
        rows.append((f"命令 {cmd}", hit is not None, hit or "无用例"))

    # 2. NO/BAD 台词各至少 1 例（回放语义不断引擎拦截）。
    blob = " ".join(_imap_responses(d) for _, d in cmds)
    for needle, name in [("NO ", "NO 台词"), ("BAD", "BAD 台词")]:
        hit = re.search(needle, blob) is not None
        rows.append((name, hit, "台词出现" if hit else "无用例"))

    # 3. literal 双形（LiteralBody 上行 + B64/占位替换）与 IDLE 轮各至少 1 例。
    lit = next((cid for cid, p in _imap_commands(cases)
                for item in (p.get("commands") or [])
                if isinstance(item, dict) and
                (item.get("literal_body") or item.get("literal_body_b64"))),
               None)
    rows.append(("literal 体", lit is not None, lit or "无用例"))
    idle = next((cid for cid, p in _imap_commands(cases)
                 for item in (p.get("commands") or [])
                 if isinstance(item, dict) and item.get("emit_idle")),
                None)
    rows.append(("IDLE 轮", idle is not None, idle or "无用例"))

    # 4. 多事务三项：多轮 FETCH / 无 LOGOUT 断线 / 多 NOOP。
    hit = next((cid for cid, d in cmds
                if _imap_tokens(d).count("FETCH") >= 2), None)
    rows.append(("多事务（同连接两 FETCH）", hit is not None, hit or "无用例"))

    def abnormal(d):
        toks = _imap_tokens(d)
        return "FETCH" in toks and "LOGOUT" not in toks
    hit = next((cid for cid, d in cmds if abnormal(d)), None)
    rows.append(("异常断线（无 LOGOUT）", hit is not None, hit or "无用例"))
    hit = next((cid for cid, d in cmds
                if _imap_tokens(d).count("NOOP") >= 2), None)
    rows.append(("长保活（多 NOOP）", hit is not None, hit or "无用例"))

    # 5. 双组合流：两条各含登录 + ≥3 业务动作的流（T-60/T-79 成对，§9 双组合流）。
    def composite(d):
        toks = _imap_tokens(d)
        if "LOGIN" not in toks or "LOGOUT" not in toks:
            return False
        biz = [t for t in toks if t not in ("LOGIN", "LOGOUT")]
        return len(set(biz)) >= 3
    comp = [cid for cid, d in cmds if composite(d)]
    rows.append(("复合流 A", len(comp) >= 1, comp[0] if comp else "无用例"))
    rows.append(("复合流 B（第二条）", len(comp) >= 2,
                 comp[1] if len(comp) >= 2 else "无用例"))

    # 6. MIME 双附件下载（与 smtp_t033/pop3_t037 对称；FETCH mime_body 双附件）。
    hit = next((cid for cid, p in _imap_commands(cases)
                for item in (p.get("commands") or [])
                if isinstance(item, dict) and
                len(((item.get("mime_body") or {}).get("attachments")
                     or [])) >= 2), None)
    rows.append(("MIME 双附件下载", hit is not None, hit or "无用例"))

    # 7. validator 代表分支收口（Tag 超长/Tag SP/Response CRLF/互斥×2/
    # 解码错/EmitIDLE 无 IDLE/Cancel 越界/Push CRLF/Timeout 枚举/DoneTag SP/
    # DoneResponse CRLF/Responses 上限）。
    blob_exp = json.dumps([(c.get("id"), (c.get("expect") or {}).get(
        "error_contains")) for c in cases], ensure_ascii=False)
    for needle, name in [("Tag length", "Tag 超长拒"),
                         ("contains SP/CRLF", "Tag SP 拒"),
                         ("split into multiple", "Response CRLF 拒"),
                         ("mutually exclusive", "互斥拒"),
                         ("decode error", "B64 解码错拒"),
                         ("EmitIDLE=true but IMAPConfig.IDLE is nil",
                          "EmitIDLE 无 IDLE 拒"),
                         ("CancelAfterResponses", "Cancel 越界拒"),
                         ("PushResponses[0] contains CRLF", "Push CRLF 拒"),
                         ("must be one of", "Timeout 枚举错拒"),
                         ("DoneTag", "DoneTag 拒"),
                         ("DoneResponse contains CRLF", "DoneResponse 拒"),
                         ("Responses count", "Responses 上限拒")]:
        hit = needle in blob_exp
        rows.append((name, hit, "锚词出现" if hit else "无用例"))

    # 8. 全缺省双流放行（与 smtp_t024/pop3_t046 对称；静态门反例）。
    hit = next((c.get("id", "?") for c in cases
                if ((c.get("strategy_fc") or {}).get("value") == 2 and
                    all((lay.get("ip") or {}) == {} and
                        (lay.get("tcp") or {}) == {} and
                        (lay.get("imap") or {}) == {}
                        for lay in (c.get("spec_json", {}) or {}).get(
                            "layers", []) if "ip" in (lay or {}) or
                        "tcp" in (lay or {}) or "imap" in (lay or {})))), None)
    rows.append(("全缺省双流", hit is not None, hit or "无用例"))

    # 9. 现网三家映射（id/summary/notes 关键字，地板线）。
    texts = {c.get("id", "?"): json.dumps(
        [c.get("id"), c.get("summary"),
         (c.get("expect") or {}).get("notes")], ensure_ascii=False).lower()
             for c in cases}
    for kw in IMAP_COMMERCIAL:
        hit = next((cid for cid, t in texts.items() if kw in t), None)
        rows.append((f"现网映射 {kw}", hit is not None, hit or "无用例"))

    return rows


CHECKS = {"smtp": check_smtp, "pop3": check_pop3, "imap": check_imap}


# --------------------------------------------------------------------------
# MCP 检查表（D-MCP-1 P3 清单机器版：方法表 + 通知族 + 错误码 + 传输×版本 +
# state 终态 + content 类型 + validator 锚词 + 多会话 + 组合流 + 双向方法 +
# 现网三家；回放语义下错误响应是用户写的 responses 原文，台词版也算——
# C 类边界见 D 条目）
# --------------------------------------------------------------------------

MCP_METHODS = ["ping", "tools/list", "tools/call", "resources/list",
               "resources/read", "resources/subscribe",
               "resources/templates/list", "resources/unsubscribe",
               "prompts/list", "prompts/get", "completion/complete",
               "logging/setLevel", "roots/list", "sampling/createMessage"]
MCP_NOTIFICATIONS = ["notifications/progress", "notifications/message",
                     "notifications/cancelled",
                     "notifications/roots/list_changed",
                     "notifications/resources/updated",
                     "notifications/resources/list_changed"]
MCP_ERROR_CODES = ["-32700", "-32600", "-32601", "-32602", "-32603",
                   "-32002", "-1"]
MCP_TRANSPORTS = ["stdio", "http_sse", "streamable"]
MCP_VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18"]
MCP_STATE_FINALS = ["completed", "input_required", "failed", "canceled"]
MCP_CONTENT_TYPES = ["text", "image", "audio", "resource", "resource_link"]
MCP_VALIDATOR_ANCHORS = [
    ("invalid transport", "非法 transport 拒"),
    ("invalid protocol_version", "非法版本拒"),
    ("invalid auth scheme", "非法 auth 拒"),
    ("invalid state.initial", "非法 state 拒"),
    ("must be a JSON object", "caps 形状拒"),
    (".method is required", "空 method 拒"),
    ("must be >= 0", "负计数器拒"),
    (".role", "parts role 拒"),
    (".step=", "通知 Step 越界拒"),
    ("error.code=", "错误码越界拒"),
    ("mixed auto and explicit id assignment", "id 混用拒"),
    ("no longer accepts a top-level mcp sub-config", "顶层 mcp presence 拒"),
    ("static four-tuple", "静态复制拒"),
]
MCP_COMMERCIAL = ["claude", "cursor", "flowb"]


def _mcp_layers(cases):
    """逐个产出 (case_id, mcp层dict)。顶层 mcp 键（presence 负例）不算。"""
    for c in cases:
        spec = c.get("spec_json", {}) or {}
        for layer in spec.get("layers", []) or []:
            mcp = (layer or {}).get("mcp")
            if isinstance(mcp, dict):
                yield c.get("id", "?"), mcp


def check_mcp(cases):
    """返回 [(检查名, 通过?, 证据case_id或缺口说明)]。"""
    rows = []
    lays = list(_mcp_layers(cases))

    # 1. 方法表 14 个（notifications/initialized 由生成器固定注入，t064 帧
    # 断言锁，不入 requests 扫描面）。
    def methods_of(mcp):
        return [(r.get("method") or "") for r in (mcp.get("requests") or [])
                if isinstance(r, dict)]
    for method in MCP_METHODS:
        hit = next((cid for cid, m in lays if method in methods_of(m)), None)
        rows.append((f"方法 {method}", hit is not None, hit or "无用例"))

    # 2. 通知族 6 形各至少 1 例。
    for n in MCP_NOTIFICATIONS:
        hit = next((cid for cid, m in lays
                    for item in (m.get("notifications") or [])
                    if isinstance(item, dict) and item.get("method") == n),
                   None)
        rows.append((f"通知 {n}", hit is not None, hit or "无用例"))

    # 3. 错误码 7 个（responses[].error.code 字面；台词版也算）。
    blob = json.dumps([(m.get("responses") or []) for _, m in lays],
                      ensure_ascii=False)
    for code in MCP_ERROR_CODES:
        hit = re.search(r'"code":\s*' + re.escape(code) + r'(?![0-9])',
                        blob) is not None
        rows.append((f"错误码 {code}", hit, "台词出现" if hit else "无用例"))

    # 4. 传输 3 × 版本 3（版本含显式三值各 1 例；缺省=2024-11-05 由生成器
    # 承担，t011 降级例附带）。
    for t in MCP_TRANSPORTS:
        hit = next((cid for cid, m in lays if m.get("transport") == t), None)
        rows.append((f"传输 {t}", hit is not None, hit or "无用例"))
    for v in MCP_VERSIONS:
        # 证据两路：层配置显式 protocol_version，或 expect 帧十六进制解码后
        # 出现 "protocolVersion":"<v>"（t011 降级例：客户端 2025-06-18，
        # 服务端响应 2024-11-05 钉在 wire——wire 钉死比配置回显更强）。
        frame_hit = any(
            any('"protocolVersion":"' + v + '"' in bytes.fromhex(
                f.get("hex", "").replace(" ", "")
            ).decode("ascii", errors="ignore")
            for f in (c.get("expect") or {}).get("frames") or [])
            for c in cases)
        hit = next((cid for cid, m in lays
                    if m.get("protocol_version") == v), None)
        ok = hit is not None or frame_hit
        rows.append((f"版本 {v}", ok, hit or ("帧钉死" if frame_hit else "无用例")))

    # 5. state 终态 4（state.final 字段面；initial/final 同枚举面，一例代表）。
    for f in MCP_STATE_FINALS:
        hit = next((cid for cid, m in lays
                    if (m.get("state") or {}).get("final") == f), None)
        rows.append((f"state 终态 {f}", hit is not None, hit or "无用例"))

    # 6. content 类型 5（requests/responses 内 content.type 字面）。
    for ct in MCP_CONTENT_TYPES:
        hit = re.search(r'"type":\s*"' + ct + r'"', blob) is not None
        rows.append((f"content {ct}", hit, "字面出现" if hit else "无用例"))

    # 7. validator 锚词收口（错误锚词 + presence/静态复制负例，字面出现）。
    blob_exp = json.dumps([(c.get("id"), c.get("spec_json", {}),
                            (c.get("expect") or {}).get("error_contains"),
                            (c.get("expect") or {}).get("notes"))
                           for c in cases], ensure_ascii=False)
    for needle, name in MCP_VALIDATOR_ANCHORS:
        hit = needle in blob_exp
        rows.append((name, hit, "锚词出现" if hit else "无用例"))

    # 8. 多会话（flows>=2 至少 2 例：独立 4-tuple 聚合 + id 独立）。
    multi = [c.get("id", "?") for c in cases
             if ((c.get("strategy_fc") or {}).get("value") or 0) >= 2]
    rows.append(("多会话（flows>=2）", len(multi) >= 1,
                 multi[0] if multi else "无用例"))
    rows.append(("多会话（第二条）", len(multi) >= 2,
                 multi[1] if len(multi) >= 2 else "无用例"))

    # 9. 双组合流（§9：至少两条、每条会话内 >=3 不同业务方法）。
    def composite(mcp):
        ms = {x for x in methods_of(mcp)
              if x not in ("notifications/initialized",)}
        return len(ms) >= 3
    comp = [cid for cid, m in lays if composite(m)]
    rows.append(("组合流 A（>=3 方法）", len(comp) >= 1,
                 comp[0] if comp else "无用例"))
    rows.append(("组合流 B（第二条）", len(comp) >= 2,
                 comp[1] if len(comp) >= 2 else "无用例"))

    # 10. 双向方法（S→C 反查：roots/list + sampling/createMessage 已在方法
    # 表逐个点名；此处锁"响应侧带 capability 声明"的协商例至少 1）。
    hit = next((cid for cid, m in lays
                if isinstance(m.get("client_capabilities"), (dict, str))
                and isinstance(m.get("server_capabilities"), (dict, str))
                and methods_of(m)), None)
    rows.append(("双向能力协商", hit is not None, hit or "无用例"))

    # 11. shutdown 双形（缺省挥手 + shutdown:false 无挥手）。
    hit = next((cid for cid, m in lays if m.get("shutdown") is False), None)
    rows.append(("shutdown:false 无挥手", hit is not None, hit or "无用例"))

    # 12. rounds 多轮至少 1 例。
    hit = next((cid for cid, m in lays
                if (m.get("rounds") or 0) > 1), None)
    rows.append(("rounds>1 多轮", hit is not None, hit or "无用例"))

    # 13. 现网三家映射（id/summary/notes 关键字，地板线：Claude Desktop /
    # Cursor / flowB 自家服务端形）。
    texts = {c.get("id", "?"): json.dumps(
        [c.get("id"), c.get("summary"),
         (c.get("expect") or {}).get("notes")], ensure_ascii=False).lower()
             for c in cases}
    for kw in MCP_COMMERCIAL:
        hit = next((cid for cid, t in texts.items() if kw in t), None)
        rows.append((f"现网映射 {kw}", hit is not None, hit or "无用例"))

    return rows


CHECKS = {"smtp": check_smtp, "pop3": check_pop3, "imap": check_imap,
          "mcp": check_mcp}


def main(argv):
    proto = argv[1] if len(argv) > 1 else ""
    cases_path = None
    if "--cases" in argv:
        cases_path = argv[argv.index("--cases") + 1]
    if proto not in CHECKS:
        print(f"该协议检查表未登记：{proto or '(空)'}（按协议逐个登记，不挡路）")
        return 2
    if cases_path is None:
        here = Path(__file__).resolve()
        cases_path = (here.parent / ".." / "test" / "protocol_pcap"
                      / "cases" / f"{proto}.json")
    try:
        cases = json.loads(Path(cases_path).read_text())
    except FileNotFoundError:
        print(f"用例文件缺失：{cases_path}")
        return 2
    rows = CHECKS[proto](cases)
    n_pass = sum(1 for _, ok, _ in rows if ok)
    print(f"== 覆盖反查：{proto}（{len(cases)} 例，{len(rows)} 项）")
    for name, ok, ev in rows:
        print(f"[{'PASS' if ok else 'MISS'}] {name} —— {ev}")
    print(f"反查：{n_pass}/{len(rows)} 通过"
          + (" —— 绿" if n_pass == len(rows) else " —— 红，有缺口，停"))
    return 0 if n_pass == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
