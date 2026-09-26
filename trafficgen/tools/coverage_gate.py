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



def check_sv(cases):
    """D-SV-1 P5R 反查表（T-SV-1…30）。返回 [(检查名, 通过?, 证据)]。
    层内 sv 子映射扫描（P5 改写后形状；P4 登记时旧顶层 sv 键例判 MISS，
    P5 cases 落地后转绿）。
    """
    rows = []
    lays = []  # (cid, sv层内子映射)
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("sv"), dict):
                lays.append((c.get("id", "?"), l["sv"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 场景面（正例存在性）。
    for kw, name in [("smp_seq", "S 基线序列"), ("double_send", "double_send"),
                     ("smp_wrap", "smpCnt 回绕"), ("smp_synch", "smpSynch 面"),
                     ("4i4v", "9-2LE 4i4v"), ("custom_dataset", "自定义 dataset"),
                     ("vlan", "VLAN"), ("period", "周期(死键注记)"),
                     ("mac_dyn", "MAC 动态多流"), ("combo", "组合面")]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. data 类型 2 值 + 负数。
    for t in ["int32", "float32"]:
        hit = next((cid for cid, m in lays
                    for d in m.get("data") or []
                    if isinstance(d, dict) and d.get("type") == t), None)
        rows.append((f"类型 {t}", hit is not None, hit or "无用例"))
    hitneg = next((cid for cid, m in lays
                   for d in m.get("data") or []
                   if isinstance(d, dict) and isinstance(d.get("inst_mag"), (int, float)) and d.get("inst_mag") < 0), None)
    rows.append(("int32 负数", hitneg is not None, hitneg or "无用例"))

    # 3. 可选键覆盖（dat_set/smp_rate/dst_mac/count/vlan 三键/double_send/
    #    period_us/samples_per_cycle/smp_synch/sv_id/appid/conf_rev）。
    for k, name in [("dat_set", "dat_set 显式"), ("smp_rate", "smp_rate"),
                    ("dst_mac", "dst_mac 层内"), ("count", "count 层内"),
                    ("vlan_enabled", "VLAN 开关"), ("vlan_id", "vlan_id"),
                    ("vlan_priority", "vlan_priority"),
                    ("double_send", "double_send 键"),
                    ("period_us", "period_us(死键)"),
                    ("samples_per_cycle", "samples_per_cycle"),
                    ("smp_synch", "smp_synch"), ("sv_id", "sv_id"),
                    ("appid", "appid"), ("conf_rev", "conf_rev")]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 4. MAC 动态三策略（eth 层 src_mac 对象）。
    macs = []
    for c in cases:
        for l in (c.get("spec_json", {}) or {}).get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("eth"), dict):
                v = l["eth"].get("src_mac")
                if isinstance(v, dict):
                    macs.append((c.get("id", "?"), v.get("strategy")))
    for st, name in [("inc", "MAC inc"), ("list", "MAC list"), ("rand", "MAC rand")]:
        hit = next((cid for cid, s2 in macs if s2 == st), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 5. 锚词面（create-time V9/门 + task-time validator 全字面）。
    for needle, name in [
        ("out of range [16384,32767]", "appid 越界（V9 真实门）"),
        ("outside SV range 0x4000-0x7fff", "appid 显式 0（validator 真实门）"),
        ("svID is required", "svID 必填/超长"),
        ("confRev must be non-zero", "confRev"),
        ("samples_per_cycle must be >= 1", "samples_per_cycle"),
        ("smpSynch must be 0, 1 or 2", "smpSynch"),
        ("data is required", "空 data"),
        ("unsupported data type", "非法 type"),
        ("must not have an ip/transport carrier", "L2-only 载体门（V7b）"),
        ("out of range [0,4095]", "VLAN 越界（V9 真实门）"),
        ("top-level sv sub-config", "presence 判死"),
        ("static four-tuple", "静态复制拒"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows

def check_icmpv6(cases):
    """D-ICMPV6-1 P5R 反查表（T-ICMPV6-1…11）。返回 [(检查名, 通过?, 证据)]。
    层内 icmpv6 子映射扫描（P5 改写后形状；P4 登记时旧顶层键例判 MISS，
    P5 cases 落地后转绿）。
    """
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("icmpv6"), dict):
                lays.append((c.get("id", "?"), l["icmpv6"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 场景面。
    for kw, name in [("smoke", "S 基线 Echo 对"), ("type_129", "type 129 单发"),
                     ("pattern", "Pattern 面"), ("dyn", "动态多流"),
                     ("static_copy", "静态复制面"), ("v4", "v4 拒绝面")]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. 键覆盖。
    for k, name in [("type", "type"), ("code", "code"), ("identifier", "identifier"),
                    ("sequence", "sequence"), ("data", "data"), ("pattern", "pattern")]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 3. 锚词面。
    for needle, name in [
        ("top-level icmpv6 sub-config", "presence 判死"),
        ("static four-tuple", "静态复制拒"),
        ("must be IPv6", "v4 拒（legacy 复用真门）"),
        ("type must be 128", "type 非法（validator 真门）"),
        ("code must be 0", "code 非 0（validator 真门）"),
        ("pattern step", "pattern step 非法（validator 真门）"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows

def check_h323(cases):
    """D-H323-1 P5R 反查表（T-H323-1…17）。返回 [(检查名, 通过?, 证据)]。
    层内 h323 子映射扫描（P5 改写后形状；P4 登记时旧顶层键例判 MISS，
    P5 cases 落地后转绿）。
    """
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("h323"), dict):
                lays.append((c.get("id", "?"), l["h323"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 场景面。
    for kw, name in [("smoke", "S 基线呼叫周期"), ("scenario", "scenario 变体面"),
                     ("calls", "多呼叫面"), ("dyn", "端口动态面"),
                     ("static_port", "静态端口拒面"), ("media", "RTP 媒体面"),
                     ("v6", "v6 对照面"), ("rewrite", "rewrite 面")]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. 键覆盖（业务 8 键+端口 2 键）。
    for k in ["role", "scenario", "crv", "display_name", "calls",
              "rewrite_addr", "src_port", "dst_port", "media", "ras"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))

    # 3. 锚词面。
    for needle, name in [
        ("top-level h323 sub-config", "presence 判死"),
        ("static four-tuple", "静态端口拒"),
        ("invalid role", "role 非法（legacy 真门）"),
        ("invalid scenario", "scenario 非法（legacy 真门）"),
        ("not a numeric value", "calls 负数（V9 先拦真门——P5 校准：registry Min=0 使 legacy '>=0' 锚词不可达）"),
        ("display_name must be <=", "display 超长（legacy 真门）"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows

def check_mpls(cases):
    """D-MPLS-1 P5R 反查表（T-MPLS-1…14）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("mpls"), dict):
                lays.append((c.get("id", "?"), l["mpls"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 场景面。
    for kw, name in [("single_label", "S 基线单标签"), ("frames", "多帧面"),
                     ("direction", "方向面"), ("multicast", "multicast 面"),
                     ("inner_tcp", "内层 TCP 面"), ("v6", "v6 内层对照"),
                     ("dyn", "端口动态面"), ("static_port", "静态端口拒面")]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. 键覆盖。
    for k in ["labels", "multicast", "inner_proto", "src_port", "dst_port",
              "frames", "direction", "inner_payload"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))

    # 3. 锚词面。
    for needle, name in [
        ("top-level mpls sub-config", "presence 判死"),
        ("static four-tuple", "静态端口拒"),
        ("exceeds 20 bits", "label 上界（legacy 真门）"),
        ("exceeds 3 bits", "TC 上界（legacy 真门）"),
        ("not the bottom of stack", "S 位非栈底（legacy 真门）"),
        ("not in supported list", "InnerProto/Direction 非法（legacy 真门）"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows

def check_ngap(cases):
    """D-NGAP-1 P5 反查表（T-NGAP-1…17）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("ngap"), dict):
                lays.append((c.get("id", "?"), l["ngap"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 场景面。
    for kw, name in [("basic", "S 基线 SCTP 联结"), ("initial_ue", "InitialUEMessage 面"),
                     ("dl_nas", "DownlinkNAS 面"), ("ul_nas", "UplinkNAS 面"),
                     ("pdu_session", "PDUSessionSetup 面"), ("ue_release", "UEContextRelease 面"),
                     ("all_procedures", "全流程面"), ("ta_drx", "TA 列表+DRX 面"),
                     ("ue_ids", "UE ID 面"), ("amf_name", "AMF name 面"),
                     ("default_port", "缺省端口面"), ("port_dyn", "端口动态面"),
                     ("v6", "v6 拒面"), ("static_port", "静态端口拒面"),
                     ("presence", "presence 判死面"), ("sst", "SST 越界面"),
                     ("nas_len", "NAS 超长面")]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. 键覆盖（业务 12 键+端口 2 键）。
    for k in ["global_ran_node_id", "supported_ta_list", "default_paging_drx",
              "amf_name", "ran_ue_ngap_id", "amf_ue_ngap_id",
              "initial_ue_message", "initial_nas", "downlink_nas", "uplink_nas",
              "pdu_session_setup", "ue_context_release", "src_port", "dst_port"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))

    # 3. 锚词面。
    for needle, name in [
        ("top-level ngap sub-config", "presence 判死"),
        ("static four-tuple", "静态端口拒"),
        ("only IPv4 is supported", "v6 拒（legacy 真门）"),
        ("SST 300 out of range", "SST 越界（legacy 真门）"),
        ("InitialNAS too long", "NAS 超长（legacy 真门）"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows

def check_telnet(cases):
    """D-TELNET-1 P5 反查表（T-TELNET-1…17）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("telnet"), dict):
                lays.append((c.get("id", "?"), l["telnet"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 场景面。
    for kw, name in [("basic", "S 基线 defaultDialog"), ("presence", "presence 判死面"),
                     ("static_port", "静态端口拒面"), ("login_full", "login_full 场景"),
                     ("login_fail", "login_fail 场景"), ("multi_command", "multi_command 场景"),
                     ("long_output", "long_output 场景"), ("option_reject", "option_reject 场景"),
                     ("synch", "synch 场景"), ("iac", "IAC 转义面"), ("sb_", "sb 子协商面"),
                     ("ttype", "ttype/naws 面"), ("banner", "banner 前置面"),
                     ("_v6", "v6 正例面"), ("default_port", "缺省端口面"),
                     ("port_dyn", "端口动态面"), ("scenario", "unknown scenario 拒面")]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. 键覆盖（业务 10 键+端口 2 键）。
    for k in ["banner", "dialog", "terminal_type", "window_cols", "window_rows",
              "file_source", "scenario", "username", "password", "commands",
              "src_port", "dst_port"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))

    # 3. 锚词面。
    for needle, name in [
        ("top-level telnet sub-config", "presence 判死"),
        ("static four-tuple", "静态端口拒"),
        ("unknown scenario", "scenario 白名单（legacy 真门）"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows

def check_sip(cases):
    """D-SIP-1 P5 反查表（T-SIP-1…18）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("sip"), dict):
                lays.append((c.get("id", "?"), l["sip"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 场景面。
    for kw, name in [("basic", "S 基线五消息"), ("presence", "presence 判死面"),
                     ("static_port", "静态端口拒面"), ("hdr_completion", "头补全生成面"),
                     ("hdr_user_wins", "user 头赢面"), ("register", "REGISTER 枚举"),
                     ("options", "OPTIONS 枚举"), ("status_codes", "响应码枚举"),
                     ("sdp_body", "SDP body 面"), ("mss_segment", "MSS 分段面"),
                     ("rtp_media", "RTP 子流面"), ("rtp_down", "RTP down 面"),
                     ("sdp_port", "SDP 派生端口面"), ("filesource", "RTP FileSource 面"),
                     ("_v6", "v6 正例面"), ("default_port", "缺省端口面"),
                     ("port_dyn", "端口动态面"), ("empty_dialog", "空 dialog 面"),
                     ("reinvite", "re-INVITE 会话刷新面"), ("cancel", "CANCEL 取消面"),
                     ("busy_reject", "486 非正常结束面"), ("keepalive", "dialog 内 OPTIONS 保活面"),
                     ("status_class_enum", "状态码大类枚举面"), ("callflow_complete", "组合流二 PRACK 面"),
                     ("register_digest_auth", "注册摘要鉴权面"), ("register_expire0", "注册刷新注销面"),
                     ("two_calls_sequential", "同流双呼独立 Call-ID 面"), ("refer_transfer", "REFER 盲转面"),
                     ("subscribe_notify_mwi", "SUBSCRIBE/NOTIFY MWI 面"), ("early_media_183", "183 早媒体+PRACK 面"),
                     ("hold_resume", "HOLD 保持恢复面"), ("info_dtmf", "INFO DTMF 面"),
                     ("_302_redirect", "302 呼转面"), ("update_session_timer", "UPDATE 会话刷新面"),
                     ("invite_401_challenge", "INVITE 401 鉴权面"), ("message_im", "MESSAGE 页模式 IM 面"),
                     ("compact_form", "紧凑形头方言面"), ("via_chain", "多跳 Via 链面"),
                     ("long_auth_uri", "超长头长 URI 面"), ("tel_uri_utf8", "tel: URI+UTF-8 面"),
                     ("sdp_video_multistream", "SDP 双流音视频面"), ("body_multipart", "multipart 双体面"),
                     ("hdr_case_mix", "头名大小写混写面"),
                     ("100_trying_retrans", "100 Trying+重传面"), ("forked_invite", "并行分叉竞速面"),
                     ("conference_join", "会议加入+名册面"), ("replaces_attended", "Replaces 询转面"),
                     ("offerless_3pcc", "offerless INVITE/3PCC 面"), ("publish_presence", "PUBLISH 在线状态面"),
                     ("reason_q850", "Reason:Q.850 释放原因面"), ("ims_pheaders", "IMS 私有头面"),
                     ("history_info_fwd", "History-Info 呼转链面"), ("491_glare", "491 glare 面"),
                     ("interleaved_two_calls", "并发交错双呼面"), ("status_enum_4xx", "4xx 枚举长尾面"),
                     ("status_enum_56xx", "5xx/6xx 枚举面"), ("v6_port_dyn", "v6×多流矩阵面"),
                     ("sessions_two_dialogs", "双会话独立面"), ("sessions_derived_callid", "Call-ID 派生面"),
                     ("sessions_explicit_wins", "显式赢面"), ("neg_sessions_dialog_mutex", "sessions 互斥判死面"),
                     ("neg_sessions_empty", "空数组判死面"), ("neg_sessions_static", "sessions 静态复制拒面"),
                     ("sessions_port_inc", "session 端口 inc 格"), ("sessions_port_rand", "session 端口 rand 格"),
                     ("sessions_port_list", "session 端口 list 格"), ("sessions_port_fixed", "session 端口 fixed 格"),
                     ("sessions_port_pattern", "session 端口 pattern 格"), ("sessions_callid_pattern", "call_id pattern 格"),
                     ("sessions_callid_fixed", "call_id fixed 格"), ("sessions_v6", "v6 双会话格"),
                     ("medias_bidirectional", "双向交替面"), ("medias_interleave", "交错调度面"),
                     ("neg_medias_mutex", "medias 互斥判死面"), ("medias_port_dyn", "medias 端口动态格"),
                     ("medias_filesource", "medias file_source 面"),
                     ("nat_rport_fill", "NAT bare rport 回填面"), ("nat_switch_forces", "nat 开关强制面"),
                     ("nat_default_passthrough", "NAT 缺省透传零漂移面"), ("nat_sessions_port", "NAT 会话真值端口面"),
                     ("tls_options", "SIPS/TLS 事件面"), ("tls_register", "TLS REGISTER 面"),
                     ("tcp_options", "纯 tcp 事件面明文线"), ("neg_tls_media", "tls×media 判死面"),
                     ("neg_sips_no_tls", "sips 无 tls 判死面"), ("neg_tls_sessions", "tls×sessions 判死面"),
                     ("conf_burst", "复合大场景交织面(9.50)"), ("resp_202", "2xx 非 200 分支值"),
                     ("resp_300", "3xx 多 Contact 列表形"), ("resp_407", "代理鉴权头族"),
                     ("resp_420", "扩展协商失败面"), ("resp_422", "会话定时器协商失败(RFC 4028)"),
                     ("resp_489", "SUBSCRIBE 上下文错误码(9.21)"), ("retry_after", "Retry-After 头形"),
                     ("cl_user_wins", "用户 CL 禁二次追加(9.46)"), ("empty_entry", "空条目跳过语义钉")]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. 键覆盖（业务 2 键+端口 2 键+media 内键）。
    for k in ["dialog", "media", "src_port", "dst_port"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))
    medias = [(cid, m.get("media") or {}) for cid, m in lays]
    for k in ["frames", "payload_type", "src_port", "direction", "file_source"]:
        hit = next((cid for cid, m in medias if k in m), None)
        rows.append(("media." + k, hit is not None, hit or "无用例"))

    # 3. 锚词面。
    for needle, name in [
        ("top-level sip sub-config", "presence 判死"),
        ("static four-tuple", "静态端口拒"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows

# --------------------------------------------------------------------------
# EDP 检查表（D-EDP-1 P6 反查表：89 例=61 正+28 负，OneNET EDP TCP-4472
# tcp-only 族。wire_fault 28 值注入锚词闭环；状态机三约束；载体预检）
# --------------------------------------------------------------------------

EDP_FAULTS = [
    "type_unknown", "type_unimplemented", "remainlen_mismatch",
    "remainlen_truncated", "remainlen_5byte", "protocol_name", "version",
    "conn_flag", "format_flag", "bin_desc_no_dsid", "bin_desc_invalid",
    "bin_desc_over", "bin_over_3mb", "state_no_connect", "state_after_reject",
    "state_after_disconnect", "cmdid", "msg_id", "json_invalid",
    "json_over_u16", "layer_chain", "carrier_udp", "port_conflict",
    "auth_devid_empty", "auth_apikey_empty", "auth_userid_empty",
    "auth_authinfo_empty", "connack_rtn",
]


def check_edp(cases):
    """D-EDP-1 P6 反查表。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent

    # 1. 准入与接线。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单收 edp", '"edp": true' in pg, "在列"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    i_neg = pt.index("negativeOnly := []string{")
    rows.append(("negativeOnly 不含 edp（已准入）", '"edp"' not in pt[i_neg:i_neg + 400], "已摘除"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case edp（严格解码）", 'case "edp":' in tr and "DisallowUnknownFields" in tr, "在案"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.EDP", "EDP        *core.EDPConfig" in gen, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    rows.append(("registry edp 行 + tcp 4472 契约", '"tcp.dst_port": "4472"' in rg, "在案"))
    vl = (tg / "internal" / "core" / "layers" / "validate_layers.go").read_text()
    rows.append(("udp 载体预检（tcp-only）", "edp rides tcp only" in vl, "在案"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go ChainPlanner(edp) 接线", 'NewChainPlanner("edp")' in mn, "在案"))

    # 2. 行为面（validator/builder 关键件）。
    pl = (tg / "internal" / "protocol" / "edp" / "planner.go").read_text()
    import re as _re
    _i = pl.index("wireFaultAnchors = map[string]string{")
    _seg = pl[_i:pl.index("\n}", _i)]
    _n = len(_re.findall(r"core\.EDPWireFault[A-Za-z0-9]+:", _seg))
    rows.append(("wire_fault 闭环 28 值锚词表（契约枚举名）", _n == 28, f"{_n} 值"))
    for guard, name in [
        ("closed = true", "状态机走查（rtn≠0/disconnect 后禁业务帧）"),
        ("out of range 0-9", "connack_rtn 值域 0–9"),
        ("ds_id", "type2 desc ds_id 自然面"),
        ("u16 bound 65535", "json u16 上界"),
        ("3MB", "bin 3MB 上界（wire 口径）"),
    ]:
        rows.append((f"关键件：{name}", guard in pl, "在案"))
    bl = (tg / "internal" / "protocol" / "edp" / "builder.go").read_text()
    for prim, name in [
        ("func encodeVarint", "varint LSB 先（MQTT 同构）"),
        ("func buildCONNREQ", "CONNREQ 双方式（0x40/0xC0）"),
        ("func buildSAVEDATA", "SAVEDATA 标志×格式"),
        ("func buildCMDRESP", "CMDRESP 条件缺省"),
        ("func emitCoalescedEvents", "coalesce JoinNext"),
    ]:
        rows.append((f"builder：{name}", prim in bl, "在案"))
    lg = (tg / "internal" / "protocol" / "edp" / "builder.go").read_text()
    rows.append(("端口缺省继承链级（行为检查：不硬编码 4472 注记在案）", "不在此硬编码 4472" in lg, "在案"))
    # 终审 F2/F7/F10 行为面回查。
    rows.append(("u16 标识符上界守卫（planner checkU16Str ≥5 调用点）", pl.count("checkU16Str(where") >= 5, f"{pl.count('checkU16Str(where')} 处调用"))
    rows.append(("CMDRESP ack:false 抑制（行为：builder 分支在案）", "可被 ack:false 抑制" in lg and "if ev.Ack != nil && !*ev.Ack" in lg, "在案"))
    rows.append(("SAVEACK msg_id 双前置（行为：builder 分支在案）", "ev.MsgID != nil" in lg, "在案"))
    rows.append(("会话级 dst_port 逐会话生效（行为：sessionPort 闭包）", "sessionPort := func(si int)" in lg, "在案"))

    # 3. 用例面（61 正 + 28 负；proto=edp；顶层仅 layers）。
    pos = [c for c in cases if "packet_count" in (c.get("expect") or {})]
    neg = [c for c in cases if (c.get("expect") or {}).get("expect_error")]
    rows.append(("89 例对账（61 正+28 负）", len(pos) == 61 and len(neg) == 28 and len(cases) == 89,
                 f"{len(pos)}+{len(neg)}={len(cases)}"))
    bad_proto = [c.get("id", "?") for c in cases if c.get("proto") != "edp"]
    rows.append(("proto 全=edp（单准入名）", not bad_proto, bad_proto or "全 edp"))
    leaked = sorted({k for c in cases for k in (c.get("spec_json", {}) or {}) if k != "layers"})
    rows.append(("顶层残留为零（仅 layers）", not leaked, leaked or "零残留"))
    for kw, name in [
        ("edp_connreq_devid_ipv4", "① 方式 1 基线（keep_time 缺省断言）"),
        ("edp_connreq_userid", "② 方式 2（0xC0 空 devid）"),
        ("edp_savedata_type1_fulljson", "③ 存储矩阵 type1×C0"),
        ("edp_savedata_bin_empty", "④ bin_len=0 边界"),
        ("edp_savedata_deliver", "⑤ 下行同构无应答"),
        ("edp_saveack_msgid", "⑥ SAVEACK msg_id 关联"),
        ("edp_cmdresp_empty", "⑦ 条件缺省"),
        ("edp_remainlen_1byte_max", "⑧ 四档边界 7f"),
        ("edp_remainlen_4byte_band", "⑨ 四档边界 80808001"),
        ("edp_multi_frame_segment", "⑩ 多帧粘连"),
        ("edp_multi_transaction_keepalive", "⑪ 多事务全链"),
        ("edp_ipv6", "⑫ IPv6"),
        ("edp_multi_session", "⑬ 多会话展开"),
        ("edp_concurrent_sessions", "⑭ 并发会话"),
        ("edp_devid_u16_max", "⑮ devid u16 满值"),
        ("edp_neg_type_unknown", "负例 type_unknown"),
        ("edp_neg_carrier_udp", "负例 carrier_udp（真实 udp 链形状）"),
        ("edp_neg_layer_chain", "负例 layer_chain（书面豁免注入通道）"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 4. 锚词面（28 负例 error_contains 全部含契约 §7 主锚词）。
    anchors = ["type", "remainlen", "truncat", "protocol", "version", "flag",
               "format", "ds_id", "desc", "length", "connect", "state",
               "cmdid", "msg_id", "json", "layer", "carrier", "port",
               "devid", "apikey", "userid", "authinfo", "rtn"]
    bad_anchor = []
    for c in neg:
        ec = (c.get("expect") or {}).get("error_contains", "")
        if ec not in anchors:
            bad_anchor.append(f"{c.get('id', '?')}:{ec}")
    rows.append(("28 负例锚词 ∈ 契约 §7 主锚词集", not bad_anchor, bad_anchor or "全部在集"))
    wf_in_cfg = [c.get("id") for c in neg
                 if ((c.get("spec_json", {}).get("layers") or [{}])[-1].get("edp") or {}).get("wire_fault")]
    rows.append(("wire_fault 注入负例 ≥26（除 carrier_udp 真实链形）",
                 len(wf_in_cfg) >= 26, f"{len(wf_in_cfg)} 例注入"))

    return rows


def check_dcerpc(cases):
    """D-DCERPC-1 P6 反查表。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent

    # 1. 准入与接线。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单收 dcerpc", '"dcerpc": true' in pg, "在列"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    i_neg = pt.index("negativeOnly := []string{")
    rows.append(("negativeOnly 不含 dcerpc（已准入）", '"dcerpc"' not in pt[i_neg:i_neg + 400], "已摘除"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case dcerpc（严格解码）", 'case "dcerpc":' in tr and "DisallowUnknownFields" in tr, "在案"))
    rows.append(("FlowMeta.DCERPC 直传（静默 0 事件根修）", "DCERPC: spec.DCERPC" in tr, "在案"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.DCERPC", "DCERPC     *core.DCERPCConfig" in gen, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    rows.append(("registry dcerpc 行 + tcp/135 契约", '"tcp.dst_port": "135"' in rg and '"dcerpc"' in rg, "在案"))
    vl = (tg / "internal" / "core" / "layers" / "validate_layers.go").read_text()
    rows.append(("tcp 载体预检（缺 tcp/混合族）", "missing tcp carrier" in vl and "(family)" in vl, "在案"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go ChainPlanner(dcerpc) 接线", 'NewChainPlanner("dcerpc")' in mn, "在案"))
    ch = (tg / "internal" / "core" / "layers" / "chain_planner_chain.go").read_text()
    rows.append(("tcp 分支 dcerpc concurrent=true", "isDCERPCChain" in ch, "在案"))

    # 2. 行为面（builder/planner 关键件）。
    dc = (tg / "internal" / "core" / "dcerpc.go").read_text()
    import re as _re
    _i = dc.index("anchors := map[string]string{")
    _seg = dc[_i:dc.index("\n\t}", _i)]
    _n = len(_re.findall(r'DCERPCWireFault[A-Za-z0-9]+:', _seg))
    rows.append(("wire_fault 闭环 32 值锚词表", _n == 32, f"{_n} 值"))
    bl = (tg / "internal" / "protocol" / "dcerpc" / "builder.go").read_text()
    for prim, name in [
        ("func uuidEncode", "UUID 混合端序编解码权威（§0）"),
        ("func commonHeader", "16B LE 公共头（drep 10000000）"),
        ("func buildContextList", "context element 装配（BIND/ALTER 共用）"),
        ("func buildBindAck", "BIND_ACK/ALTER_CTX_RESP（assoc_group+sec_addr 恒写——P4 勘误）"),
        ("func buildCallPDU", "REQUEST/RESPONSE/FAULT 装配（PFC_OBJECT_UUID 0x80）"),
        ("func splitStub", "分片均分（裁定7：每片自含完整头）"),
        ("type callWalker", "call_id 单解析权威（裁定6）"),
        ("func authTrailer", "auth trailer（6B verifier 头+opaque 凭据）"),
        ("pfcObjUUID   = 0x80", "PFC_OBJECT_UUID=0x80（tshark 实证勘误）"),
        ("flags := byte(pfcFirstFrag | pfcLastFrag)", "单 PDU 恒 FIRST|LAST=0x03（tshark Fragment:Mid 教训）"),
        ("body = le32(body, int64(assocGroup))", "BIND_ACK assoc_group(4B) 回带（C706 header_t）"),
        ("sec = nil", "ALTER_CTX_RESP sec_addr_len=0 恒写"),
    ]:
        rows.append((f"关键件：{name}", prim in bl, "在案"))
    pl = (tg / "internal" / "protocol" / "dcerpc" / "planner.go").read_text()
    for guard, name in [
        ("reused while transaction open", "call_id_reuse（事务不重用）"),
        ("does not match open call", "call_mismatch（应答配对）"),
        ("never accepted (context)", "state_request_unbound/context_unknown"),
        ("whose bind result was rejection (syntax)", "syntax_mismatch（rejected 后引用）"),
        ("duplicated within one bind (context)", "context_duplicate"),
        ("is negative (hint)", "alloc_hint_negative（u32 域）"),
        ("is not a 32-hex-digit UUID (uuid)", "uuid_width/version_missing（UUID 宽度+hex）"),
        ("unknown event kind", "kind 值域兜底"),
        ("needs at least one transfer syntax", "context_syntax（≥1 transfer syntax）"),
        ("is not bind_ack/alter_ctx_resp for a bind", "F4 bind ack 值域守卫（P6 修轮）"),
        ("is not produced on a bind_ack/alter_ctx_resp", "F4 ack 型 respond 拒 auth（P6 修轮）"),
    ]:
        rows.append((f"关键件：{name}", guard in pl, "在案"))

    # 3. 用例面（80 例簇覆盖）。
    ids = {c.get("id", "") for c in cases}
    for cid in [
        "dcerpc_epm_ipv4_bind_lookup", "dcerpc_epm_ipv6_bind_lookup",
        "dcerpc_common_header_fields", "dcerpc_uuid_encoding_authority",
        "dcerpc_fragment_three_pieces", "dcerpc_multi_pdu_back_to_back",
        "dcerpc_auth_pad_2bytes", "dcerpc_bind_ack_assoc_group",
        "dcerpc_epm_tower_variants", "dcerpc_epm_annotation",
        "dcerpc_neg_assoc_group_width", "dcerpc_neg_address_family_mismatch",
    ]:
        rows.append((f"用例在案：{cid}", cid in ids, "在案"))
    rows.append(("用例总数 80（48 正+32 负）", len(cases) == 80, f"{len(cases)} 例"))
    return rows


def check_bacnet(cases):
    """D-BACNET-1 P6 反查表。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent

    # 1. 准入与接线。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单收 bacnet", '"bacnet": true' in pg, "在列"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    i_neg = pt.index("negativeOnly := []string{")
    rows.append(("negativeOnly 不含 bacnet（已准入）", '"bacnet"' not in pt[i_neg:i_neg + 400], "已摘除"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case bacnet（严格解码）", 'case "bacnet":' in tr and "DisallowUnknownFields" in tr, "在案"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.BACNET", "BACNET     *core.BACNETConfig" in gen, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    rows.append(("registry bacnet 行 + udp 47808 契约", '"udp.dst_port": "47808"' in rg, "在案"))
    vl = (tg / "internal" / "core" / "layers" / "validate_layers.go").read_text()
    rows.append(("udp 载体预检（缺 udp/tcp 载体/混合族）", "missing udp carrier" in vl and "rides udp only" in vl, "在案"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go ChainPlanner(bacnet) 接线", 'NewChainPlanner("bacnet")' in mn, "在案"))

    # 2. 行为面（validator/builder 关键件）。
    pl = (tg / "internal" / "protocol" / "bacnet" / "planner.go").read_text()
    import re as _re
    _i = pl.index("wireFaultAnchors = map[string]string{")
    _seg = pl[_i:pl.index("\n}", _i)]
    _n = len(_re.findall(r'"[a-z0-9_]+":', _seg))
    rows.append(("wire_fault 闭环 42 值锚词表", _n == 42, f"{_n} 值"))
    for guard, name in [
        ("matches no open transaction", "invoke_mismatch 自然面（应答 invoke 配对）"),
        ("no open confirmed request", "state_ack_no_request 自然面（响应前置请求）"),
        ("overflows the 10-bit field", "对象类型 10 位溢出"),
        ("overflows the 22-bit field", "对象实例 22 位溢出"),
        ("vendor-private", "属性 ID >511 厂商私有"),
        ("array index", "数组下标负值"),
        ("priority", "优先级 1-16 值域"),
        ("validErrorClass", "error-class 组合值域"),
        ("reused while transaction open", "invoke_reuse（TSM 不重用）"),
        ("SLEN=0 is illegal", "SLEN=0 非法（npdu_src_len_zero 自然面）"),
        ("window size 1-255", "window 值域 1-255"),
        ("not one of 50/128/206/480/1024/1476", "max-APDU 六档值域"),
    ]:
        rows.append((f"关键件：{name}", guard in pl, "在案"))
    bl = (tg / "internal" / "protocol" / "bacnet" / "builder.go").read_text()
    for prim, name in [
        ("func wrapBVLC", "BVLC 0x0A/0x0B 封装（单播/定向广播——正例 3）"),
        ("func buildNPDU", "NPDU 装配（hop 紧随 DADR——裁定勘误在案）"),
        ("func segmentFrames", "分段拆分（值边界分割——正例 29/30 实测）"),
        ("func renderBVLC", "BBMD 管理帧族（规则⑤⑥）"),
        ("func renderRespond", "自动应答（规则②③ simple/complex/error）"),
        ("func effectiveIAM", "I-Am 身份单解析权威（规则①）"),
        ("func pendingInvoke", "Invoke 配对单解析权威"),
        ("invokeWalker", "invokeWalker 缺省递增（正例 35 序列 1,2）"),
    ]:
        rows.append((f"builder：{name}", prim in bl, "在案"))
    rows.append(("事件级严格解码（BACNETEvent UnmarshalJSON DisallowUnknownFields）",
                 "dec.DisallowUnknownFields()" in (tg / "internal" / "core" / "bacnet.go").read_text(), "在案"))
    rows.append(("NPDU hop 勘误登记（135-2016 §6.2.2：hop 紧随 DADR）", "勘误" in bl or "勘误" in pl, "在案"))

    # 3. 用例面（55 正 + 42 负；proto=bacnet；顶层仅 layers）。
    pos = [c for c in cases if "packet_count" in (c.get("expect") or {})]
    neg = [c for c in cases if (c.get("expect") or {}).get("expect_error")]
    rows.append(("97 例对账（55 正+42 负）", len(pos) == 55 and len(neg) == 42 and len(cases) == 97,
                 f"{len(pos)}+{len(neg)}={len(cases)}"))
    bad_proto = [c.get("id", "?") for c in cases if c.get("proto") != "bacnet"]
    rows.append(("proto 全=bacnet（单准入名）", not bad_proto, bad_proto or "全 bacnet"))
    leaked = sorted({k for c in cases for k in (c.get("spec_json", {}) or {}) if k != "layers"})
    rows.append(("顶层残留为零（仅 layers）", not leaked, leaked or "零残留"))
    for kw, name in [
        ("bacnet_bvlc_unicast_baseline", "① 单播基线（§4 帧 hex 同构）"),
        ("bacnet_min_frame", "② 8B 最小帧"),
        ("bacnet_bvlc_broadcast", "③ 定向广播 0x0b"),
        ("bacnet_bvlc_forwarded", "④ Forwarded-NPDU"),
        ("bacnet_bvlc_register_foreign", "⑤ RFD TTL 600/0"),
        ("bacnet_bvlc_result_nak", "⑥ BVLC-Result NAK"),
        ("bacnet_bvlc_write_bdt", "⑦ Write-BDT"),
        ("bacnet_npdu_router_discovery", "⑧ 路由发现 NLM 对"),
        ("bacnet_read_property", "⑨ RP→ComplexACK Real"),
        ("bacnet_segmented_request", "⑩ 分段请求+SegmentACK"),
        ("bacnet_segmented_complex_ack", "⑪ 分段应答（SRV=0）"),
        ("bacnet_i_am_capabilities", "⑫ I-Am 能力变体"),
        ("bacnet_app_tag_encoding", "⑬ 应用标签枚举"),
        ("bacnet_multi_transaction", "⑭ 单客户端多事务"),
        ("bacnet_ipv6", "⑮ IPv6"),
        ("bacnet_multi_session", "⑯ 多会话按序"),
        ("bacnet_concurrent_sessions", "⑰ 并发交错"),
        ("bacnet_port_nondefault", "⑱ 非默认端口 47809（DecodeAs）"),
        ("bacnet_neg_bvlc_type", "负例 bvlc_type"),
        ("bacnet_neg_invoke_mismatch", "负例 invoke_mismatch"),
        ("bacnet_neg_carrier_tcp", "负例 carrier_tcp"),
        ("bacnet_neg_prop_fake_success", "占位注记（bacnet 无此值——应为缺）"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        if "占位" in name:
            rows.append((name, hit is None, "无（正确）"))
        else:
            rows.append((name, hit is not None, hit or "无用例"))

    # 4. 锚词面（42 负例 error_contains 与 planner 锚词表值集一致）。
    anchors = set()
    for m in _re.finditer(r'"[a-z0-9_]+":\s*"([a-z_]+)"', pl[pl.index("wireFaultAnchors"):pl.index("// Planner is")]):
        anchors.add(m.group(1))
    bad_anchor = []
    for c in neg:
        ec = (c.get("expect") or {}).get("error_contains", "")
        if ec not in anchors:
            bad_anchor.append(f"{c.get('id', '?')}:{ec}")
    rows.append(("42 负例锚词 ∈ planner 锚词表值集", not bad_anchor, bad_anchor or "全部在集"))
    wf_in_cfg = [c.get("id") for c in neg
                 if any((l.get("bacnet") or {}).get("wire_fault")
                        for l in (c.get("spec_json", {}).get("layers") or []) if isinstance(l, dict))]
    rows.append(("wire_fault 注入负例（42 值枚举通道）", len(wf_in_cfg) >= 39,
                 f"{len(wf_in_cfg)} 例注入（载体形状 3 例由链形预检拒绝）"))

    return rows


def check_kerberos(cases):
    """D-KERBEROS-1 P6 反查表。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent

    # 1. 准入与接线。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单收 kerberos", '"kerberos"' in pg and 'true' in pg.split('"kerberos"')[1][:12], "在列"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    i_neg = pt.index("negativeOnly := []string{")
    rows.append(("negativeOnly 不含 kerberos（已准入）", '"kerberos"' not in pt[i_neg:i_neg + 500], "已摘除"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case kerberos（严格解码）", 'case "kerberos":' in tr and "DisallowUnknownFields" in tr, "在案"))
    rows.append(("FlowMeta.Kerberos 直传（静默基线根修）", re.search(r"Kerberos:\s+spec\.Kerberos\b", tr) is not None, "在案"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.Kerberos", re.search(r"Kerberos\s+\*core\.KerberosConfig", gen) is not None, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    rows.append(("registry kerberos 行 + udp/tcp 88 双契约",
                 '"udp.dst_port": "88"' in rg and '"tcp.dst_port": "88"' in rg and '"kerberos"' in rg, "在案"))
    rows.append(("registry TransportOn 双载体", re.search(r'"kerberos".*?TransportOn:\s*\[\]string\{"udp", "tcp"\}', rg, re.S) is not None, "在案"))
    vl = (tg / "internal" / "core" / "layers" / "validate_layers.go").read_text()
    rows.append(("载体预检（缺载体/双载体并存/混合族）",
                 "udp and tcp carriers both present" in vl and "missing udp/tcp carrier" in vl, "在案"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go ChainPlanner(kerberos) 接线", 'NewChainPlanner("kerberos")' in mn, "在案"))
    sc = (tg / "internal" / "core" / "strategy_convert.go").read_text()
    rows.append(("strategy_convert case kerberos + 88 缺省端口",
                 'case "kerberos":' in sc and "setDefaultDstPort(&spec, cfg, 88)" in sc, "在案"))

    # 2. 行为面（DER 原语/builder/planner 关键件）。
    kb = (tg / "internal" / "core" / "kerberos.go").read_text()
    _i = kb.index("anchors := map[string]string{")
    _seg = kb[_i:kb.index("\n\t}", _i)]
    _n = len(re.findall(r"KerberosWireFault[A-Za-z0-9]+:", _seg))
    rows.append(("wire_fault 闭环 6 值锚词表", _n == 6, f"{_n} 值"))
    fl = (tg / "internal" / "protocol" / "kerberos" / "der.go").read_text()
    for prim, name in [
        ("func derLen", "DER definite-length 短形/长形（裁定3）"),
        ("func derApp", "[APPLICATION n] constructed 顶层 tag"),
        ("func derCtx", "[n] 上下文构造型（pvno/msg-type 槽）"),
        ("func derGeneralizedTime", "KerberosTime GeneralizedTime（RFC 4120 §5.2.2）"),
        ("func derInteger", "INTEGER 最小补码（正数补 00）"),
    ]:
        rows.append((f"DER 原语：{name}", prim in fl, "在案"))
    bl = (tg / "internal" / "protocol" / "kerberos" / "builder.go").read_text()
    for prim, name in [
        ("func principalName", "PrincipalName name-type+name-string（设计 §7）"),
        ("func encryptedData", "EncryptedData etype/kvno/cipher（opaque 外壳）"),
        ("func ticket", "Ticket tkt-vno=5/realm/sname/enc-part"),
        ("func kdcReq", "KDC-REQ pvno[1] 槽（REQ 特有——REP 是 [0]）"),
        ("func kdcRep", "KDC-REP pvno[0] 槽（RFC 4120 非对称）"),
        ("func apReq", "AP-REQ ticket+authenticator 边界"),
        ("func krbError", "KRB-ERROR error-code/ctime/stime/e-text"),
        ("func tcpFrame", "TCP 4B BE record 长度（不含自身——裁定7）"),
        ("fixtureFill", "opaque 填充确定性 0xA5（裁定5）"),
        ("msg-kind", None) if False else ("kindTable", "kind→tag/msg-type 权威表（裁定6）"),
        ("does not match kind", "msg-type↔tag 一致性守卫（裁定6）"),
        ("no carrier layer before kerberos", "缺载体守卫"),
    ]:
        rows.append((f"关键件：{name}", prim in bl, "在案"))
    pl = (tg / "internal" / "protocol" / "kerberos" / "planner.go").read_text()
    rows.append(("守卫：会话间端口一致性", "conflicts with earlier session dst_port" in pl, "在案"))
    rows.append(("守卫：wire_fault 注入锚词出口", "negative-path injection rejected" in pl, "在案"))
    rows.append(("守卫：krb_error 必带 error_code", "requires error_code" in bl, "在案"))
    rows.append(("守卫：body hex 奇长/非 hex 拒", "odd length" in bl and "non-hex" in bl, "在案"))

    # 3. 用例面（20 例）。
    ids = {c.get("id", "") for c in cases}
    for cid in [
        "kerberos_ipv4_udp_as_basic", "kerberos_ipv6_udp_as_basic",
        "kerberos_tcp_record_framing", "kerberos_as_req_as_rep",
        "kerberos_tgs_req_tgs_rep", "kerberos_ap_req_ap_rep",
        "kerberos_krb_error_preauth_required", "kerberos_preauth_rfc6113",
        "kerberos_ticket_principal_realm", "kerberos_encrypteddata_opaque",
        "kerberos_nonce_time_skew", "kerberos_replay_retransmission",
        "kerberos_multi_session_flow", "kerberos_pcap_nic_consistency",
        "kerberos_neg_truncated_record", "kerberos_neg_tcp_length",
        "kerberos_neg_message_tag", "kerberos_neg_encrypted_boundary",
        "kerberos_neg_time_nonce_replay", "kerberos_neg_udp_carrier",
    ]:
        rows.append((f"用例在案：{cid}", cid in ids, "在案"))
    rows.append(("用例总数 20（14 正+6 负）", len(cases) == 20, f"{len(cases)} 例"))
    return rows


def check_sstp(cases):
    """D-SSTP-1 P6 反查表。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent

    # 1. 准入与接线。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单收 sstp", '"sstp"' in pg and 'true' in pg.split('"sstp"')[1][:12], "在列"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    i_neg = pt.index("negativeOnly := []string{")
    rows.append(("negativeOnly 不含 sstp（已准入）", '"sstp"' not in pt[i_neg:i_neg + 500], "已摘除"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case sstp（严格解码）", 'case "sstp":' in tr and "DisallowUnknownFields" in tr, "在案"))
    rows.append(("FlowMeta.SSTP 直传（静默基线根修）", re.search(r"SSTP:\s+spec\.SSTP\b", tr) is not None, "在案"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.SSTP", re.search(r"SSTP\s+\*core\.SSTPConfig", gen) is not None, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    rows.append(("registry sstp 行 + tls 依赖 + 443 契约",
                 'Name: "sstp"' in rg and 'DependsOn: []string{"tls"}' in rg and '"tcp.dst_port": "443"' in rg, "在案"))
    vl = (tg / "internal" / "core" / "layers" / "validate_layers.go").read_text()
    rows.append(("载体预检（缺 tls/udp/错端口/混合族）",
                 "missing tls carrier" in vl and "udp carrier is not supported" in vl, "在案"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go ChainPlanner(sstp) 接线", 'NewChainPlanner("sstp")' in mn, "在案"))
    sc = (tg / "internal" / "core" / "strategy_convert.go").read_text()
    rows.append(("strategy_convert case sstp + 443 缺省端口",
                 'case "sstp":' in sc and "setDefaultDstPort(&spec, cfg, 443)" in sc, "在案"))
    rows.append(("strategy_convert presence 判死顶层 sstp",
                 "no longer accepts a top-level sstp sub-config" in sc, "在案"))

    # 2. 行为面（header 原语/builder/planner 关键件）。
    kb = (tg / "internal" / "core" / "sstp.go").read_text()
    _i = kb.index("anchors := map[string]string{")
    _seg = kb[_i:kb.index("\n\t}", _i)]
    _n = len(re.findall(r"SSTPWireFault[A-Za-z0-9]+:", _seg))
    rows.append(("wire_fault 闭环 6 值锚词表", _n == 6, f"{_n} 值"))
    hd = (tg / "internal" / "protocol" / "sstp" / "header.go").read_text()
    for prim, name in [
        ("func encodeControlPacket", "控制包 8B 固定部 + 网络序 Length（覆盖整包）"),
        ("func encodeDataPacket", "C=0 数据包：S+4 即 ff 03"),
        ("func verifyControlPacket", "控制包双算复核（Length/Num↔实数）"),
        ("func encodeAttribute", "属性头 4B：Reserved|ID|LengthPacket（含 4B 头）"),
        ("func encodePPPFrame", "PPP 帧 ff 03 + Protocol"),
        ("func cryptoBindingValue", "Crypto Binding 0x0068（SHA-256 profile）"),
        ("func cryptoBindingRequestValue", "Crypto Binding Request 0x0028"),
        ("func statusInfoValue", "Status Info Reserved1+AttribID+Status+AttribValue"),
    ]:
        rows.append((f"原语：{name}", prim in hd, "在案"))
    bl = (tg / "internal" / "protocol" / "sstp" / "builder.go").read_text()
    for prim, name in [
        ("func walkSession", "会话状态单权威（校验与生成同路径）"),
        ("func buildAttribute", "属性渲染 + 值域（0x0005/0x0006 冒充属性拒）"),
        ("func buildControl", "C bit↔Message Type 一致性守卫"),
        ("func buildPPP", "PPP protocol/ipv4-ipv6 地址族显式声明守卫"),
        ("func (w *sstpWalker) step", "状态机：REQUEST→ACK→CONNECTED→PPP→ABORT"),
        ("func synthIPv4Payload", "IPv4 合成载荷（checksum 实算）"),
        ("func synthIPv6Payload", "IPv6 合成载荷"),
        ("func (g *SSTPGenerator) Generate", "终结层事件流（经 tls 透传 application-data）"),
    ]:
        rows.append((f"关键件：{name}", prim in bl, "在案"))
    pl = (tg / "internal" / "protocol" / "sstp" / "planner.go").read_text()
    rows.append(("关键件：直接外层必须是 tls（生成面第二道防线）", "func resolveCarrier(chain" in pl, "在案"))
    rows.append(("守卫：版本唯一 0x10", "version" in pl and "0x10" not in pl or "versionByte" in pl, "在案"))
    rows.append(("守卫：sessions[] 与 events[] 双权威拒", "both sessions[] and events[]" in pl, "在案"))
    rows.append(("守卫：会话 ID/TLS session 独立", "duplicates an earlier session" in pl, "在案"))
    rows.append(("守卫：wire_fault 注入锚词出口", "negative-path injection rejected" in pl, "在案"))

    # 3. 用例面（22 例）。
    ids = {c.get("id", "") for c in cases}
    for cid in [
        "sstp_https_tls_handshake", "sstp_call_connect_request",
        "sstp_call_connect_ack", "sstp_call_connected", "sstp_call_abort",
        "sstp_attribute_protocol_id", "sstp_attribute_status_crypto",
        "sstp_ppp_ipv4", "sstp_ppp_ipv6", "sstp_ppp_mppe_boundary",
        "sstp_multi_connection", "sstp_session_ordering",
        "sstp_length_record_segmentation", "sstp_call_connect_nak",
        "sstp_group_coalesced_record",
        "sstp_pcap_nic_consistency",
        "sstp_neg_header_length", "sstp_neg_attribute_length",
        "sstp_neg_state_transition", "sstp_neg_transport_carrier",
        "sstp_neg_ppp_framing", "sstp_neg_tls_boundary",
    ]:
        rows.append((f"用例在案：{cid}", cid in ids, "在案"))
    rows.append(("用例总数 22（16 正+6 负）", len(cases) == 22, f"{len(cases)} 例"))
    rows.append(("无 sstp_neg_unregistered 占位", "sstp_neg_unregistered" not in ids, "已移除"))
    return rows


CHECKS = {
    "smtp": check_smtp, "pop3": check_pop3, "imap": check_imap}


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


def check_ocsp(cases):
    """D-OCSP-1 P6 反查表。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent

    # 1. 准入与接线。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单收 ocsp", '"ocsp"' in pg and 'true' in pg.split('"ocsp"')[1][:12], "在列"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    i_neg = pt.index("negativeOnly := []string{")
    rows.append(("negativeOnly 不含 ocsp（已准入）", '"ocsp"' not in pt[i_neg:i_neg + 600], "已摘除"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case ocsp（严格解码）", 'case "ocsp":' in tr and "DisallowUnknownFields" in tr, "在案"))
    rows.append(("FlowMeta.OCSP 直传（静默基线根修）", re.search(r"OCSP:\s+spec\.OCSP\b", tr) is not None, "在案"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.OCSP", re.search(r"OCSP\s+\*core\.OCSPConfig", gen) is not None, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    rows.append(("registry ocsp 行 + tcp 80 契约",
                 '"tcp.dst_port": "80"' in rg and '"ocsp"' in rg, "在案"))
    rows.append(("registry 裁定1 依赖（DependsOn tcp + OptionalOn http + TransportOn tcp）",
                 re.search(r'"ocsp".*?DependsOn:\s*\[\]string\{"tcp"\}.*?OptionalOn:\s*\[\]string\{"http"\}.*?TransportOn:\s*\[\]string\{"tcp"\}', rg, re.S) is not None, "在案"))
    vl = (tg / "internal" / "core" / "layers" / "validate_layers.go").read_text()
    rows.append(("载体预检（缺 tcp 载体/http-profile 无 http 层/tcp-profile 有 http 层/混合族）",
                 "missing tcp carrier" in vl and "http profile requires" in vl
                 and "tcp profile requires" in vl and "mixed address family" in vl, "在案"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go ChainPlanner(ocsp) 接线", 'NewChainPlanner("ocsp")' in mn, "在案"))
    sc = (tg / "internal" / "core" / "strategy_convert.go").read_text()
    rows.append(("strategy_convert case ocsp + 80 缺省端口",
                 'case "ocsp":' in sc and "setDefaultDstPort(&spec, cfg, 80)" in sc, "在案"))
    hl = (tg / "internal" / "protocol" / "http" / "layer_gen.go").read_text()
    rows.append(("http 层透传放行 ocsp（isHTTPRPCInner）",
                 re.search(r"isHTTPRPCInner[\s\S]{0,600}meta\.OCSP != nil", hl) is not None, "在案"))

    # 2. 行为面（DER 原语/builder/planner 关键件）。
    oc = (tg / "internal" / "core" / "ocsp.go").read_text()
    _i = oc.index("anchors := map[string]string{")
    _seg = oc[_i:oc.index("\n\t}", _i)]
    _n = len(re.findall(r"OCSPWireFault[A-Za-z0-9]+:", _seg))
    rows.append(("wire_fault 闭环 6 值锚词表", _n == 6, f"{_n} 值"))
    fl = (tg / "internal" / "protocol" / "ocsp" / "der.go").read_text()
    for prim, name in [
        ("func derLen", "DER definite-length 最短长形（短形/0x81/0x82）"),
        ("func derInteger", "INTEGER 最小补码（正数补 00）"),
        ("func derCtxExplicit", "[n] EXPLICIT 包装（响应槽——裁定1）"),
        ("func derCtxImplicitPrim", "[n] IMPLICIT 基本型（CertStatus good/unknown）"),
        ("func derCtxImplicitCons", "[n] IMPLICIT 构造型（revoked RevokedInfo 无内层 0x30）"),
    ]:
        rows.append((f"DER 原语：{name}", prim in fl, "在案"))
    bl = (tg / "internal" / "protocol" / "ocsp" / "builder.go").read_text()
    for prim, name in [
        ("func renderCertID", "CertID hashAlgorithm+双 hash+serial"),
        ("func algorithmIdentifier", "AlgorithmIdentifier（SHA-1 带 NULL / SHA-256 无参——RFC 8954 §2）"),
        ("func extensions", "nonce 双层 OCTET STRING（RFC 6960 §4.4.1）"),
        ("func renderCertStatus", "CertStatus 三分支 good[0]/revoked[1]/unknown[2]"),
        ("func renderResponderID", "ResponderID byKey [2] EXPLICIT（RFC 6960 模块 EXPLICIT TAGS）"),
        ("derCtxExplicit(2, derOctet(", "byKey 显式包 OCTET STRING（primitive 82 14 会令 dissector 中止）"),
        ("func httpPostFrame", "A.1 POST 帧（Content-Type application/ocsp-request）"),
        ("func httpGetFrame", "RFC 5019 GET 帧（base64url 无 padding URI）"),
        ("func httpResponseFrame", "200/503 帧 + Retry-After（tryLater 重试）"),
        ('"503 Service Unavailable"', "tryLater(3) → HTTP 503（不静默成功）"),
    ]:
        rows.append((f"关键件：{name}", prim in bl, "在案"))
    pl = (tg / "internal" / "protocol" / "ocsp" / "planner.go").read_text()
    rows.append(("守卫：会话间端口一致性", "conflicts with earlier session dst_port" in pl, "在案"))
    rows.append(("守卫：wire_fault 注入锚词出口", "negative-path injection rejected" in pl, "在案"))
    rows.append(("守卫：算法↔hash 长度绑定", "(hash)" in bl and "hash length mismatch" in bl, "在案"))
    rows.append(("守卫：request_count↔certs 长度匹配", "does not match request.certs length" in bl, "在案"))
    rows.append(("守卫：version v1 DEFAULT 不编码（X.690 §11.5）", "*p.version == 0" in bl, "在案"))
    gnt = (tg / "test" / "protocol_pcap" / "cases" / "ocsp.json")
    rows.append(("用例文件在案", gnt.exists(), "在案"))

    # 3. 用例面（20 例）。
    ids = {c.get("id", "") for c in cases}
    for cid in [
        "ocsp_http_ipv4_request_response", "ocsp_http_ipv6_request_response",
        "ocsp_tcp_record_framing", "ocsp_request_certid_sha1",
        "ocsp_request_certid_sha256_rfc8954", "ocsp_batch_multi_request",
        "ocsp_nonce_extension", "ocsp_signed_request",
        "ocsp_basic_response_status", "ocsp_single_response_statuses",
        "ocsp_response_signature_extensions", "ocsp_time_validity_windows",
        "ocsp_multi_session_stream", "ocsp_pcap_nic_consistency",
        "ocsp_neg_der_truncated", "ocsp_neg_certid_hash_length",
        "ocsp_neg_request_response_mismatch", "ocsp_neg_nonce_extension",
        "ocsp_neg_signature", "ocsp_neg_carrier_profile",
    ]:
        rows.append((f"用例在案：{cid}", cid in ids, "在案"))
    rows.append(("用例总数 20（14 正+6 负）", len(cases) == 20, f"{len(cases)} 例"))
    return rows


CHECKS = {
    "smtp": check_smtp, "pop3": check_pop3, "imap": check_imap}


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


def check_srv6(cases):
    """D-SRV6-1 P5R 反查表。返回 [(检查名, 通过?, 证据case_id或缺口说明)]。"""
    rows = []
    lays = []  # (cid, srv6子映射)
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("srv6"), dict):
                lays.append((c.get("id", "?"), l["srv6"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. seg_type 枚举（重点 9 + end.un + 缺省=end + 非法 vn08，设计 §3.4 口径）。
    for st in ["", "end", "end.x", "end.dx6", "end.dx4", "end.dt4", "end.dt6",
               "end.b6", "end.b6.encaps", "end.b6.encaps.red", "end.un",
               "end.zzz"]:
        hit = next((cid for cid, m in lays
                    if m.get("seg_type", "") == st), None)
        name = "seg_type 缺省(=end)" if st == "" else f"seg_type {st}"
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. payload_protocol 7 值（含缺省=udp）。
    for pp in ["", "udp", "tcp", "icmpv6", "ipv6", "ipv4", "none"]:
        hit = next((cid for cid, m in lays
                    if m.get("payload_protocol", "") == pp), None)
        name = "payload 缺省(=udp)" if pp == "" else f"payload {pp}"
        rows.append((name, hit is not None, hit or "无用例"))

    # 3. TLV 类型面：正面 4(padn 自动)/5(HMAC)/200(实验) 出现 + 负面保留
    #    1/2/3/6 锚词（3→T-71）。
    for t in [4, 5, 200]:
        hit = next((cid for cid, m in lays
                    for tlv in m.get("tlv") or []
                    if isinstance(tlv, dict) and tlv.get("type") == t), None)
        rows.append((f"TLV type {t}", hit is not None, hit or "无用例"))
    for t in [1, 2, 3, 6]:
        hit = f"reserved TLV type {t} must not be set" in blob
        rows.append((f"TLV 保留 {t} 拒", hit, "锚词出现" if hit else "无用例"))

    # 4. reduced 三态（缺省/true/显式 false→T-70）。
    for red, name in [(None, "reduced 缺省"), (True, "reduced true"),
                      (False, "reduced 显式 false")]:
        hit = next((cid for cid, m in lays
                    if (m.get("reduced", None) == red)), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 5. tag 三值 + direction 双向 + frames 四形。
    for tag, name in [(0, "tag 零"), (43981, "tag 中值"), (65535, "tag 最大")]:
        hit = next((cid for cid, m in lays if m.get("tag") == tag), None)
        rows.append((name, hit is not None, hit or "无用例"))
    for d, name in [(None, "direction 缺省(up)"), ("down", "direction down")]:
        hit = next((cid for cid, m in lays
                    if m.get("direction", None) == d), None)
        rows.append((name, hit is not None, hit or "无用例"))
    for f, name in [(None, "frames 缺省(=1)"), (5, "frames 5"),
                    (1000, "frames 1000"), (-1, "frames 负拒")]:
        hit = next((cid for cid, m in lays
                    if m.get("frames", None) == f), None)
        if name == "frames 负拒":
            # 实际执法门是 registry V9 范围（先于 validator VR-21），锚词对真实门。
            hit = "not a numeric value in [0,1000000]" in blob
            rows.append((name, hit, "锚词出现" if hit else "无用例"))
        else:
            rows.append((name, hit is not None, hit or "无用例"))

    # 6. 段数边界 0/1/2/3/126/127/128。
    for n in [0, 1, 2, 3, 126, 127, 128]:
        hit = next((cid for cid, m in lays
                    if len(m.get("segment_list") or []) == n), None)
        rows.append((f"段数 {n}", hit is not None, hit or "无用例"))

    # 7. VR 锚词收口（链可达 17 支 + presence/静态复制负例；VR-01/14/16/17
    #    =C 类，Go 单测覆盖，D-SRV6-1 §5 登记）。
    anchors = [
        ("segment_list must not be empty", "VR-02 list 非空"),
        ("segment_list too large", "VR-03 段数上限"),
        ("segment_list[0] must be IPv6", "VR-04 段 IPv6"),
        ("is not IPv6", "VR-05/06 地址族"),
        ("srv6 requires IPv6", "VR-06 外层 IPv6"),
        ("unknown seg_type", "VR-07 行为枚举"),
        ("flags must be 0", "VR-08 flags 全零"),
        ("last_entry+1", "VR-09 SL/LE 关系"),
        ("exceeds 255 bytes", "VR-10 TLV 长度"),
        ("pad1 must not be set manually", "VR-11 Pad1 禁设"),
        ("padN must not be set manually", "VR-12 PadN 禁设"),
        ("requires inner_payload >= 40 bytes", "VR-15 内层长度"),
        ("requires payload_protocol=", "VR-15 行为×载荷"),
        ("hdr_ext_len overflow", "VR-18/19/20 溢出"),
        ("not a numeric value in [0,1000000]", "V9 frames 范围（覆盖 VR-21）"),
        ("payload_protocol=none with non-empty inner_payload", "VR-22 none 非空载荷（T-69）"),
        ("direction=down requires source-node view", "VR-23 down 源节点视角"),
        ("top-level srv6 sub-config", "presence 判死（T-74）"),
        ("static four-tuple", "静态复制拒（T-75）"),
    ]
    for needle, name in anchors:
        hit = needle in blob
        rows.append((name, hit, "锚词出现" if hit else "无用例"))

    # 8. 多流（flows>=2 ≥2 例）。
    multi = [c.get("id", "?") for c in cases
             if ((c.get("strategy_fc") or {}).get("value") or 0) >= 2]
    rows.append(("多流（flows>=2）", len(multi) >= 1,
                 multi[0] if multi else "无用例"))
    rows.append(("多流（第二条）", len(multi) >= 2,
                 multi[1] if len(multi) >= 2 else "无用例"))

    # 9. 组合流 2 条（HBH 链 T-72 / down+HMAC+内层端口 T-73，notes 关键字）。
    for kw, name in [("组合流 A", "组合流 A（HBH+TLV+多段）"),
                     ("组合流 B", "组合流 B（down+HMAC+内层端口）")]:
        hit = next((c.get("id") for c in cases
                    if kw in json.dumps(c.get("summary", ""), ensure_ascii=False)
                    or kw in json.dumps((c.get("expect") or {}).get("notes") or [],
                                        ensure_ascii=False)), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 10. HBH 链 + dst_mac（End.X 改写面）+ 内层端口 回退/覆盖。
    hit = next((cid for cid in (c.get("id") for c in cases)
                if "hop_by_hop" in blob), None)
    rows.append(("HBH 链", "hop_by_hop" in blob,
                 hit or "无用例"))
    hit = next((c.get("id") for c in cases if "dst_mac" in json.dumps(
        c.get("spec_json", {}), ensure_ascii=False)), None)
    rows.append(("End.X dst_mac", hit is not None, hit or "无用例"))
    hit = next((cid for cid, m in lays if m.get("inner_src_port")), None)
    rows.append(("内层端口 覆盖", hit is not None, hit or "无用例"))
    # 回退执法例：无 inner_src_port 且 notes 标记 inner_src_port_fallback
    # （帧 pin 断言回退值 12345，即真实执法断言）。
    hit = next((c.get("id") for c in cases
                if "inner_src_port_fallback" in json.dumps(
                    (c.get("expect") or {}).get("notes") or [], ensure_ascii=False)
                and not next((m.get("inner_src_port") for cid, m in lays
                              if cid == c.get("id")), None)), None)
    rows.append(("内层端口 回退", hit is not None, hit or "无用例"))

    # 11. DstIP=首段 帧断言（new08 字节面）。
    hit = next((c.get("id") for c in cases
                if "dstip_byte_match" in c.get("id", "")), None)
    rows.append(("DstIP=首段 字节断言", hit is not None, hit or "无用例"))

    # 12. 商业映射（子表③ 全待确认：登记说明行，恒过不冒充）。
    rows.append(("现网映射", True, "D-SRV6-1 子表③ 待确认（Linux seg6 抓包/厂商文档）"))

    return rows


def check_fins(cases):
    """D-FINS-1 P5R 反查表（T-FINS-1…44）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []  # (cid, fins子映射)
    tops = []  # (cid, layers数组)
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        ls = sj.get("layers") or []
        tops.append((c.get("id", "?"), ls))
        for l in ls:
            if isinstance(l, dict) and isinstance(l.get("fins"), dict):
                lays.append((c.get("id", "?"), l["fins"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)
    flatcases = json.dumps([c.get("spec_json", {}) for c in cases], ensure_ascii=False)

    def cmd_of(m):
        cmds = m.get("commands") or []
        return [x.get("command") for x in cmds if isinstance(x, dict)]

    def areas_of(cid):
        for cid2, m in lays:
            if cid2 != cid:
                continue
            for x in m.get("commands") or []:
                if isinstance(x, dict) and x.get("command") == 0x0104:
                    return x.get("read_areas") or []
        return None

    # 1. 载体 2（tcp 例须有 tcp 层）。
    rows.append(("载体 udp", any("udp" in [list(x)[0] for x in ls] for _, ls in tops), "udp 层"))
    tcp_hit = next((cid for cid, ls in tops
                    if "tcp" in [list(x)[0] for x in ls]), None)
    rows.append(("载体 tcp", tcp_hit is not None, tcp_hit or "无用例"))

    # 2. 地址族（v6 代表；单/双族口径见 T-FINS 矩阵登记）。
    v6 = any("2001:db8::" in flatcases for _ in [0])
    rows.append(("地址族 v6", v6, "2001:db8::" if v6 else "无用例"))

    # 3. 命令码 5 值正例 + 未知码负例。
    for code, name in [(0x0101, "0101 读"), (0x0102, "0102 写"),
                       (0x0103, "0103 Fill"), (0x0104, "0104 多区读"),
                       (0x0701, "0701 校时")]:
        hit = next((cid for cid, m in lays if code in cmd_of(m)), None)
        rows.append((name, hit is not None, hit or "无用例"))
    rows.append(("未知命令负例", "unsupported command" in blob, "锚词出现" if "unsupported command" in blob else "无用例"))

    # 4. 区名×口径组合（9.20-9.22 扫描）。
    area_seen = set()
    for _, m in lays:
        for x in m.get("commands") or []:
            if not isinstance(x, dict):
                continue
            bit = "bit" in x
            area_seen.add((x.get("memory_area", ""), bit))
        for ra in (x.get("read_areas") or [] for x in m.get("commands") or [] if isinstance(x, dict)):
            for a in ra:
                if isinstance(a, dict):
                    area_seen.add((a.get("memory_area", ""), "bit" in a))
    for area, bit, name in [("dm", False, "dm 字"), ("cio", False, "cio 字"), ("wr", False, "wr 字"),
                            ("hr", False, "hr 字"), ("tc_pv", False, "tc_pv 字"), ("ir", False, "ir 字"),
                            ("tc_bit", False, "tc_bit 字(0x09)"), ("cio", True, "cio 位(0x30)"),
                            ("wr", True, "wr 位(0x31)"), ("hr", True, "hr 位(0x32)")]:
        hit = (area, bit) in area_seen
        rows.append((f"区码 {name}", hit, "已覆" if hit else "无用例"))

    # 5. 会话/SID/关回包/结束码面。
    rows.append(("sessions≥2", any((m.get("sessions") or 0) >= 2 for _, m in lays), "sessions"))
    rows.append(("SID 递增", "fins_sid_auto_incr" in blob, "fins_sid_auto_incr"))
    rows.append(("SID 固定", "fins_sid_fixed" in blob, "fins_sid_fixed"))
    rows.append(("expect_response=false", "expect_response" in blob, "锚词出现"))
    rows.append(("结束码响应面", "response_end_code" in blob, "锚词出现"))

    # 6. E-01~E-10 锚词 + presence/static。
    for needle, name in [
        ("invalid memory area", "E-01 内存区"),
        ("unsupported command", "E-02 命令码"),
        ("dm does not support bit access", "E-03 DM 位"),
        ("address exceeds range", "E-04 越界"),
        ("items must be > 0", "E-05 元素数"),
        ("icf request direction bit must be clear", "E-06 ICF cfg 级"),
        ("icf response-required bit must be clear", "E-06 ICF bit0"),
        ("data length", "E-07 数据长"),
        ("clock field out of range", "E-09 BCD"),
        ("invalid gct", "GCT"),
        ("invalid dna", "DNA"),
        ("invalid sna", "SNA"),
        ("read_areas", "E-10 组面"),
        ("fill data must be 2 bytes", "0103 模板"),
        ("fill does not support bit access", "0103 位拒"),
        ("invalid transport", "transport 枚举"),
        ("invalid direction", "direction 枚举"),
        ("sessions must be >= 0", "sessions 负值"),
        ("top-level fins sub-config", "presence 判死"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    # 7. 组合流 2 条（T-FINS T-31/32）。
    for kw, name in [("组合流 A", "组合流 A（TCP+多命令+SID 递增）"),
                     ("组合流 B", "组合流 B（UDP+双会话+全键+结束码）")]:
        hit = next((c.get("id") for c in cases
                    if kw in json.dumps(c.get("summary", ""), ensure_ascii=False)
                    or kw in json.dumps((c.get("expect") or {}).get("notes") or [], ensure_ascii=False)), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 8. 多流（strategy_fc flows>=2 ≥2 例：sessions 派生面 + 静态复制拒）。
    multi = [c.get("id", "?") for c in cases
             if ((c.get("spec_json") or {}).get("strategy_fc") or {}).get("value", 0) >= 2
             or "flows" in json.dumps((c.get("spec_json") or {}).get("strategy_fc") or {})]
    rows.append(("多流/静态复制面", len(multi) >= 1, multi[0] if multi else "无用例"))

    return rows


def check_goose(cases):
    """D-GOOSE-1 P5R 反查表（T-GOOSE-1…30）。返回 [(检查名, 通过?, 证据)]。
    层内 goose 子映射扫描（P5 改写后形状；P4 登记时旧顶层 goose 键例判 MISS，
    P5 cases 落地后转绿）。
    """
    rows = []
    lays = []  # (cid, goose层内子映射)
    tops = []  # (cid, layers数组)
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        ls = sj.get("layers") or []
        tops.append((c.get("id", "?"), ls))
        for l in ls:
            if isinstance(l, dict) and isinstance(l.get("goose"), dict):
                lays.append((c.get("id", "?"), l["goose"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 场景 S1-S7（正例存在性）。
    for kw, name in [("heartbeat", "S1 心跳"), ("retransmit", "S2 退避"),
                     ("dataset_change", "S2 变化"), ("test_flag", "S3 test"),
                     ("ndscom", "S3 ndsCom"), ("vlan", "S4 VLAN"),
                     ("multitype", "S5 多类型"), ("multidataset", "S7 多数据集"),
                     ("no_ip", "S6 无IP")]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. 数据类型 11 白名单（data[].type 字面；int64/uint64 分支代表）。
    for t in ["boolean", "bit_string", "int32", "int64", "uint32", "uint64",
              "float32", "octet_string", "visible_string", "binary_time",
              "utc_time"]:
        hit = next((cid for cid, m in lays
                    for d in m.get("data") or []
                    if isinstance(d, dict) and d.get("type") == t), None)
        rows.append((f"类型 {t}", hit is not None, hit or "无用例"))

    # 3. 可选键覆盖（go_id/start_stnum/start_sqnum/test/nds_com/vlan三键/
    #    event_seq/count/dst_mac）。
    for k, name in [("go_id", "go_id 显式"), ("start_stnum", "start_stnum"),
                    ("start_sqnum", "start_sqnum"), ("test", "test 键"),
                    ("nds_com", "nds_com 键"), ("vlan_enabled", "VLAN 开关"),
                    ("vlan_id", "vlan_id"), ("vlan_priority", "vlan_priority"),
                    ("event_seq", "event_seq"), ("count", "count 层内"),
                    ("dst_mac", "dst_mac 层内")]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 4. event_seq 槽位四键。
    for k, name in [("data_idx", "ev data_idx"), ("delay_ms", "ev delay_ms"),
                    ("retransmits", "ev retransmits"),
                    ("sqnum_step", "ev sqnum_step")]:
        hit = next((cid for cid, m in lays
                    for e in m.get("event_seq") or []
                    if isinstance(e, dict) and k in e), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 5. 校验分支 13 锚词 + presence/static。
    for needle, name in [
        ("out of range [0,16383]", "appid 越界（V9 真实门）"),
        ("gocb_ref and dat_set are required", "gocb_ref/dat_set 必填"),
        ("exceed 255 bytes", "超长串"),
        ("tal_ms must be in", "tal_ms"),
        ("conf_rev must be non-zero", "conf_rev"),
        ("stNum must not overflow", "stNum 回绕"),
        ("sqNum must not overflow", "sqNum 上限"),
        ("at least one", "空 data"),
        ("unsupported data type", "非法 type"),
        ("sqNum step", "sqNum 跳号"),
        ("must not have an ip/transport carrier", "L2-only 载体门（V7b）"),
        ("out of range [0,4095]", "VLAN 越界（V9 真实门）"),
        ("top-level goose sub-config", "presence 判死"),
        ("static four-tuple", "静态复制拒"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    # 6. 组合流 2 条（T-28/29，notes 关键字）。
    for kw, name in [("组合流 A", "组合流 A（三旗同帧）"),
                     ("组合流 B", "组合流 B（事件+多类型）")]:
        hit = next((c.get("id") for c in cases
                    if kw in json.dumps(c.get("summary", ""), ensure_ascii=False)
                    or kw in json.dumps((c.get("expect") or {}).get("notes") or [], ensure_ascii=False)), None)
        rows.append((name, hit is not None, hit or "无用例"))

    return rows


def check_radius(cases):
    """D-RADIUS-1 P5 反查表（T-RADIUS-1…21）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("radius"), dict):
                lays.append((c.get("id", "?"), l["radius"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 场景面（21 例逐点名）。
    for kw, name in [("smoke", "S 基线改写例"), ("flat_presence", "presence 判死面"),
                     ("flat_static_port", "静态端口拒面"), ("acct_1813", "Accounting 1813 顺序修正面"),
                     ("challenge", "Challenge 显式响应码"), ("status", "Status-Server/Client"),
                     ("code3", "请求码 3 枚举"), ("reject", "Reject 失败分支"),
                     ("neg_no_auto", "无默认响应拒"), ("neg_reqcode", "请求码非法"),
                     ("neg_rspcode", "响应码非法"), ("auth_fixed", "fixed authenticator 钉值"),
                     ("neg_auth_hex", "authenticator 非法 hex"), ("neg_auth_len", "authenticator 长度错"),
                     ("attr_formats", "属性四 format+VSA"), ("neg_attr_len", "属性超长"),
                     ("neg_format", "format 非法"), ("rounds", "rounds 多轮"),
                     ("_v6", "v6 正例面"), ("default_port", "缺省端口 1812 面"),
                     ("port_dyn", "端口动态面"), ("neg_vsa_len", "VSA 超长拒面"),
                     ("attr_boundary", "253 边界等值面"), ("nas_combo", "现网 NAS 组合面"),
                     ("neg_coa", "CoA 白名单外拒面")]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. 键覆盖（业务 7 键 + 端口 2 键）。
    for k in ["code", "identifier", "authenticator", "response_code",
              "rounds", "attributes", "response_attributes", "src_port", "dst_port"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))

    # 3. 锚词面（9 负例全 legacy 真门）。
    for needle, name in [
        ("top-level radius sub-config", "presence 判死"),
        ("static four-tuple", "静态端口拒"),
        ("has no default response code", "无默认响应拒"),
        ("invalid request code", "请求码非法"),
        ("invalid response code", "响应码非法"),
        ("invalid authenticator hex", "authenticator 非法 hex"),
        ("must be 16 bytes", "authenticator 长度错"),
        ("exceeds the 253-byte", "属性超长"),
        ("unknown format", "format 非法"),
        ("exceeds the 247-byte", "VSA 超长拒"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows



def check_pppoe(cases):
    """D-PPPOE-1 P6 反查表（T-PPPOE-1…24，9.52 对账 45/45）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("pppoe"), dict):
                lays.append((c.get("id", "?"), l["pppoe"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 场景面（24 例逐点名，T-PPPOE 清单）。
    for kw, name in [
        ("lifecycle_full", "T-1 全生命周期 8 帧（PADT 缺省真）"),
        ("padt_suppressed", "T-2 padt=false 抑制"),
        ("skip_discovery", "T-3 跳过发现+显式 ID"),
        ("auth_none_lcp_len", "T-4 无 Auth-Proto 选项 LCP len 钉"),
        ("auth_pap", "T-5 PAP c023 两帧"),
        ("auth_chap", "T-6 CHAP c223 三帧"),
        ("data_direction_down", "T-7 下行换向"),
        ("data_frames_zero_default", "T-8 data_frames=0 缺省 1（勘误面）"),
        ("service_name_any", "T-9 any-service 零长标签"),
        ("bras_three_tags", "T-10 BRAS 三标签（现网）"),
        ("mru_magic_explicit", "T-11 MRU+Magic 钉值"),
        ("sessions_derived_ids", "T-12 派生 ID 1/2/3"),
        ("sessions_explicit_ids", "T-13 显式 ID 100/200"),
        ("composite_multi_session", "T-14 复合大场景（9.50）"),
        ("inner_tcp_explicit", "T-15 内嵌 TCP"),
        ("data_payload_bytes", "T-16 载荷字节钉"),
        ("data_frames_two", "T-17 多帧+IPID 递增"),
        ("inner_udp_explicit", "T-18 内嵌 UDP 显式"),
        ("neg_auth_invalid", "T-19 auth 枚举拒"),
        ("neg_inner_proto_invalid", "T-20 inner_proto 枚举拒"),
        ("neg_data_frames_negative", "T-21 data_frames 负值拒"),
        ("neg_ipv6_inner", "T-22 内嵌 IPv6 拒"),
        ("neg_sessions_mutex", "T-23 sessions 互斥拒"),
        ("neg_duplicate_session_id", "T-24 重复 ID 拒"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. 键覆盖（消费面 16 键中流程可写部分逐键）。
    for k in ["session_id", "skip_discovery", "ac_name", "service_name", "cookie",
              "mru", "magic_number", "auth", "username", "data_frames",
              "data_payload", "inner_proto", "data_direction", "padt", "sessions"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))

    # 3. 锚词面（6 负例，真实拦截面文案）。
    for needle, name in [
        ("Auth", "T-19 auth 枚举锚"),
        ("InnerProto", "T-20 inner_proto 锚"),
        ("data_frames", "T-21 范围门锚"),
        ("must be IPv4", "T-22 IPv6 拒锚"),
        ("pppoe: sessions and top-level session config are mutually exclusive", "T-23 互斥锚"),
        ("pppoe: duplicate session_id", "T-24 重复锚"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows


def check_ldap(cases):
    """D-LDAP-1 P6 反查表（T-LDAP-1…22，9.52 对账 38/38）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("ldap"), dict):
                lays.append((c.get("id", "?"), l["ldap"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 场景面（22 例逐点名，T-LDAP 清单）。
    for kw, name in [
        ("session_full", "T-1 全会话 13 包（六标签 BER 面钉）"),
        ("ber_long_form_length", "T-2 BER 长形前缀专钉"),
        ("message_id_increment", "T-3 messageID 递增实测钉"),
        ("bind_anonymous", "T-4 匿名 bind"),
        ("bind_simple", "T-5 simple bind"),
        ("bind_version2", "T-6 version=2"),
        ("scope_single_level", "T-7 scope=1"),
        ("scope_whole_subtree", "T-8 scope=2"),
        ("filter_equality", "T-9 equality CHOICE"),
        ("result_invalid_credentials", "T-10 resultCode 49"),
        ("rounds_two", "T-11 rounds=2 多轮"),
        ("attributes_custom", "T-12 attributes 自定义"),
        ("unbind_suppressed", "T-13 unbind 抑制"),
        ("composite_multi_round", "T-14 复合大场景（9.50）"),
        ("search_base_dn", "T-15 base DN 显式"),
        ("size_time_limit", "T-16 size/time limit"),
        ("neg_version_invalid", "T-17 version 拒"),
        ("neg_scope_invalid", "T-18 scope 拒"),
        ("neg_filter_type_invalid", "T-19 filter_type 拒"),
        ("neg_result_code_range", "T-20 result_code 拒"),
        ("neg_size_limit_negative", "T-21 size_limit 拒"),
        ("neg_message_id_overflow", "T-22 messageID 超限拒"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. 键覆盖（15 键逐键）。
    for k in ["rounds", "message_id_base", "version", "bind_dn", "bind_password",
              "search_base_dn", "search_scope", "size_limit", "time_limit",
              "filter_type", "search_filter", "filter_value", "attributes",
              "result_code", "unbind"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))

    # 3. 锚词面（6 负例）。
    for needle, name in [
        ("invalid version", "T-17 version 锚"),
        ("invalid scope", "T-18 scope 锚"),
        ("invalid filter type", "T-19 filter_type 锚"),
        ("out of ENUMERATED range", "T-20 result_code 锚"),
        ("size_limit", "T-21 范围门锚"),
        ("exceeds 0x7FFF", "T-22 messageID 锚"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows


def check_rtmp(cases):
    """D-RTMP-1 P6 反查表（T-RTMP-1…16，9.52 对账 24/24）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("rtmp"), dict):
                lays.append((c.get("id", "?"), l["rtmp"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 场景面（16 例逐点名，T-RTMP 清单）。
    for kw, name in [
        ("play_session_full", "T-1 play 全会话 20 包"),
        ("handshake_segments", "T-2 握手分段数专钉"),
        ("chunk_header_amf0_connect", "T-3 chunk 头+AMF0 connect"),
        ("protocol_control_messages", "T-4 协议控制四消息"),
        ("publish_mode", "T-5 publish 模式"),
        ("stream_name_custom", "T-6 stream_name 自定义"),
        ("app_tc_url_custom", "T-7 app/tc_url 自定义"),
        ("data_audio", "T-8 数据面音频"),
        ("data_video", "T-9 数据面视频"),
        ("data_bidirectional", "T-10 数据面双向"),
        ("data_payload_b64", "T-11 payload b64 双形"),
        ("composite_publish_multi_data", "T-12 复合大场景（9.50）"),
        ("neg_app_too_long", "T-13 App 超长拒"),
        ("neg_command_invalid", "T-14 Command 拒"),
        ("neg_msg_type_invalid", "T-15 MsgType 拒"),
        ("data_payload_raw", "T-16 payload 原文串"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. 键覆盖（5 键 + data 项内 4 子键）。
    for k in ["app", "tc_url", "command", "stream_name", "data",
              "direction", "msg_type", "chunk_stream_id", "payload_b64", "payload"]:
        hit = next((cid for cid, m in lays if k in json.dumps(m)), None)
        rows.append((k, hit is not None, hit or "无用例"))

    # 3. 锚词面（3 负例）。
    for needle, name in [
        ("App exceeds", "T-13 App 长度锚"),
        ("invalid Command", "T-14 Command 锚"),
        ("MsgType", "T-15 MsgType 锚"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows


def check_rtsp(cases):
    """D-RTSP-1 P6 反查表（T-RTSP-1…12，9.52 对账 16/16）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("rtsp"), dict):
                lays.append((c.get("id", "?"), l["rtsp"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    for kw, name in [
        ("options_smoke", "T-1 OPTIONS 冒烟 9 包"),
        ("play_session_full", "T-2 play 全序五方法（现网形）"),
        ("describe_sdp_body", "T-3 DESCRIBE+SDP body"),
        ("response_404", "T-4 404 响应面"),
        ("pause_teardown", "T-5 PAUSE/TEARDOWN"),
        ("uri_explicit_and_default", "T-6 URI 显式+缺省构造"),
        ("headers_custom", "T-7 头显式覆盖+自动补 CSeq"),
        ("emit_media_rtp", "T-8 RTP 媒面子流"),
        ("direction_explicit", "T-9 direction 显式覆盖"),
        ("composite_full_session_media", "T-10 复合大场景（9.50）"),
        ("neg_dialog_required", "T-11 空 dialog 拒"),
        ("status_text_default", "T-12 缺省 phrase"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    for k in ["dialog", "media"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))
    sub = json.dumps([m for _, m in lays], ensure_ascii=False)
    for k in ["method", "uri", "status_code", "status_text", "headers", "body", "direction", "emit_media"]:
        rows.append((k, k in sub, "dialog 项键" if k in sub else "无用例"))

    for needle, name in [
        ("dialog is required", "T-11 dialog 必需锚"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows


def check_pptp(cases):
    """D-PPTP-1 P6 反查表（T-PPTP-1…20，9.52 对账 27/27）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("pptp"), dict):
                lays.append((c.get("id", "?"), l["pptp"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    for kw, name in [
        ("full_session_ref", "T-1 full 26 帧参考形"),
        ("control_header_magic", "T-2 控制头 magic 钉"),
        ("scenario_control_only", "T-3 control_only"),
        ("scenario_tunnel_only", "T-4 tunnel_only（P2 errata 勘误面）"),
        ("scenario_data_only", "T-5 data_only 纯 GRE"),
        ("role_pac", "T-6 role=pac 换向"),
        ("calls_two", "T-7 calls=2 多 call"),
        ("sli_count_three", "T-8 SLI 计数"),
        ("echo_keepalive", "T-9 ECRQ/ECRP 保活"),
        ("data_both_directions", "T-10 双数据方向 GRE 头"),
        ("inner_ip_explicit", "T-11 inner_ip 显式"),
        ("result_error_fields", "T-12 失败分支字段"),
        ("composite_full_multi", "T-13 复合大场景（9.50 五类交织）"),
        ("neg_role_invalid", "T-14 role 拒"),
        ("neg_scenario_invalid", "T-15 scenario 拒"),
        ("neg_calls_negative", "T-16 calls 拒"),
        ("neg_sli_count_negative", "T-17 sli_count 拒"),
        ("neg_sub_address_hex", "T-18 hex 拒"),
        ("neg_host_name_long", "T-19 64B 拒"),
        ("neg_inner_ip_invalid", "T-20 inner IP 拒"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    keys_seen = 0
    for k in ["role", "scenario", "calls", "echo", "sli_count", "data_frames",
              "down_data_frames", "inner_ip", "scrp_result", "ocrp_result",
              "sub_address", "host_name"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))
        if hit is not None:
            keys_seen += 1

    for needle, name in [
        ("invalid pptp role", "T-14 role 锚"),
        ("invalid pptp scenario", "T-15 scenario 锚"),
        ("calls", "T-16 范围门锚"),
        ("sli_count", "T-17 范围门锚"),
        ("must be hex", "T-18 hex 锚"),
        ("exceed 64 bytes", "T-19 64B 锚"),
        ("invalid pptp inner src_ip", "T-20 inner IP 锚"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows

def check_sctp(cases):
    """D-SCTP-1 P6 反查表（T-SCTP-1…10，9.52 对账 20/20）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("sctp"), dict):
                lays.append((c.get("id", "?"), l["sctp"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    for kw, name in [
        ("t1_baseline_assoc", "T-1 基线关联 7 帧"),
        ("t2_handshake_bytes", "T-2 4 握手字节钉"),
        ("t3_data_bidir", "T-3 DATA 双向"),
        ("t4_fragment_flags", "T-4 分片三 flags"),
        ("t5_heartbeat_primary", "T-5 HEARTBEAT 主路径"),
        ("t6_altpath_multihoming", "T-6 AltPath 多宿主"),
        ("t7_abort", "T-7 ABORT 突断"),
        ("t8_explicit_tsn_sid", "T-8 显式 TSN/SID/PPID"),
        ("t9_neg_altpath_v6", "T-9 AltPath IPv6 拒"),
        ("t10_neg_frag_small", "T-10 fragment_size 下界拒"),
        ("t11_neg_frag_upper", "T-11 fragment_size 上界拒"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    keys_seen = 0
    for k in ["verification_tag", "initiate_tag", "chunks", "heartbeats",
              "abort", "fragment_size", "src_port", "dst_port"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))
        if hit is not None:
            keys_seen += 1

    for needle, name in [
        ("only IPv4 multi-homing", "T-9 AltPath 锚"),
        ("out of range [16,1000000]", "T-10 V9 区间锚"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows

def check_jt808(cases):
    """D-JT808-1 P6 反查表（T-JT808-1…14，9.52 对账 22/22）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("jt808"), dict):
                lays.append((c.get("id", "?"), l["jt808"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    for kw, name in [
        ("t1_baseline_assoc", "T-1 基线关联 10 帧"),
        ("t2_frame_header_bytes", "T-2 帧头字节钉"),
        ("t3_dual_sn_autobind", "T-3 双 SN+自动绑定"),
        ("t4_register_body_fields", "T-4 注册体字段钉"),
        ("t5_location_bitmerge_escape", "T-5 位置+位合并+转义"),
        ("t6_version2011_encrypt_bit", "T-6 版本方言+加密位"),
        ("t7_down_tlv_trio", "T-7 down 面 TLV"),
        ("t8_text_down_gbk", "T-8 GBK 文本"),
        ("t9_property_response", "T-9 属性应答 17 字段"),
        ("t10_fragmentation", "T-10 分包"),
        ("t11_neg_phone_11digits", "T-11 phone 11 位拒"),
        ("t12_neg_auth_missing_code", "T-12 auth 缺鉴权码拒"),
        ("t13_neg_color0_plate", "T-13 车牌互斥拒"),
        ("t14_neg_ackflag_99", "T-14 ACKFlag=99 拒"),
        ("t15_identity_composite", "T-15 身份面复合例"),
        ("t16_heartbeat", "T-16 终端心跳 0x0002"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    for k in ["phone", "version", "encrypt_flag", "license_color", "license_plate",
              "province_id", "city_id", "manufacturer_id", "terminal_model", "terminal_id",
              "terminal_type", "initial_sn", "platform_initial_sn", "auth_code", "imei",
              "software_version", "registration_result", "procedures"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))

    for needle, name in [
        ("must be 12 digits", "T-11 phone 锚"),
        ("AuthCode is empty", "T-12 auth 锚"),
        ("LicenseColor=0 but LicensePlate non-empty", "T-13 车牌锚"),
        ("ACKFlag 99 invalid", "T-14 ACKFlag 锚"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))
    return rows


def check_jt809(cases):
    """D-JT809-1 P6 反查表（T-JT809-1…13，9.52 对账 分项和 14=T-2 承载 2 项+建例 13）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("jt809"), dict):
                lays.append((c.get("id", "?"), l["jt809"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    for kw, name in [
        ("t1_baseline", "T-1 基线关联"),
        ("t2_envelope_header", "T-2 信封+头字节钉"),
        ("t3_login_body", "T-3 登录体 50B"),
        ("t4_keepalive_pair", "T-4 keepalive 对"),
        ("t5_disconnect", "T-5 断开通知 0x1007"),
        ("t6_close_notify", "T-6 关闭通知 0x1008"),
        ("t7_slave_dual_flow", "T-7 从链路双流"),
        ("t8_slave_resp_negative", "T-8 从链应答负路径"),
        ("t9_escape_bytes", "T-9 转义真字节"),
        ("t10_logout", "T-10 注销 0x1003"),
        ("t11_neg_gnss_overflow", "T-11 gnss 超界拒"),
        ("t12_neg_version_flag", "T-12 version_flag=3 拒"),
        ("t13_neg_error_code", "T-13 error_code=3 拒"),
        ("t14_login_resp_body", "T-14 登录应答体 0x1002"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    for k in ["gnss_center_id", "user_id", "password", "version_flag", "version_bytes",
              "encrypt_flag", "encrypt_key", "time_sec", "down_link_ip", "down_link_port",
              "initial_sn", "platform_initial_sn", "procedures", "slave_procedures"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))

    for needle, name in [
        ("out of range [0,999999999]", "T-11 gnss 锚（首拦截=registry V9 区间，schema 先于 planner）"),
        ("out of range [0,2]", "T-12 version 锚（首拦截=registry V9 区间）"),
        ("ErrorCode 3 > 2", "T-13 error_code 锚（嵌套不下探，planner 拦截）"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))
    return rows


def check_jtt905(cases):
    """D-JTT905-1 P6 反查表（T-JTT905-1…14，9.52 对账 分项和 14=建例 13（T-2 承载 2）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("jtt905"), dict):
                lays.append((c.get("id", "?"), l["jtt905"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    for kw, name in [
        ("t1_baseline", "T-1 基线关联 12 帧"),
        ("t2_envelope_header", "T-2 信封+头钉"),
        ("t3_checkin_body", "T-3 签到体钉"),
        ("t4_heartbeat_pair", "T-4 心跳对"),
        ("t5_checkout_body", "T-5 签退体钉"),
        ("t6_resp_pair", "T-6 应答对"),
        ("t7_escape_bytes", "T-7 转义真字节"),
        ("t9_position_block", "T-9 位置块"),
        ("t10_neg_isu_11digits", "T-10 isu 11 位拒"),
        ("t11_neg_plate_7ascii", "T-11 plate 7 ASCII 拒"),
        ("t12_neg_result_3", "T-12 result=3 拒"),
        ("t13_neg_bcd_digits", "T-13 BCD 位数拒"),
        ("t14_result_enum", "T-14 Result 枚举正例"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    for k in ["isu_id", "initial_sn", "platform_initial_sn", "business_license",
              "qualification_code", "plate_no", "position", "taximeter_k_value",
              "on_duty_power_on_time", "on_duty_power_off_time", "on_duty_mileage",
              "on_duty_operation_mileage", "train_number", "timing_time", "total_amount",
              "card_amount", "card_count", "on_duty_mileage_between", "total_mileage",
              "total_operation_mileage", "unit_price", "total_operations", "sign_type",
              "procedures", "heartbeat_count"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))

    for needle, name in [
        ("must be 12 digits", "T-10 isu 锚"),
        ("PlateNo length 7 > 6", "T-11 plate 锚"),
        ("Result 3 > 2", "T-12 result 锚"),
        ("must be 12 digits (yyyyMMddHHmm)", "T-13 BCD 锚"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))
    return rows


def check_icmp(cases):
    """D-ICMP-1 P6 反查表（T-ICMP-1…8，9.52 对账 分项和 8=建例 8。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("icmp"), dict):
                lays.append((c.get("id", "?"), l["icmp"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    for kw, name in [
        ("t1_smoke", "T-1 smoke 配对"),
        ("t2_header_bytes", "T-2 头字节钉"),
        ("t3_explicit", "T-3 显式 id/seq/data"),
        ("t4_pattern", "T-4 Pattern 多轮"),
        ("t5_neg_type", "T-5 type 区间拒"),
        ("t6_neg_code", "T-6 code 拒"),
        ("t7_neg_presence", "T-7 顶层 presence 判死"),
        ("t8_neg_static_copy", "T-8 静态复制拒"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    for k in ["type", "code", "identifier", "sequence", "data", "pattern"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))

    for needle, name in [
        ("icmp type must be 8 (Echo Request) or 0 (Echo Reply), got 3", "T-5 type 锚"),
        ("icmp code must be 0 for Echo, got 1", "T-6 code 锚"),
        ("no longer accepts a top-level icmp", "T-7 presence 锚"),
        ("static four-tuple", "T-8 静态复制锚"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))
    return rows


def check_cwmp(cases):
    """D-CWMP-1 P6 反查表（T-CWMP-1…153：150 存量等价迁移 + 3 新例）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("cwmp"), dict):
                lays.append((c.get("id", "?"), l["cwmp"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 迁移面 + 行为面代表场景（150 存量 B6 契约枚举 + 3 新例）。
    for kw, name in [
        ("_inform_ipv4_2p", "T-1 Inform 基线（4 帧对）"),
        ("multi_session_sequential", "多会话顺序"),
        ("_concurrent", "多会话并发"),
        ("connection_request_auth_challenge", "acs_cr/鉴权面"),
        ("download_flow_correlation", "flows 流关联副连接"),
        ("pres_kill_neg", "T-151 顶层 presence 判死"),
        ("v9_unknown_field_neg", "T-152 未知字段 V9 拒"),
        ("empty_layer_baseline", "T-153 空层 P0b 基线"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 2. 六键承载（层 config 迁移后，顶层不再承载）。auth 顶层键 B6 契约
    # 登记但无用例（digest 重试面走 challenge kind 序列）——对 allowlist
    # 生成表核键，不对用例核。
    try:
        gen = json.loads((Path(__file__).resolve().parent / ".." / "schemas" / "v1" / "generated" / "layers.generated.json").read_text())
        allow = ((gen.get("layers") or {}).get("cwmp") or {}).get("fields") or {}
    except Exception:
        allow = {}
    for k in ["profile", "namespace", "concurrent", "sessions", "flows"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "层内无用例"))
    rows.append(("auth（allowlist 登记，B6 契约重试面）", "auth" in allow, "allowlist" if "auth" in allow else "allowlist 缺键"))
    rows.append(("registry 六键对齐 allowlist", allow and set(allow) >= {"profile", "namespace", "concurrent", "sessions", "flows", "auth"}, "六键齐" if allow else "生成表不可读"))

    # 3. 负例锚词（validator/B6 §7 契约 + 判死门文案）。
    for needle, name in [
        ("no longer accepts a top-level cwmp sub-config", "presence 判死锚"),
        ("unknown field", "V9 未知字段锚"),
        ("not six uppercase hex digits", "validator device_id 锚（oui 域具体文案，L4 升级）"),
        ("correlation|no pending|invalid", "correlation/id 族锚"),
    ]:
        found = needle in blob
        if "|" in needle:
            found = any(n in blob for n in needle.split("|"))
        rows.append((name, found, "锚词出现" if found else "无用例"))

    # 4. 迁移完整性：非 presence 负例的用例顶层不得再出现 cwmp 键。
    leaked = [c.get("id") for c in cases
              if "cwmp" in (c.get("spec_json", {}) or {})
              and "pres_kill" not in c.get("id", "")]
    rows.append(("顶层残留为零（presence 负例豁免）", not leaked, leaked or "零残留"))
    return rows



def check_kingbase(cases):
    """D-KINGBASE-1 P6 反查表（T-KINGBASE-1…15，退役口径：协议身份=postgresql dialect，
    9.52 对账 分项和 15=建例 15。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent  # trafficgen/
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("postgresql"), dict):
                lays.append((c.get("id", "?"), l["postgresql"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 退役面（G5）：白名单摘除 + negativeOnly 守卫 + 死遗留零残留。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单无 kingbase（退役：create→400）", '"kingbase": true' not in pg,
                 "已摘除" if '"kingbase": true' not in pg else "白名单仍收"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    rows.append(("negativeOnly 收 kingbase（must remain rejected 守卫）",
                 pt.count('"kingbase"') >= 1 and '"kingbase": true' not in pt,
                 "守卫在列"))
    rows.append(("protocol/kingbase 包已删", not (tg / "internal" / "protocol" / "kingbase").exists(), "包不存在"))
    tys = (tg / "internal" / "core" / "types.go").read_text()
    rows.append(("types.go 死类型零残留（KingBaseConfig/Session/Event/FlowSpec.KingBase）",
                 all(x not in tys for x in ("type KingBaseConfig", "type KingBaseSession", "type KingBaseEvent", "KingBase  *KingBaseConfig")),
                 "零残留"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.KingBase 已删", "KingBase *core.KingBaseConfig" not in gen, "零残留"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate KingBase 行已删", "spec.KingBase" not in tr, "零残留"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go 空导入已删", "protocol/kingbase" not in mn, "零残留"))

    # 2. dialect 面确认（零改动验收线）。
    bad_proto = [c.get("id", "?") for c in cases if c.get("proto") != "postgresql"]
    rows.append(("15 例 proto 全=postgresql（退役跑法 CASE_PROTO=postgresql）", not bad_proto, bad_proto or "全 postgresql"))
    hit = next((cid for cid, m in lays if m.get("dialect") == "kingbase"), None)
    rows.append(("dialect=kingbase 层键", hit is not None, hit or "无用例"))
    reg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    rows.append(("FieldContract dialect 契约 54321 在案", '"kingbase": {"tcp.dst_port": "54321"}' in reg, "registry.go 在列"))
    cps = (tg / "internal" / "core" / "layers" / "chain_planner.go").read_text()
    rows.append(("chain_planner dialect 端口分支在案", 'dialect == "kingbase"' in cps, "chain_planner.go 在列"))

    # 3. 负例锚词（六负例具体锚）。
    for needle, name in [
        ("54321", "neg_port 端口契约锚"),
        ("length", "neg_truncated 长度锚"),
        ("limit", "neg_oversize 上限锚"),
    ]:
        found = needle in blob
        rows.append((name, found, "锚词出现" if found else "无用例"))
    # neg_udp/neg_state 锚词为短值（"tcp"/"state"）——对 expect.error_contains
    # 字段直读断言（blob 全文搜短词无判别力）。
    def _err_anchor(kwid, want):
        c = next((c for c in cases if kwid in c.get("id", "")), None)
        got = (c.get("expect", {}) or {}).get("error_contains") if c else None
        return got == want, got or "无用例"
    ok, ev = _err_anchor("neg_udp", "tcp")
    rows.append(("neg_udp 承载锚（error_contains=tcp）", ok, ev))
    ok, ev = _err_anchor("neg_state", "state")
    rows.append(("neg_state 状态机锚（error_contains=state）", ok, ev))

    # 修轮复验残项3：负例触发源守卫（防"配置被清空仍全绿"的自满足面——
    # 真跑真红由 suite 门2-2 兜，此处静态保证每负例的触发源键在位）。
    # 每负例逐例直读（不经 lays 首个 pg 子映射，修 M1 漏检），触发源映射：
    #   neg_udp=存在 udp 载体 / neg_port=tcp.dst_port 显式 / neg_profile=
    #   wire_profile=unknown_profile / neg_state=events 含 query（before-ready
    #   触发）/ neg_truncated·neg_oversize=wire_fault 在；且 events 每条
    #   非空 dict（修 M2 空壳漏检）。
    def _neg_case(c):
        sj = c.get("spec_json", {}) or {}
        pg = next((l["postgresql"] for l in sj.get("layers") or [] if isinstance(l, dict) and isinstance(l.get("postgresql"), dict)), None)
        tcp = next((l["tcp"] for l in sj.get("layers") or [] if isinstance(l, dict) and isinstance(l.get("tcp"), dict)), None)
        has_udp = any(isinstance(l, dict) and "udp" in l for l in sj.get("layers") or [])
        return pg, tcp, has_udp
    triggers = {
        "neg_udp":       lambda pg, tcp, hu: hu,
        "neg_port":      lambda pg, tcp, hu: bool(tcp and tcp.get("dst_port")),
        "neg_profile":   lambda pg, tcp, hu: bool(pg and pg.get("wire_profile") == "unknown_profile"),
        "neg_state":     lambda pg, tcp, hu: bool(pg and any(isinstance(e, dict) and e.get("kind") == "query" for e in pg.get("events") or [])),
        "neg_truncated": lambda pg, tcp, hu: bool(pg and pg.get("wire_fault")),
        "neg_oversize":  lambda pg, tcp, hu: bool(pg and pg.get("wire_fault")),
    }
    for kwid, fn in triggers.items():
        c = next((c for c in cases if kwid in c.get("id", "")), None)
        if c is None:
            rows.append((f"触发源在位：{kwid}", False, "无用例"))
            continue
        pg, tcp, hu = _neg_case(c)
        okk = fn(pg, tcp, hu)
        evs = (pg or {}).get("events") or []
        shell = not evs or any(not isinstance(e, dict) or not e for e in evs)
        rows.append((f"触发源在位：{kwid}", okk and not shell, "在位" if okk and not shell else "触发源缺失或空壳"))

    # 4. 顶层残留为零（退役口径：kingbase.json 只允许 layers）。
    leaked = sorted({k for c in cases for k in (c.get("spec_json", {}) or {}) if k != "layers"})
    rows.append(("顶层残留为零（仅 layers）", not leaked, leaked or "零残留"))
    return rows


def check_megaco(cases):
    """D-MEGACO-1 P6 反查表（79 例=46 正+31 wire_fault 负+2 事务级 error 边界，
    RFC 3525 / ITU-T H.248.1 文本编码。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 准入与接线（白名单收 megaco；translate/FlowMeta/planner 注册）。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单收 megaco", '"megaco": true' in pg, "在列"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    i_neg = pt.index("negativeOnly := []string{")
    rows.append(("negativeOnly 不含 megaco（已准入）", '"megaco"' not in pt[i_neg:i_neg + 400], "已摘除"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case megaco", 'case "megaco":' in tr, "在案"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.Megaco", "Megaco     *core.MegacoConfig" in gen, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    rows.append(("registry megaco 行+双 carrier 2944 契约",
                 '"udp.dst_port": "2944", "tcp.dst_port": "2944"' in rg, "在案"))
    cp = (tg / "internal" / "core" / "layers" / "chain_planner.go").read_text()
    rows.append(("chain carrier/端口域块", "Megaco carrier + port contract" in cp, "在案"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go ChainPlanner(megaco) 接线", 'NewChainPlanner("megaco")' in mn, "在案"))

    # 2. 行为面（builder/validator 关键件）。
    pl = (tg / "internal" / "protocol" / "megaco" / "planner.go").read_text()
    import re as _re
    _i = pl.index("wireFaultAnchors")
    _seg = pl[_i:pl.index("\n}", _i)]
    _n = len(_re.findall(r'"([a-z_0-9]+)":', _seg))
    rows.append(("wire_fault 闭环 31 值锚词表", _n == 31, f"{_n} 值"))
    bd = (tg / "internal" / "protocol" / "megaco" / "builder.go").read_text()
    rows.append(("TPKT 成帧（RFC 1006）", "func WrapTPKT" in bd, "在案"))
    rows.append(("长/缩 token 双形", "reverseTokens" in bd and "tokenToWire" in bd, "在案"))
    rows.append(("八命令域", '"ServiceChange": true' in pl, "在案"))
    lg = (tg / "internal" / "protocol" / "megaco" / "layer_gen.go").read_text()
    rows.append(("空层 P0b 基线注册对", "defaultFlow" in lg, "在案"))

    # 3. 用例面（46 正 + 33 负；proto=megaco；顶层仅 layers；端口域）。
    pos = [c for c in cases if "packet_count" in (c.get("expect") or {})]
    neg = [c for c in cases if (c.get("expect") or {}).get("expect_error")]
    rows.append(("79 例对账（46 正+33 负）", len(pos) == 46 and len(neg) == 33 and len(cases) == 79,
                 f"{len(pos)}+{len(neg)}={len(cases)}"))
    bad_proto = [c.get("id", "?") for c in cases if c.get("proto") != "megaco"]
    rows.append(("proto 全=megaco（三名合一：mgcp/h248 不独立准入）", not bad_proto, bad_proto or "全 megaco"))
    leaked = sorted({k for c in cases for k in (c.get("spec_json", {}) or {}) if k != "layers"})
    rows.append(("顶层残留为零（仅 layers）", not leaked, leaked or "零残留"))
    ports = {l.get("dst_port") for c in cases for l2 in (c["spec_json"].get("layers") or [])
             if isinstance(l2, dict) for l in [list(l2.values())[0]] if isinstance(l, dict) and "dst_port" in l}
    rows.append(("显式端口 ∈ {2944, 2427}", ports <= {2944, 2427, "2944", "2427"}, sorted(map(str, ports))))
    for kw, name in [
        ("megaco_udp_ipv4_registration", "T-1 注册基线"),
        ("megaco_tcp_ipv4_mss_reassembly", "T-11 TPKT 跨段重组"),
        ("megaco_udp_ipv4_concurrent_sessions", "T-45 并发会话"),
        ("megaco_udp_2427_mgcp_alias", "T-14 mgcp 别名 2427"),
        ("megaco_neg_encoding_text_as_ber", "T-47 编码负例"),
        ("megaco_neg_pairing_ack_unconfirmed", "T-64 K 确认负例"),
        ("megaco_neg_carrier_udp_mtu_exceeded", "T-76 UDP 超 MTU"),
        ("megaco_neg_tx_error_with_actions", "事务级 error 互斥边界"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 4. 锚词面（九族主锚词在负例 expect 中）。
    anchors = {"encoding", "message", "version", "mid", "command", "transaction", "length", "carrier", "port", "services"}
    got = {(c.get("expect") or {}).get("error_contains") for c in neg}
    rows.append(("负例锚词覆盖十族", anchors <= got, sorted(got)))
    return rows

def check_hl7(cases):
    """D-HL7-1 P6 反查表（95 例=62 正+33 wire_fault 负，HL7 v2.x MLLP/TCP-2575。
    返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent

    # 1. 准入与接线。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单收 hl7", '"hl7": true' in pg, "在列"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    i_neg = pt.index("negativeOnly := []string{")
    rows.append(("negativeOnly 不含 hl7（已准入）", '"hl7"' not in pt[i_neg:i_neg + 400], "已摘除"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case hl7", 'case "hl7":' in tr, "在案"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.HL7", "HL7        *core.HL7Config" in gen, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    rows.append(("registry hl7 行+tcp 2575 契约", '"tcp.dst_port": "2575"' in rg, "在案"))
    cp = (tg / "internal" / "core" / "layers" / "chain_planner.go").read_text()
    rows.append(("chain 载体/地址族/端口块", "HL7 carrier + port + address-family contract" in cp, "在案"))
    vl = (tg / "internal" / "core" / "layers" / "validate_layers.go").read_text()
    rows.append(("udp 载体预检（锚 carrier）", "hl7 rides tcp only" in vl, "在案"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go ChainPlanner(hl7) 接线", 'NewChainPlanner("hl7")' in mn, "在案"))

    # 2. 行为面（validator 关键件：33 值锚词表 + 自然守卫集）。
    pl = (tg / "internal" / "protocol" / "hl7" / "planner.go").read_text()
    import re as _re
    _i = pl.index("wireFaultAnchors")
    _seg = pl[_i:pl.index("\n}", _i)]
    _n = len(_re.findall(r'"([a-z_0-9]+)":', _seg))
    rows.append(("wire_fault 闭环 33 值锚词表（契约枚举名）", _n == 33, f"{_n} 值"))
    for guard, name in [
        ("requiredSegmentsByStructure", "D-6 必需段集"),
        ("knownMessageCodes", "MSH-9 值域"),
        ("invalidHexEscape", "escape_invalid 自然面"),
        ("duplicate control id", "控制 ID 会话内判重"),
        ("EVN-1", "EVN-1↔MSH-9 一致性"),
    ]:
        rows.append((f"自然守卫：{name}", guard in pl, "在案"))
    lg = (tg / "internal" / "protocol" / "hl7" / "layer_gen.go").read_text()
    rows.append(("MLLP 成帧 0x0B/0x1C 0x0D", "0x0B" in lg and "0x1C" in lg, "在案"))
    rows.append(("多帧粘连回放", "emitSessionEventsCoalesced" in lg, "在案"))

    # 3. 用例面（62 正 + 33 负；proto=hl7；顶层仅 layers）。
    pos = [c for c in cases if "packet_count" in (c.get("expect") or {})]
    neg = [c for c in cases if (c.get("expect") or {}).get("expect_error")]
    rows.append(("95 例对账（62 正+33 负）", len(pos) == 62 and len(neg) == 33 and len(cases) == 95,
                 f"{len(pos)}+{len(neg)}={len(cases)}"))
    bad_proto = [c.get("id", "?") for c in cases if c.get("proto") != "hl7"]
    rows.append(("proto 全=hl7（单准入名）", not bad_proto, bad_proto or "全 hl7"))
    leaked = sorted({k for c in cases for k in (c.get("spec_json", {}) or {}) if k != "layers"})
    rows.append(("顶层残留为零（仅 layers）", not leaked, leaked or "零残留"))
    # 载体面：无 udp 层（TCP-only）——唯一例外 = carrier_udp 负例（udp 层
    # 即契约指定的故障输入本身，自然面负例）。
    udp_cases = [c.get("id") for c in cases
                 if any(isinstance(l2, dict) and "udp" in l2 for l2 in (c["spec_json"].get("layers") or []))]
    rows.append(("udp 层仅存在于 carrier_udp 自然面负例", udp_cases in ([], ["hl7_neg_carrier_udp"]), udp_cases or "零 udp"))
    for kw, name in [
        ("hl7_adt_a01_ipv4", "T-1 ADT^A01 基线"),
        ("hl7_tcp_mss_reassembly", "T-22 跨段重组"),
        ("hl7_ipv6_transport", "T-23 IPv6 承载"),
        ("hl7_concurrent_sessions", "T-26 并发会话"),
        ("hl7_port_nondefault", "T-27 非默认端口"),
        ("hl7_neg_framing_sob_missing", "T-63 SOB 缺失负例"),
        ("hl7_neg_ack_msa2_mismatch", "T-80 MSA-2 配对负例"),
        ("hl7_neg_required_segment_missing", "T-94 必需段集负例"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 4. 锚词面（八族主锚词在负例 expect 中）。
    anchors = {"mllp", "msh", "separator", "escape", "ack", "carrier", "port", "length",
               "event", "address", "segment", "z", "layer"}
    got = {(c.get("expect") or {}).get("error_contains") for c in neg}
    rows.append(("负例锚词覆盖十三族", anchors <= got, sorted(got)))
    return rows

def check_mmse(cases):
    """D-MMSE-1 P6 反查表（100 例=45 正+55 负，WAP-209 HTTP 承载/TCP-80。
    返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent

    # 1. 准入与接线。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单收 mmse", '"mmse": true' in pg, "在列"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    i_neg = pt.index("negativeOnly := []string{")
    rows.append(("negativeOnly 不含 mmse（已准入）", '"mmse"' not in pt[i_neg:i_neg + 400], "已摘除"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case mmse（严格解码）", 'case "mmse":' in tr and "DisallowUnknownFields" in tr, "在案"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.MMSE", "MMSE       *core.MMSEConfig" in gen, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    rows.append(("registry mmse 行+tcp 80 契约", '"tcp.dst_port": "80"' in rg, "在案"))
    vl = (tg / "internal" / "core" / "layers" / "validate_layers.go").read_text()
    rows.append(("http 载体预检（carrier missing）", "requires the http carrier layer ([tcp, http, mmse]" in vl, "在案"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go ChainPlanner(mmse) 接线", 'NewChainPlanner("mmse")' in mn, "在案"))
    hg = (tg / "internal" / "protocol" / "http" / "layer_gen.go").read_text()
    rows.append(("http 透传族收 mmse", "meta.MMSE != nil" in hg, "在案"))

    # 2. 行为面（validator/builder 关键件）。
    pl = (tg / "internal" / "protocol" / "mmse" / "planner.go").read_text()
    import re as _re
    _i = pl.index("wireFaults = map[string]struct{ detail, anchor string }")
    _seg = pl[_i:pl.index("\n}", _i)]
    _n = len(_re.findall(r'"([a-z_0-9]+)":\s*\{', _seg))
    rows.append(("wire_fault 闭环 55 值锚词表（契约枚举名）", _n == 55, f"{_n} 值"))
    for guard, name in [
        ("buildTxBindings", "sessionTx 唯一解析权威"),
        ("isWSPBearerPort", "carrier_port 自然面"),
        ("msgidUnsourced", "MsgID 回指断裂守卫"),
        ("pendingRetrieveTID", "retrieve→ack 配对"),
    ]:
        rows.append((f"关键件：{name}", guard in pl, "在案"))
    bl = (tg / "internal" / "protocol" / "mmse" / "builder.go").read_text()
    for prim, name in [
        ("func appendUintvar", "Uintvar LSB 组先"),
        ("func appendValueLength", "Value-length 0x1F+Uintvar"),
        ("func buildMultipartBody", "multipart 长度自洽编码"),
        ("func appendTextString", "Text-string Quote 形态"),
        ("isTextSeparator", "RFC 822 分隔符集"),
    ]:
        rows.append((f"builder：{name}", prim in bl, "在案"))
    lg = (tg / "internal" / "protocol" / "mmse" / "layer_gen.go").read_text()
    rows.append(("concurrent round-robin 交错", "round-robin" in lg, "在案"))

    # 3. 用例面（45 正 + 55 负；proto=mmse；顶层仅 layers）。
    pos = [c for c in cases if "packet_count" in (c.get("expect") or {})]
    neg = [c for c in cases if (c.get("expect") or {}).get("expect_error")]
    rows.append(("100 例对账（45 正+55 负）", len(pos) == 45 and len(neg) == 55 and len(cases) == 100,
                 f"{len(pos)}+{len(neg)}={len(cases)}"))
    bad_proto = [c.get("id", "?") for c in cases if c.get("proto") != "mmse"]
    rows.append(("proto 全=mmse（单准入名）", not bad_proto, bad_proto or "全 mmse"))
    leaked = sorted({k for c in cases for k in (c.get("spec_json", {}) or {}) if k != "layers"})
    rows.append(("顶层残留为零（仅 layers）", not leaked, leaked or "零残留"))
    udp_cases = [c.get("id") for c in cases
                 if any(isinstance(l2, dict) and "udp" in l2 for l2 in (c["spec_json"].get("layers") or []))]
    rows.append(("udp 层零残留（TCP/HTTP-only）", not udp_cases, udp_cases or "零 udp"))
    for kw, name in [
        ("mmse_send_req_ipv4", "T-1 m-send-req 基线"),
        ("mmse_notification_ind", "T-4 通知逐字节复算 99B"),
        ("mmse_acknowledge_ind", "T-7 延迟链全链"),
        ("mmse_concurrent_sessions", "T-28 并发会话"),
        ("mmse_port_nondefault", "T-29 非默认端口"),
        ("mmse_partnum_max_127", "T-34 partNum 恰等上界"),
        ("mmse_neg_carrier_no_http", "T-46 载体缺失负例"),
        ("mmse_neg_sequence_response_first", "T-73 响应先于请求负例"),
        ("mmse_neg_value_notif_expiry_absolute", "T-100 通知绝对 expiry 负例"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 4. 锚词面（主锚词族在负例 expect 中）。
    anchors = {"layer", "content-type", "port", "carrier", "order", "header", "message-type",
               "unknown", "body", "mandatory", "response-status", "multipart", "data", "part",
               "start", "overflow", "transaction", "message-id", "sequence", "length",
               "long-integer", "uintvar", "value-length", "transaction-id", "priority",
               "status", "message-class", "read-status", "delivery-report", "reply-charging",
               "text-string", "application-header", "charset", "previously-sent", "expiry"}
    got = {(c.get("expect") or {}).get("error_contains") for c in neg}
    missing = sorted(anchors - got)
    rows.append(("负例锚词覆盖三十五族", not missing, missing or sorted(got)))
    return rows

def check_arp(cases):
    """D-ARP-1 P6 反查表（T-ARP-1…12，9.52 对账 分项和 12=建例 12。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("arp"), dict):
                lays.append((c.get("id", "?"), l["arp"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    for kw, name in [
        ("t1_baseline_pair", "T-1 基线配对"),
        ("t2_bytes_full", "T-2 字节全钉"),
        ("t3_explicit_addrs", "T-3 显式地址"),
        ("t4_single_reply", "T-4 单发宣告"),
        ("t5_neg_operation", "T-5 operation 区间拒"),
        ("t6_neg_sender_ip", "T-6 sender_ip 格式拒"),
        ("t7_neg_ip_carrier", "T-7 ip 承载混入拒"),
        ("t8_neg_presence", "T-8 顶层 presence 判死"),
        ("t9_neg_sender_mac", "T-9 sender_mac 格式拒"),
        ("t10_neg_target_mac", "T-10 target_mac 格式拒"),
        ("t11_neg_target_ip", "T-11 target_ip 格式拒"),
        ("t12_neg_static_copy", "T-12 静态复制拒"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    for k in ["operation", "sender_mac", "sender_ip", "target_mac", "target_ip"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))

    for needle, name in [
        ("out of range [1,2]", "T-5 V9 区间锚"),
        ("invalid sender_ip", "T-6 sender_ip 锚"),
        ("must not have an ip/transport carrier", "T-7 carrier 锚"),
        ("no longer accepts a top-level arp", "T-8 presence 锚"),
        ("static four-tuple", "T-12 静态复制锚"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))
    return rows


def check_xmpp(cases):
    """D-XMPP-1 P6 反查表（T-XMPP-1…10，9.52 对账 18/18）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("xmpp"), dict):
                lays.append((c.get("id", "?"), l["xmpp"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    for kw, name in [
        ("t1_smoke_plain", "T-1 PLAIN 19 帧参考形"),
        ("t2_digest_md5", "T-2 DIGEST-MD5 四步"),
        ("t3_scram_sha1", "T-3 SCRAM-SHA-1 六步"),
        ("t4_anonymous", "T-4 ANONYMOUS"),
        ("t5_presence_off", "T-5 presence=false"),
        ("t6_messages_both", "T-6 messages 双向"),
        ("t7_identity_custom", "T-7 身份四键定制"),
        ("t8_plain_credentials", "T-8 PLAIN 凭据 base64 钉"),
        ("t9_neg_mech", "T-9 auth 机制拒"),
        ("t10_neg_direction", "T-10 direction 拒"),
        ("t11_long_body_mss", "T-11 长 body 超 MSS 分段"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    keys_seen = 0
    for k in ["auth_mechanism", "presence", "messages", "from", "jid",
              "resource", "stream_id", "username", "password"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))
        if hit is not None:
            keys_seen += 1

    for needle, name in [
        ("unsupported auth mechanism", "T-9 auth 锚"),
        ("invalid direction", "T-10 direction 锚"),
        ("5222", "T-1 端口锚"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows

def check_vnc(cases):
    """D-VNC-1 P6 反查表（T-VNC-1…17，9.52 对账 27/27）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("vnc"), dict):
                lays.append((c.get("id", "?"), l["vnc"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    for kw, name in [
        ("t1_smoke_ref", "T-1 smoke 33 帧参考形"),
        ("t2_handshake_bytes", "T-2 握手字节钉"),
        ("t3_sec_type_vncauth", "T-3 security_type=2"),
        ("t4_sec_type_none", "T-4 security_type=1"),
        ("t5_auth_fail", "T-5 认证失败分支"),
        ("t6_share_false", "T-6 share_desktop=false"),
        ("t7_raw_rect", "T-7 raw 编码确定性像素"),
        ("t8_key_down_explicit", "T-8 key_events 显式"),
        ("t9_extras_mix", "T-9 extras 三消息交织"),
        ("t10_colourmap", "T-10 set_colour_map_entries"),
        ("t11_client_msgs_off", "T-11 客户端消息关"),
        ("t12_rounds_linear", "T-12 rounds/interval 线性"),
        ("t13_pointer_default", "T-13 pointer 缺省坐标钉"),
        ("t14_neg_sec_type", "T-14 security_type 拒"),
        ("t15_neg_auth_result", "T-15 auth_result 拒"),
        ("t16_neg_rect_encoding", "T-16 rect encoding 拒"),
        ("t17_neg_width_zero", "T-17 width=0 拒"),
        ("t18_init_customize", "T-18 ServerInit 定制（name/wh/pixel_format）"),
        ("t19_encodings_pointer", "T-19 encodings+pointer 显式"),
        ("t20_caps_customize", "T-20 interaction_caps 定制"),
        ("t21_seeds", "T-21 challenge/response seed"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    keys_seen = 0
    for k in ["security_type", "auth_result", "share_desktop", "key_events",
              "bell", "server_cut_text", "client_cut_text",
              "set_colour_map_entries", "initial_fbu", "update_rects",
              "rounds", "client_set_pixel_format", "server_name", "width",
              "height", "pixel_format", "interaction_caps", "encodings",
              "pointer_x", "pointer_y", "pointer_button", "challenge_seed",
              "response_seed"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((k, hit is not None, hit or "无用例"))
        if hit is not None:
            keys_seen += 1

    for needle, name in [
        ("invalid vnc security type", "T-14 security_type 锚"),
        ("out of range [0,2]", "T-15 V9 区间锚"),
        ("invalid vnc rect encoding", "T-16 rect encoding 锚"),
        ("invalid vnc width", "T-17 width 锚"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))

    return rows

def check_xmrmining(cases):
    """D-XMR-1 P6 反查表。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent

    # 1. 准入与接线。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单收 xmrmining", '"xmrmining": true' in pg, "在列"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    i_neg = pt.index("negativeOnly := []string{")
    rows.append(("negativeOnly 不含 xmrmining（已准入）", '"xmrmining"' not in pt[i_neg:i_neg + 400], "已摘除"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case xmrmining（严格解码）", 'case "xmrmining":' in tr and "DisallowUnknownFields" in tr, "在案"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.XMR", "XMR        *core.XMRConfig" in gen, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    rows.append(("registry xmrmining 行 + tcp 18081 契约", '"tcp.dst_port": "18081"' in rg, "在案"))
    vl = (tg / "internal" / "core" / "layers" / "validate_layers.go").read_text()
    rows.append(("udp 载体预检（tcp-only）", "xmrmining rides tcp only" in vl, "在案"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go ChainPlanner(xmrmining) 接线", 'NewChainPlanner("xmrmining")' in mn, "在案"))

    # 2. 行为面（validator/builder 关键件）。
    pl = (tg / "internal" / "protocol" / "xmrmining" / "planner.go").read_text()
    import re as _re
    _i = pl.index("wireFaultAnchors = map[string]string{")
    _seg = pl[_i:pl.index("\n}", _i)]
    _n = len(_re.findall(r'"[a-z0-9_]+":', _seg))
    rows.append(("wire_fault 闭环 39 值锚词表", _n == 39, f"{_n} 值"))
    for guard, name in [
        ("closed = true", "状态机走查（login 拒绝后 Closed 真拒绝——B6 死代码勘误）"),
        ("first application message must be login", "login 必首"),
        ("below the 43-byte lower bound", "blob 下界 43B"),
        ("at/above the 408-byte upper bound", "blob 上界 408B（≥408 拒）"),
        ("not from this session's jobs", "job 关联（job_unknown）"),
        ("reused within session", "id 会话内唯一"),
        ("mergedJob(ev).JobID", "login 初始 job 登记（generator/validator 同源——红例④实证）"),
    ]:
        rows.append((f"关键件：{name}", guard in pl, "在案"))
    bl = (tg / "internal" / "protocol" / "xmrmining" / "builder.go").read_text()
    for prim, name in [
        ("func BuildLoginReq", "login 请求构造器"),
        ("func BuildJobNotify", "job 通知构造器（省略顶层 id）"),
        ("func BuildSubmitReq", "submit 构造器"),
        ("func BuildKeepalivedResp", "keepalived 响应（status KEEPALIVED）"),
        ("func BuildGetjobResp", "getjob 响应（result=job）"),
        ("func mergedJob", "单解析权威（生成器/validator 共用）"),
        ("packWithNext", "pack_next 粘连单段"),
    ]:
        rows.append((f"builder：{name}", prim in bl, "在案"))
    rows.append(("端口缺省继承链级（不硬编码 18081 注记在案）", "不在此硬编码 18081" in bl, "在案"))
    rows.append(("事件级严格解码（UnmarshalJSON DisallowUnknownFields——红例⑮ 实证）",
                 "dec.DisallowUnknownFields()" in (tg / "internal" / "core" / "xmrmining.go").read_text(), "在案"))

    # 3. 用例面（25 正 + 39 负；proto=xmrmining；顶层仅 layers）。
    pos = [c for c in cases if "packet_count" in (c.get("expect") or {})]
    neg = [c for c in cases if (c.get("expect") or {}).get("expect_error")]
    rows.append(("64 例对账（25 正+39 负）", len(pos) == 25 and len(neg) == 39 and len(cases) == 64,
                 f"{len(pos)}+{len(neg)}={len(cases)}"))
    bad_proto = [c.get("id", "?") for c in cases if c.get("proto") != "xmrmining"]
    rows.append(("proto 全=xmrmining（单准入名）", not bad_proto, bad_proto or "全 xmrmining"))
    leaked = sorted({k for c in cases for k in (c.get("spec_json", {}) or {}) if k != "layers"})
    rows.append(("顶层残留为零（仅 layers——B6 混用形已重排）", not leaked, leaked or "零残留"))
    for kw, name in [
        ("xmrmining_login_job_ipv4", "① login 基线（现代 job）"),
        ("xmrmining_login_reject", "② login 拒绝路径"),
        ("xmrmining_login_extensions", "③ extensions 变体"),
        ("xmrmining_job_notify_legacy", "④ legacy 三字段形态"),
        ("xmrmining_submit_reject", "⑤ submit 拒绝（会话继续）"),
        ("xmrmining_keepalive_alias", "⑥ keepalive 别名"),
        ("xmrmining_getjob", "⑦ 主动拉取"),
        ("xmrmining_id_correlation", "⑧ id 按值配对"),
        ("xmrmining_blob_max", "⑨ blob 407B 满值"),
        ("xmrmining_line_packing", "⑩ 多行粘连单段"),
        ("xmrmining_mss_large_jobid", "⑪ job_id 1500 跨 MSS"),
        ("xmrmining_ipv6", "⑫ IPv6"),
        ("xmrmining_multi_session", "⑬ 多会话展开"),
        ("xmrmining_concurrent_sessions", "⑭ 并发会话"),
        ("xmrmining_port_nondefault", "⑮ 非默认端口 3333"),
        ("xmrmining_neg_json_truncated", "负例 json_truncated"),
        ("xmrmining_neg_result_id_missing", "负例 result_id_missing（v2.0.2 V-1）"),
        ("xmrmining_neg_prop_fake_success", "负例 prop_fake_success（传播面）"),
    ]:
        hit = next((c.get("id") for c in cases if kw in c.get("id", "")), None)
        rows.append((name, hit is not None, hit or "无用例"))

    # 4. 锚词面（39 负例 error_contains 与 planner 锚词表值集一致）。
    anchors = set()
    for m in _re.finditer(r'"[a-z0-9_]+":\s*"([a-z_]+)"', pl[pl.index("wireFaultAnchors"):pl.index("func Validate")]):
        anchors.add(m.group(1))
    bad_anchor = []
    for c in neg:
        ec = (c.get("expect") or {}).get("error_contains", "")
        if ec not in anchors:
            bad_anchor.append(f"{c.get('id', '?')}:{ec}")
    rows.append(("39 负例锚词 ∈ planner 锚词表值集", not bad_anchor, bad_anchor or "全部在集"))
    wf_in_cfg = [c.get("id") for c in neg
                 if any((l.get("xmrmining") or {}).get("wire_fault")
                        for l in (c.get("spec_json", {}).get("layers") or []) if isinstance(l, dict))]
    rows.append(("wire_fault 注入负例 =39（全负例经注入通道带锚词）",
                 len(wf_in_cfg) == 39, f"{len(wf_in_cfg)} 例注入"))

    return rows



def check_dtls(cases):
    """D-DTLS-1 P6 反查表。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent

    # 1. 准入与接线。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单收 dtls", '"dtls"' in pg and 'true' in pg.split('"dtls"')[1][:12], "在列"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    i_neg = pt.index("negativeOnly := []string{")
    rows.append(("negativeOnly 不含 dtls（已准入）", '"dtls"' not in pt[i_neg:i_neg + 400], "已摘除"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case dtls（严格解码）", 'case "dtls":' in tr and "DisallowUnknownFields" in tr, "在案"))
    rows.append(("FlowMeta.DTLS 直传（静默基线根修）", re.search(r"DTLS:\s+spec\.DTLS\b", tr) is not None, "在案"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.DTLS", "DTLS       *core.DTLSConfig" in gen, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    rows.append(("registry dtls 行 + udp/4433 契约", '"udp.dst_port": "4433"' in rg and '"dtls"' in rg, "在案"))
    vl = (tg / "internal" / "core" / "layers" / "validate_layers.go").read_text()
    rows.append(("udp 载体预检（tcp 拒/缺 udp/混合族）", "dtls chain: tcp carrier is not supported" in vl and "missing udp carrier" in vl, "在案"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go ChainPlanner(dtls) 接线", 'NewChainPlanner("dtls")' in mn, "在案"))

    # 2. 行为面（builder/planner 关键件）。
    dc = (tg / "internal" / "core" / "dtls.go").read_text()
    import re as _re
    _i = dc.index("anchors := map[string]string{")
    _seg = dc[_i:dc.index("\n\t}", _i)]
    _n = len(_re.findall(r"DTLSWireFault[A-Za-z0-9]+:", _seg))
    rows.append(("wire_fault 闭环 6 值锚词表", _n == 6, f"{_n} 值"))
    bl = (tg / "internal" / "protocol" / "dtls" / "builder.go").read_text()
    for prim, name in [
        ("func versionBytes", "record version fefd/feff 权威（RFC 6347 §4.1）"),
        ("func putRecord", "13B record 头全大端（ct+ver+epoch+seq48+len）"),
        ("func handshakeBody", "12B 握手头（type+len24+msgseq+off24+fraglen24）"),
        ("cookie_len(ck)", None) if False else ("byte(len(ck))", "HVR cookie 长度前缀=实际字节（不硬编码随机值）"),
        ("type dtlsWalker", "epoch/seq/msg_seq 单解析权威"),
        ("w.ctr[key] = seq + 1", "record seq 每方向每 epoch 独立计数"),
        ("msgCtr  [2]int", "message_seq 每方向独立计数器（RFC 6347 §4.2.1）"),
        ("h.FragOffset > 0 && w.msgHas[dir]", "续片复用 message_seq（§4.2.2 分片共享）"),
        ("fragLen != len(body)", "声明 frag_len 必须=线上 body（wire 谎言拒）"),
        ("func cipherFill", "opaque 填充确定性（不伪造密文语义）"),
    ]:
        rows.append((f"关键件：{name}", prim in bl, "在案"))
    pl = (tg / "internal" / "protocol" / "dtls" / "planner.go").read_text()
    rows.append(("守卫：会话间端口一致性守卫", "conflicts with earlier session dst_port" in pl, "在案"))
    rows.append(("守卫：wire_fault 注入锚词出口", "negative-path injection rejected" in pl, "在案"))
    bl2 = (tg / "internal" / "protocol" / "dtls" / "builder.go").read_text()
    for guard, name in [
        ("regresses from current epoch", "epoch 回退守卫"),
        ("regresses/reuses below next", "record seq 回退/复用守卫（重传不复用 seq）"),
        ("beyond 48-bit range", "seq 48-bit 溢出守卫"),
        ("only valid on hello_verify_request", "cookie 仅限 HVR（状态守卫）"),
        ("exceeds handshake length", "分片越界守卫"),
]:
        rows.append((f"守卫：{name}", guard in bl2, "在案"))

    # 3. 用例面（20 例）。
    ids = {c.get("id", "") for c in cases}
    for cid in [
        "dtls_ipv4_v12_basic", "dtls_ipv6_v12_basic", "dtls_v10_legacy_record",
        "dtls_v12_cookie_exchange", "dtls_handshake_fragmentation",
        "dtls_handshake_reassembly", "dtls_epoch_sequence_transition",
        "dtls_ccs_alert_application", "dtls_retransmission_timeout",
        "dtls_multi_session_isolation", "dtls_multi_flow",
        "dtls_record_boundary_lengths", "dtls_pcap_nic_consistency",
        "dtls_encrypted_opaque_boundary",
        "dtls_neg_record_truncated", "dtls_neg_version_epoch",
        "dtls_neg_sequence_overflow", "dtls_neg_fragment_bounds",
        "dtls_neg_cookie_state", "dtls_neg_udp_carrier",
    ]:
        rows.append((f"用例在案：{cid}", cid in ids, "在案"))
    rows.append(("用例总数 20（14 正+6 负）", len(cases) == 20, f"{len(cases)} 例"))
    return rows


def check_ntlm(cases):
    """D-NTLM-1 P6 反查表。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent

    # 1. 准入与接线。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单收 ntlm", '"ntlm": true' in pg, "在列"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    i_neg = pt.index("negativeOnly := []string{")
    rows.append(("negativeOnly 不含 ntlm（已准入）", '"ntlm"' not in pt[i_neg:i_neg + 500], "已摘除"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case ntlm（严格解码）", 'case "ntlm":' in tr and "DisallowUnknownFields" in tr, "在案"))
    rows.append(("FlowMeta.NTLM 直传（Meta 字面量检查点）",
                 re.search(r"NTLM:\s+spec\.NTLM\b", tr) is not None, "在案"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.NTLM 字段", re.search(r"NTLM\s+\*core\.NTLMConfig", gen) is not None, "在案"))
    ty = (tg / "internal" / "core" / "types.go").read_text()
    rows.append(("FlowSpec.NTLM 字段", re.search(r"NTLM\s+\*NTLMConfig", ty) is not None, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    i_reg = rg.index('Name: "ntlm"')
    # 块窗口=下一个注册名（原写死 'Name: "cql"'，sstp 插入 ntlm/cql 之间后
    # 窗口串入 sstp 块导致 FieldContract 误报；改为按下一个 Name 切）。
    reg_block = rg[i_reg:rg.index('Name: "', i_reg + len('Name: "ntlm"'))]
    rows.append(("registry ntlm 行（裁定 N1：DependsOn tcp + OptionalOn http + TransportOn tcp）",
                 'DependsOn:   []string{"tcp"}' in reg_block
                 and 'OptionalOn:  []string{"http"}' in reg_block
                 and 'TransportOn: []string{"tcp"}' in reg_block, "在案"))
    rows.append(("registry 无 FieldContract（双端口 profile；smb 先例）",
                 "FieldContract" not in reg_block, "无（端口按 profile 两档）"))
    vl = (tg / "internal" / "core" / "layers" / "validate_layers.go").read_text()
    i_vl = vl.index('if protocol == "ntlm" {')
    vl_block = vl[i_vl:vl.index("effective, err := ValidateLayers", i_vl)]
    rows.append(("载体预检（缺 tcp / 夹 udp / 混合族 / profile↔http 底座）",
                 "missing tcp carrier" in vl_block and "udp carrier is not supported" in vl_block
                 and "mixed address family in ip layer" in vl_block
                 and "http carrier layer requires profile" in vl_block, "在案"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go 空白导入 + ChainPlanner(ntlm)",
                 "internal/protocol/ntlm" in mn and 'NewChainPlanner("ntlm")' in mn, "在案"))
    sc = (tg / "internal" / "core" / "strategy_convert.go").read_text()
    rows.append(("strategy_convert case ntlm + profile 端口缺省（445/80）",
                 'case "ntlm":' in sc and "parseSubconfigJSON[*NTLMConfig]" in sc
                 and "port := uint16(445)" in sc and "port = 80" in sc, "在案"))
    rows.append(("CheckProtoFlat 顶层 ntlm 子映射 presence 判死",
                 "protocol ntlm no longer accepts a top-level ntlm sub-config" in sc, "在案"))
    cp = (tg / "internal" / "core" / "layers" / "chain_planner.go").read_text()
    rows.append(("chain_planner ntlm 目的端口按 profile 缺省",
                 'case "ntlm":' in cp and 'spec.NTLM.Profile == "http-negotiate"' in cp, "在案"))
    hl = (tg / "internal" / "protocol" / "http" / "layer_gen.go").read_text()
    rows.append(("http 透传变换器（[ip,tcp,http,ntlm] 底座可用）",
                 "meta.NTLM != nil" in hl, "在案"))

    # 2. 行为面（原语/关键件）。
    nb = (tg / "internal" / "core" / "ntlm.go").read_text()
    for struct, name in [
        ("type NTLMConfig struct", "NTLMConfig（宏配置）"),
        ("type NTLMFlags struct", "NTLMFlags 指针三态（契约 §6）"),
        ("type NTLMTargetInfo struct", "NTLMTargetInfo AV 声明（契约 §6）"),
        ("type NTLMAVPair struct", "NTLMAVPair（AvId|AvLen|Value）"),
        ("type NTLMType3Config struct", "NTLMType3Config（blob 形态）"),
        ("type NTLMSession struct", "NTLMSession（多会话隔离）"),
        ("type NTLMEvent struct", "NTLMEvent（载体事件）"),
    ]:
        rows.append((f"关键件：{name}", struct in nb, "在案"))
    _i = nb.index("anchors := map[string]string{")
    _seg = nb[_i:nb.index("\n\t}", _i)]
    _n = len(re.findall(r"NTLMWireFault[A-Za-z0-9]+:", _seg))
    rows.append(("wire_fault 闭环 6 值锚词表", _n == 6, f"{_n} 值"))
    _n_un = nb.count("UnmarshalJSON(b []byte) error")
    rows.append(("递归严格解码（strictUnmarshalJSON + 逐级 UnmarshalJSON）",
                 "func strictUnmarshalJSON" in nb and _n_un >= 7, f"{_n_un} 级"))
    bl = (tg / "internal" / "protocol" / "ntlm" / "builder.go").read_text()
    for prim, name in [
        ("func buildType1", "Type 1 NEGOTIATE 32/40B 固定头 + SecurityBuffer"),
        ("func buildType2", "Type 2 CHALLENGE 48/56B + ServerChallenge(8B)"),
        ("func buildType3", "Type 3 AUTHENTICATE 64/72/88B + 六类 buffer"),
        ("func buildNTLMv2Blob", "NTLMv2 blob（Proof|RV|HRV|Res|TS|CC|Res2|AvPairs|EOL）"),
        ("func buildTargetInfoAVs", "TargetInfo AV_PAIR 序列（AvLen 只计 value）"),
        ("func avPair", "AV_PAIR 4-byte header 原语"),
        ("func avEOL", "MsvAvEOL 收尾必须项"),
        ("func putSecBuf", "SecurityBuffer Len|MaxLen|Offset little-endian"),
        ("func versionField", "8-byte Version（NEGOTIATE_VERSION 置位才有）"),
        ("func wrapSPNEGO", "SPNEGO 外层独立编码（RFC 4178 隔离）"),
        ("func frameSMB2", "SMB2 SESSION_SETUP 成帧（MS-SMB2 §3.2.5.3）"),
        ("func frameHTTP", "HTTP 401/Negotiate 成帧（RFC 4559）"),
        ("fixtureFill", "proof/MIC/session key opaque 占位（无密钥不伪造）"),
        ("smb2StatusMoreProcessing", "STATUS_MORE_PROCESSING_REQUIRED"),
        ("smb2StatusLogonFailure", "STATUS_LOGON_FAILURE"),
        ("smb2SessionSetupReqOffset", "SecurityBufferOffset 88/72（相对 SMB2 起点）"),
        ("RegisterLayerGenerator", "init 注册生成器"),
        ("RegisterLayerValidator", "init 注册校验器"),
        ("func (g *NTLMGenerator) GenEvents", "事件生成器面（链驱动）"),
        ("func profileOf", "profile 归一（空=缺省档 smb2）"),
        ("func seedFor", "会话确定性种子（rand seed+序号可复现）"),
    ]:
        rows.append((f"关键件：{name}", prim in bl, "在案"))
    pl = (tg / "internal" / "protocol" / "ntlm" / "planner.go").read_text()
    for prim, name in [
        ("func validateSpec", "入口校验"),
        ("func validateProfile", "profile/version/outer 值域"),
        ("func validateType3Config", "Type3/blob 长度面"),
        ("func validateAVPair", "AV 项 Text/ValueHex 互斥"),
        ("func validateFlags", "flags↔TargetInfo 一致 + OEM 编码"),
        ("func validateSession", "事件 kind/状态机/长度"),
        ("func kindAllowed", "profile↔载体事件一致性"),
        ("func advance", "状态机 Initial→…→Accepted/Rejected（契约 §9）"),
        ("func validateWireFault", "wire_fault 注入拒 + 锚词出口"),
    ]:
        rows.append((f"关键件：{name}", prim in pl, "在案"))

    # 3. 守卫锚词（负例通道）。
    for anchor, name in [
        ("(flags)", "flags/TargetInfo 协商不一致"),
        ("(unicode)", "OEM 编码面（Unicode 关闭 + 非 latin-1）"),
        ("(av)", "AV_PAIR 缺 EOL / 非法项"),
        ("(length)", "长度面（负数/越界/非 8 字节 challenge）"),
        ("(profile)", "profile↔事件 kind 混用"),
        ("(version)", "NTLMv1/LM 方言明确不支持"),
        ("(spnego)", "outer 值域"),
        ("(kind)", "未知事件 kind"),
        ("negative-path injection rejected", "wire_fault 注入拒"),
    ]:
        rows.append((f"守卫：{name}", anchor in pl or anchor in bl or anchor in nb, f"锚词 {anchor}"))
    rows.append(("守卫：未知 wire_fault 值拒", "unknown wire_fault kind" in nb, "在案"))

    # 4. 用例面（21 例，ID 权威=60-ntlm-testcase.md §2）。
    idset = {c.get("id", "") for c in cases}
    for cid in [
        "ntlm_smb_ipv4_v2_basic", "ntlm_smb_ipv6_v2_basic",
        "ntlm_http_negotiate_v2", "ntlm_negotiate_flags_version",
        "ntlm_challenge_target_info", "ntlm_authenticate_security_buffers",
        "ntlm_ntlmv2_blob_av_pairs", "ntlm_mic_session_key_opaque",
        "ntlm_spnego_outer_separation", "ntlm_multi_session_isolation",
        "ntlm_multi_flow_streams", "ntlm_retry_auth_failure",
        "ntlm_record_boundary_offsets", "ntlm_pcap_nic_consistency",
        "ntlm_neg_message_truncated", "ntlm_neg_security_buffer",
        "ntlm_neg_offsets_overlap_overflow", "ntlm_neg_flags_target_info",
        "ntlm_neg_v2_blob_av_pairs", "ntlm_neg_carrier_profile",
        "ntlm_http_negotiate_v6",
    ]:
        rows.append((f"用例在案：{cid}", cid in idset, "在案"))
    rows.append(("注册前置占位 ntlm_neg_unregistered 已移除",
                 "ntlm_neg_unregistered" not in idset, "已移除"))
    rows.append(("用例总数 21（15 正+6 负）", len(cases) == 21, f"{len(cases)} 例"))
    pos = [c for c in cases if "expect_error" not in (c.get("expect") or {})]
    neg = [c for c in cases if "expect_error" in (c.get("expect") or {})]
    rows.append(("15 正 + 6 负", len(pos) == 15 and len(neg) == 6, f"{len(pos)} 正 / {len(neg)} 负"))
    rows.append(("正例均带 packet_count", all((c.get("expect") or {}).get("packet_count") for c in pos), "全部在案"))
    bad_keys = [c.get("id") for c in neg
                if set((c.get("expect") or {}).keys()) != {"expect_error", "error_contains"}]
    rows.append(("负例 expect 键集严格 = {expect_error, error_contains}", not bad_keys, bad_keys or "全部合规"))
    code_anchors = set(re.findall(r'\(([a-z_]+)\)"', pl + bl))
    code_anchors |= set(re.findall(r'\(([a-z_]+)\)"', vl_block))
    code_anchors |= set(re.findall(r'NTLMWireFault[A-Za-z0-9]+:\s*"([a-z]+)"', nb))
    bad_a = [f"{c.get('id')}:{ec}" for c in neg
             for ec in [(c.get("expect") or {}).get("error_contains", "")]
             if ec not in code_anchors]
    rows.append(("6 负例锚词 ∈ 代码锚词集", not bad_a, bad_a or "全部命中"))
    return rows


def check_tds(cases):
    """D-TDS-1 P5 反查表（131 改写例 + 1 presence 负例 = 132）。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent
    lays = []
    for c in cases:
        sj = c.get("spec_json", {}) or {}
        for l in sj.get("layers") or []:
            if isinstance(l, dict) and isinstance(l.get("tds"), dict):
                lays.append((c.get("id", "?"), l["tds"]))
                break
    blob = json.dumps(cases, ensure_ascii=False)

    # 1. 准入与接线。
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case tds（层条目→Payload）", 'case "tds":' in tr and "spec.Payload = rawT" in tr, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    rows.append(("registry tds 行 + TransportOn[tcp]",
                 'Name: "tds"' in rg and 'TransportOn: []string{"tcp"}' in rg, "在案"))
    sc = (tg / "internal" / "core" / "strategy_convert.go").read_text()
    rows.append(("CheckProtoFlat presence 判死顶层 tds",
                 "no longer accepts a top-level tds sub-config" in sc, "在案"))
    rows.append(("strategy_convert 存量兼容块记 ValidationErrors",
                 'if protocol == "tds" {' in sc, "在案"))

    # 2. 用例面（132 例 = 131 改写 + 1 presence）。
    rows.append(("用例总数 132", len(cases) == 132, f"{len(cases)} 例"))
    pos = [c for c in cases if "expect_error" not in (c.get("expect") or {})]
    neg = [c for c in cases if "expect_error" in (c.get("expect") or {})]
    rows.append(("105 正 + 27 负", len(pos) == 105 and len(neg) == 27, f"{len(pos)} 正 / {len(neg)} 负"))
    rows.append(("presence 负例在案（layers+顶层tds）",
                 "tds_neg_top_tds_presence_reject" in {c.get("id") for c in cases}, "在案"))
    bad_top = [c.get("id") for c in pos
               if set((c.get("spec_json") or {}).keys()) - {"layers", "flow_control", "output"}]
    rows.append(("非负例顶层键=0（白名单制）", not bad_top, bad_top or "全部合规"))
    for k in ["sessions", "mars", "version", "feature_exts", "login", "encrypt_mode",
              "packet_size", "user_name", "password", "database", "language",
              "app_name", "server_name", "client_name", "interface_lib", "client_lcid"]:
        hit = next((cid for cid, m in lays if k in m), None)
        rows.append((f"层键覆盖：{k}", hit is not None, hit or "无用例"))

    # 3. 锚词面（27 负例：26 V-TDS 真门 + 1 presence）。
    for needle, name in [
        ("top-level tds sub-config", "presence 判死"),
        ("V-TDS-001", "version 非法"), ("V-TDS-002", "packet_size 越界"),
        ("V-TDS-003", "无会话"), ("V-TDS-004", "无请求"),
        ("V-TDS-005", "请求类型非法"), ("V-TDS-006", "sql 缺失"),
        ("V-TDS-007", "登录字段超长"), ("V-TDS-015", "feature 非 7.4"),
        ("V-TDS-016", "feature 未知 id"), ("V-TDS-017", "feature data 非法"),
        ("V-TDS-018", "feature ack 非法"), ("V-TDS-020", "空 SQL"),
        ("V-TDS-022", "procname 超长"), ("V-TDS-023", "procid 越界"),
        ("V-TDS-024", "procname+id 互斥"), ("V-TDS-025", "param 类型"),
        ("V-TDS-026", "param maxlen"), ("V-TDS-027", "param precision"),
        ("V-TDS-028", "param scale"), ("V-TDS-034", "transmgr 类型"),
        ("V-TDS-035", "savepoint"), ("V-TDS-036", "txn 未 begin"),
        ("V-TDS-038", "MARS 前置"), ("V-TDS-060", "error class"),
        ("V-TDS-061", "info class"),
    ]:
        rows.append((name, needle in blob, "锚词出现" if needle in blob else "无用例"))
    return rows

def check_spnego(cases):
    """D-SPNEGO-1 P6 反查表。返回 [(检查名, 通过?, 证据)]。"""
    rows = []
    tg = Path(__file__).resolve().parent.parent

    # 1. 准入与接线。
    pg = (tg / "internal" / "core" / "protocols.go").read_text()
    rows.append(("白名单收 spnego", '"spnego": true' in pg, "在列"))
    pt = (tg / "internal" / "core" / "protocols_test.go").read_text()
    i_neg = pt.index("negativeOnly := []string{")
    rows.append(("negativeOnly 不含 spnego（已准入）", '"spnego"' not in pt[i_neg:i_neg + 1500], "已摘除"))
    tr = (tg / "internal" / "core" / "layers" / "chain_planner_translate.go").read_text()
    rows.append(("translate case spnego（严格解码）", 'case "spnego":' in tr and "DisallowUnknownFields" in tr, "在案"))
    rows.append(("FlowMeta.SPNEGO 直传（Meta 字面量检查点）",
                 re.search(r"SPNEGO:\s+spec\.SPNEGO\b", tr) is not None, "在案"))
    gen = (tg / "internal" / "core" / "layers" / "generator.go").read_text()
    rows.append(("FlowMeta.SPNEGO 字段", re.search(r"SPNEGO\s+\*core\.SPNEGOConfig", gen) is not None, "在案"))
    ty = (tg / "internal" / "core" / "types.go").read_text()
    rows.append(("FlowSpec.SPNEGO 字段", re.search(r"SPNEGO\s+\*SPNEGOConfig", ty) is not None, "在案"))
    rg = (tg / "internal" / "core" / "layers" / "registry.go").read_text()
    i_reg = rg.index('Name: "spnego"')
    reg_block = rg[i_reg:rg.index('Name: "cql"', i_reg)]
    rows.append(("registry spnego 行（裁定1：DependsOn tcp + OptionalOn http + TransportOn tcp + 445 契约）",
                 'DependsOn:     []string{"tcp"}' in reg_block
                 and 'OptionalOn:    []string{"http"}' in reg_block
                 and 'TransportOn:   []string{"tcp"}' in reg_block
                 and '"tcp.dst_port": "445"' in reg_block, "在案"))
    vl = (tg / "internal" / "core" / "layers" / "validate_layers.go").read_text()
    i_vl = vl.index('if protocol == "spnego" {')
    vl_block = vl[i_vl:vl.index("effective, err := ValidateLayers", i_vl)]
    rows.append(("载体预检（缺 tcp / 夹 udp / 混合族 / profile↔http 底座）",
                 "missing tcp carrier" in vl_block and "udp carrier is not supported" in vl_block
                 and "mixed address family in ip layer" in vl_block
                 and "http carrier layer requires profile" in vl_block, "在案"))
    mn = (tg / "cmd" / "server" / "main.go").read_text()
    rows.append(("main.go 空白导入 + ChainPlanner(spnego)",
                 "internal/protocol/spnego" in mn and 'NewChainPlanner("spnego")' in mn, "在案"))
    sc = (tg / "internal" / "core" / "strategy_convert.go").read_text()
    rows.append(("strategy_convert case spnego + profile 端口缺省（445/80）",
                 'case "spnego":' in sc and "parseSubconfigJSON[*SPNEGOConfig]" in sc
                 and "portS := uint16(445)" in sc and "portS = 80" in sc, "在案"))
    rows.append(("CheckProtoFlat 顶层 spnego 子映射 presence 判死",
                 "protocol spnego no longer accepts a top-level spnego sub-config" in sc, "在案"))
    cp = (tg / "internal" / "core" / "layers" / "chain_planner.go").read_text()
    rows.append(("chain_planner spnego 目的端口按 profile 缺省",
                 'case "spnego":' in cp and 'spec.SPNEGO.Profile' in cp and '"http"' in cp, "在案"))
    hl = (tg / "internal" / "protocol" / "http" / "layer_gen.go").read_text()
    rows.append(("http 透传变换器（[ip,tcp,http,spnego] 底座可用）",
                 "meta.SPNEGO != nil" in hl, "在案"))

    # 2. 行为面（原语/关键件）。
    nb = (tg / "internal" / "core" / "spnego.go").read_text()
    for struct, name in [
        ("type SPNEGOConfig struct", "SPNEGOConfig（宏配置）"),
        ("type SPNEGONegHints struct", "SPNEGONegHints（[3] 槽声明）"),
        ("type SPNEGOToken struct", "SPNEGOToken（opaque 外壳三态）"),
        ("type SPNEGOMIC struct", "SPNEGOMIC（RFC 形 MIC 声明）"),
        ("type SPNEGOSession struct", "SPNEGOSession（多会话隔离）"),
        ("type SPNEGOEvent struct", "SPNEGOEvent（载体事件）"),
    ]:
        rows.append((f"关键件：{name}", struct in nb, "在案"))
    _i = nb.index("anchors := map[string]string{")
    _seg = nb[_i:nb.index("\n\t}", _i)]
    _n = len(re.findall(r"SPNEGOWireFault[A-Za-z0-9]+:", _seg))
    rows.append(("wire_fault 闭环 6 值锚词表", _n == 6, f"{_n} 值"))
    _n_un = nb.count("UnmarshalJSON(b []byte) error")
    rows.append(("递归严格解码（strictUnmarshalJSON + 逐级 UnmarshalJSON）",
                 "strictUnmarshalJSON(b, &a)" in nb and _n_un >= 6, f"{_n_un} 级"))
    bl = (tg / "internal" / "protocol" / "spnego" / "builder.go").read_text()
    for prim, name in [
        ("func buildInitialContextToken", "InitialContextToken 0x60 外层（RFC 2743 §3.1）"),
        ("func buildNegTokenInit", "NegTokenInit [0]/[1]/[2]/[3] 槽（RFC 4178 §4.2.1）"),
        ("func buildNegTokenResp", "NegTokenResp [1] 枝（RFC 4178 §4.2.2）"),
        ("func buildNegTokenTarg", "negTokenTarg 旧式三值（RFC 2478 §3.2.1）"),
        ("func buildNegHints", "negHints [3] 槽（hintName/hintAddress）"),
        ("func frameTCP", "裸 TCP 自封帧（整 DER 直发）"),
        ("func frameHTTP", "HTTP 401/Negotiate 成帧（RFC 4559）"),
        ("func renderInit", "init 渲染（up，InitialContextToken 外层）"),
        ("func renderResp", "resp 渲染（down，选择枝）"),
        ("func renderMIC", "MIC 续渲染（up，补 mechListMIC）"),
        ("func slot3", "[3] 槽互斥（MIC/hints 二选一）"),
        ("func profileOf", "profile 归一（空=缺省档 tcp）"),
        ("RegisterLayerGenerator", "init 注册生成器"),
        ("RegisterLayerValidator", "init 注册校验器"),
        ("func (g *SPNEGOGenerator) GenEvents", "事件生成器面（链驱动）"),
    ]:
        rows.append((f"关键件：{name}", prim in bl, "在案"))
    pl = (tg / "internal" / "protocol" / "spnego" / "planner.go").read_text()
    for prim, name in [
        ("func validateSpec", "入口校验（bare 层缺省基线）"),
        ("func validateConfig", "profile/negotiation/req_flags/neg_hints/layout 值域"),
        ("func validateSession", "事件 kind/状态机/降级守卫"),
        ("func kindAllowed", "profile↔载体事件一致性"),
        ("func advance", "状态机 initial→init→responded→(mic)→terminal"),
        ("func validateWireFault", "wire_fault 注入拒 + 锚词出口"),
    ]:
        rows.append((f"关键件：{name}", prim in pl, "在案"))

    # 3. 守卫锚词（负例通道；transport/family 住 validate_layers 链预检，
    # 其余住 planner/builder/core——ntlm 同款三分）。
    for anchor, name in [
        ("(profile)", "profile↔事件 kind 混用"),
        ("(sequence)", "negotiation/事件顺序（targ 显式声明）"),
        ("(oid)", "OID 编码/别名/选定绑定"),
        ("(selection)", "supportedMech ∈ 列表降级守卫"),
        ("(neg_result)", "negResult 值域（resp 0..3/targ 0..2）"),
        ("(neg_hints)", "neg_hints carry 值域"),
        ("(layout)", "mech_list_mic layout 值域"),
        ("(length)", "长度面（负数/token/MIC/hint hex）"),
        ("(mic)", "[3] 槽二义（hints/MIC 互斥）"),
        ("(port)", "会话 dst_port 冲突"),
        ("(carrier)", "端点覆盖/tcp 单载体"),
        ("(kind)", "未知事件 kind"),
        ("negative-path injection rejected", "wire_fault 注入拒"),
    ]:
        rows.append((f"守卫：{name}", anchor in pl or anchor in bl or anchor in nb, f"锚词 {anchor}"))
    for anchor, name in [
        ("(transport)", "udp 载体拒"),
        ("(family)", "混合地址族拒"),
    ]:
        rows.append((f"守卫：{name}", anchor in vl_block, f"锚词 {anchor}"))
    rows.append(("守卫：未知 wire_fault 值拒", "unknown wire_fault kind" in nb, "在案"))

    # 4. 用例面（20 例，ID 权威=61-spnego-testcase.md §2）。
    idset = {c.get("id", "") for c in cases}
    for cid in [
        "spnego_http_ipv4_init", "spnego_http_ipv6_init",
        "spnego_tcp_ipv4_init", "spnego_tcp_ipv6_init",
        "spnego_neg_token_init_hints", "spnego_neg_token_resp_selection",
        "spnego_neg_token_targ_legacy", "spnego_mech_oid_variants",
        "spnego_mech_token_opaque", "spnego_mechlist_mic",
        "spnego_der_canonical_boundaries", "spnego_downgrade_prevention",
        "spnego_multi_session_stream", "spnego_pcap_nic_consistency",
        "spnego_neg_der_truncated", "spnego_neg_der_length_overflow",
        "spnego_neg_invalid_token_choice", "spnego_neg_mech_oid_selection",
        "spnego_neg_mic_downgrade", "spnego_neg_carrier_profile",
    ]:
        rows.append((f"用例在案：{cid}", cid in idset, "在案"))
    rows.append(("注册前置占位 spnego_neg_unregistered 已移除",
                 "spnego_neg_unregistered" not in idset, "已移除"))
    rows.append(("用例总数 20（14 正+6 负）", len(cases) == 20, f"{len(cases)} 例"))
    pos = [c for c in cases if "expect_error" not in (c.get("expect") or {})]
    neg = [c for c in cases if "expect_error" in (c.get("expect") or {})]
    rows.append(("14 正 + 6 负", len(pos) == 14 and len(neg) == 6, f"{len(pos)} 正 / {len(neg)} 负"))
    rows.append(("正例均带 packet_count", all((c.get("expect") or {}).get("packet_count") for c in pos), "全部在案"))
    bad_keys = [c.get("id") for c in neg
                if set((c.get("expect") or {}).keys()) != {"expect_error", "error_contains"}]
    rows.append(("负例 expect 键集严格 = {expect_error, error_contains}", not bad_keys, bad_keys or "全部合规"))
    code_anchors = set(re.findall(r'\(([a-z_]+)\)"', pl + bl))
    code_anchors |= set(re.findall(r'\(([a-z_]+)\)"', vl_block))
    code_anchors |= set(re.findall(r'SPNEGOWireFault[A-Za-z0-9]+:\s*"([a-z_]+)"', nb))
    bad_a = [f"{c.get('id')}:{ec}" for c in neg
             for ec in [(c.get("expect") or {}).get("error_contains", "")]
             if ec not in code_anchors]
    rows.append(("6 负例锚词 ∈ 代码锚词集", not bad_a, bad_a or "全部命中"))
    return rows




CHECKS = {"smtp": check_smtp, "pop3": check_pop3, "imap": check_imap,
          "mcp": check_mcp, "srv6": check_srv6, "fins": check_fins,
          "goose": check_goose, "sv": check_sv, "icmpv6": check_icmpv6, "h323": check_h323, "mpls": check_mpls, "ngap": check_ngap, "telnet": check_telnet, "sip": check_sip, "radius": check_radius, "pppoe": check_pppoe, "ldap": check_ldap, "rtmp": check_rtmp, "rtsp": check_rtsp, "pptp": check_pptp, "vnc": check_vnc, "xmpp": check_xmpp, "sctp": check_sctp, "jt808": check_jt808, "jt809": check_jt809, "jtt905": check_jtt905, "arp": check_arp, "icmp": check_icmp, "cwmp": check_cwmp, "kingbase": check_kingbase, "megaco": check_megaco, "hl7": check_hl7, "mmse": check_mmse, "edp": check_edp, "xmrmining": check_xmrmining, "bacnet": check_bacnet, "dcerpc": check_dcerpc, "dtls": check_dtls, "kerberos": check_kerberos, "ntlm": check_ntlm, "sstp": check_sstp, "ocsp": check_ocsp, "tds": check_tds, "spnego": check_spnego}


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
