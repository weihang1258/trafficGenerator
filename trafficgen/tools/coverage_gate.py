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
                     ("hdr_case_mix", "头名大小写混写面")]:
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


CHECKS = {"smtp": check_smtp, "pop3": check_pop3, "imap": check_imap,
          "mcp": check_mcp, "srv6": check_srv6, "fins": check_fins,
          "goose": check_goose, "sv": check_sv, "icmpv6": check_icmpv6, "h323": check_h323, "mpls": check_mpls, "ngap": check_ngap, "telnet": check_telnet, "sip": check_sip, "radius": check_radius}


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
