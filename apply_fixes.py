# -*- coding: utf-8 -*-
"""
apply_fixes.py — VulnGym n8n 样本修复交付脚本（PR 标准版）

设计原则（单一事实来源，避免脚本与交付物失同步）：
  1. 以 `entries.fixed.jsonl`（已人工校验通过）为「修复规范」，其中包含 6 条 entry
     的 entry_point / critical_operation / trace 的最终正确内容。
  2. 从基础数据集 `data/entries.jsonl` 读取这 6 条的原始 entry，保留其身份字段
     （report_id / source_link / project / repo_url / commit / vuln_ids /
      vuln_category_* / vuln_title / origin），仅替换 entry_point /
      critical_operation / trace 为修复规范中的内容。
  3. 重新写出 `entries.fixed.jsonl`（字段字母序），并原样保留
     `entries.fixed.diff.csv` 与 `entries.fixed.notes.md` 两个说明文档。
  4. 生成后对 `entries.fixed.jsonl` 做内置自检：verbatim 代码与声称行号对齐、
     SCHEMA 不变量、与原始 entries/reports 的元数据一致性。任一检查失败则非零退出。

运行：py apply_fixes.py
"""
import json, os, re

ROOT = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(ROOT, 'data', 'entries.jsonl')
SPEC = os.path.join(ROOT, 'entries.fixed.jsonl')
OUT_JSONL = SPEC
OUT_CSV = os.path.join(ROOT, 'entries.fixed.diff.csv')
OUT_NOTES = os.path.join(ROOT, 'entries.fixed.notes.md')

# commit -> 用于选择源码副本（仅自检阶段核对 verbatim 用）
COMMIT_C1 = "8ab4492e8c0b743455e51fc111441d8d5010a6ad"
COMMIT_C4 = "09e2c2b5547b49a824a8265d312583f5d1f5c79f"
FORBIDDEN = {"description","human_remark","pipeline_id","annotated_by","is_active",
             "created_at","generality","detection_type","ground_truth","taint_source",
             "taint_sink","vuln_category_l3"}

FIXED_IDS = ['entry-00099','entry-00100','entry-00103','entry-00176','entry-00511','entry-00512']

def load(path, key='entry_id'):
    out = {}
    with open(path, encoding='utf-8') as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            e = json.loads(ln)
            out[e[key]] = e
    return out

base = load(BASE)
spec = load(SPEC)

# ---- 1. 合并：基础身份字段 + 修复规范的节点内容 ----
results = []
for eid in FIXED_IDS:
    if eid not in base:
        raise SystemExit(f"FATAL: {eid} not found in base dataset")
    if eid not in spec:
        raise SystemExit(f"FATAL: {eid} not found in fix spec")
    e = dict(base[eid])            # 身份字段来自基础数据集，保证元数据一致
    s = spec[eid]
    e['entry_point'] = s['entry_point']
    e['critical_operation'] = s['critical_operation']
    e['trace'] = s['trace']
    # 强制 verify 与基础一致（修复不改变人工审计状态）
    results.append(e)

with open(OUT_JSONL, 'w', encoding='utf-8') as f:
    for e in results:
        s = json.dumps(e, ensure_ascii=False, sort_keys=True)
        json.loads(s)              # sanity re-parse
        f.write(s + '\n')

# ---- 2. 原样保留说明文档（已是人工校验通过版本） ----
for dst in (OUT_CSV, OUT_NOTES):
    with open(dst, encoding='utf-8') as f:
        content = f.read()
    with open(dst, 'w', encoding='utf-8') as f:
        f.write(content)

# ---- 3. 内置自检 ----
def local_file(repo_path, commit):
    base_name = os.path.basename(repo_path)
    if base_name == "expression.ts":
        return "c4_expression.ts" if commit == COMMIT_C4 else "c1_expression.ts"
    if base_name == "expression-sandboxing.ts":
        return "c4_expression-sandboxing.ts" if commit == COMMIT_C4 else "c1_expression-sandboxing.ts"
    m = {"expression-evaluator-proxy.ts":"c1_expression-evaluator-proxy.ts",
         "workflows.controller.ts":"c1_workflows.controller.ts",
         "html-sandbox.ts":"c2_html-sandbox.ts","webhook-helpers.ts":"c2_webhook-helpers.ts",
         "webhook-request-handler.ts":"c2_webhook-request-handler.ts","Code.node.ts":"c3_Code.node.ts",
         "PythonTaskRunnerSandbox.ts":"c3_PythonTaskRunnerSandbox.ts","constants.py":"c3_constants.py",
         "task_analyzer.py":"c3_task_analyzer.py","task_runner.py":"c3_task_runner.py",
         "extend.ts":"c4_extend.ts","reset.ts":"c4_reset.ts"}
    return m[base_name]

def pl(line):
    if isinstance(line, int): return (line, line)
    a, b = line.split('-')
    return (int(a), int(b))

prob = []
written = load(OUT_JSONL)
reports = load(os.path.join(ROOT, 'data', 'reports.jsonl'), key='report_id')

for eid, e in written.items():
    commit = e['commit']
    cache = {}
    def get_src(rp):
        lf = local_file(rp, commit)
        if lf not in cache:
            with open(os.path.join(ROOT, lf), encoding='utf-8') as sf:
                cache[lf] = sf.read().split('\n')
        return cache[lf]
    def check(node, where):
        rp = node['file']; line = node['line']; code = node['code']
        s, en = pl(line); src = get_src(rp)
        if s < 1 or en < s:
            prob.append(f"[{eid}] {where}: line {line} invalid"); return
        if en > len(src):
            prob.append(f"[{eid}] {where}: end {en}>{len(src)} {os.path.basename(rp)}"); return
        if "\n".join(src[s-1:en]) != code:
            full = "\n".join(src)
            if code in full:
                occ = full.find(code); ol = full[:occ].count('\n') + 1
                prob.append(f"[{eid}] {where}: code not at {line}, actually @ {ol}")
            else:
                prob.append(f"[{eid}] {where}: code NOT verbatim in {os.path.basename(rp)}@{line}")
    check(e['entry_point'], 'entry_point'); check(e['critical_operation'], 'critical_operation')
    for i, t in enumerate(e.get('trace', [])):
        check(t, f"trace[{i}]")
    # schema
    keys = list(e.keys())
    if keys != sorted(keys):
        prob.append(f"[{eid}] keys not sorted: {keys}")
    for fk in FORBIDDEN:
        if fk in e:
            prob.append(f"[{eid}] forbidden {fk}")
    if e.get('verify') not in (0, 1):
        prob.append(f"[{eid}] verify {e.get('verify')!r}")
    if not re.fullmatch(r"[0-9a-f]{40}", e.get('commit', '')):
        prob.append(f"[{eid}] bad commit")
    if not str(e.get('repo_url', '')).startswith('https://github.com/'):
        prob.append(f"[{eid}] bad repo_url")
    sl = e.get('source_link', '')
    if 'github.com/advisories/' not in sl:
        prob.append(f"[{eid}] bad source_link")
    m = re.search(r"GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}", sl, re.I)
    if not m or m.group(0).upper() != e.get('report_id', '').upper():
        prob.append(f"[{eid}] GHSA != report_id")
    vids = e.get('vuln_ids', []); norm = [v.upper() for v in vids]
    if len(norm) != len(set(norm)):
        prob.append(f"[{eid}] vuln_ids not unique")
    if [v for v in norm if v.startswith('CVE-')] + [v for v in norm if v.startswith('GHSA-')] != norm:
        prob.append(f"[{eid}] vuln_ids order: {vids}")
    # metadata consistency with base
    o = base.get(eid)
    if o:
        for k in ('report_id','source_link','project','repo_url','commit','vuln_ids',
                  'vuln_category_l1','vuln_category_l2','vuln_title','origin'):
            if e.get(k) != o.get(k):
                prob.append(f"[{eid}] identity {k} drift vs base: {e.get(k)!r} != {o.get(k)!r}")
    # report linkage
    rid = e['report_id']
    if rid not in reports:
        prob.append(f"[{eid}] report_id {rid} missing in reports.jsonl")
    elif eid not in reports[rid].get('entry_ids', []):
        prob.append(f"[{eid}] not in reports entry_ids")

print(f"WROTE {OUT_JSONL} ({len(written)} entries)")
print(f"SELF-CHECK PROBLEMS: {len(prob)}")
for p in prob:
    print("  -", p)
if prob:
    raise SystemExit("SELF-CHECK FAILED")
print("SELF-CHECK OK — deliverables are consistent and valid.")
