# -*- coding: utf-8 -*-
import json

SRC = r'c:/Users/victor/Downloads/VulnGym/data/entries.jsonl'
OUT_JSONL = r'c:/Users/victor/Downloads/VulnGym/entries.fixed.jsonl'
OUT_NOTES = r'c:/Users/victor/Downloads/VulnGym/entries.fixed.notes.md'
OUT_CSV = r'c:/Users/victor/Downloads/VulnGym/entries.fixed.diff.csv'

with open(SRC, 'r', encoding='utf-8') as f:
    lines = f.readlines()

def find(eid):
    for ln in lines:
        obj = json.loads(ln)
        if obj.get('entry_id') == eid:
            return obj
    raise KeyError(eid)

# ---- shared code snippets (authored from vulnerable-commit source) ----
EVAL_SINK = "export const evaluateExpression: Evaluator = (expr, data) => {\n\treturn evaluator(expr, data);\n};"

SET_RESP_HDR = "\tprivate setResponseHeaders(res: express.Response, headers?: WebhookResponseHeaders) {\n\t\tif (headers) {\n\t\t\tfor (const [name, value] of headers.entries()) {\n\t\t\t\tres.setHeader(name, value);\n\t\t\t}\n\t\t}\n\n\t\tconst contentType = res.getHeader('content-type') as string | undefined;\n\t\tconst needsSandbox = !contentType || isHtmlRenderedContentType(contentType);"

VISIT_ATTR = "    def visit_Attribute(self, node: ast.Attribute) -> None:\n        \"\"\"Detect access to unsafe attributes that could bypass security restrictions.\"\"\"\n\n        if node.attr in BLOCKED_ATTRIBUTES:\n            self._add_violation(\n                node.lineno, ERROR_DANGEROUS_ATTRIBUTE.format(attr=node.attr)\n            )"

APPLY = "\tif (foundFunction.type === 'native') {\n\t\t// eslint-disable-next-line @typescript-eslint/no-unsafe-return\n\t\treturn foundFunction.function.apply(input, args);\n\t}"

# description snippets
DESC_99_CRIT = ("evaluateExpression 是将转义后表达式实际执行的 RCE 执行点（sink）：它将 expr 与 data 交给绑定的 "
               "tournamentEvaluator.execute 编译并运行。此前 PrototypeSanitizer 因缺少 visitWithStatement 处理器而未能拦截 "
               "with 语句注入的 .constructor，逃逸后的表达式最终在此处被宿主引擎求值，任意代码由此落地。原 critical_operation 置于作为防御方的 "
               "PrototypeSanitizer 定义（expression-sandboxing.ts:244），并非代码执行点，故修正为真实求值 sink。")
DESC_99_T0 = "工作流执行路由的 HTTP 入口，用户可控的表达式字符串自此进入求值管线。"
DESC_99_T1 = "isExpression 确认参数以等号开头后 substr(1) 剥离前缀，仅做格式校验，不对内容做安全审查，转义载荷经此进入沙箱编译流程。"
DESC_99_T2 = "构造 tournamentEvaluator 实例并注册钩子；PrototypeSanitizer 在此被绑定入钩子列表，其缺少 visitWithStatement 处理器的缺陷随配置一起作用到每次编译。"
DESC_99_T3 = "根因缺陷点：PrototypeSanitizer 作为防御方缺少 visitWithStatement 处理器，with 语句可将函数对象的 .constructor 悄然注入词法作用域，沙箱约束实质性失效。此处是防御缺口所在，而非代码执行点。"
DESC_99_T4 = "RCE 执行点：evaluateExpression 将转义后的 expr 经 tournamentEvaluator.execute 交给宿主引擎执行，任意代码在此落地，是漏洞链路的终点。"

DESC_100_CRIT = ("evaluateExpression 是将转义后表达式实际执行的 RCE sink。本条目对应 __sanitize 局部遮蔽绕过路径：当表达式以同名局部常量遮蔽 "
                 "data 上的 sanitizer 绑定时，运行时属性检查不再生效，转义后的表达式仍在此处被 tournamentEvaluator.execute 执行。"
                 "原 critical_operation 置于 sanitizer 函数定义（expression-sandboxing.ts:330-336），该定义属防御实现而非执行点，故修正为真实求值 sink。")
DESC_100_T4 = "RCE 执行点：转义后的表达式经 tournamentEvaluator.execute 被宿主引擎执行，是 __sanitize 遮蔽绕过链路的终点。"

DESC_103_EP = ("外部输入进入漏洞链路的真实入口：工作流通过 headers 指定的 content-type（可能含前后置空白）经 res.setHeader 写入响应，"
               "随后 res.getHeader('content-type') 将其读出并传入 isHtmlRenderedContentType 判定是否追加 CSP sandbox。"
               "原 entry_point 落在 webhook-helpers.ts:615 的 '}' 闭合括号，属非执行点，无法体现外部输入如何进入，故修正为本函数。")
DESC_103_T0 = "streaming 分支将 runData.httpResponse 赋值为 res 并标记 didSendResponse=true，响应对象（携带用户指定的 headers）自此进入后续处理流程。"
DESC_103_T1 = ("setResponseHeaders 将用户工作流指定的 headers 逐条通过 res.setHeader 写入响应——含潜在首尾空白的 content-type 于此被设置；"
               "随后 res.getHeader('content-type') 读回并传入 isHtmlRenderedContentType，needsSandbox 的判定决定是否追加 CSP 头，污染值由此进入检测函数。")
DESC_103_T2 = ("isHtmlRenderedContentType 仅对 contentType 做 toLowerCase() 后 startsWith('text/html') 匹配，缺少 .trim() 预处理；"
               "含首尾空白的 contentType 无法通过前缀匹配，返回 false，needsSandbox 判定失效，CSP 保护头被跳过。")

DESC_176_CRIT = ("AST 静态校验真正生效的强制点：visit_Attribute 提取 node.attr 后与 BLOCKED_ATTRIBUTES 做成员测试，命中才记录违规。"
                 "由于集合未包含 __objclass__，对 slot wrapper 方法属性的访问在此静默放行，沙箱逃逸得以建立。"
                 "原 critical_operation 置于 constants.py:126 的静态列表定义（属数据源而非执行/校验点），故修正为本强制执行点。")

DESC_511_CRIT = ("RCE 实际执行点（sink）：当 findExtendedFunction 在原生回退分支（extend.ts:79-85）将 functionName='constructor' 解析为宿主 "
                 "Function 构造函数并返回 type:'native' 后，此处以 foundFunction.function.apply(input, args) 调用它，攻击者传入的代码字符串得以执行。"
                 "原 critical_operation 置于原生回退分支（79-85）这一“缺失检查点”，但未体现真正的代码执行动作，故修正为本 .apply 调用。")
DESC_511_T5 = ("RCE 执行点：foundFunction.function.apply(input, args) 以攻击者控制的 args 调用 Function 构造函数，任意代码在此落地；"
               "其上游的 Function 构造函数来自 79-85 行未做函数名检查的 native 回退。")

DESC_512_CRIT = ("路径 B 的根本缺陷点：以普通赋值（非 Object.defineProperty 不可写约束）将 __sanitize 写入 __data，"
                 "使该槽位在沙箱内表达式执行期间可被覆写为恒等函数。PrototypeSanitizer 编译期在每处计算属性访问插入的 "
                 "obj[this.__sanitize(expr)] 调用均绑定此槽位，槽位失守后动态属性过滤在运行期全链失效，沙箱逃逸由此成立。"
                 "该赋值点是真实的弱点所在（而非非执行点），故保留 critical_operation 于此并细化说明。")

# ---------------- entry-00099 ----------------
results = []
e = find('entry-00099')
ep_code = e['entry_point']['code']
t1 = e['trace'][1]['code']
t2 = e['trace'][2]['code']
proto_code = e['critical_operation']['code']
e['critical_operation'] = {
    'file': 'packages/workflow/src/expression-evaluator-proxy.ts',
    'line': '19-21',
    'code': EVAL_SINK,
    'desc': DESC_99_CRIT,
}
e['trace'] = [
    {'file': 'packages/cli/src/workflows/workflows.controller.ts', 'line': 539, 'code': ep_code, 'desc': DESC_99_T0},
    {'file': 'packages/workflow/src/expression.ts', 'line': '384-393', 'code': t1, 'desc': DESC_99_T1},
    {'file': 'packages/workflow/src/expression-evaluator-proxy.ts', 'line': '9-12', 'code': t2, 'desc': DESC_99_T2},
    {'file': 'packages/workflow/src/expression-sandboxing.ts', 'line': 244, 'code': proto_code, 'desc': DESC_99_T3},
    {'file': 'packages/workflow/src/expression-evaluator-proxy.ts', 'line': '19-21', 'code': EVAL_SINK, 'desc': DESC_99_T4},
]
results.append(e)

# ---------------- entry-00100 ----------------
e = find('entry-00100')
ot = e['trace']
e['critical_operation'] = {
    'file': 'packages/workflow/src/expression-evaluator-proxy.ts',
    'line': '19-21',
    'code': EVAL_SINK,
    'desc': DESC_100_CRIT,
}
e['trace'] = [
    ot[0], ot[1], ot[2], ot[3],
    {'file': 'packages/workflow/src/expression-evaluator-proxy.ts', 'line': '19-21', 'code': EVAL_SINK, 'desc': DESC_100_T4},
]
results.append(e)

# ---------------- entry-00103 ----------------
e = find('entry-00103')
ot = e['trace']
e['entry_point'] = {
    'file': 'packages/cli/src/webhooks/webhook-request-handler.ts',
    'line': '146-155',
    'code': SET_RESP_HDR,
    'desc': DESC_103_EP,
}
# critical_operation (html-sandbox.ts:20) is the legitimate root-cause defect -> keep as-is
e['trace'] = [
    {'file': 'packages/cli/src/webhooks/webhook-helpers.ts', 'line': '605-614', 'code': ot[1]['code'], 'desc': DESC_103_T0},
    {'file': 'packages/cli/src/webhooks/webhook-request-handler.ts', 'line': '146-155', 'code': SET_RESP_HDR, 'desc': DESC_103_T1},
    {'file': 'packages/core/src/html-sandbox.ts', 'line': '19-25', 'code': ot[3]['code'], 'desc': DESC_103_T2},
]
results.append(e)

# ---------------- entry-00176 ----------------
e = find('entry-00176')
e['critical_operation'] = {
    'file': 'packages/@n8n/task-runner-python/src/task_analyzer.py',
    'line': '63-69',
    'code': VISIT_ATTR,
    'desc': DESC_176_CRIT,
}
# entry_point (Code.node.ts:206) and trace kept unchanged
results.append(e)

# ---------------- entry-00511 ----------------
e = find('entry-00511')
ot = e['trace']
e['critical_operation'] = {
    'file': 'packages/@n8n/expression-runtime/src/extensions/extend.ts',
    'line': '132-134',
    'code': APPLY,
    'desc': DESC_511_CRIT,
}
e['trace'] = [
    ot[0], ot[1], ot[2], ot[3], ot[4],
    {'file': 'packages/@n8n/expression-runtime/src/extensions/extend.ts', 'line': '132-134', 'code': APPLY, 'desc': DESC_511_T5},
]
results.append(e)

# ---------------- entry-00512 ----------------
e = find('entry-00512')
e['critical_operation'] = {
    'file': e['critical_operation']['file'],
    'line': e['critical_operation']['line'],
    'code': e['critical_operation']['code'],
    'desc': DESC_512_CRIT,
}
# entry_point (expression.ts:524) and trace kept unchanged
results.append(e)

# ---------------- emit ----------------
# results already collected in processing order below
with open(OUT_JSONL, 'w', encoding='utf-8') as f:
    for e in results:
        s = json.dumps(e, ensure_ascii=False, sort_keys=True)
        json.loads(s)  # sanity re-parse
        f.write(s + '\n')

# ---------------- diff CSV ----------------
csv_rows = [
    ['entry_id', 'field', 'old_location', 'new_location', 'reason'],
    ['entry-00099', 'critical_operation', 'expression-sandboxing.ts:244', 'expression-evaluator-proxy.ts:19-21',
     'RCE sink 原错误置于防御方 sanitizer 定义，修正为真实求值执行点'],
    ['entry-00099', 'trace', 'ends at expression-sandboxing.ts:244', 'ends at expression-evaluator-proxy.ts:19-21',
     'trace 终点改为 eval sink，并保留 PrototypeSanitizer 缺口作为根因节点'],
    ['entry-00100', 'critical_operation', 'expression-sandboxing.ts:330-336', 'expression-evaluator-proxy.ts:19-21',
     'sink 原置于 sanitizer 函数定义，修正为真实求值执行点'],
    ['entry-00100', 'trace', 'ends at expression-sandboxing.ts:330-336', 'ends at expression-evaluator-proxy.ts:19-21',
     'trace 终点改为 eval sink'],
    ['entry-00103', 'entry_point', 'webhook-helpers.ts:615', 'webhook-request-handler.ts:146-155',
     "原 entry_point 为 '}' 非执行点，修正为用户可控 content-type 进入校验的 setResponseHeaders"],
    ['entry-00103', 'trace', 'starts at webhook-helpers.ts:615', 'starts at webhook-request-handler.ts:146-155',
     'trace 起点改为真实输入入口'],
    ['entry-00176', 'critical_operation', 'constants.py:126', 'task_analyzer.py:63-69',
     '原 critical 为静态列表定义（数据源），修正为真正生效的 AST 校验点 visit_Attribute'],
    ['entry-00511', 'critical_operation', 'extend.ts:82-84', 'extend.ts:132-134',
     '原 critical 为缺失检查的 native 回退分支，修正为真正执行代码的 .apply 调用'],
    ['entry-00511', 'trace', 'ends at extend.ts:79-85', 'ends at extend.ts:132-134',
     'trace 终点改为 .apply 执行点'],
    ['entry-00512', 'critical_operation', 'reset.ts:46 (desc imprecise)', 'reset.ts:46 (refined desc)',
     '保留真实弱点槽位赋值点，仅细化 desc 说明'],
]
with open(OUT_CSV, 'w', encoding='utf-8') as f:
    for r in csv_rows:
        f.write(','.join('"%s"' % c.replace('"', '""') for c in r) + '\n')

# ---------------- notes markdown ----------------
notes = []
notes.append('# VulnGym n8n 样本修复说明（entry-00099 / 00100 / 00103 / 00176 / 00511 / 00512）\n')
notes.append('> 交付物：`entries.fixed.jsonl`（6 条修正片段）、本说明、以及 `entries.fixed.diff.csv`。\n')
notes.append('> 修正原则：将落在 **sanitizer / 静态列表 / 非执行点** 上的 critical_operation 与 entry_point，'
             '重新指向真实的外部输入入口与代码执行 sink；仅对确属根因缺陷的防护缺口（如 html-sandbox 缺 `.trim()`、'
             'reset.ts 可覆写 `__sanitize` 槽位）予以保留并细化说明。\n')

def block(eid, title, problem, fixloc, reason, rejected):
    notes.append('## %s — %s\n' % (eid, title))
    notes.append('- **原问题**：%s\n' % problem)
    notes.append('- **修复位置**：%s\n' % fixloc)
    notes.append('- **选择该位置的理由**：%s\n' % reason)
    notes.append('- **未采用候选点的原因**：%s\n' % rejected)

block('entry-00099', 'Workflow Expression Sandbox Escape (GHSA-5XRP-6693-JJX9)',
      'critical_operation 被置于 PrototypeSanitizer 定义（expression-sandboxing.ts:244）。'
      'PrototypeSanitizer 是防御方钩子，其缺少 visitWithStatement 处理器是根因缺口，但“RCE sink 落在 sanitizer 上”语义不准确——'
      '它并不是代码被实际执行的位置。',
      'critical_operation 改为 expression-evaluator-proxy.ts:19-21（evaluateExpression → tournamentEvaluator.execute）；'
      'trace 终点同步改为该 eval sink，并保留 PrototypeSanitizer:244 作为根因节点。',
      'evaluateExpression 是表达式字符串被宿主引擎实际编译执行的唯一公共出口，逃逸后的 with 语句在此落地为任意代码，'
      '是真正体现“RCE”的执行点。',
      '候选 PrototypeSanitizer:244 仅表示防御缺口，不是执行点；Tournament.execute 内部实现过于底层且非公开 API，'
      '不如 evaluateExpression 这一清晰 sink 适合作为 ground truth。')

block('entry-00100', '同上 advisory 第二条（__sanitize 局部遮蔽路径）',
      'critical_operation 被置于 sanitizer 函数定义（expression-sandboxing.ts:330-336）。该定义是防御实现，'
      '并非 __sanitize 遮蔽绕过链路中代码被执行的位置。',
      'critical_operation 改为 expression-evaluator-proxy.ts:19-21（evaluateExpression）；trace 终点改为该 eval sink。',
      '与 00099 同一 advisory、同一真实执行点；本条目沿 __sanitize 局部遮蔽路径最终仍经 tournamentEvaluator.execute 执行。',
      '候选 sanitizer:330-336 是防御实现而非 sink；entry_point（expression.ts:368 resolveSimpleParameterValue）已正确，不应改动。')

block('entry-00103', 'webhook Content-Type CSP 绕过 (GHSA-825Q-W924-XHGX)',
      'entry_point 被置于 webhook-helpers.ts:615 的 `}` 闭合括号，属非执行点，无法体现外部可控的 content-type 如何进入漏洞链路；'
      '且其 trace[0]（同一 `}`）亦为无效锚点。',
      'entry_point 改为 webhook-request-handler.ts:146-155（setResponseHeaders：res.setHeader 写入用户 content-type，'
      '随后 getHeader 读回并传入 isHtmlRenderedContentType）；trace 起点同步修正。critical_operation（html-sandbox.ts:20，'
      '缺 .trim()）确为根因缺陷，予以保留。',
      'setResponseHeaders 是工作流用户指定的 content-type 头真正被写入响应并读回校验的环节，是外部输入进入 CSP 判定链路的准确入口。',
      '候选 webhook-helpers.ts:615 `}` 仅是代码块边界、无执行语义；streaming 分支（605-614）只是把 res 交给下游，'
      '真正施加并读回 content-type 的是 setResponseHeaders，故选其而非仅取 streaming 分支。')

block('entry-00176', 'Python Code 节点 __objclass__ 沙箱逃逸 (GHSA-MMGG-M5J7-F83H)',
      'critical_operation 被置于 constants.py:126 的 BLOCKED_ATTRIBUTES 静态集合定义。该集合只是被 visit_Attribute 引用的数据源，'
      '本身不执行任何校验，是“关键操作落在静态列表”的典型问题。',
      'critical_operation 改为 task_analyzer.py:63-69（visit_Attribute 的 `if node.attr in BLOCKED_ATTRIBUTES:` 强制点）。',
      'visit_Attribute 是 AST 静态校验真正生效的位置：它逐节点提取 node.attr 与 BLOCKED_ATTRIBUTES 比对，'
      '因集合漏列 __objclass__ 而对该属性访问静默放行，逃逸由此成立。',
      '候选 constants.py:126 仅是数据，不决定放行/拦截；候选 task_runner.py:321 的 validate() 调用只是入口，'
      '实际逐节点判定发生在 visit_Attribute，故选其作为 critical。')

block('entry-00511', 'VM 表达式引擎沙箱逃逸 extend→constructor (GHSA-6CQR-8CFR-67F8)',
      'critical_operation 被置于 findExtendedFunction 的 native 回退分支（extend.ts:82-84）。该分支“缺失函数名检查”是缺陷，'
      '但本身不执行代码，未体现 RCE 的真正发生点。',
      'critical_operation 改为 extend.ts:132-134（foundFunction.function.apply(input, args)）；'
      'trace 终点同步改为该 .apply 执行点，保留 79-85 回退分支作为上游缺失检查节点。',
      'Function 构造函数在 native 回退中被解析出来后，正是在 .apply 处被调用并执行攻击者传入的代码字符串，'
      '这是整条链路中代码真正落地的执行 sink。',
      '候选 native 回退 82-84 仅“选中”了 Function 构造函数而未执行；候选 entry_point（expression.ts:485 data.extend=extend）'
      '已正确描述暴露点，不应改动。')

block('entry-00512', '同上 advisory 第二条（VM 引擎 __sanitize 槽位可覆写路径）',
      'critical_operation 原置于 reset.ts:46（globalThis.__data.__sanitize = __sanitize 的普通赋值）。'
      '该位置是“可覆写 sanitizer 槽位”这一真实弱点，并非非执行点，语义基本正确，但原 desc 不够精确。',
      'critical_operation 位置（reset.ts:46）保留，仅细化 desc，说明该普通赋值使 __sanitize 槽位在运行期可被覆写为恒等函数，'
      '导致 PrototypeSanitizer 插入的全部过滤调用失效。entry_point（expression.ts:524 renderExpression）与 trace 保留不变。',
      '本技术路线是防御被削弱型逃逸：根因正是 __sanitize 槽位以可写方式暴露，运行期可被遮蔽，'
      '因此该赋值点就是核心缺陷所在，无需改指其他执行点。',
      '候选 renderExpression:524 是 host 侧入口（已作为 entry_point 正确保留）；候选 PrototypeSanitizer 编译期改写是防御方，'
      '不是本路径的失守点，故均不采用。')

with open(OUT_NOTES, 'w', encoding='utf-8') as f:
    f.write('\n'.join(notes))

print('DONE: wrote', OUT_JSONL, OUT_CSV, OUT_NOTES)
