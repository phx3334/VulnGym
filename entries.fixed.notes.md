# VulnGym n8n 样本修复说明（entry-00099 / 00100 / 00103 / 00176 / 00511 / 00512）

> 交付物：`entries.fixed.jsonl`（6 条修正片段）、本说明、以及 `entries.fixed.diff.csv`。

> 修正原则：将落在 **sanitizer / 静态列表 / 非执行点** 上的 critical_operation 与 entry_point，重新指向真实的外部输入入口与代码执行 sink；仅对确属根因缺陷的防护缺口（如 html-sandbox 缺 `.trim()`、reset.ts 可覆写 `__sanitize` 槽位）予以保留并细化说明。

## entry-00099 — Workflow Expression Sandbox Escape (GHSA-5XRP-6693-JJX9)

- **原问题**：critical_operation 被置于 PrototypeSanitizer 定义（expression-sandboxing.ts:244）。PrototypeSanitizer 是防御方钩子，其缺少 visitWithStatement 处理器是根因缺口，但“RCE sink 落在 sanitizer 上”语义不准确——它并不是代码被实际执行的位置。

- **修复位置**：critical_operation 改为 expression-evaluator-proxy.ts:19-21（evaluateExpression → tournamentEvaluator.execute）；trace 终点同步改为该 eval sink，并保留 PrototypeSanitizer:244 作为根因节点。

- **选择该位置的理由**：evaluateExpression 是表达式字符串被宿主引擎实际编译执行的唯一公共出口，逃逸后的 with 语句在此落地为任意代码，是真正体现“RCE”的执行点。

- **未采用候选点的原因**：候选 PrototypeSanitizer:244 仅表示防御缺口，不是执行点；Tournament.execute 内部实现过于底层且非公开 API，不如 evaluateExpression 这一清晰 sink 适合作为 ground truth。

## entry-00100 — 同上 advisory 第二条（__sanitize 局部遮蔽路径）

- **原问题**：critical_operation 被置于 sanitizer 函数定义（expression-sandboxing.ts:330-336）。该定义是防御实现，并非 __sanitize 遮蔽绕过链路中代码被执行的位置。

- **修复位置**：critical_operation 改为 expression-evaluator-proxy.ts:19-21（evaluateExpression）；trace 终点改为该 eval sink。

- **选择该位置的理由**：与 00099 同一 advisory、同一真实执行点；本条目沿 __sanitize 局部遮蔽路径最终仍经 tournamentEvaluator.execute 执行。

- **未采用候选点的原因**：候选 sanitizer:330-336 是防御实现而非 sink；entry_point（expression.ts:368 resolveSimpleParameterValue）已正确，不应改动。

## entry-00103 — webhook Content-Type CSP 绕过 (GHSA-825Q-W924-XHGX)

- **原问题**：entry_point 被置于 webhook-helpers.ts:615 的 `}` 闭合括号，属非执行点，无法体现外部可控的 content-type 如何进入漏洞链路；且其 trace[0]（同一 `}`）亦为无效锚点。

- **修复位置**：entry_point 改为 webhook-request-handler.ts:146-155（setResponseHeaders：res.setHeader 写入用户 content-type，随后 getHeader 读回并传入 isHtmlRenderedContentType）；trace 起点同步修正。critical_operation（html-sandbox.ts:20，缺 .trim()）确为根因缺陷，予以保留。

- **选择该位置的理由**：setResponseHeaders 是工作流用户指定的 content-type 头真正被写入响应并读回校验的环节，是外部输入进入 CSP 判定链路的准确入口。

- **未采用候选点的原因**：候选 webhook-helpers.ts:615 `}` 仅是代码块边界、无执行语义；streaming 分支（605-614）只是把 res 交给下游，真正施加并读回 content-type 的是 setResponseHeaders，故选其而非仅取 streaming 分支。

## entry-00176 — Python Code 节点 __objclass__ 沙箱逃逸 (GHSA-MMGG-M5J7-F83H)

- **原问题**：critical_operation 被置于 constants.py:126 的 BLOCKED_ATTRIBUTES 静态集合定义。该集合只是被 visit_Attribute 引用的数据源，本身不执行任何校验，是“关键操作落在静态列表”的典型问题。

- **修复位置**：critical_operation 改为 task_analyzer.py:63-69（visit_Attribute 的 `if node.attr in BLOCKED_ATTRIBUTES:` 强制点）。

- **选择该位置的理由**：visit_Attribute 是 AST 静态校验真正生效的位置：它逐节点提取 node.attr 与 BLOCKED_ATTRIBUTES 比对，因集合漏列 __objclass__ 而对该属性访问静默放行，逃逸由此成立。

- **未采用候选点的原因**：候选 constants.py:126 仅是数据，不决定放行/拦截；候选 task_runner.py:321 的 validate() 调用只是入口，实际逐节点判定发生在 visit_Attribute，故选其作为 critical。

## entry-00511 — VM 表达式引擎沙箱逃逸 extend→constructor (GHSA-6CQR-8CFR-67F8)

- **原问题**：critical_operation 被置于 findExtendedFunction 的 native 回退分支（extend.ts:82-84）。该分支“缺失函数名检查”是缺陷，但本身不执行代码，未体现 RCE 的真正发生点。

- **修复位置**：critical_operation 改为 extend.ts:132-134（foundFunction.function.apply(input, args)）；trace 终点同步改为该 .apply 执行点，保留 79-85 回退分支作为上游缺失检查节点。

- **选择该位置的理由**：Function 构造函数在 native 回退中被解析出来后，正是在 .apply 处被调用并执行攻击者传入的代码字符串，这是整条链路中代码真正落地的执行 sink。

- **未采用候选点的原因**：候选 native 回退 82-84 仅“选中”了 Function 构造函数而未执行；候选 entry_point（expression.ts:485 data.extend=extend）已正确描述暴露点，不应改动。

## entry-00512 — 同上 advisory 第二条（VM 引擎 __sanitize 槽位可覆写路径）

- **原问题**：critical_operation 原置于 reset.ts:46（globalThis.__data.__sanitize = __sanitize 的普通赋值）。该位置是“可覆写 sanitizer 槽位”这一真实弱点，并非非执行点，语义基本正确，但原 desc 不够精确。

- **修复位置**：critical_operation 位置（reset.ts:46）保留，仅细化 desc，说明该普通赋值使 __sanitize 槽位在运行期可被覆写为恒等函数，导致 PrototypeSanitizer 插入的全部过滤调用失效。entry_point（expression.ts:524 renderExpression）与 trace 保留不变。

- **选择该位置的理由**：本技术路线是防御被削弱型逃逸：根因正是 __sanitize 槽位以可写方式暴露，运行期可被遮蔽，因此该赋值点就是核心缺陷所在，无需改指其他执行点。

- **未采用候选点的原因**：候选 renderExpression:524 是 host 侧入口（已作为 entry_point 正确保留）；候选 PrototypeSanitizer 编译期改写是防御方，不是本路径的失守点，故均不采用。
