$ProgressPreference = 'SilentlyContinue'
$base = 'c:\Users\victor\Downloads\VulnGym'

function Dl($commit, $path, $out) {
    $url = "https://raw.githubusercontent.com/n8n-io/n8n/$commit/$path"
    try {
        Invoke-WebRequest -Uri $url -OutFile (Join-Path $base $out) -TimeoutSec 60
        Write-Host "OK $out $((Get-Item (Join-Path $base $out)).Length)"
    } catch {
        Write-Host "ERR $out $($_.Exception.Message)"
    }
}

# entry-00099 / 00100  (commit 8ab4492e8c0b743455e51fc111441d8d5010a6ad)
$c1 = '8ab4492e8c0b743455e51fc111441d8d5010a6ad'
Dl $c1 'packages/workflow/src/expression-sandboxing.ts' 'c1_expression-sandboxing.ts'
Dl $c1 'packages/workflow/src/expression.ts' 'c1_expression.ts'
Dl $c1 'packages/cli/src/workflows/workflows.controller.ts' 'c1_workflows.controller.ts'

# entry-00103  (commit 57d6015f2ea0442c24e0449105325b7e36f066df)
$c2 = '57d6015f2ea0442c24e0449105325b7e36f066df'
Dl $c2 'packages/core/src/html-sandbox.ts' 'c2_html-sandbox.ts'
Dl $c2 'packages/cli/src/webhooks/webhook-helpers.ts' 'c2_webhook-helpers.ts'

# entry-00176  (commit 3af9095245be3aaad6bc16622f379f79c6c6068f)
$c3 = '3af9095245be3aaad6bc16622f379f79c6c6068f'
Dl $c3 'packages/@n8n/task-runner-python/src/constants.py' 'c3_constants.py'
Dl $c3 'packages/nodes-base/nodes/Code/Code.node.ts' 'c3_Code.node.ts'

# entry-00511 / 00512  (commit 09e2c2b5547b49a824a8265d312583f5d1f5c79f)
$c4 = '09e2c2b5547b49a824a8265d312583f5d1f5c79f'
Dl $c4 'packages/@n8n/expression-runtime/src/extensions/extend.ts' 'c4_extend.ts'
Dl $c4 'packages/@n8n/expression-runtime/src/runtime/reset.ts' 'c4_reset.ts'
Dl $c4 'packages/workflow/src/expression.ts' 'c4_expression.ts'
