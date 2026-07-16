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
# evaluation sink for c1 (00099/00100)
Dl '8ab4492e8c0b743455e51fc111441d8d5010a6ad' 'packages/workflow/src/expression-evaluator-proxy.ts' 'c1_expression-evaluator-proxy.ts'
# caller of isHtmlRenderedContentType for c2 (00103) - decide CSP
Dl '57d6015f2ea0442c24e0449105325b7e36f066df' 'packages/cli/src/webhooks/webhook-response.ts' 'c2_webhook-response.ts'
# python AST visitor for c3 (00176)
Dl '3af9095245be3aaad6bc16622f379f79c6c6068f' 'packages/@n8n/task-runner-python/src/task_analyzer.py' 'c3_task_analyzer.py'
