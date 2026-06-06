pub const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Chaffra Management Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f1117;color:#e1e4e8;line-height:1.6}
.header{background:#161b22;border-bottom:1px solid #30363d;padding:16px 24px;display:flex;align-items:center;gap:12px}
.header h1{font-size:20px;font-weight:600}
.header .badge{background:#238636;color:#fff;padding:2px 8px;border-radius:12px;font-size:12px}
.container{max-width:1200px;margin:0 auto;padding:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px}
.card h3{font-size:14px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}
.card .value{font-size:32px;font-weight:700;color:#58a6ff}
.card .value.green{color:#3fb950}
.card .value.yellow{color:#d29922}
.card .value.red{color:#f85149}
.section{margin-bottom:24px}
.section h2{font-size:18px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #30363d}
table{width:100%;border-collapse:collapse}
table th,table td{text-align:left;padding:8px 12px;border-bottom:1px solid #21262d}
table th{color:#8b949e;font-size:13px;font-weight:600}
.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.status-dot.ok{background:#3fb950}
.status-dot.error{background:#f85149}
.status-dot.unknown{background:#8b949e}
.sparkline{display:flex;align-items:flex-end;gap:1px;height:30px}
.sparkline .bar{background:#58a6ff;min-width:3px;border-radius:1px 1px 0 0}
.refresh-info{color:#8b949e;font-size:12px;text-align:right;margin-top:8px}
#error-banner{display:none;background:#f8514922;border:1px solid #f85149;color:#f85149;padding:12px;border-radius:8px;margin-bottom:16px}
</style>
</head>
<body>
<div class="header">
<h1>Chaffra</h1>
<span class="badge" id="status-badge">Loading...</span>
</div>
<div class="container">
<div id="error-banner"></div>
<div class="grid" id="summary-cards"></div>
<div class="section">
<h2>Modules</h2>
<table id="modules-table">
<thead><tr><th>Module</th><th>Status</th><th>Findings</th><th>Duration</th></tr></thead>
<tbody></tbody>
</table>
</div>
<div class="section">
<h2>Telemetry Backends</h2>
<table id="backends-table">
<thead><tr><th>Backend</th><th>Type</th><th>Status</th><th>Message</th></tr></thead>
<tbody></tbody>
</table>
</div>
<div class="section">
<h2>Finding Churn</h2>
<div class="grid" id="churn-cards"></div>
</div>
<div class="refresh-info">Auto-refreshes every 10s | <a href="/api/v1/metrics" style="color:#58a6ff">API</a></div>
</div>
<script>
const BASE='/api/v1';
function el(id){return document.getElementById(id)}
function card(title,value,cls){return `<div class="card"><h3>${title}</h3><div class="value ${cls||''}">${value}</div></div>`}
async function fetchJSON(path){
  const r=await fetch(BASE+path);
  if(!r.ok)throw new Error(r.statusText);
  return r.json();
}
async function refresh(){
  try{
    const[health,modules,findings,churn,metrics]=await Promise.all([
      fetchJSON('/health'),fetchJSON('/modules'),fetchJSON('/findings/summary'),
      fetchJSON('/findings/churn'),fetchJSON('/metrics')
    ]);
    el('error-banner').style.display='none';
    el('status-badge').textContent='Connected';
    el('status-badge').style.background='#238636';
    let cards='';
    cards+=card('Health Score',health.score!=null?health.score:'—',
      health.score>=80?'green':health.score>=60?'yellow':'red');
    cards+=card('Total Findings',findings.total!=null?findings.total:'—');
    cards+=card('Files Analyzed',metrics.files_total!=null?metrics.files_total:'—');
    cards+=card('Analysis Duration',metrics.analysis_duration_ms!=null?metrics.analysis_duration_ms+'ms':'—');
    el('summary-cards').innerHTML=cards;
    let mrows='';
    if(modules.modules){for(const m of modules.modules){
      const dot=m.status==='healthy'?'ok':m.status==='error'?'error':'unknown';
      mrows+=`<tr><td>${m.id}</td><td><span class="status-dot ${dot}"></span>${m.status}</td><td>${m.finding_count!=null?m.finding_count:'—'}</td><td>${m.duration_ms!=null?m.duration_ms+'ms':'—'}</td></tr>`;
    }}
    el('modules-table').querySelector('tbody').innerHTML=mrows||'<tr><td colspan="4">No modules loaded</td></tr>';
    let brows='';
    if(metrics.backends){for(const b of metrics.backends){
      const dot=b.connected?'ok':'error';
      brows+=`<tr><td>${b.name}</td><td>${b.kind}</td><td><span class="status-dot ${dot}"></span>${b.connected?'Connected':'Disconnected'}</td><td>${b.message}</td></tr>`;
    }}
    el('backends-table').querySelector('tbody').innerHTML=brows||'<tr><td colspan="4">No backends configured</td></tr>';
    let cc='';
    cc+=card('New',churn.new_count!=null?churn.new_count:'0','red');
    cc+=card('Resolved',churn.resolved_count!=null?churn.resolved_count:'0','green');
    cc+=card('Unchanged',churn.unchanged_count!=null?churn.unchanged_count:'0');
    el('churn-cards').innerHTML=cc;
  }catch(e){
    el('error-banner').textContent='Connection error: '+e.message;
    el('error-banner').style.display='block';
    el('status-badge').textContent='Disconnected';
    el('status-badge').style.background='#f85149';
  }
}
refresh();
setInterval(refresh,10000);
</script>
</body>
</html>"#;
