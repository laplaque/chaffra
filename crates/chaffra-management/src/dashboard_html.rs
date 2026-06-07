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
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;cursor:pointer;transition:border-color 0.15s}
.card:hover{border-color:#58a6ff}
.card h3{font-size:14px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}
.card .value{font-size:32px;font-weight:700;color:#58a6ff}
.card .value.green{color:#3fb950}
.card .value.yellow{color:#d29922}
.card .value.red{color:#f85149}
.section{margin-bottom:24px}
.section h2{font-size:18px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #30363d}
.section-header{display:flex;align-items:center;justify-content:space-between}
.section-header .inspect-btn{background:#21262d;color:#8b949e;border:1px solid #30363d;border-radius:4px;padding:2px 8px;font-size:12px;cursor:pointer;font-family:monospace}
.section-header .inspect-btn:hover{color:#58a6ff;border-color:#58a6ff}
table{width:100%;border-collapse:collapse}
table th,table td{text-align:left;padding:8px 12px;border-bottom:1px solid #21262d}
table th{color:#8b949e;font-size:13px;font-weight:600}
.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.status-dot.ok{background:#3fb950}
.status-dot.error{background:#f85149}
.status-dot.unknown{background:#8b949e}
.refresh-info{color:#8b949e;font-size:12px;text-align:right;margin-top:8px}
#error-banner{display:none;background:#f8514922;border:1px solid #f85149;color:#f85149;padding:12px;border-radius:8px;margin-bottom:16px}
#detail-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);z-index:100}
#detail-panel{position:fixed;top:10%;right:0;bottom:0;width:520px;background:#161b22;border-left:1px solid #30363d;z-index:101;display:none;flex-direction:column}
#detail-panel .dp-header{display:flex;align-items:center;justify-content:space-between;padding:16px;border-bottom:1px solid #30363d}
#detail-panel .dp-header h3{font-size:16px}
#detail-panel .dp-close{background:none;border:none;color:#8b949e;font-size:20px;cursor:pointer;padding:4px 8px}
#detail-panel .dp-close:hover{color:#e1e4e8}
#detail-panel .dp-body{flex:1;overflow-y:auto;padding:16px}
#detail-panel .dp-body pre{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:12px;font-size:13px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;color:#e1e4e8}
#detail-panel .dp-body table{margin-top:8px}
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
<div class="section-header">
<h2>Modules</h2>
<button class="inspect-btn" onclick="showDetail('/modules','Modules')">Inspect JSON</button>
</div>
<table id="modules-table">
<thead><tr><th>Module</th><th>Status</th><th>Findings</th><th>Duration</th></tr></thead>
<tbody></tbody>
</table>
</div>
<div class="section">
<div class="section-header">
<h2>Telemetry Backends</h2>
<button class="inspect-btn" onclick="showDetail('/metrics','Metrics')">Inspect JSON</button>
</div>
<table id="backends-table">
<thead><tr><th>Backend</th><th>Type</th><th>Status</th><th>Message</th></tr></thead>
<tbody></tbody>
</table>
</div>
<div class="section">
<div class="section-header">
<h2>Finding Churn</h2>
<button class="inspect-btn" onclick="showDetail('/findings/churn','Finding Churn')">Inspect JSON</button>
</div>
<div class="grid" id="churn-cards"></div>
</div>
<div class="section">
<div class="section-header">
<h2>Configuration</h2>
<button class="inspect-btn" onclick="showDetail('/config','Configuration')">Inspect JSON</button>
</div>
<div id="config-summary"></div>
</div>
<div class="refresh-info">Auto-refreshes every 10s</div>
</div>
<div id="detail-overlay" onclick="closeDetail()"></div>
<div id="detail-panel">
<div class="dp-header">
<h3 id="detail-title"></h3>
<button class="dp-close" onclick="closeDetail()">&times;</button>
</div>
<div class="dp-body" id="detail-body"></div>
</div>
<script>
const BASE='/api/v1';
function el(id){return document.getElementById(id)}
function card(title,value,cls,endpoint){
  return `<div class="card" onclick="showDetail('${endpoint}','${title}')"><h3>${title}</h3><div class="value ${cls||''}">${value}</div></div>`;
}
async function fetchJSON(path){
  const r=await fetch(BASE+path);
  if(!r.ok)throw new Error(r.statusText);
  return r.json();
}
function closeDetail(){
  el('detail-overlay').style.display='none';
  el('detail-panel').style.display='none';
}
function renderTable(headers,rows){
  let h='<table><thead><tr>'+headers.map(c=>'<th>'+c+'</th>').join('')+'</tr></thead><tbody>';
  for(const r of rows)h+='<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>';
  return h+'</tbody></table>';
}
function hdr(t){return '<h4 style="margin:16px 0 8px;color:#8b949e">'+t+'</h4>';}
function bar(pct,color){return '<div style="display:inline-block;width:80px;height:10px;background:#21262d;border-radius:3px;vertical-align:middle;margin-right:6px"><div style="width:'+Math.min(100,Math.max(0,pct))+'%;height:100%;background:'+(color||'#58a6ff')+';border-radius:3px"></div></div>';}
function sevColor(s){return s==='error'?'#f85149':s==='warning'?'#d29922':'#8b949e';}
function insight(text){return '<div style="margin:12px 0;padding:10px 12px;background:#0d1117;border-left:3px solid #58a6ff;border-radius:0 4px 4px 0;font-size:13px;color:#c9d1d9">'+text+'</div>';}
async function showDetail(endpoint,title){
  el('detail-title').textContent=title;
  let html='';
  try{
    if(endpoint==='/health'){
      const[health,metrics,modules,findings]=await Promise.all([fetchJSON('/health'),fetchJSON('/metrics'),fetchJSON('/modules'),fetchJSON('/findings/summary')]);
      const avg=health.score;
      html+=hdr('Aggregate Health');
      html+=renderTable(['Metric','Value'],[['Score',avg!=null?avg.toFixed(1):'—'],['Grade',health.grade]]);
      const hps=metrics.data_points.filter(p=>p.name.includes('.health_score')).map(p=>{
        const mid=p.name.replace('chaffra.module.','').replace('.health_score','');
        const mod=modules.modules.find(m=>m.id===mid);
        const fc=(findings.by_module||{})[mid]||0;
        return {module:mid,score:p.value,findings:fc,duration:mod?mod.duration_ms:0,status:mod?mod.status:'—',delta:avg!=null?p.value-avg:0};
      }).sort((a,b)=>a.score-b.score);
      if(hps.length){
        html+=hdr('Per-module Health (sorted worst-first)');
        html+=renderTable(['Module','Score','','Findings','Duration','Status'],hps.map(h=>{
          const c=h.score>=80?'#3fb950':h.score>=60?'#d29922':'#f85149';
          return [h.module,h.score.toFixed(1),bar(h.score,c),h.findings,h.duration+'ms','<span class="status-dot '+(h.status==='error'?'error':'ok')+'"></span>'+h.status];
        }));
        if(avg!=null){
          const worst=hps[0];
          html+=insight('Lowest contributor: <strong>'+worst.module+'</strong> at '+worst.score.toFixed(1)+' ('+(worst.delta>=0?'+':'')+worst.delta.toFixed(1)+' from average). '+(worst.findings>0?worst.findings+' finding(s) from this module.':'No findings from this module.'));
        }
      }
      const errs=metrics.data_points.filter(p=>p.name==='chaffra.module.error_total');
      if(errs.length){
        html+=hdr('Module Errors');
        html+=renderTable(['Module','Error Count'],errs.map(e=>[e.labels.module||'—',e.value]));
      }
    }else if(endpoint==='/findings/summary'){
      const[findings,metrics,modules]=await Promise.all([fetchJSON('/findings/summary'),fetchJSON('/metrics'),fetchJSON('/modules')]);
      html+=hdr('Severity Breakdown');
      const sevs=Object.entries(findings.by_severity).sort((a,b)=>b[1]-a[1]);
      const maxSev=sevs.length?sevs[0][1]:1;
      html+=renderTable(['Severity','Count',''],sevs.map(([s,c])=>[s,c,bar(c/maxSev*100,sevColor(s))]));
      const bySev=metrics.data_points.filter(p=>p.name==='chaffra.analysis.findings_by_severity');
      if(bySev.length){
        html+=hdr('Module x Severity');
        const mods=new Map();
        for(const p of bySev){
          const mid=p.labels.module||'—';
          if(!mods.has(mid))mods.set(mid,{});
          mods.get(mid)[p.labels.severity||'—']=p.value;
        }
        const allSevs=[...new Set(bySev.map(p=>p.labels.severity||'—'))].sort();
        const rows=[];
        for(const[mid,ss]of mods){
          const mod=modules.modules.find(m=>m.id===mid);
          const total=Object.values(ss).reduce((a,b)=>a+b,0);
          rows.push({mid,ss,total,dur:mod?mod.duration_ms:0});
        }
        rows.sort((a,b)=>b.total-a.total);
        html+=renderTable(['Module',...allSevs,'Total','Duration'],rows.map(r=>[r.mid,...allSevs.map(s=>(r.ss[s]||0).toString()),r.total,r.dur+'ms']));
        if(rows.length){
          const top=rows[0];
          const topSev=Object.entries(top.ss).sort((a,b)=>b[1]-a[1])[0];
          html+=insight('Highest concentration: <strong>'+top.mid+'</strong> with '+top.total+' finding(s). '+(topSev?'Most common severity: '+topSev[0]+' ('+topSev[1]+').':''));
        }
      }else{
        html+=hdr('By Module');
        const mods=Object.entries(findings.by_module).sort((a,b)=>b[1]-a[1]);
        html+=renderTable(['Module','Findings'],mods.map(([k,v])=>[k,v]));
      }
    }else if(endpoint==='/modules'){
      const[modules,metrics,findings]=await Promise.all([fetchJSON('/modules'),fetchJSON('/metrics'),fetchJSON('/findings/summary')]);
      html+=hdr('Module Performance');
      const totalDur=modules.modules.reduce((s,m)=>s+m.duration_ms,0)||1;
      const sorted=[...modules.modules].sort((a,b)=>b.duration_ms-a.duration_ms);
      html+=renderTable(['Module','Status','Duration','% of Total','Findings','Rate'],sorted.map(m=>{
        const pct=(m.duration_ms/totalDur*100);
        const rate=m.duration_ms>0?(m.finding_count/(m.duration_ms/1000)).toFixed(1)+'/s':'—';
        return [m.id,'<span class="status-dot '+(m.status==='error'?'error':'ok')+'"></span>'+m.status,m.duration_ms+'ms',bar(pct)+(pct).toFixed(1)+'%',m.finding_count,rate];
      }));
      const modMetrics=new Map();
      for(const p of metrics.data_points){
        if(p.name.startsWith('chaffra.module.')&&!['chaffra.module.call_duration_ms','chaffra.module.error_total','chaffra.module.startup_duration_ms','chaffra.module.load_error_total'].includes(p.name)){
          const parts=p.name.replace('chaffra.module.','').split('.');
          if(parts.length>=2){
            const mid=parts.slice(0,-1).join('.');
            const key=parts[parts.length-1];
            if(!modMetrics.has(mid))modMetrics.set(mid,{});
            modMetrics.get(mid)[key]=p.value;
          }
        }
      }
      if(modMetrics.size){
        html+=hdr('Module-specific Metrics');
        for(const[mid,kv]of modMetrics){
          html+='<div style="margin:8px 0 4px;font-size:13px;color:#58a6ff;font-weight:600">'+mid+'</div>';
          html+=renderTable(['Metric','Value'],Object.entries(kv).map(([k,v])=>[k,typeof v==='number'?v.toFixed(2):v]));
        }
      }
      const errMods=modules.modules.filter(m=>m.status==='error');
      if(errMods.length){
        html+=insight(errMods.length+' module(s) in error state: '+errMods.map(m=>'<strong>'+m.id+'</strong>').join(', ')+'.');
      }
    }else if(endpoint==='/findings/churn'){
      const[churn,findings]=await Promise.all([fetchJSON('/findings/churn'),fetchJSON('/findings/summary')]);
      html+=hdr('Churn Summary');
      html+=renderTable(['Metric','Value'],[['New findings',churn.new_count],['Resolved findings',churn.resolved_count],['Unchanged',churn.unchanged_count],['Churn rate',(churn.churn_rate*100).toFixed(1)+'%']]);
      const net=churn.new_count-churn.resolved_count;
      const total=findings.total||0;
      let status,color;
      if(net<0){status='Improving';color='#3fb950';}
      else if(net===0){status='Stable';color='#8b949e';}
      else{status='Degrading';color='#f85149';}
      html+=hdr('Trend Analysis');
      html+='<div style="margin:8px 0;font-size:24px;font-weight:700;color:'+color+'">'+status+'</div>';
      html+=renderTable(['Metric','Value'],[
        ['Net change (new - resolved)',(net>=0?'+':'')+net],
        ['Total current findings',total],
        ['Churn as % of total',total>0?((churn.new_count+churn.resolved_count)/total*100).toFixed(1)+'%':'—']
      ]);
      if(net>0)html+=insight(net+' more finding(s) introduced than resolved. '+churn.new_count+' new finding(s) against '+churn.unchanged_count+' unchanged — churn rate '+(churn.churn_rate*100).toFixed(1)+'%.');
      else if(net<0)html+=insight(Math.abs(net)+' more finding(s) resolved than introduced. Codebase quality is improving.');
      else html+=insight('Equal new and resolved findings. Codebase churn is stable.');
    }else if(endpoint==='/metrics'){
      const metrics=await fetchJSON('/metrics');
      html+=hdr('Backend Status');
      html+=renderTable(['Name','Kind','Status','Message'],(metrics.backends||[]).map(b=>[b.name,b.kind,'<span class="status-dot '+(b.connected?'ok':'error')+'"></span>'+(b.connected?'Connected':'Disconnected'),b.message]));
      html+=hdr('Metric Coverage');
      const grouped=new Map();
      for(const p of metrics.data_points){
        if(!grouped.has(p.name))grouped.set(p.name,{count:0,labels:new Set()});
        const g=grouped.get(p.name);
        g.count++;
        for(const k of Object.keys(p.labels))g.labels.add(k);
      }
      html+=renderTable(['Metric Name','Data Points','Label Dimensions'],[...grouped.entries()].sort((a,b)=>b[1].count-a[1].count).map(([n,g])=>[n,g.count,[...g.labels].join(', ')||'none']));
      html+=insight(metrics.data_points.length+' data point(s) across '+grouped.size+' distinct metric(s). '+(metrics.backends||[]).filter(b=>b.connected).length+' of '+(metrics.backends||[]).length+' backend(s) connected.');
    }else if(endpoint==='/config'){
      const[cfg,metrics]=await Promise.all([fetchJSON('/config'),fetchJSON('/metrics')]);
      html+=hdr('Telemetry Configuration');
      html+=renderTable(['Setting','Value'],[['Audience',cfg.audience],['Sampling Rate',cfg.sampling_rate],['Sampling Strategy',cfg.sampling_strategy],['Backends',cfg.backends.join(', ')||'—']]);
      html+=hdr('Collection Summary');
      const metricNames=new Set(metrics.data_points.map(p=>p.name));
      html+=renderTable(['Metric','Value'],[
        ['Active metrics',metricNames.size],
        ['Total data points',metrics.data_points.length],
        ['Connected backends',(metrics.backends||[]).filter(b=>b.connected).length+' / '+(metrics.backends||[]).length]
      ]);
      if(cfg.sampling_rate<1.0)html+=insight('Sampling rate is '+(cfg.sampling_rate*100).toFixed(0)+'% — operator metrics are emitted on ~1 in '+Math.round(1/cfg.sampling_rate)+' runs.');
    }else{
      const data=await fetchJSON(endpoint);
      html='<pre>'+JSON.stringify(data,null,2).replace(/</g,'&lt;')+'</pre>';
    }
  }catch(e){
    html='<pre>Error: '+e.message+'</pre>';
  }
  el('detail-body').innerHTML=html;
  el('detail-overlay').style.display='block';
  el('detail-panel').style.display='flex';
}
async function refresh(){
  try{
    const[health,modules,findings,churn,metrics,config]=await Promise.all([
      fetchJSON('/health'),fetchJSON('/modules'),fetchJSON('/findings/summary'),
      fetchJSON('/findings/churn'),fetchJSON('/metrics'),fetchJSON('/config')
    ]);
    el('error-banner').style.display='none';
    el('status-badge').textContent='Connected';
    el('status-badge').style.background='#238636';
    let cards='';
    cards+=card('Health Score',health.score!=null?health.score:'—',
      health.score>=80?'green':health.score>=60?'yellow':'red','/health');
    cards+=card('Total Findings',findings.total!=null?findings.total:'—','','/findings/summary');
    cards+=card('Files Analyzed',metrics.files_total!=null?metrics.files_total:'—','','/metrics');
    cards+=card('Analysis Duration',metrics.analysis_duration_ms!=null?metrics.analysis_duration_ms+'ms':'—','','/metrics');
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
    cc+=card('New',churn.new_count!=null?churn.new_count:'0','red','/findings/churn');
    cc+=card('Resolved',churn.resolved_count!=null?churn.resolved_count:'0','green','/findings/churn');
    cc+=card('Unchanged',churn.unchanged_count!=null?churn.unchanged_count:'0','','/findings/churn');
    el('churn-cards').innerHTML=cc;
    el('config-summary').innerHTML=`<table><tr><td>Audience</td><td>${config.audience}</td></tr><tr><td>Sampling</td><td>${config.sampling_rate} (${config.sampling_strategy})</td></tr><tr><td>Backends</td><td>${config.backends.join(', ')||'—'}</td></tr></table>`;
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
