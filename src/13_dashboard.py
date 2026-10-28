"""Activity 8 - self-contained interactive remediation dashboard.

  python src/13_dashboard.py

Open results/dashboard.html in a browser. The page has no server or external
asset requirements; all charts and finding details are built into the file.
"""
import os

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = f"{ROOT}/results"
PLAN_PATH = f"{RESULTS}/remediation_plan.csv"
OUTPUT_PATH = f"{RESULTS}/dashboard.html"

# Outcome labels are intentionally excluded: the dashboard is for prioritizing
# findings, not displaying the future outcomes used to evaluate the ranker.
OUTCOME_COLUMNS = {"kev_12m", "poc_12m", "cand_kev", "cand_poc"}
FIELD_LABELS = {
    "rank": "Plan rank",
    "project": "Project",
    "name": "Package",
    "version": "Installed version",
    "ecosystem": "Ecosystem",
    "component": "Package identifier",
    "ghsa_id": "Advisory",
    "cve": "CVE",
    "has_cve": "Has CVE",
    "cvss_base": "CVSS base score",
    "severity_label": "Severity",
    "has_fix": "Fix available",
    "kev_at_T": "Already in KEV at snapshot",
    "kev_override": "KEV priority override",
    "poc_count_at_T": "Public PoCs known at snapshot",
    "epss_at_T": "EPSS at snapshot",
    "is_direct": "Direct dependency",
    "depth": "Dependency depth",
    "fan_in": "Direct dependents",
    "descendants": "Downstream dependents",
    "pagerank": "Graph PageRank",
    "days_since_last_release": "Days since last release",
    "releases_prior_12m": "Releases in prior 12 months",
    "version_lag_days": "Installed-version lag (days)",
    "abandoned": "Package marked abandoned",
    "exploit_pct": "Predicted exploitation percentile",
    "exploit_source": "Exploitation score source",
    "exposure": "Graph exposure score",
    "health_penalty": "Package-health penalty",
    "risk_score": "Combined risk score",
    "tier": "Priority tier",
    "action": "Recommended action",
    "reasons": "Recommendation reasons",
}

if not os.path.exists(PLAN_PATH):
    raise SystemExit(f"Missing {PLAN_PATH}. Run: python src/11_hybrid_engine.py")

plan = pd.read_csv(PLAN_PATH)
display_columns = [c for c in plan.columns if c not in OUTCOME_COLUMNS]
unknown = [c for c in display_columns if c not in FIELD_LABELS]
if unknown:
    raise SystemExit(f"Add dashboard labels for remediation fields: {', '.join(unknown)}")
display_plan = plan[display_columns].copy()
display_plan["project"] = display_plan["project"].str.replace("__", "/", regex=False)
data_json = display_plan.to_json(orient="records")

evaluation_path = f"{RESULTS}/hybrid_ablation.csv"
if os.path.exists(evaluation_path):
    evaluation = pd.read_csv(evaluation_path)
    evaluation_columns = [
        "label", "variant", "selected_on_validation", "positives", "roc_auc",
        "auc_ci95", "avg_precision", "recall_top5pct", "recall_top5_ci95",
    ]
    evaluation_json = evaluation[evaluation_columns].to_json(orient="records")
else:
    evaluation_json = "[]"

page = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Supply-chain remediation priorities</title>
<style>
:root{color-scheme:light dark;--bg:#f4f6fa;--card:#fff;--ink:#172033;--mut:#596579;--line:#dce2eb;--accent:#315fce;--p1:#c43d4d;--p2:#e18435;--p3:#e4b83f;--p4:#77859b;--green:#33866a}
@media(prefers-color-scheme:dark){:root{--bg:#10151d;--card:#18212d;--ink:#e7edf7;--mut:#a7b3c5;--line:#2b3849;--accent:#82aaff;--p1:#ed6673;--p2:#f0a35f;--p3:#e9c85d;--p4:#8b9bb4;--green:#69c5a1}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,Segoe UI,Arial,sans-serif}
.hero-header{position:relative;overflow:hidden;color:#f5f8ff;background:linear-gradient(115deg,#101d36 0%,#183967 55%,#28558e 100%);border-bottom:1px solid #28486f;padding:34px max(20px,calc((100vw - 1440px)/2)) 32px}
.hero-header:after{content:"";position:absolute;width:420px;height:420px;right:max(0px,calc((100vw - 1500px)/2));top:-260px;border:1px solid rgba(255,255,255,.12);border-radius:50%;box-shadow:0 0 0 38px rgba(255,255,255,.035),0 0 0 78px rgba(255,255,255,.025);pointer-events:none}
.hero-inner{position:relative;z-index:1;display:flex;justify-content:space-between;align-items:center;gap:28px;max-width:1440px;margin:auto}
.hero-copy{max-width:760px}.eyebrow{display:flex;align-items:center;gap:8px;margin:0 0 11px;color:#bcd3fa;font-size:11px;font-weight:750;letter-spacing:.13em;text-transform:uppercase}
.brand-mark{display:grid;place-items:center;width:25px;height:25px;border:1px solid rgba(196,218,255,.45);border-radius:8px;background:rgba(129,172,255,.14);color:#c6ddff;font-size:13px;letter-spacing:0}
.hero-header h1{font-size:clamp(27px,3vw,39px);line-height:1.12;letter-spacing:-.035em;margin:0;color:#fff}
.hero-description{max-width:680px;margin:11px 0 0;color:#d0def3;font-size:14px;line-height:1.65}
.hero-meta{display:grid;gap:10px;min-width:220px;padding:15px 17px;border:1px solid rgba(213,229,255,.2);border-radius:13px;background:rgba(7,20,42,.27);backdrop-filter:blur(8px)}
.meta-label{display:block;color:#a9c2e8;font-size:10px;font-weight:750;letter-spacing:.1em;text-transform:uppercase}
.meta-value{display:block;margin-top:3px;color:#fff;font-size:14px;font-weight:650}
.meta-divider{height:1px;background:rgba(213,229,255,.16)}
main{max-width:1480px;margin:auto;padding:20px}
h2{font-size:17px;margin:0 0 12px}.sub{color:var(--mut);font-size:12px;margin:-6px 0 12px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px;margin-bottom:16px}
.card,.chart,.details-card{background:var(--card);border:1px solid var(--line);border-radius:10px}
.card{padding:12px 14px}.card b{display:block;font-size:23px}.card span{font-size:12px;color:var(--mut)}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,440px),1fr));gap:12px;margin:14px 0 20px}
.chart{padding:16px;min-width:0;border-radius:13px;box-shadow:0 2px 10px rgba(20,35,60,.045)}.chart h3{margin:0;font-size:14px;font-weight:700;letter-spacing:-.01em}.chart p{margin:3px 0 10px;color:var(--mut);font-size:12px}
.widget-toolbar{display:flex;justify-content:space-between;align-items:end;gap:12px;flex-wrap:wrap;margin-top:12px}
.widget-toolbar h2{margin:0}.widget-toolbar p{margin:2px 0 0;color:var(--mut);font-size:12px}
.widget-controls{display:flex;flex-wrap:wrap;align-items:center;gap:8px}.widget-controls select{min-width:190px}
.widget-controls button,.widget-remove{background:var(--card)}
.widget-status{min-width:140px;color:var(--mut);font-size:12px}
.widget-head{display:flex;justify-content:space-between;align-items:start;gap:8px}
.widget-remove{padding:4px 8px;color:var(--mut);line-height:1.2}.widget-remove:hover{color:var(--p1);border-color:var(--p1)}
.chart svg{display:block;width:100%;height:auto;overflow:visible}.chart text{fill:var(--mut);font:11px system-ui,Segoe UI,Arial,sans-serif}.chart .axis{stroke:var(--line);stroke-width:1}.chart .gridline{stroke:var(--line);stroke-width:1;stroke-dasharray:2 4}.chart .bar-track{fill:color-mix(in srgb,var(--line) 55%,var(--card))}.chart .bar-label{fill:var(--ink);font-weight:600}.chart .bar-value{fill:var(--ink);font-weight:700;font-variant-numeric:tabular-nums}.chart .chart-tick{font-size:10px;font-variant-numeric:tabular-nums}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}select,input,button{padding:8px 10px;border:1px solid var(--line);border-radius:7px;background:var(--card);color:var(--ink);font:inherit}
input{min-width:220px}button{cursor:pointer}button:hover{border-color:var(--accent)}
.wrap{overflow:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}
th{cursor:pointer;position:sticky;top:0;background:var(--card);z-index:1}th:hover{color:var(--accent)}tr.finding:hover{background:color-mix(in srgb,var(--accent) 7%,var(--card));cursor:pointer}
.tag{display:inline-block;padding:2px 8px;border-radius:20px;font-size:12px;font-weight:650}.P1{background:var(--p1);color:white}.P2{background:var(--p2);color:#171717}.P3{background:var(--p3);color:#171717}.P4{background:var(--p4);color:white}
.action{font-weight:650}.score{font-variant-numeric:tabular-nums;font-weight:650}.riskbar{width:86px;height:7px;background:var(--line);border-radius:8px;display:inline-block;margin-right:6px;vertical-align:middle;overflow:hidden}.riskbar i{display:block;height:100%;background:var(--accent)}
.detail-row td{white-space:normal;padding:0}.detail{padding:16px;background:color-mix(in srgb,var(--accent) 4%,var(--card))}
.detail h3{margin:0 0 8px;font-size:15px}.detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px}
.details-card{padding:10px 12px}.details-card h4{margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}
.field{display:grid;grid-template-columns:minmax(105px, .8fr) minmax(0,1.2fr);gap:8px;padding:3px 0;border-bottom:1px dotted var(--line)}
.field:last-child{border-bottom:0}.field dt{margin:0;color:var(--mut)}.field dd{margin:0;font-weight:550;overflow-wrap:anywhere}
.reason{border-left:3px solid var(--accent);padding:8px 10px;margin:0 0 10px;background:var(--card);border-radius:4px}
.small{font-size:12px;color:var(--mut);margin:8px 0}.empty{padding:24px;text-align:center;color:var(--mut)}
details{margin:20px 0;background:var(--card);border:1px solid var(--line);border-radius:9px;padding:12px}summary{cursor:pointer;font-weight:650}
@media(max-width:680px){main{padding:12px}.hero-header{padding:24px 16px}.hero-inner{align-items:stretch;flex-direction:column;gap:18px}.hero-description{font-size:13px}.hero-meta{grid-template-columns:1fr auto 1fr;min-width:0}.meta-divider{width:1px;height:28px;justify-self:center;grid-column:2;grid-row:1}.charts{grid-template-columns:1fr}input{min-width:0;flex:1}}
</style>
</head>
<body>
<header class="hero-header"><div class="hero-inner">
<div class="hero-copy"><p class="eyebrow"><span class="brand-mark" aria-hidden="true">⌁</span> Project 6 <span aria-hidden="true">/</span> Software supply-chain security</p>
<h1>Dependency risk, made actionable.</h1>
<p class="hero-description">A clear view of vulnerable third-party dependencies, their project impact, and the next remediation step—ranked to help teams focus attention where it matters.</p></div>
<aside class="hero-meta" aria-label="Dashboard context"><div><span class="meta-label">Assessment snapshot</span><span class="meta-value">October 8, 2025</span></div><div class="meta-divider" aria-hidden="true"></div><div><span class="meta-label">Coverage</span><span class="meta-value" id="header-coverage">Loading findings…</span></div></aside>
</div></header>
<main>
<section aria-label="Finding summary"><div class="cards" id="cards"></div></section>
<section aria-label="Customizable finding charts">
<div class="widget-toolbar"><div><h2>Charts</h2><p>Add or remove chart widgets. Your selection is saved in this browser.</p></div>
<div class="widget-controls"><select id="widget-picker" aria-label="Choose a chart widget to add"></select><button id="add-widget" type="button">Add widget</button><button id="reset-widgets" type="button">Reset widgets</button><span id="widget-status" class="widget-status" aria-live="polite"></span></div></div>
<div class="charts" id="charts"></div></section>
<section aria-label="Findings">
<h2>Findings</h2><p class="sub">Select a row to expand the complete available record. Click column headings to sort.</p>
<div class="filters"><select id="fp" aria-label="Filter by project"></select><select id="ft" aria-label="Filter by priority tier"></select><select id="fa" aria-label="Filter by recommended action"></select><input id="fs" aria-label="Search findings" placeholder="Search package, project, advisory, or CVE"><button id="clear">Clear filters</button><button id="dl">Download shown findings (CSV)</button></div>
<div class="wrap"><table><thead><tr id="head"></tr></thead><tbody id="body"></tbody></table></div>
<p class="small" id="count" aria-live="polite"></p>
</section>
<details open><summary>Held-out evaluation summary (2025 CVE cohort)</summary><div class="wrap"><table id="eval"></table></div>
<p class="small">KEV is a sparse, uncertain exploitation signal; PoC existence is a denser but imperfect proxy. Recall in the top 5% is the share of future-positive CVEs found in the top five percent of the ranked list.</p></details>
<details><summary>Interpretation and limitations</summary><ul class="small"><li>Exposure means metadata indicates an affected dependency version; it does not prove vulnerable code is reachable.</li><li>KEV listings and public PoC creation are proxies, not direct observations of all exploitation.</li><li>Priority tiers and actions come from a transparent policy, not an automated proof of required remediation.</li><li>Findings without a CVE may be ranked using severity-only evidence; the expanded record identifies the exploitation score source.</li></ul></details>
</main>
<script>
const D=__DATA__,EV=__EVAL__;
const LABELS=__LABELS__;
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmt=v=>v==null||v===''?'Not available':typeof v==='number'?Number.isInteger(v)?String(v):v.toFixed(4):v===true?'Yes':v===false?'No':String(v);
const COLS=[['rank','#'],['project','Project'],['name','Package'],['version','Version'],['cve','CVE / advisory'],['cvss_base','CVSS'],['tier','Tier'],['action','Action'],['risk_score','Risk score']];
const GROUPS=[
 ['Finding identity',['rank','project','ecosystem','component','name','version','ghsa_id','cve','has_cve']],
 ['Vulnerability and evidence',['cvss_base','severity_label','has_fix','poc_count_at_T','epss_at_T','exploit_pct','exploit_source']],
 ['Dependency graph',['is_direct','depth','fan_in','descendants','pagerank','exposure']],
 ['Package health',['days_since_last_release','releases_prior_12m','version_lag_days','abandoned','health_penalty']],
 ['Priority and decision',['risk_score','tier','action','reasons']]
];
let sortKey='rank',ascending=true,openRank=null;
const $=id=>document.getElementById(id);
function options(id,values,label){$(id).innerHTML='<option value="">'+label+'</option>'+values.map(v=>'<option value="'+esc(v)+'">'+esc(v)+'</option>').join('')}
options('fp',[...new Set(D.map(r=>r.project))].sort(),'All projects');
options('ft',['P1','P2','P3','P4'],'All tiers');
options('fa',['upgrade','replace','isolate','monitor','accept'],'All actions');
$('head').innerHTML=COLS.map(([k,n])=>'<th scope="col" data-k="'+k+'">'+n+'</th>').join('');
document.querySelectorAll('#head th').forEach(th=>th.onclick=()=>{const k=th.dataset.k;ascending=sortKey===k?!ascending:true;sortKey=k;render()});
function selectedRows(){
 const project=$('fp').value,tier=$('ft').value,action=$('fa').value,q=$('fs').value.trim().toLowerCase();
 return D.filter(r=>(!project||r.project===project)&&(!tier||r.tier===tier)&&(!action||r.action===action)&&(!q||[r.name,r.project,r.cve,r.ghsa_id,r.component].some(v=>String(v||'').toLowerCase().includes(q))))
  .sort((a,b)=>{const x=a[sortKey],y=b[sortKey];const c=typeof x==='number'&&typeof y==='number'?x-y:String(x??'').localeCompare(String(y??''));return ascending?c:-c});
}
function detailHtml(r){
 const sections=GROUPS.map(([title,keys])=>'<section class="details-card"><h4>'+title+'</h4><dl>'+keys.filter(k=>Object.hasOwn(r,k)).map(k=>'<div class="field"><dt>'+esc(LABELS[k])+'</dt><dd>'+esc(k==='reasons'?fmt(r[k]):fmt(r[k]))+'</dd></div>').join('')+'</dl></section>').join('');
 return '<tr class="detail-row"><td colspan="'+COLS.length+'"><div class="detail"><h3>Finding details: '+esc(r.name)+' '+esc(r.version)+'</h3><p class="reason"><b>Why this is prioritized:</b> '+esc(fmt(r.reasons))+'</p><div class="detail-grid">'+sections+'</div></div></td></tr>';
}
function renderTable(rows){
 $('body').innerHTML=rows.length?rows.map(r=>'<tr class="finding" data-rank="'+r.rank+'" aria-expanded="'+(openRank===r.rank)+'"><td>'+fmt(r.rank)+'</td><td>'+esc(r.project)+'</td><td>'+esc(r.name)+'</td><td>'+esc(r.version)+'</td><td>'+esc(r.cve||r.ghsa_id||'Not available')+'</td><td>'+esc(fmt(r.cvss_base))+'</td><td><span class="tag '+esc(r.tier)+'">'+esc(r.tier)+'</span></td><td class="action">'+esc(r.action)+'</td><td><span class="riskbar"><i style="width:'+Math.max(0,Math.min(1,Number(r.risk_score)||0))*100+'%"></i></span><span class="score">'+Number(r.risk_score).toFixed(2)+'</span></td></tr>' +(openRank===r.rank?detailHtml(r):'')).join(''):'<tr><td class="empty" colspan="'+COLS.length+'">No findings match these filters.</td></tr>';
 document.querySelectorAll('tr.finding').forEach(tr=>tr.onclick=()=>{const n=Number(tr.dataset.rank);openRank=openRank===n?null:n;render()});
}
const COLORS={P1:'var(--p1)',P2:'var(--p2)',P3:'var(--p3)',P4:'var(--p4)',upgrade:'var(--accent)',replace:'var(--p1)',isolate:'var(--p2)',monitor:'var(--p3)',accept:'var(--p4)'};
function svg(content,w=560,h=220,label='Chart'){
 return '<svg viewBox="0 0 '+w+' '+h+'" role="img" aria-label="'+esc(label)+'" xmlns="http://www.w3.org/2000/svg">'+content+'</svg>';
}
function barChart(container,items,label){
 const w=560,row=36,left=142,right=42,top=16,max=Math.max(1,...items.map(x=>x.value)),plot=w-left-right,base=top+items.length*row-5,steps=Math.min(4,max);
 let body='';
 for(let i=0;i<=steps;i++){
  const x=left+plot*i/steps,value=Math.round(max*i/steps);
  body+='<line class="gridline" x1="'+x+'" y1="'+(top-5)+'" x2="'+x+'" y2="'+base+'"/><text class="chart-tick" x="'+x+'" y="'+(base+17)+'" text-anchor="middle">'+value+'</text>';
 }
 body+=items.map((x,i)=>{
  const y=top+i*row+3,bw=plot*x.value/max;
  return '<text class="bar-label" x="'+(left-12)+'" y="'+(y+14)+'" text-anchor="end">'+esc(x.label)+'</text><rect class="bar-track" x="'+left+'" y="'+y+'" width="'+plot+'" height="19" rx="7"/><rect x="'+left+'" y="'+y+'" width="'+Math.max(x.value?3:0,bw)+'" height="19" rx="7" fill="'+(COLORS[x.key]||'var(--accent)')+'"><title>'+esc(x.label)+': '+x.value+'</title></rect><text class="bar-value" x="'+(left+bw+8)+'" y="'+(y+14)+'">'+x.value+'</text>';
 }).join('');
 $(container).innerHTML=svg(body,w,base+27,label);
}
function renderSummary(rows){
 const count=(key,val)=>rows.filter(r=>r[key]===val).length;
 $('header-coverage').textContent=D.length+' findings · '+new Set(D.map(r=>r.project)).size+' projects';
 $('cards').innerHTML=[[rows.length,'findings shown'],[new Set(rows.map(r=>r.project)).size,'projects shown'],[count('tier','P1'),'P1 · urgent'],[count('action','upgrade'),'upgrade'],[count('action','replace'),'replace'],[count('action','isolate'),'isolate']].map(([n,l])=>'<article class="card"><b>'+n+'</b><span>'+l+'</span></article>').join('');
}
function renderTierChart(rows,container){
 const count=(key,val)=>rows.filter(r=>r[key]===val).length;
 barChart(container,['P1','P2','P3','P4'].map(k=>({key:k,label:k,value:count('tier',k)})),'Finding counts by priority tier');
}
function renderActionChart(rows,container){
 const count=(key,val)=>rows.filter(r=>r[key]===val).length;
 barChart(container,['upgrade','replace','isolate','monitor','accept'].map(k=>({key:k,label:k,value:count('action',k)})),'Finding counts by recommended action');
}
function renderRiskChart(rows,container){
 const bins=Array.from({length:10},(_,i)=>({label:(i/10).toFixed(1)+'–'+((i+1)/10).toFixed(1),value:0}));
 rows.forEach(r=>{const i=Math.min(9,Math.max(0,Math.floor(Number(r.risk_score)*10)));bins[i].value++});
 const w=560,h=220,l=44,right=12,bottom=34,top=14,plotW=w-l-right,plotH=h-bottom-top,max=Math.max(1,...bins.map(x=>x.value)),barW=plotW/bins.length,steps=Math.min(4,max);
 let body='';
 for(let i=0;i<=steps;i++){
  const y=top+plotH-plotH*i/steps,value=Math.round(max*i/steps);
  body+='<line class="gridline" x1="'+l+'" y1="'+y+'" x2="'+(w-right)+'" y2="'+y+'"/><text class="chart-tick" x="'+(l-8)+'" y="'+(y+3)+'" text-anchor="end">'+value+'</text>';
 }
 bins.forEach((v,i)=>{
  const bh=plotH*v.value/max,x=l+i*barW+3,y=top+plotH-bh,bw=barW-6;
  body+='<rect x="'+x+'" y="'+y+'" width="'+bw+'" height="'+bh+'" rx="4" fill="var(--accent)"><title>Risk '+v.label+': '+v.value+' findings</title></rect>';
  if(v.value)body+='<text class="bar-value" x="'+(x+bw/2)+'" y="'+(y-5)+'" text-anchor="middle">'+v.value+'</text>';
  if(i%2===0)body+='<text class="chart-tick" x="'+(l+i*barW)+'" y="'+(top+plotH+17)+'" text-anchor="middle">'+(i/10).toFixed(1)+'</text>';
 });
 body+='<text class="chart-tick" x="'+(w-right)+'" y="'+(top+plotH+17)+'" text-anchor="end">1.0</text>';
 $(container).innerHTML=svg(body,w,h,'Risk-score distribution; horizontal axis is risk score from 0 to 1 and bar height is finding count');
}
function renderProjectChart(rows,container){
 const projects=[...new Set(rows.map(r=>r.project))].sort((a,b)=>rows.filter(r=>r.project===b).length-rows.filter(r=>r.project===a).length).slice(0,12);
 const stacked=projects.map(p=>{const tierCounts=['P1','P2','P3','P4'].map(t=>rows.filter(r=>r.project===p&&r.tier===t).length);return {label:p.length>22?'…'+p.slice(-20):p,key:p,value:tierCounts.reduce((a,b)=>a+b,0),counts:tierCounts}});
 const sw=680,sh=Math.max(100,stacked.length*27+18),sl=188,splot=sw-sl-34,smax=Math.max(1,...stacked.map(x=>x.value));
 let sb=stacked.map((x,i)=>{const y=6+i*27+3;let xx=sl,parts='<text x="'+(sl-8)+'" y="'+(y+13)+'" text-anchor="end"><title>'+esc(x.label)+'</title>'+esc(x.label)+'</text>';['P1','P2','P3','P4'].forEach((t,j)=>{const bw=splot*x.counts[j]/smax;if(bw>0)parts+='<rect x="'+xx+'" y="'+y+'" width="'+bw+'" height="16" fill="'+COLORS[t]+'"><title>'+esc(x.label)+' — '+t+': '+x.counts[j]+'</title></rect>';xx+=bw});return parts+'<text x="'+(sl+splot*x.value/smax+5)+'" y="'+(y+13)+'">'+x.value+'</text>'}).join('');
 sb+='<g>';let lx=sl;['P1','P2','P3','P4'].forEach(t=>{sb+='<rect x="'+lx+'" y="'+(sh-17)+'" width="10" height="10" fill="'+COLORS[t]+'"/><text x="'+(lx+14)+'" y="'+(sh-8)+'">'+t+'</text>';lx+=48});sb+='</g>';
 $(container).innerHTML=svg(sb,sw,sh,'Top projects by finding count, stacked by priority tier');
}
const WIDGETS={
 tier:{title:'Priority tiers',description:'Finding counts by policy tier in the current view.',render:renderTierChart},
 actions:{title:'Recommended actions',description:'Distribution of upgrade, replace, isolate, monitor, and accept decisions.',render:renderActionChart},
 risk:{title:'Risk-score distribution',description:'Number of findings within each combined risk-score band.',render:renderRiskChart},
 projects:{title:'Projects by priority tier',description:'Top 12 projects by finding count, stacked by tier in the current view.',render:renderProjectChart}
};
const DEFAULT_WIDGETS=['tier','actions','risk','projects'];
const WIDGET_STORAGE_KEY='supply-chain-dashboard-widgets-v1';
function loadWidgets(){
 try{
  const saved=JSON.parse(localStorage.getItem(WIDGET_STORAGE_KEY)||'null');
  if(Array.isArray(saved)&&saved.every(id=>typeof id==='string'&&Object.hasOwn(WIDGETS,id))&&new Set(saved).size===saved.length)return saved;
 }catch(error){console.warn('Could not load saved chart widgets.',error)}
 return DEFAULT_WIDGETS.slice();
}
let activeWidgets=loadWidgets();
function saveWidgets(){
 try{localStorage.setItem(WIDGET_STORAGE_KEY,JSON.stringify(activeWidgets));$('widget-status').textContent='Layout saved in this browser.'}
 catch(error){console.warn('Could not save chart widget layout.',error);$('widget-status').textContent='Browser storage unavailable; layout will reset on reload.'}
}
function renderWidgetControls(){
 const available=Object.keys(WIDGETS).filter(id=>!activeWidgets.includes(id));
 $('widget-picker').innerHTML=available.length?available.map(id=>'<option value="'+id+'">'+esc(WIDGETS[id].title)+'</option>').join(''):'<option value="">All widgets are on the page</option>';
 $('widget-picker').disabled=!available.length;$('add-widget').disabled=!available.length;
}
function renderWidgets(rows){
 $('charts').innerHTML=activeWidgets.length?activeWidgets.map(id=>'<article class="chart" data-widget="'+id+'"><div class="widget-head"><h3>'+esc(WIDGETS[id].title)+'</h3><button class="widget-remove" type="button" data-remove="'+id+'" aria-label="Remove '+esc(WIDGETS[id].title)+' widget" title="Remove widget">Remove</button></div><p>'+esc(WIDGETS[id].description)+'</p><div id="widget-content-'+id+'"></div></article>').join(''):'<p class="empty">No chart widgets are shown. Add one using the menu above.</p>';
 activeWidgets.forEach(id=>WIDGETS[id].render(rows,'widget-content-'+id));
 renderWidgetControls();
}
function render(){
 const rows=selectedRows();renderTable(rows);renderSummary(rows);renderWidgets(rows);
 $('count').textContent='Showing '+rows.length+' of '+D.length+' findings. Click any row to expand its full available record.';
}
['fp','ft','fa','fs'].forEach(id=>$(id).addEventListener(id==='fs'?'input':'change',()=>{openRank=null;render()}));
$('clear').onclick=()=>{$('fp').value='';$('ft').value='';$('fa').value='';$('fs').value='';openRank=null;render()};
$('add-widget').onclick=()=>{const id=$('widget-picker').value;if(id&&Object.hasOwn(WIDGETS,id)&&!activeWidgets.includes(id)){activeWidgets.push(id);saveWidgets();render()}};
$('reset-widgets').onclick=()=>{activeWidgets=DEFAULT_WIDGETS.slice();saveWidgets();render()};
$('charts').addEventListener('click',event=>{const button=event.target.closest('[data-remove]');if(!button)return;activeWidgets=activeWidgets.filter(id=>id!==button.dataset.remove);saveWidgets();render()});
$('dl').onclick=()=>{const rows=selectedRows(),headers=Object.keys(D[0]||{}),quote=v=>'"'+String(v??'').replace(/"/g,'""')+'"';const csv=[headers.map(quote).join(',')].concat(rows.map(r=>headers.map(k=>quote(r[k])).join(','))).join('\r\n');const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));a.download='remediation_findings_filtered.csv';a.click();URL.revokeObjectURL(a.href)};
if(EV.length){$('eval').innerHTML='<thead><tr><th>Label</th><th>Method</th><th>Positives</th><th>ROC AUC (95% CI)</th><th>Average precision</th><th>Recall top 5% (95% CI)</th></tr></thead><tbody>'+EV.map(e=>'<tr><td>'+esc(e.label)+'</td><td>'+esc(e.variant)+(e.selected_on_validation?' (validation-selected)':'')+'</td><td>'+e.positives+'</td><td>'+e.roc_auc+' ('+esc(e.auc_ci95)+')</td><td>'+e.avg_precision+'</td><td>'+e.recall_top5pct+' ('+esc(e.recall_top5_ci95)+')</td></tr>').join('')+'</tbody>'}
else{$('eval').outerHTML='<p class="small">Evaluation summary is not available yet. Run Activity 7 to generate it.</p>'}
render();
</script>
</body></html>"""

page = (
    page.replace("__DATA__", data_json.replace("</", "<\\/"))
    .replace("__EVAL__", evaluation_json.replace("</", "<\\/"))
    .replace("__LABELS__", pd.Series(FIELD_LABELS).to_json())
)
os.makedirs(RESULTS, exist_ok=True)
with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write(page)
print(f"Dashboard written: results/dashboard.html ({len(display_plan)} findings, {os.path.getsize(OUTPUT_PATH) / 1024:.0f} KB)")
