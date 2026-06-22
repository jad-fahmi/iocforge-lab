"""Small dependency-free analyst workbench served with the API."""

ANALYST_UI = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IOCForge Analyst Workbench</title>
<style>
:root { color-scheme: dark; --bg:#0b1220; --panel:#121d31; --line:#273650; --ink:#e6edf7; --muted:#9db0ca; --blue:#64b5ff; --red:#ff8686; --amber:#ffd166; --green:#6ee7b7; }
* { box-sizing:border-box } body { margin:0; font:15px system-ui,sans-serif; background:var(--bg); color:var(--ink) } header { padding:24px max(5vw,24px); border-bottom:1px solid var(--line); display:flex; justify-content:space-between; gap:20px; align-items:center } h1 { margin:0; font-size:1.45rem } h2 { margin:0 0 16px; font-size:1.1rem } p { color:var(--muted) } nav { display:flex; gap:8px; flex-wrap:wrap } button, input, select { font:inherit; border-radius:7px; padding:9px 12px; border:1px solid var(--line) } button { color:var(--ink); background:#1a2b47; cursor:pointer } button:hover,button.active { background:#244d7e; border-color:var(--blue) } input, select { width:min(640px,100%); background:#091221; color:var(--ink) } main { max-width:1200px; margin:auto; padding:28px 5vw 60px } section[hidden] { display:none } .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; margin-bottom:20px } .card,.panel { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:16px } .metric { font-size:1.7rem; font-weight:700; color:var(--blue) } .label { color:var(--muted); font-size:.85rem; text-transform:uppercase; letter-spacing:.06em } .panel { margin-top:16px } .row { display:flex; flex-wrap:wrap; gap:10px; align-items:center } table { width:100%; border-collapse:collapse } th,td { text-align:left; padding:9px; border-bottom:1px solid var(--line); vertical-align:top } th { color:var(--muted); font-size:.8rem } .status { padding:3px 8px; border-radius:12px; display:inline-block; background:#24364f } .malicious { color:var(--red) } .suspicious { color:var(--amber) } .clean { color:var(--green) } .error { color:var(--red); white-space:pre-wrap } .list { margin:0; padding-left:20px } .empty { color:var(--muted); padding:12px 0 } code { color:#b9d7ff; overflow-wrap:anywhere } pre { max-height:420px; overflow:auto; white-space:pre-wrap; overflow-wrap:anywhere; background:#091221; border-radius:7px; padding:12px } details { margin:8px 0 } .timeline-row { border-left:2px solid var(--line); margin:0 0 0 8px; padding:8px 14px } .timeline-row time { color:var(--muted); font-size:.82rem } .actions { display:flex; gap:8px; flex-wrap:wrap; align-items:center } a { color:var(--blue) } @media(max-width:600px) { header { align-items:flex-start; flex-direction:column } th:nth-child(4),td:nth-child(4) { display:none } }
</style></head><body>
<header><div><h1>IOCForge Analyst Workbench</h1><p>Evidence-led indicator triage and investigation context.</p></div><nav aria-label="Workbench sections"><button class="active" data-view="dashboard">Dashboard</button><button data-view="search">IOC search</button><button data-view="history">History</button><button data-view="cases">Investigations</button></nav></header>
<main>
<section id="dashboard"><h2>Operational dashboard</h2><div class="grid" id="metrics"></div><div class="panel"><h2>Provider health</h2><div id="providers"></div></div><div class="panel"><h2>Recent enrichment</h2><div id="recent"></div></div></section>
<section id="search" hidden><h2>IOC search</h2><form id="search-form" class="row"><input id="ioc" required placeholder="Domain, URL, IP, hash, email, CVE, ASN…" aria-label="Indicator of compromise"><button>Enrich indicator</button></form><div id="result"></div></section>
<section id="history" hidden><h2>Enrichment history</h2><div id="history-data"></div><div id="history-detail"></div></section>
<section id="cases" hidden><h2>Investigations</h2><form id="case-form" class="row"><input id="case-title" required maxlength="200" placeholder="Investigation title" aria-label="Investigation title"><input id="case-description" maxlength="2000" placeholder="Optional description" aria-label="Investigation description"><button>Create investigation</button></form><form id="bundle-form" class="row panel"><label for="bundle-file">Inspect an .iocforge bundle</label><input id="bundle-file" type="file" accept=".iocforge,application/zip" required><button>Validate and replay offline</button></form><div id="bundle-result"></div><div id="case-data"></div><div id="case-detail"></div></section>
</main>
<script>
const API = '/api/v1';
const byId = id => document.getElementById(id);
function clear(node) { node.replaceChildren(); }
function node(tag, value, className) { const item = document.createElement(tag); if (value !== undefined) item.textContent = value; if (className) item.className = className; return item; }
function table(headers, rows) { const t=document.createElement('table'), head=document.createElement('thead'), body=document.createElement('tbody'), tr=document.createElement('tr'); headers.forEach(h=>tr.append(node('th',h))); head.append(tr); rows.forEach(row=>{const r=document.createElement('tr'); row.forEach(cell=>{const c=document.createElement('td'); if (cell instanceof Node) c.append(cell); else c.textContent=cell ?? '—'; r.append(c)}); body.append(r)}); t.append(head,body); return t; }
function empty(message) { return node('p', message, 'empty'); }
async function api(path, options) { const response=await fetch(API+path, options); if (!response.ok) { const body=await response.json().catch(()=>({})); throw new Error(typeof body.detail==='string' ? body.detail : body.detail ? JSON.stringify(body.detail) : `Request failed (${response.status})`); } return response.json(); }
function renderError(target, error) { clear(target); target.append(node('p', error.message, 'error')); }
function verdict(value) { return node('span', value || 'unknown', `status ${value || ''}`); }
function renderList(title, values) { const panel=node('div', undefined, 'panel'); panel.append(node('h2', title)); if (!values || !values.length) panel.append(empty('None recorded.')); else { const list=node('ul', undefined, 'list'); values.forEach(value=>list.append(node('li', typeof value==='string' ? value : JSON.stringify(value)))); panel.append(list); } return panel; }
async function loadDashboard() { const target=byId('dashboard'); try { const data=await api('/dashboard'); const metrics=byId('metrics'); clear(metrics); const verdicts=data.verdict_counts || {}; const investigation=data.investigation_counts || {}; [['Indicators enriched', Object.values(verdicts).reduce((a,b)=>a+b,0)], ['Open investigations', investigation.open || 0], ['Ready providers', (data.providers||[]).filter(p=>p.available).length], ['Providers configured', (data.providers||[]).length]].forEach(([label,value])=>{const card=node('div',undefined,'card');card.append(node('div',label,'label'),node('div',String(value),'metric'));metrics.append(card)}); const providers=byId('providers');clear(providers); providers.append((data.providers||[]).length ? table(['Provider','Status','Reliability','Detail'], data.providers.map(p=>[p.name, verdict(p.enabled ? (p.available ? 'ready' : 'unavailable') : 'disabled'), p.reliability ?? '—', p.requires_api_key && !p.configured ? 'credential not configured' : 'available'])) : empty('No providers are configured.')); const recent=byId('recent');clear(recent); const entries=data.recent_enrichments || []; recent.append(entries.length ? table(['Indicator','Verdict','Score','Looked up'], entries.map(e=>[e.ioc,verdict(e.verdict),e.score,e.looked_up_at])) : empty('No enrichment has been recorded yet.')); } catch(error) { renderError(target,error); } }
byId('search-form').addEventListener('submit', async event=>{ event.preventDefault(); const target=byId('result'); clear(target); target.append(empty('Enriching indicator…')); try { const data=await api('/enrich',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ioc:byId('ioc').value})}); const relationships=await api(`/indicators/${encodeURIComponent(data.ioc)}/relationships`).catch(()=>[]); const investigations=(await api('/investigations').catch(()=>({items:[]}))).items; renderResult(data,relationships,investigations); } catch(error) { renderError(target,error); } });
byId('case-form').addEventListener('submit', async event=>{ event.preventDefault(); const target=byId('case-data'); try { await api('/investigations',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:byId('case-title').value,description:byId('case-description').value})}); event.target.reset(); await loadCases(); } catch(error) { renderError(target,error); } });
document.querySelectorAll('[data-view]').forEach(button=>button.addEventListener('click',()=>{document.querySelectorAll('[data-view]').forEach(b=>b.classList.remove('active'));button.classList.add('active');document.querySelectorAll('main section').forEach(section=>section.hidden=section.id!==button.dataset.view);if(button.dataset.view==='dashboard')loadDashboard();if(button.dataset.view==='history')loadHistory();if(button.dataset.view==='cases')loadCases();}));
function structuredPanel(title,value,open=false) { const panel=node('div',undefined,'panel'),details=node('details');details.open=open;details.append(node('summary',title),node('pre',JSON.stringify(value,null,2)));panel.append(details);return panel; }
function actionButton(label,action) { const button=node('button',label);button.type='button';button.addEventListener('click',action);return button; }
function renderSourceDetails(source) { const details=node('details');details.append(node('summary',`${source.source}: ${source.found?(source.malicious===true?'malicious':source.malicious===false?'benign':'found'):source.error?'error':'no data'} | ${source.raw_response_sha256||'no response hash'}`),node('pre',JSON.stringify({observed_at:source.observed_at,collected_at:source.collected_at,connector_version:source.connector_version,normalization_version:source.normalization_version,confidence:source.confidence,freshness:source.freshness,latency_ms:source.latency_ms,cache_hit:source.cache_hit,error:source.error,raw:source.raw,related_entities:source.related_entities},null,2)));return details; }
function renderResult(data,relationships,investigations) { const target=byId('result');clear(target);const summary=node('div',undefined,'panel');summary.append(node('h2',data.ioc),node('p',`${data.ioc_type} | ${data.confidence} confidence | scoring ${data.scoring_version}`));const grid=node('div',undefined,'grid');[['Verdict',data.verdict],['Score',data.score],['Recommended action',data.recommended_action]].forEach(([label,value])=>{const card=node('div',undefined,'card');card.append(node('div',label,'label'),label==='Verdict'?verdict(value):node('div',String(value),'metric'));grid.append(card)});summary.append(grid);target.append(summary,renderList('Supporting evidence',data.evidence),renderList('Counter-evidence',data.counter_evidence),renderList('No-data sources',data.no_data),renderList('Provider errors',data.errors));const provenance=node('div',undefined,'panel');provenance.append(node('h2','Source observations and provenance'));provenance.append(data.sources?.length?data.sources.map(renderSourceDetails):empty('No provider responses.'));target.append(provenance,structuredPanel('Decision trace and scoring inputs',data.decision_trace));const related=node('div',undefined,'panel');related.append(node('h2','Evidence-backed relationships'));related.append(relationships.length?table(['Source','Relationship','Target','Confidence','Provider','Valid from'],relationships.map(r=>[r.source_ioc,r.relationship_type,r.target_ioc,r.confidence,r.evidence_source,r.valid_from])):empty('No persisted relationships for this indicator.'));target.append(related);const casePanel=node('div',undefined,'panel');casePanel.append(node('h2','Add to investigation'));if(!investigations.length)casePanel.append(empty('Create an investigation first.'));else{const form=node('form',undefined,'row'),select=node('select');investigations.forEach(i=>{const option=node('option',i.title);option.value=i.id;select.append(option)});form.append(select,node('button','Add indicator'));form.addEventListener('submit',async event=>{event.preventDefault();try{const investigation=await api(`/investigations/${select.value}/indicators`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ioc:data.ioc})});casePanel.append(node('p','Indicator added to investigation.','clean'));await loadCases();await openCase(investigation.id);}catch(error){casePanel.append(node('p',error.message,'error'));}});casePanel.append(form)}target.append(casePanel); }
async function loadHistory() {
  const target=byId('history-data'), detail=byId('history-detail');
  clear(target); clear(detail); target.append(empty('Loading history...'));
  try {
    const data=await api('/history?limit=100'); clear(target);
    if (!data.items?.length) { target.append(empty('No enrichment history yet.')); return; }
    const rows=data.items.map(item=>[
      item.id, item.ioc, verdict(item.verdict), item.score, item.looked_up_at,
      actionButton('Replay',async()=>{
        clear(detail); detail.append(empty(`Replaying snapshot ${item.id}...`));
        try {
          const replay=await api(`/history/${item.id}/replay`); clear(detail);
          detail.append(structuredPanel(`Snapshot ${item.id} replay`,{
            replayable:replay.replayable, matches_original:replay.matches_original,
            original:replay.original, replayed:replay.replayed,
            observations:replay.observations
          },true));
        } catch(error) { renderError(detail,error); }
      })
    ]);
    target.append(table(['ID','Indicator','Verdict','Score','Looked up','Evidence replay'],rows));
  } catch(error) { renderError(target,error); }
}
function caseTimeline(events,indicatorEvents,snapshots) { const items=[];(events||[]).forEach(event=>items.push({at:event.created_at,kind:'Case: '+event.event_type,detail:event.data}));(indicatorEvents||[]).forEach(event=>items.push({at:event.created_at,kind:'Indicator: '+event.event_type,detail:event.data}));(snapshots||[]).forEach(item=>items.push({at:item.looked_up_at,kind:`Enrichment #${item.id}: ${item.verdict} (score ${item.score})`,detail:{confidence:item.confidence,scoring_version:item.result?.scoring_version}}));items.sort((a,b)=>String(b.at||'').localeCompare(String(a.at||'')));if(!items.length)return empty('No timeline events or enrichment snapshots.');const list=node('div');items.forEach(item=>{const row=node('div',undefined,'timeline-row');row.append(node('time',item.at||'Unknown time'),node('p',item.kind),node('code',JSON.stringify(item.detail)));list.append(row)});return list; }
async function inspectCaseIndicator(investigationId, ioc, caseEvents) {
  const timeline = byId('case-timeline');
  const graphTarget = byId('case-graph');
  const snapshotsTarget = byId('case-snapshots');
  const comparisonTarget = byId('case-comparison');
  [timeline, graphTarget, snapshotsTarget, comparisonTarget].forEach(clear);
  timeline.append(empty('Loading indicator evidence and timeline...'));
  try {
    const encoded = encodeURIComponent(ioc);
    const [history, indicatorEvents, indicatorIntegrity, graph, pivots] = await Promise.all([
      api(`/history?ioc=${encoded}&limit=100`),
      api(`/indicators/${encoded}/events?limit=100`),
      api(`/indicators/${encoded}/integrity`).catch(() => null),
      api(`/indicators/${encoded}/graph?depth=3&limit=100`),
      api(`/indicators/${encoded}/pivots?limit=25`)
    ]);
    clear(timeline);
    timeline.append(
      node('h3', `Investigation and indicator timeline: ${ioc}`),
      node('p', indicatorIntegrity ? `Indicator event chain: ${indicatorIntegrity.valid ? 'valid' : 'INVALID'} (${indicatorIntegrity.checked_events} event(s))` : 'No indicator event chain is recorded yet.', indicatorIntegrity?.valid === false ? 'error' : 'empty'),
      caseTimeline(caseEvents, indicatorEvents, history.items)
    );

    graphTarget.append(node('h3', `Typed relationship graph for ${ioc}`));
    if (graph.edges.length) {
      graphTarget.append(table(
        ['From', 'Relationship', 'To', 'Entity types', 'Confidence', 'Source / observation', 'Valid from'],
        graph.edges.map(edge => [
          edge.source_ioc,
          edge.relationship_type,
          edge.target_ioc,
          `${edge.source_entity_type} -> ${edge.target_entity_type}`,
          edge.confidence,
          `${edge.evidence_source} / ${edge.evidence_observation_id ? 'observation ' + edge.evidence_observation_id : 'analyst'}`,
          edge.valid_from
        ])
      ));
      graphTarget.append(structuredPanel('Graph nodes and edge provenance', graph));
    } else {
      graphTarget.append(empty('No persisted relationships for this indicator.'));
    }
    graphTarget.append(
      renderList('Ranked pivots', pivots.candidates.map(candidate =>
        `${candidate.entity_type}: ${candidate.ioc} (score ${candidate.priority_score}; ${candidate.supporting_edges.length} supporting edge(s))`
      )),
      node('p', `Depth ${graph.max_depth}; ${graph.edges.length} edge(s); truncated: ${graph.truncated}.`, 'empty')
    );

    const snapshots = history.items || [];
    snapshotsTarget.append(node('h3', `Historical snapshots: ${ioc}`));
    if (!snapshots.length) {
      snapshotsTarget.append(empty('No saved enrichments for this indicator.'));
      return;
    }

    const baseline = node('select');
    const comparison = node('select');
    snapshots.slice().reverse().forEach(item => {
      const label = `#${item.id} | ${item.looked_up_at} | ${item.verdict} | ${item.score}`;
      [baseline, comparison].forEach(select => {
        const option = node('option', label);
        option.value = item.id;
        select.append(option);
      });
    });
    baseline.value = snapshots[snapshots.length - 1].id;
    comparison.value = snapshots[0].id;

    const compareSnapshots = async () => {
      clear(comparisonTarget);
      comparisonTarget.append(empty('Comparing snapshots...'));
      try {
        const result = await api(`/history/${baseline.value}/compare/${comparison.value}`);
        clear(comparisonTarget);
        comparisonTarget.append(
          node('h3', `Historical comparison: ${ioc}`),
          node('p', `Verdict ${result.baseline.verdict} -> ${result.comparison.verdict}; score delta ${result.score_delta}; verdict changed: ${result.verdict_changed}.`),
          node('p', `Replay matches: baseline ${result.replay.baseline_matches}; comparison ${result.replay.comparison_matches}.`),
          renderList('Added evidence', result.evidence.added),
          renderList('Removed from snapshot', result.evidence.removed_from_snapshot),
          renderList('Graph changes', {
            added_edges: result.graph.added_edges,
            removed_edges: result.graph.removed_edges,
            added_nodes: result.graph.added_nodes,
            removed_nodes: result.graph.removed_nodes
          }),
          structuredPanel('Full evidence, replay, scoring, and graph diff', result)
        );
      } catch (error) {
        renderError(comparisonTarget, error);
      }
    };
    const compareButton = actionButton('Compare snapshots', compareSnapshots);
    compareButton.disabled = snapshots.length < 2;
    const compareForm = node('form', undefined, 'row');
    compareForm.append(
      node('label', 'Historical snapshot'),
      baseline,
      node('label', 'compare with'),
      comparison,
      compareButton
    );
    snapshotsTarget.append(compareForm);

    const snapshotRows = snapshots.map(item => {
      const replayButton = actionButton('Replay and inspect', async () => {
        clear(comparisonTarget);
        comparisonTarget.append(empty(`Replaying snapshot ${item.id}...`));
        try {
          const replay = await api(`/history/${item.id}/replay`);
          clear(comparisonTarget);
          comparisonTarget.append(
            node('h3', `Historical replay #${item.id}`),
            node('p', `Replayable: ${replay.replayable}; matches original: ${replay.matches_original}`),
            structuredPanel('Decision trace, evidence hashes, provider versions, and replay inputs', {
              original: replay.original,
              replayed: replay.replayed,
              observations: replay.observations
            }, true)
          );
        } catch (error) {
          renderError(comparisonTarget, error);
        }
      });
      return [
        item.id,
        verdict(item.verdict),
        item.score,
        item.confidence,
        item.result?.scoring_version,
        replayButton
      ];
    });
    snapshotsTarget.append(table(
      ['Snapshot', 'Verdict', 'Score', 'Confidence', 'Method', 'Inspect'],
      snapshotRows
    ));
  } catch (error) {
    renderError(timeline, error);
    graphTarget.append(empty('Graph and pivots could not be loaded.'));
    snapshotsTarget.append(empty('Snapshot history could not be loaded.'));
  }
}
async function openCase(id) { const target=byId('case-detail');clear(target);target.append(empty(`Loading investigation ${id}...`));try{const [investigation,events,integrity]=await Promise.all([api(`/investigations/${id}`),api(`/investigations/${id}/events?limit=200`),api(`/investigations/${id}/integrity`)]);clear(target);const header=node('div',undefined,'panel');header.append(node('h2',investigation.title),node('p',`${investigation.status} | ${investigation.indicators.length} indicator(s) | updated ${investigation.updated_at}`),node('p',investigation.description||'No description.'));const actions=node('div',undefined,'actions'),bundle=node('a','Download reproducible .iocforge bundle');bundle.href=`${API}/investigations/${id}/bundle`;bundle.download=`iocforge-investigation-${id}.iocforge`;actions.append(bundle,node('span',`Event chain: ${integrity.valid?'valid':'INVALID'} (${integrity.checked_events} event(s))`,integrity.valid?'clean':'error'));header.append(actions);target.append(header);const eventPanel=node('div',undefined,'panel');eventPanel.append(node('h3','Investigation event timeline'),caseTimeline(events,[],[]));target.append(eventPanel);const selectForm=node('form',undefined,'row panel'),select=node('select');investigation.indicators.forEach(ioc=>{const option=node('option',ioc);option.value=ioc;select.append(option)});selectForm.append(node('label','Inspect indicator'),select,actionButton('Load evidence and graph',()=>inspectCaseIndicator(id,select.value,events)));target.append(selectForm);const timeline=node('div',undefined,'panel'),graph=node('div',undefined,'panel'),snapshots=node('div',undefined,'panel'),comparison=node('div',undefined,'panel');timeline.id='case-timeline';graph.id='case-graph';snapshots.id='case-snapshots';comparison.id='case-comparison';target.append(timeline,graph,snapshots,comparison);if(investigation.indicators.length)await inspectCaseIndicator(id,investigation.indicators[0],events);else timeline.append(empty('Add an indicator to inspect its evidence.'));}catch(error){renderError(target,error)} }
byId('bundle-form').addEventListener('submit',async event=>{event.preventDefault();const target=byId('bundle-result');clear(target);const file=byId('bundle-file').files[0];if(!file){target.append(empty('Choose an .iocforge bundle first.'));return}target.append(empty('Validating bundle checksums, event chains, and offline replay...'));try{const report=await api('/investigations/bundles/inspect',{method:'POST',headers:{'Content-Type':'application/zip'},body:file});clear(target);target.append(node('h3','Offline bundle inspection'),node('p',`Investigation: ${report.investigation?.title||'unknown'} | event integrity: ${report.event_integrity?.investigation?.valid?'valid':'invalid'}`),structuredPanel('Validation and replay report',report,true));}catch(error){renderError(target,error)}});
loadDashboard();
</script></body></html>"""
