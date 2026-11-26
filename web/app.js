"use strict";
const $ = (s) => document.querySelector(s);
const themeToggle = $("#theme-toggle");

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  themeToggle.setAttribute("aria-pressed", String(theme === "dark"));
}

applyTheme(localStorage.getItem("xa-theme") === "light" ? "light" : "dark");
themeToggle.addEventListener("click", () => {
  const theme = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  applyTheme(theme);
  localStorage.setItem("xa-theme", theme);
});
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let state = null, projectId = localStorage.getItem("xa-project"), scanId = null, scan = null, view = "overview", busy = false, toastTimer, settingsDirty=false;
const names = {overview:"Overview",findings:"Findings",history:"Scan history",coverage:"Coverage & checks",settings:"Website settings"};
const active = s => ["queued","running"].includes(s);
const date = s => new Date(s).toLocaleString(undefined,{month:"short",day:"numeric",hour:"numeric",minute:"2-digit"});
const badge = v => `<span class="badge ${esc(v)}">${esc(v)}</span>`;
const selected = () => state?.projects.find(p => p.id === projectId);
function toast(message) { $("#toast").textContent=message; $("#toast").hidden=false; clearTimeout(toastTimer); toastTimer=setTimeout(()=>$("#toast").hidden=true,3500); }
async function api(path,body) {
  const response=await fetch(path,body === undefined ? {signal:AbortSignal.timeout(10000)} : {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body),signal:AbortSignal.timeout(10000)});
  const data=await response.json(); if(!response.ok) throw new Error(data.error || "Request failed"); return data;
}
function showView(next) {
  view=next; $("#view-crumb").textContent=names[view];
  document.querySelectorAll(".nav").forEach(b=>b.classList.toggle("active",b.dataset.view===view));
  document.querySelectorAll(".view").forEach(el=>el.hidden=el.id!==`${view}-view`);
  render();
}
async function refresh(force=false) {
  if(busy) { if(force) { await new Promise(resolve=>setTimeout(resolve,100)); return refresh(force); } return; } busy=true;
  try {
    const next=await api("/api/state"); state=next;
    if(!selected()) { projectId=state.projects[0]?.id || null; scanId=null; }
    const p=selected();
    if(p && (!scanId || !p.scans.some(s=>s.id===scanId))) scanId=p.scans[0]?.id || null;
    scan=scanId ? await api(`/api/scans/${scanId}`) : null;
    $("#connection-error").hidden=true;
    $(".engine-status").textContent="Local engine connected";
    if(force || !document.querySelector("dialog[open]") && !["finding-search","severity-filter","status-filter"].includes(document.activeElement.id)) render();
  } catch(error) {
    $("#connection-error").textContent=`${error.message} Keep the local application running; refresh this page after a restart.`;
    $("#connection-error").hidden=false; $(".engine-status").textContent="Engine unavailable";
  } finally { busy=false; }
}
function render() {
  if(!state) return;
  const p=selected(), r=scan?.result, findings=r?.findings || [];
  $("#version").textContent=`VERSION ${state.version} · LOCAL ENGINE`;
  $("#website-select").innerHTML=state.projects.length ? state.projects.map(p=>`<option value="${p.id}">${esc(p.name)}</option>`).join("") : '<option value="">No websites yet</option>';
  $("#website-select").value=projectId || "";
  $("#empty-state").hidden=!!p; $("#project-workspace").hidden=!p;
  $("#page-title").textContent=p ? (view==="overview" ? p.name : names[view]) : "Know where your website stands.";
  $("#page-subtitle").textContent=p ? p.url : "Find issues, understand the evidence, and keep track of what changes.";
  $("#new-scan").textContent=p ? "＋ New scan" : "＋ Add website";
  $("#nav-count").textContent=findings.filter(f=>f.status!=="accepted").length;
  if(!p) return;
  const running=p.scans.find(s=>active(s.status));
  $("#new-scan").disabled=!!running;
  const strip=$("#scan-strip"); strip.classList.toggle("live",active(r?.status));
  strip.innerHTML=r ? `${active(r.status)?'<span class="pulse"></span>':badge(r.status)}<strong>${active(r.status)?esc(r.phase):"Selected scan"}</strong><span>${date(scan.created_at)}</span><div class="scan-meta"><span>${r.requests} requests · ${r.duration_seconds || 0}s</span>${active(r.status)?`<button class="secondary" data-cancel="${scan.id}">Cancel scan</button>`:`<button class="text-button export" data-format="html">Export report</button>`}</div>` : '<strong>Ready when you are.</strong><span>Run your first scan to see findings here.</span>';
  if(running && running.id!==scanId) strip.innerHTML+=`<button class="text-button" data-scan="${running.id}">View active scan</button>`;
  const open=findings.filter(f=>f.status!=="accepted");
  const groups=groupFindings(open);
  $("#metric-open").textContent=r ? groups.length : "—";
  $("#metric-occurrences").textContent=r ? `${open.length} occurrences across ${new Set(open.map(f=>f.url)).size} locations` : "Across the selected scan";
  $("#metric-high").textContent=r ? open.filter(f=>["high","critical"].includes(f.severity)).length : "—";
  $("#metric-pages").textContent=r ? r.pages.length : "—";
  $("#metric-requests").textContent=r ? `${r.requests} requests made` : "No requests yet";
  $("#metric-new").textContent=r?.comparison?.new ?? "—";
  $("#metric-baseline").textContent=r?.comparison?.baseline_id ? `${r.comparison.not_seen ?? "—"} previous findings not seen` : "Run a second matching scan";
  $("#priority-list").innerHTML=open.length ? groups.slice(0,5).map(group=>{const f=group[0];return `<button class="priority-item" data-finding="${f.id}">${badge(f.severity)}<span class="priority-text"><strong>${esc(f.title)}</strong><small>${group.length} occurrences · ${new Set(group.map(f=>f.url)).size} locations</small></span></button>`;}).join("") : `<div class="blank">${!r ? "Your findings will appear after your first scan." : active(r.status) ? "Scanning… findings will appear as pages are checked." : !r.pages.length ? "No pages were checked. Open Coverage & checks to review errors." : "No open findings in this scan.<br>Review coverage before drawing conclusions."}</div>`;
  $("#severity-bars").innerHTML=["high","medium","low","info"].map(s=>{const n=findings.filter(f=>f.severity===s).length;return `<div class="severity-row"><span>${s[0].toUpperCase()+s.slice(1)}</span><progress class="severity-progress ${s}" value="${n}" max="${Math.max(findings.length,1)}" aria-label="${s} findings"></progress><strong>${n}</strong></div>`;}).join("");
  if(view==="findings") renderFindings();
  if(view==="history") renderHistory();
  if(view==="coverage") renderCoverage();
  if(view==="settings" && !settingsDirty && !$("#settings-form").contains(document.activeElement)) renderSettings();
}
function groupFindings(findings) { const groups=new Map(); for(const f of findings) { if(!groups.has(f.rule)) groups.set(f.rule,[]); groups.get(f.rule).push(f); } return [...groups.values()]; }
function renderFindings() {
  const q=$("#finding-search").value.toLowerCase(), severity=$("#severity-filter").value, status=$("#status-filter").value;
  const findings=(scan?.result.findings || []).filter(f=>(!severity || f.severity===severity)&&(!status || f.status===status)&&(!q || [f.title,f.url,f.evidence,f.category].join(" ").toLowerCase().includes(q)));
  if($("#group-findings").checked) {
    $("#finding-table").innerHTML=findings.length ? `<table><thead><tr><th>Severity</th><th>Issue type</th><th>Occurrences</th><th>Locations</th><th>Open / reviewing</th></tr></thead><tbody>${groupFindings(findings).map(group=>{const f=group[0];return `<tr><td>${badge(f.severity)}</td><td><button class="finding-title" data-finding="${f.id}">${esc(f.title)}</button><small>${esc(f.category)}</small></td><td>${group.length}</td><td>${new Set(group.map(f=>f.url)).size}</td><td>${group.filter(f=>f.status!=="accepted").length}</td></tr>`;}).join("")}</tbody></table>` : '<div class="blank">No findings match this view.</div>';
    return;
  }
  $("#finding-table").innerHTML=findings.length ? `<table><thead><tr><th>Severity</th><th>Finding / affected page</th><th>Confidence</th><th>Status</th><th>Change</th></tr></thead><tbody>${findings.map(f=>`<tr><td>${badge(f.severity)}</td><td><button class="finding-title" data-finding="${f.id}">${esc(f.title)}</button><small>${esc(f.url)}</small></td><td>${esc(f.confidence)}</td><td>${badge(f.status)}</td><td>${esc(f.change)}</td></tr>`).join("")}</tbody></table>` : '<div class="blank">No findings match this view.</div>';
  document.querySelectorAll(".export").forEach(b=>b.disabled=!scan);
}
function renderHistory() {
  const rows=selected()?.scans || [];
  $("#history-table").innerHTML=rows.length ? `<table><thead><tr><th>Started</th><th>Status</th><th>Findings</th><th>Pages</th><th>Duration</th><th></th></tr></thead><tbody>${rows.map(s=>`<tr><td>${date(s.created_at)}${s.id===scanId?'<small>Selected scan</small>':""}</td><td>${badge(s.status)}</td><td>${s.findings}</td><td>${s.pages}</td><td>${s.duration_seconds}s</td><td><button class="secondary" data-scan="${s.id}">Open scan</button></td></tr>`).join("")}</tbody></table>` : '<div class="blank">No scans yet.</div>';
}
function renderCoverage() {
  const r=scan?.result;
  $("#coverage-content").innerHTML=r ? `<div class="coverage-summary"><span>${r.pages.length} pages observed</span><span>${r.checked_rules.length} rules evaluated</span><span>${r.requests} requests</span><span>${r.errors.length} errors / incomplete checks</span><span>${r.auth_used?"Authentication supplied":"Unauthenticated"}</span></div><p class="hint">${esc(r.comparison?.note || "")}</p><ul class="coverage-list">${r.limitations.map(x=>`<li>${esc(x)}</li>`).join("")}</ul>${r.errors.length?'<h3>Errors and incomplete checks</h3>':""}${r.errors.map(x=>`<div class="error-list"><strong>${esc(x.url)}</strong><br>${esc(x.message)}</div>`).join("")}<details><summary>Skipped URLs (${r.skipped.length} retained examples)</summary>${r.skipped.map(x=>`<p class="hint">${esc(x.url)}<br>${esc(x.reason)}</p>`).join("") || '<p class="hint">No skipped examples recorded.</p>'}</details>` : '<p class="blank">Run a scan to see its exact coverage.</p>';
  $("#pages-table").innerHTML=r?.pages.length ? `<table><thead><tr><th>HTTP</th><th>URL / title</th><th>Time</th><th>TLS</th></tr></thead><tbody>${r.pages.map(p=>`<tr><td>${p.status}</td><td class="url-cell">${esc(p.url)}<small>${esc(p.title)}${p.truncated?" · BODY TRUNCATED":""}</small></td><td>${p.elapsed_ms}ms</td><td>${esc(p.tls.protocol || "HTTP")}${p.tls.verified?'<small>Certificate verified</small>':""}</td></tr>`).join("")}</tbody></table>` : '<div class="blank">No pages recorded.</div>';
  renderSurface(r);
  $("#rule-table").innerHTML=`<table><thead><tr><th>Check</th><th>Category</th><th>Severity</th><th>Coverage</th></tr></thead><tbody>${state.rules.map(rule=>`<tr><td>${esc(rule.title)}<small>${esc(rule.id)}</small></td><td>${esc(rule.category)}</td><td>${badge(rule.severity)}</td><td>${r?.checked_rules.includes(rule.id)?"Evaluated":"Not evaluated"}</td></tr>`).join("")}</tbody></table>`;
}
function renderSurface(r) {
  if(!r) { $("#surface-content").innerHTML=""; return; }
  const network=r.network, tls=r.tls_checks;
  const table=(headers,rows)=>`<div class="table-wrap"><table><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map(value=>`<td class="url-cell">${esc(value)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  let content='<h3>Surface inventory</h3><p class="hint">Observed hosts are leads, not proof of ownership. Only your selected target is scanned.</p>';
  content+=table(["Host","Observed in","Scope"],(r.assets||[]).map(a=>[a.host,a.source,a.scope]));
  content+='<h3>Selected-host TCP checks</h3>';
  content+=network?`<p class="hint">${esc(network.note)}</p>`+table(["Address","Port","State","Service hint"],network.observations.map(n=>[n.address,n.port,n.state,n.service_hint])):'<p class="hint">Not evaluated for this scan.</p>';
  if(r.comparison?.new_open_ports?.length) content+=`<p class="hint">Newly observed open ports: ${esc(r.comparison.new_open_ports.join(", "))}</p>`;
  content+='<h3>TLS capabilities</h3>';
  content+=tls?`<p class="hint">${esc(tls.note)}</p>`+table(["Version","Result","Negotiated / reason"],tls.observations.map(t=>[t.protocol,t.state,t.negotiated||t.reason||""])):'<p class="hint">Not evaluated for this scan.</p>';
  content+='<details><summary>Exposure probe outcomes</summary>'+table(["URL","HTTP","Result"],(r.probes||[]).map(p=>[p.url,p.http_status||"—",p.outcome]))+'</details>';
  content+='<details><summary>Discovery documents</summary>'+table(["URL","Type","HTTP","Entries"],(r.discovery||[]).map(d=>[d.url,d.type,d.status,d.discovered||0]))+'</details>';
  $("#surface-content").innerHTML=content;
}
function settingsFields(p) {
  const o={...state.defaults,...p.options};
  return `<div class="actions"><button type="button" class="secondary" data-preset="baseline">Baseline website checks</button><button type="button" class="secondary" data-preset="enhanced">Enhanced website checks</button></div><p class="hint">Enhanced selects 200 pages, sitemap discovery and exposure checks. Save settings to apply the preset. Network and TLS probes remain separate.</p><div class="field-grid"><label>Website name<input name="name" required maxlength="100" value="${esc(p.name)}"></label><label>Target URL<input name="url" readonly value="${esc(p.url)}"></label><label>Maximum pages<input name="max_pages" type="number" min="1" max="200" value="${o.max_pages}" required></label><label>Maximum crawl depth<input name="max_depth" type="number" min="0" max="8" value="${o.max_depth}" required></label><label>Requests per second<input name="rate" type="number" min="1" max="5" value="${o.rate}" required></label><label>Path scope<input name="path_scope" value="${esc(o.path_scope)}" required></label></div><label>Excluded path fragments (one per line)<textarea name="exclude_paths" rows="6">${esc(o.exclude_paths)}</textarea></label><p class="hint">Matches anywhere in the decoded URL path. Add application-specific routes that change data. Path scope includes the selected path and its descendants.</p>${[["allow_private","Allow localhost and private network targets"],["verify_tls","Verify HTTPS certificates"],["exposure_checks","Check common exposed files and CORS (15 content probes plus control and CORS requests)"],["include_queries","Crawl links with query strings (values are redacted in reports)"],["discovery_checks","Discover pages through robots.txt and up to five sitemaps"],["network_checks","Check selected TCP ports on infrastructure I am authorized to test"],["tls_checks","Check TLS 1.0 / 1.1 / 1.2 / 1.3 capabilities without credentials"]].map(([key,label])=>`<label class="checkbox"><input type="checkbox" name="${key}" ${o[key]?"checked":""}>${label}</label>`).join("")}<label>TCP ports (up to 32, comma-separated)<input name="network_ports" value="${esc(o.network_ports)}" maxlength="250" required></label><p class="hint">TCP checks use up to four resolved IPs of the selected hostname. Shared hosting/CDN IPs may belong to another operator; enable only when you may test that infrastructure. Other discovered hostnames are listed without scanning.</p><p class="hint">Exposure checks validate environment, Git, API, diagnostic, package and backup content within your path scope and compare against a nonexistent-page control. Disabling certificate verification is for local self-signed development sites; authentication is unavailable in that mode.</p><p class="form-error" role="alert"></p><button class="primary" type="submit">Save settings</button>`;
}
function renderSettings() { const p=selected(); if(p) $("#settings-form").innerHTML=settingsFields(p); }
function openFinding(id) {
  const f=scan?.result.findings.find(f=>f.id===id); if(!f) return;
  $("#finding-detail").innerHTML=`<div class="detail-badges">${badge(f.severity)}${badge(f.status)}<span class="badge info">${esc(f.confidence)} confidence</span></div><h2>${esc(f.title)}</h2><div class="detail-url">${esc(f.url)}</div><h3>Observed evidence</h3><pre>${esc(f.evidence)}</pre><h3>Recommended fix</h3><p>${esc(f.remediation)}</p><p class="hint">${esc(f.rule)}${f.cwe?` · ${esc(f.cwe)}`:""} · ${esc(f.change)}</p><form id="triage-form" data-id="${f.id}"><label>Review status<select name="status"><option value="open">Open</option><option value="reviewing">Reviewing</option><option value="accepted">Accepted risk</option></select></label><label>Your note<textarea name="note" rows="3" maxlength="2000" placeholder="Add context or a planned fix…">${esc(f.note)}</textarea></label><p class="hint">Review status follows this finding across scans of this website. A rescan determines whether it is still observed.</p><p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="secondary close-dialog">Close</button><button class="primary" type="submit">Save review</button></div></form>`;
  const related=(scan?.result.findings || []).filter(item=>item.rule===f.rule);
  if(related.length>1) $("#finding-detail").insertAdjacentHTML("beforeend",`<details><summary>All ${related.length} occurrences of this issue</summary>${related.map(item=>`<p><button class="text-button" data-related="${item.id}">${esc(item.url)}</button> ${badge(item.status)}</p>`).join("")}</details>`);
  $("#triage-form select").value=f.status; $("#finding-dialog").showModal();
}
function openAdd() { $("#website-form").reset(); $("#website-form .form-error").textContent=""; $("#website-dialog").showModal(); }
function openScan() {
  const p=selected(); if(!p) return openAdd();
  $("#scan-form").reset(); $("#scan-form .form-error").textContent="";
  $("#scan-target").textContent=p.url;
  $("#scan-config").textContent=`Up to ${p.options.max_pages} pages · depth ${p.options.max_depth} · ${p.options.rate} requests/second · ${p.options.exposure_checks?"exposure checks enabled":"baseline checks"} · ${p.options.discovery_checks?"sitemaps on":"sitemaps off"} · ${p.options.network_checks?"TCP ports: "+p.options.network_ports:"TCP checks off"} · ${p.options.tls_checks?"TLS probes on":"TLS probes off"}`;
  $("#scan-dialog").showModal();
}
document.addEventListener("click", async event=>{
  const b=event.target.closest("button"); if(!b) return;
  if(b.classList.contains("close-dialog")) { b.closest("dialog").close(); return; }
  if(b.dataset.view) return showView(b.dataset.view);
  if(b.dataset.related) { $("#finding-dialog").close(); return openFinding(b.dataset.related); }
  if(b.dataset.finding) return openFinding(b.dataset.finding);
  if(b.classList.contains("export")) { if(scan) window.location.assign(`/api/scans/${scan.id}/${b.dataset.format}`); return; }
  if(b.id==="add-site" || b.id==="empty-add") return openAdd();
  if(b.id==="new-scan") return openScan();
  if(b.id==="all-findings") return showView("findings");
  if(b.id==="view-coverage") return showView("coverage");
  try {
    if(b.dataset.preset) {
      const form=$("#settings-form"), enhanced=b.dataset.preset==="enhanced";
      form.elements.max_pages.value=enhanced?200:30;
      form.elements.max_depth.value=enhanced?5:3;
      form.elements.discovery_checks.checked=enhanced;
      form.elements.exposure_checks.checked=enhanced;
      settingsDirty=true; toast("Preset selected. Save settings to apply it.");
    }
    if(b.dataset.scan) { scanId=b.dataset.scan; await refresh(true); showView("overview"); }
    if(b.dataset.cancel) { await api(`/api/scans/${b.dataset.cancel}/cancel`,{}); toast("Cancellation requested. The current request may take a few seconds to finish."); }
    if(b.id==="demo-scan") { b.disabled=true; const demo=await api("/api/demo",{}); projectId=demo.project_id; scanId=demo.scan_id; localStorage.setItem("xa-project",projectId); await refresh(true); toast("Scanning the local demonstration website."); }
  } catch(error) { toast(error.message); } finally { if(b.id==="demo-scan") b.disabled=false; }
});
document.addEventListener("submit", async event=>{
  event.preventDefault(); const form=event.target, submit=form.querySelector('[type="submit"]'), error=form.querySelector(".form-error");
  if(error) error.textContent=""; if(submit) submit.disabled=true;
  try {
    const values=Object.fromEntries(new FormData(form));
    if(form.id==="website-form") {
      const p=await api("/api/projects",{name:values.name,url:values.url,options:{allow_private:form.elements.allow_private.checked}});
      projectId=p.id; scanId=null; localStorage.setItem("xa-project",p.id); $("#website-dialog").close(); await refresh(true); showView("overview"); openScan();
    } else if(form.id==="scan-form") {
      const started=await api(`/api/projects/${projectId}/scan`,{auth:{Authorization:values.authorization,Cookie:values.cookie}});
      form.reset(); $("#scan-dialog").close(); scanId=started.id; await refresh(true); showView("overview");
    } else if(form.id==="settings-form") {
      const options={}; for(const key of Object.keys(state.defaults)) options[key]=typeof state.defaults[key]==="boolean" ? form.elements[key].checked : typeof state.defaults[key]==="number" ? Number(values[key]) : values[key];
      await api(`/api/projects/${projectId}`,{name:values.name,url:values.url,options}); settingsDirty=false; toast("Settings saved for your next scan."); await refresh(true);
    } else if(form.id==="triage-form") {
      await api(`/api/scans/${scanId}/findings/${form.dataset.id}`,values); $("#finding-dialog").close(); await refresh(true); toast("Finding review saved.");
    }
  } catch(e) { if(error) error.textContent=e.message; else toast(e.message); } finally { if(submit) submit.disabled=false; }
});
$("#website-select").addEventListener("change",async event=>{projectId=event.target.value;scanId=null;settingsDirty=false;localStorage.setItem("xa-project",projectId);await refresh(true);renderSettings();});
$("#settings-form").addEventListener("input",()=>settingsDirty=true);
$("#finding-search").addEventListener("input",renderFindings);
$("#group-findings").addEventListener("change",renderFindings);
$("#severity-filter").addEventListener("change",renderFindings);
$("#status-filter").addEventListener("change",renderFindings);
$("#scan-dialog").addEventListener("close",()=>$("#scan-form").reset());
refresh(true);
setInterval(()=>refresh(),1800);
