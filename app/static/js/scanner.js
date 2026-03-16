// Dillu Analyzer — Frontend Logic
let currentScanData = null, currentScanId = null;

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => { e.preventDefault(); dropZone.classList.remove('dragover'); if (e.dataTransfer.files[0]) handleFileSelected(e.dataTransfer.files[0]); });
dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', e => { if (e.target.files[0]) handleFileSelected(e.target.files[0]); });

function toggleVtKey() { const i = document.getElementById('vtApiKey'); i.type = i.type === 'password' ? 'text' : 'password'; }

async function handleFileSelected(file) {
    if (file.size > 100 * 1024 * 1024) { showError('File exceeds 100MB limit.'); return; }
    showProgress(file.name);
    const formData = new FormData();
    formData.append('file', file);
    const vtKey = document.getElementById('vtApiKey').value.trim();
    if (vtKey) formData.append('vt_api_key', vtKey);

    const steps = ['step-upload','step-hash','step-yara','step-deep','step-strings','step-vt'];
    steps.forEach((s, i) => animateStep(s, i * 900));
    setProgress(10);
    const progressInterval = startProgressAnimation();
    try {
        const res = await fetch('/api/scan', { method: 'POST', body: formData });
        clearInterval(progressInterval); setProgress(100);
        if (!res.ok) { const err = await res.json(); showError(err.error || 'Scan failed.'); return; }
        const data = await res.json();
        currentScanData = data; currentScanId = data.scan_id;
        steps.forEach(completeStep);
        await sleep(600);
        showResults(data);
    } catch (err) { clearInterval(progressInterval); showError('Network error: ' + err.message); }
}

function startProgressAnimation() {
    let pct = 10;
    return setInterval(() => { if (pct < 85) { pct += Math.random() * 2.5; setProgress(Math.min(pct, 85)); } }, 400);
}
function setProgress(pct) { pct = Math.round(pct); document.getElementById('progressBar').style.width = pct + '%'; document.getElementById('progressPct').textContent = pct + '%'; }

let stepTimers = [];
function animateStep(stepId, delay) {
    const t = setTimeout(() => {
        const all = ['step-upload','step-hash','step-yara','step-deep','step-strings','step-vt'];
        const idx = all.indexOf(stepId);
        if (idx > 0) completeStep(all[idx - 1]);
        const el = document.getElementById(stepId);
        if (!el) return;
        el.classList.add('step-active');
        el.querySelector('.step-icon').className = 'step-icon step-running';
        el.querySelector('.step-icon').textContent = '●';
    }, delay);
    stepTimers.push(t);
}
function completeStep(stepId) {
    const el = document.getElementById(stepId);
    if (!el) return;
    el.classList.remove('step-active'); el.classList.add('step-done');
    el.querySelector('.step-icon').className = 'step-icon step-done-icon';
    el.querySelector('.step-icon').textContent = '✓';
}

function showProgress(filename) {
    hide('uploadSection'); hide('resultsSection'); show('progressSection');
    document.getElementById('progressFile').textContent = filename;
    setProgress(0);
    ['step-upload','step-hash','step-yara','step-deep','step-strings','step-vt'].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        el.classList.remove('step-active','step-done');
        el.querySelector('.step-icon').className = 'step-icon step-waiting';
        el.querySelector('.step-icon').textContent = '○';
    });
}

function showResults(data) {
    hide('progressSection'); hide('uploadSection'); show('resultsSection');
    renderRiskSummary(data.risk, data);
    renderFileInfo(data.file_info);
    renderYara(data.yara_results);
    renderTypeAnalysis(data.type_analysis, data.file_info?.file_type);
    renderGeneric(data.generic_analysis);
    renderVirustotal(data.virustotal);
}

function resetScanner() {
    stepTimers.forEach(clearTimeout); stepTimers = [];
    currentScanData = null; currentScanId = null; fileInput.value = '';
    hide('resultsSection'); hide('progressSection'); show('uploadSection');
}

function renderRiskSummary(risk, data) {
    animateGauge(risk.score);
    animateNumber('riskScoreDisplay', 0, risk.score, 1200);
    const badge = document.getElementById('riskLevelBadge');
    badge.textContent = risk.level;
    badge.className = 'risk-level-badge badge-' + risk.level.toLowerCase();
    const descs = {
        CRITICAL: 'Multiple high-severity threats detected. This file is very likely malicious. Do not execute or open.',
        HIGH: 'Significant suspicious behavior detected. Treat this file with extreme caution.',
        MEDIUM: 'Moderate risk — some suspicious indicators found. Further investigation recommended.',
        LOW: 'No significant threats detected. File appears relatively safe.',
    };
    document.getElementById('riskDesc').textContent = descs[risk.level] || descs.LOW;
    const yara = data.yara_results || {}, vt = data.virustotal || {}, gen = data.generic_analysis || {};
    document.getElementById('riskStats').innerHTML = `
        <div class="risk-stat"><span class="risk-stat-val">${yara.rule_count||0}</span><span class="risk-stat-lbl">YARA Hits</span></div>
        <div class="risk-stat"><span class="risk-stat-val">${countSuspicious(data.type_analysis)}</span><span class="risk-stat-lbl">Indicators</span></div>
        <div class="risk-stat"><span class="risk-stat-val">${vt.malicious_count??'—'}</span><span class="risk-stat-lbl">VT Detections</span></div>
        <div class="risk-stat"><span class="risk-stat-val">${gen.entropy??'—'}</span><span class="risk-stat-lbl">Entropy</span></div>`;
}

function countSuspicious(ta) {
    if (!ta) return 0;
    let n = 0;
    ['pe_analysis','office_analysis','script_analysis','archive_analysis','image_analysis'].forEach(k => {
        const a = ta[k]; if (!a) return;
        n += (a.suspicious_strings?.length||0)+(a.suspicious_patterns?.length||0)+(a.suspicious_indicators?.length||0)+(a.obfuscation_indicators?.length||0)+(a.suspicious_files?.length||0);
        if (a.has_macros) n++;
    });
    if (ta.javascript) n += (ta.javascript.suspicious_patterns?.length||0);
    return n;
}

function renderFileInfo(info) {
    const el = document.getElementById('bodyFileInfo'), badge = document.getElementById('badgeFileInfo');
    const ft = info.file_type || {};
    badge.textContent = ft.type_name || info.filename?.split('.').pop()?.toUpperCase() || '—';
    badge.style.cssText = 'background:var(--surface2);border:1px solid var(--border);color:var(--text2)';
    let html = `<div class="type-banner">
        <span class="type-cat-badge">${ft.type_category?.toUpperCase()||'?'}</span>
        <span class="type-name-text">${escHtml(ft.type_name||'Unknown')}</span>
        ${ft.is_text?'<span class="type-text-badge">TEXT</span>':'<span class="type-bin-badge">BINARY</span>'}
    </div>`;
    html += '<div class="info-rows">';
    html += infoRow('Filename', escHtml(info.filename));
    html += infoRow('File Size', info.size_human||formatSize(info.size));
    html += infoRow('Extension', escHtml(ft.extension||'—'));
    html += infoRow('Scan Time', new Date(info.upload_time).toLocaleString());
    html += '</div><div style="margin-top:14px"><div class="section-label">CRYPTOGRAPHIC HASHES</div><div class="hash-group">';
    if (info.hashes) { html += hashItem('MD5', info.hashes.md5)+hashItem('SHA1', info.hashes.sha1)+hashItem('SHA256', info.hashes.sha256); }
    html += '</div></div>';
    el.innerHTML = html;
}

function renderYara(yara) {
    const el = document.getElementById('bodyYara'), badge = document.getElementById('badgeYara');
    const matches = yara.matches||[];
    setBadgeRisk(badge, yara.risk_level, `${matches.length} match${matches.length!==1?'es':''}`);
    let html = '';
    if (yara.yara_unavailable) html += `<div class="info-banner warn">⚠ yara-python not installed — using built-in signatures</div>`;
    if (matches.length === 0) { html += `<div class="no-matches"><span class="check-icon">✅</span>No signatures matched.</div>`; }
    else {
        html += '<div class="yara-list">';
        matches.forEach(m => { html += `<div class="yara-match sev-${m.severity}"><div class="yara-match-header"><span class="yara-rule">${escHtml(m.rule)}</span><span class="yara-sev sev-tag-${m.severity}">${m.severity}</span></div><div class="yara-desc">${escHtml(m.description)}</div><div class="yara-cat">Category: ${escHtml(m.category)}</div>${m.tags?.length?`<div class="tag-row">${m.tags.map(t=>`<span class="tag">${escHtml(t)}</span>`).join('')}</div>`:''}</div>`; });
        html += '</div>';
    }
    el.innerHTML = html;
}

const TYPE_ICONS = { 'PDF':'📄','PE Executable':'⚙️','ELF Binary':'🐧','Office Document':'📊','Archive':'📦','Script':'🖥️','Image':'🖼️','Generic':'🔍' };

function renderTypeAnalysis(ta, fileType) {
    const el = document.getElementById('bodyTypeAnalysis'), badge = document.getElementById('badgeTypeAnalysis');
    const title = document.getElementById('typeAnalysisTitle'), icon = document.getElementById('typeAnalysisIcon');
    const analyzer = ta?.analyzer||'Generic';
    icon.textContent = TYPE_ICONS[analyzer]||'🔬';
    title.textContent = (analyzer+' ANALYSIS').toUpperCase();
    let html = '', riskLevel = 'LOW';
    if (ta?.pe_analysis) { html = renderPE(ta.pe_analysis); riskLevel = ta.pe_analysis.risk_level; }
    else if (ta?.office_analysis) { html = renderOffice(ta.office_analysis); riskLevel = ta.office_analysis.risk_level; }
    else if (ta?.archive_analysis) { html = renderArchive(ta.archive_analysis); riskLevel = ta.archive_analysis.risk_level; }
    else if (ta?.script_analysis) { html = renderScript(ta.script_analysis); riskLevel = ta.script_analysis.risk_level; }
    else if (ta?.image_analysis) { html = renderImage(ta.image_analysis); riskLevel = ta.image_analysis.risk_level; }
    else if (ta?.javascript) { html = renderPdfDeep(ta); riskLevel = levelMax(ta.javascript?.risk_level, ta.embedded_files?.risk_level); }
    else { html = `<div class="no-matches"><span class="check-icon">ℹ️</span>Generic file — no type-specific analysis available.</div>`; }
    setBadgeRisk(badge, riskLevel, riskLevel);
    el.innerHTML = html;
}

function renderPE(pe) {
    let html = '<div class="analysis-cols"><div class="analysis-col"><div class="section-label">PROPERTIES</div><div class="info-rows">';
    html += infoRow('Architecture', pe.is_64bit?'x64':(pe.machine_type||'x86'));
    html += infoRow('Type', pe.is_dll?'DLL':(pe.is_system?'Driver':'Executable'));
    html += infoRow('Packed', pe.possibly_packed?'⚠ Possibly packed':'✓ No indicators');
    html += infoRow('Sections', (pe.sections||[]).join(', ')||'—');
    html += '</div>';
    if (pe.packed_indicators?.length) { html += `<div class="section-label" style="margin-top:14px">PACKER SIGNATURES</div><div class="pattern-list">`; pe.packed_indicators.forEach(p=>{ html+=`<div class="pattern-item"><span class="pattern-name">${escHtml(p)}</span><span class="pattern-sev sev-tag-MEDIUM">MEDIUM</span></div>`; }); html+='</div>'; }
    html += '</div><div class="analysis-col"><div class="section-label">SUSPICIOUS CAPABILITIES</div>';
    if (pe.suspicious_strings?.length) { html+='<div class="pattern-list">'; pe.suspicious_strings.forEach(s=>{ html+=`<div class="pattern-item"><span class="pattern-name">${escHtml(s)}</span><span class="pattern-sev sev-tag-HIGH">HIGH</span></div>`; }); html+='</div>'; }
    else { html+=`<div class="no-matches" style="padding:12px"><span>✅</span> No suspicious APIs</div>`; }
    html += '</div></div>'; return html;
}

function renderOffice(off) {
    let html = '<div class="analysis-cols"><div class="analysis-col"><div class="section-label">PROPERTIES</div><div class="info-rows">';
    html += infoRow('Format', off.format||'—')+infoRow('Macros Present', off.has_macros?'⚠ YES':'✓ No')+infoRow('External Links', (off.external_links?.length||0).toString())+infoRow('Embedded Objects', (off.embedded_objects?.length||0).toString());
    if (off.xml_parts!==undefined) html+=infoRow('XML Parts', off.xml_parts.toString());
    html += '</div>';
    if (off.macro_names?.length) { html+=`<div class="section-label" style="margin-top:14px">AUTO-EXEC MACROS</div><div class="tag-row">`; off.macro_names.forEach(m=>{ html+=`<span class="tag" style="color:var(--orange)">${escHtml(m)}</span>`; }); html+='</div>'; }
    html += '</div><div class="analysis-col"><div class="section-label">SUSPICIOUS PATTERNS</div>';
    if (off.suspicious_patterns?.length) { html+='<div class="pattern-list">'; off.suspicious_patterns.forEach(p=>{ html+=`<div class="pattern-item"><span class="pattern-name">${escHtml(p)}</span><span class="pattern-sev sev-tag-HIGH">HIGH</span></div>`; }); html+='</div>'; }
    else { html+=`<div class="no-matches" style="padding:12px"><span>✅</span> No suspicious macro patterns</div>`; }
    if (off.external_links?.length) { html+=`<div class="section-label" style="margin-top:14px">EXTERNAL LINKS</div><div class="pattern-list">`; off.external_links.slice(0,5).forEach(l=>{ html+=`<div class="pattern-item"><span class="pattern-name" style="font-size:10px">${escHtml(l)}</span><span class="pattern-sev sev-tag-MEDIUM">MEDIUM</span></div>`; }); html+='</div>'; }
    html += '</div></div>'; return html;
}

function renderArchive(arc) {
    let html = '<div class="analysis-cols"><div class="analysis-col"><div class="section-label">ARCHIVE INFO</div><div class="info-rows">';
    html += infoRow('Total Files', arc.file_count.toString())+infoRow('Uncompressed Size', formatSize(arc.total_size));
    if (arc.compression_ratio!==undefined) html+=infoRow('Compression Ratio', arc.compression_ratio+'x'+(arc.compression_ratio>100?' ⚠ BOMB?':''));
    html += infoRow('Nested Archives', (arc.nested_archives?.length||0).toString())+infoRow('Suspicious Files', (arc.suspicious_files?.length||0).toString())+'</div></div>';
    html += '<div class="analysis-col">';
    if (arc.suspicious_files?.length) {
        html+=`<div class="section-label">SUSPICIOUS ENTRIES</div><div class="file-list">`;
        arc.suspicious_files.slice(0,10).forEach(f=>{ const ext=f.split('.').pop()||''; html+=`<div class="file-item"><span class="file-ext dangerous">.${escHtml(ext)}</span><span class="file-name">${escHtml(f)}</span><span style="font-size:11px;color:var(--red)">⚠</span></div>`; });
        html+='</div>';
    } else {
        html+=`<div class="no-matches" style="padding:12px"><span>✅</span> No dangerous files inside archive</div>`;
        if (arc.files?.length) { html+=`<div class="section-label" style="margin-top:14px">CONTENTS (first 8)</div><div class="file-list">`; arc.files.slice(0,8).forEach(f=>{ const ext=(f.name||'').split('.').pop()||''; html+=`<div class="file-item"><span class="file-ext">.${escHtml(ext)}</span><span class="file-name">${escHtml(f.name)}</span><span style="font-size:11px;color:var(--text3)">${formatSize(f.size||0)}</span></div>`; }); html+='</div>'; }
    }
    html += '</div></div>'; return html;
}

function renderScript(sc) {
    let html = '<div class="analysis-cols"><div class="analysis-col"><div class="section-label">SCRIPT INFO</div><div class="info-rows">';
    html += infoRow('Language', sc.language||'—')+infoRow('Lines', sc.line_count?.toString()||'—')+infoRow('Risk Level', sc.risk_level||'LOW')+'</div>';
    if (sc.obfuscation_indicators?.length) { html+=`<div class="section-label" style="margin-top:14px">OBFUSCATION</div><div class="pattern-list">`; sc.obfuscation_indicators.forEach(o=>{ html+=`<div class="pattern-item"><span class="pattern-name">${escHtml(o)}</span><span class="pattern-sev sev-tag-MEDIUM">MEDIUM</span></div>`; }); html+='</div>'; }
    html += '</div><div class="analysis-col"><div class="section-label">SUSPICIOUS BEHAVIORS</div>';
    if (sc.suspicious_patterns?.length) { html+='<div class="pattern-list">'; sc.suspicious_patterns.forEach(p=>{ html+=`<div class="pattern-item"><span class="pattern-name">${escHtml(p.label)}</span><span class="pattern-sev sev-tag-${p.severity}">${p.severity}</span></div>`; }); html+='</div>'; }
    else { html+=`<div class="no-matches" style="padding:12px"><span>✅</span> No suspicious behaviors</div>`; }
    html += '</div></div>'; return html;
}

function renderImage(img) {
    let html = '<div class="analysis-cols"><div class="analysis-col"><div class="section-label">IMAGE INFO</div><div class="info-rows">';
    html += infoRow('Format', img.format||'—')+infoRow('File Size', formatSize(img.file_size||0))+infoRow('Trailing Data', img.has_trailing_data?'⚠ YES':'✓ No')+infoRow('Embedded Scripts', img.has_embedded_text?'⚠ YES':'✓ No')+'</div></div>';
    html += '<div class="analysis-col"><div class="section-label">STEGANOGRAPHY INDICATORS</div>';
    if (img.suspicious_indicators?.length) { html+='<div class="pattern-list">'; img.suspicious_indicators.forEach(s=>{ html+=`<div class="pattern-item"><span class="pattern-name">${escHtml(s)}</span><span class="pattern-sev sev-tag-MEDIUM">MEDIUM</span></div>`; }); html+='</div>'; }
    else { html+=`<div class="no-matches" style="padding:12px"><span>✅</span> No steganography indicators found</div>`; }
    html += '</div></div>'; return html;
}

function renderPdfDeep(ta) {
    const js=ta.javascript||{}, emb=ta.embedded_files||{}, meta=ta.metadata||{};
    let html = '<div class="analysis-cols"><div class="analysis-col"><div class="section-label">PDF METADATA</div><div class="info-rows">';
    if (meta.pdf_version) html+=infoRow('Version', meta.pdf_version);
    if (meta.page_count!==undefined) html+=infoRow('Pages', meta.page_count);
    if (meta.author) html+=infoRow('Author', escHtml(meta.author));
    if (meta.creator) html+=infoRow('Creator', escHtml(meta.creator));
    html+=infoRow('Encrypted', meta.encrypted?'🔒 Yes':'No')+infoRow('Objects', meta.object_count||'—')+'</div>';
    html+=`<div class="section-label" style="margin-top:14px">JAVASCRIPT</div><div class="info-rows">`;
    html+=infoRow('JS Present', js.has_javascript?'⚠ YES':'✓ No')+infoRow('Suspicious Patterns', (js.suspicious_patterns?.length||0).toString())+'</div>';
    if (js.suspicious_patterns?.length) { html+='<div class="pattern-list" style="margin-top:8px">'; js.suspicious_patterns.forEach(p=>{ html+=`<div class="pattern-item"><span class="pattern-name">${escHtml(p.pattern)}</span><span class="pattern-sev sev-tag-${p.severity}">${p.severity}</span></div>`; }); html+='</div>'; }
    html += '</div><div class="analysis-col"><div class="section-label">EMBEDDED OBJECTS</div><div class="info-rows">';
    html+=infoRow('Has Embedded', emb.has_embedded?'⚠ YES':'✓ No')+infoRow('Auto Actions', (emb.auto_actions?.length||0).toString())+infoRow('Suspicious Files', (emb.suspicious_types?.length||0).toString())+'</div>';
    if (emb.auto_actions?.length) { html+=`<div class="section-label" style="margin-top:14px">AUTO-EXEC ACTIONS</div><div class="action-list">`; emb.auto_actions.forEach(a=>{ html+=`<div class="action-item">⚡ ${escHtml(a)}</div>`; }); html+='</div>'; }
    if (emb.files?.length) { html+=`<div class="section-label" style="margin-top:14px">EMBEDDED FILES</div><div class="file-list">`; emb.files.forEach(f=>{ html+=`<div class="file-item"><span class="file-ext ${f.suspicious?'dangerous':''}">${escHtml(f.extension||'?')}</span><span class="file-name">${escHtml(f.name)}</span>${f.suspicious?'<span style="font-size:11px;color:var(--red)">⚠</span>':''}</div>`; }); html+='</div>'; }
    html += '</div></div>'; return html;
}

function renderGeneric(gen) {
    const el=document.getElementById('bodyGeneric'), badge=document.getElementById('badgeGeneric');
    const hasThreats=gen.suspicious_urls?.length||gen.suspicious_ips?.length||gen.high_entropy;
    setBadgeRisk(badge, hasThreats?'MEDIUM':'LOW', `Entropy: ${gen.entropy}`);
    let html='<div class="info-rows" style="margin-bottom:14px">';
    html+=infoRow('Entropy', `${gen.entropy} ${gen.entropy>7.5?'⚠ HIGH (packed/encrypted?)':gen.entropy>6.5?'↑ Elevated':'✓ Normal'}`);
    html+=infoRow('Strings Found', (gen.strings_found?.length||0).toString())+infoRow('Suspicious URLs', (gen.suspicious_urls?.length||0).toString())+infoRow('Public IPs', (gen.suspicious_ips?.length||0).toString())+'</div>';
    if (gen.suspicious_urls?.length) { html+=`<div class="section-label">SUSPICIOUS URLS</div><div class="ioc-list">`; gen.suspicious_urls.slice(0,8).forEach(u=>{ html+=`<div class="ioc-item"><span class="ioc-icon">🔗</span><span class="ioc-val">${escHtml(u)}</span></div>`; }); html+='</div>'; }
    if (gen.suspicious_ips?.length) { html+=`<div class="section-label" style="margin-top:12px">PUBLIC IP ADDRESSES</div><div class="ioc-list">`; gen.suspicious_ips.slice(0,8).forEach(ip=>{ html+=`<div class="ioc-item"><span class="ioc-icon">🖥</span><span class="ioc-val">${escHtml(ip)}</span></div>`; }); html+='</div>'; }
    if (gen.strings_found?.length) { html+=`<div class="section-label" style="margin-top:12px">INTERESTING STRINGS</div><div class="strings-box">`; gen.strings_found.slice(0,20).forEach(s=>{ html+=`<span class="string-chip">${escHtml(s)}</span>`; }); html+='</div>'; }
    el.innerHTML = html;
}

function renderVirustotal(vt) {
    const el=document.getElementById('bodyVt'), badge=document.getElementById('badgeVt');
    if (!vt.available) { setBadgeLow(badge,'N/A'); el.innerHTML=`<div class="vt-unavailable"><span class="vt-icon">🌐</span><h4>${escHtml(vt.error||vt.message||'VirusTotal not configured')}</h4><p>Add your VirusTotal API key above to enable scanning with 70+ AV engines.</p></div>`; return; }
    if (!vt.found) { setBadgeLow(badge,'Not Found'); el.innerHTML=`<div class="vt-unavailable"><span class="vt-icon">🔍</span><h4>File not found in VirusTotal database</h4><p>${escHtml(vt.message||'This file has not been submitted before.')}</p></div>`; return; }
    setBadgeRisk(badge, vt.risk_level, `${vt.malicious_count}/${vt.total_engines}`);
    const detRate=vt.total_engines>0?(vt.malicious_count/vt.total_engines*100):0;
    let html=`<div class="vt-summary">
        <div class="vt-stat"><span class="vt-stat-num ${vt.malicious_count>0?'danger':'safe'}">${vt.malicious_count}</span><span class="vt-stat-lbl">Malicious</span></div>
        <div class="vt-stat"><span class="vt-stat-num ${(vt.suspicious_count||0)>0?'warn':'safe'}">${vt.suspicious_count||0}</span><span class="vt-stat-lbl">Suspicious</span></div>
        <div class="vt-stat"><span class="vt-stat-num neutral">${vt.total_engines}</span><span class="vt-stat-lbl">Total Engines</span></div>
        <div class="vt-stat"><span class="vt-stat-num ${(vt.reputation||0)<0?'danger':'safe'}">${vt.reputation??0}</span><span class="vt-stat-lbl">Reputation</span></div></div>
    <div class="vt-detection-bar"><div class="vt-bar-label"><span>Detection Rate</span><span>${vt.detection_rate}</span></div><div class="vt-bar-track"><div class="vt-bar-fill" id="vtBarFill" style="width:0%"></div></div></div>`;
    if (vt.detections?.length) { html+=`<div class="section-label">DETECTIONS (${vt.detections.length})</div><div class="vt-detections">`; vt.detections.forEach(d=>{ html+=`<div class="detection-item"><div class="detection-engine">${escHtml(d.engine)}</div><div class="detection-name ${d.category==='suspicious'?'suspicious':''}">${escHtml(d.result)}</div></div>`; }); html+='</div>'; }
    else { html+=`<div class="no-matches"><span class="check-icon">✅</span>No detections by any engine.</div>`; }
    el.innerHTML=html;
    setTimeout(()=>{ const b=document.getElementById('vtBarFill'); if(b) b.style.width=detRate+'%'; },100);
}

// ── Utils ──
function animateGauge(score) {
    const totalLength=251.2, fill=document.getElementById('gaugeFill'), needle=document.getElementById('gaugeNeedle');
    const target=(score/100)*totalLength; let current=0;
    const interval=setInterval(()=>{ current=Math.min(current+target/40,target); fill.setAttribute('stroke-dasharray',`${current} ${totalLength}`); needle.setAttribute('transform',`rotate(${-90+(current/totalLength)*180}, 100, 100)`); if(current>=target)clearInterval(interval); },25);
}
function animateNumber(id,from,to,duration) {
    const el=document.getElementById(id); if(!el)return;
    const start=performance.now();
    (function u(now){const t=Math.min((now-start)/duration,1);el.textContent=Math.round(from+(to-from)*(1-Math.pow(1-t,3)));if(t<1)requestAnimationFrame(u);})(performance.now());
}
function levelMax(a,b){const r={CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1};return(r[a]||0)>=(r[b]||0)?(a||'LOW'):(b||'LOW');}
function downloadReport(){if(!currentScanId)return;const a=document.createElement('a');a.href=`/api/report/${currentScanId}`;a.download=`scan_report_${currentScanId.slice(0,8)}.json`;a.click();}
function show(id){document.getElementById(id)?.classList.remove('hidden');}
function hide(id){document.getElementById(id)?.classList.add('hidden');}
function escHtml(str){if(str==null)return'';return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function formatSize(bytes){if(!bytes)return'0 B';const u=['B','KB','MB','GB'];let i=0,s=bytes;while(s>=1024&&i<3){s/=1024;i++;}return`${s.toFixed(1)} ${u[i]}`;}
function infoRow(label,value){return`<div class="info-row"><span class="info-label">${label}</span><span class="info-val">${value}</span></div>`;}
function hashItem(type,val){return`<div class="hash-item"><span class="hash-type">${type}</span><span class="hash-val">${escHtml(val||'—')}</span></div>`;}
function setBadgeRisk(el,level,text){const cfg={CRITICAL:['rgba(255,45,85,0.2)','rgba(255,45,85,0.5)','var(--red)'],HIGH:['rgba(255,107,53,0.2)','rgba(255,107,53,0.5)','var(--orange)'],MEDIUM:['rgba(255,214,10,0.2)','rgba(255,214,10,0.5)','var(--yellow)'],LOW:['rgba(48,209,88,0.2)','rgba(48,209,88,0.5)','var(--green)']};const[bg,border,color]=cfg[level]||['var(--surface2)','var(--border)','var(--text2)'];el.textContent=text;el.style.cssText=`background:${bg};border:1px solid ${border};color:${color}`;}
function setBadgeLow(el,text){el.textContent=text;el.style.cssText='background:var(--surface2);border:1px solid var(--border);color:var(--text3)';}
function showError(msg){hide('progressSection');show('uploadSection');const el=document.createElement('div');el.style.cssText=`position:fixed;top:80px;right:24px;z-index:999;background:rgba(255,45,85,0.15);border:1px solid rgba(255,45,85,0.4);color:var(--red);padding:14px 20px;border-radius:8px;font-family:var(--mono);font-size:13px;max-width:400px;animation:fadeIn 0.3s ease`;el.textContent='⚠ '+msg;document.body.appendChild(el);setTimeout(()=>el.remove(),5000);}
function sleep(ms){return new Promise(r=>setTimeout(r,ms));}
