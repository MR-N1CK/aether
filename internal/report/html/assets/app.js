(function() {
  'use strict';

  var dataElement = document.getElementById('aether-data');
  if (!dataElement) return;

  var reportData = {};
  try {
    reportData = JSON.parse(dataElement.textContent || '{}');
  } catch (e) {
    reportData = { findings: [] };
  }

  var allFindings = reportData.findings || [];
  var currentSeverity = 'ALL';
  var currentModule = '';
  var currentSearch = '';
  var currentFilteredFindings = [];
  var currentFilteredIndex = -1;

  var tbody = document.getElementById('findings-tbody');
  var emptyState = document.getElementById('empty-state');
  var countSummary = document.getElementById('findings-count-summary');
  var searchInput = document.getElementById('search-input');
  var moduleFilter = document.getElementById('module-filter');
  var pills = document.querySelectorAll('.btn-pill');
  var themeToggle = document.getElementById('theme-toggle');
  var themeIcon = document.getElementById('theme-icon');
  var drawerOverlay = document.getElementById('detail-drawer-overlay');
  var drawerClose = document.getElementById('drawer-close');
  var drawerBody = document.getElementById('drawer-body');
  var drawerPrev = document.getElementById('drawer-prev');
  var drawerNext = document.getElementById('drawer-next');
  var btnExportCSV = document.getElementById('btn-export-csv');
  var btnExportJSON = document.getElementById('btn-export-json');
  var btnExportTriage = document.getElementById('btn-export-triage');
  var btnPrint = document.getElementById('btn-print');
  var activeRow = null;

  // 1. Theme Management
  function initTheme() {
    var saved = localStorage.getItem('aether-theme');
    if (!saved) {
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
        saved = 'light';
      } else {
        saved = 'dark';
      }
    }
    setTheme(saved);
  }

  function setTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    localStorage.setItem('aether-theme', t);
    if (themeIcon) {
      themeIcon.textContent = (t === 'light') ? '◐' : '◑';
    }
  }

  if (themeToggle) {
    themeToggle.addEventListener('click', function() {
      var current = document.documentElement.getAttribute('data-theme') || 'dark';
      var next = (current === 'dark') ? 'light' : 'dark';
      setTheme(next);
    });
  }

  initTheme();

  // 2. Safe DOM Helpers
  function clearChildren(node) {
    while (node && node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function el(tag, classNames, text) {
    var e = document.createElement(tag);
    if (classNames) {
      classNames.split(' ').forEach(function(c) {
        if (c) e.classList.add(c);
      });
    }
    if (text !== undefined && text !== null) {
      e.textContent = String(text);
    }
    return e;
  }

  function createBadge(sev) {
    var span = document.createElement('span');
    span.classList.add('badge');
    var sLower = (sev || 'info').toLowerCase();
    span.classList.add('sev-' + sLower);
    span.textContent = sev || 'INFO';
    return span;
  }

  // Safe DOM text node highlighter (strictly zero unsafe DOM manipulation)
  function appendHighlightedText(parent, text, term) {
    if (!text) return;
    if (!term) {
      parent.appendChild(document.createTextNode(text));
      return;
    }
    var lowerText = text.toLowerCase();
    var lowerTerm = term.toLowerCase();
    var startIndex = 0;
    var matchIndex = lowerText.indexOf(lowerTerm, startIndex);
    if (matchIndex === -1) {
      parent.appendChild(document.createTextNode(text));
      return;
    }
    while (matchIndex !== -1) {
      if (matchIndex > startIndex) {
        parent.appendChild(document.createTextNode(text.substring(startIndex, matchIndex)));
      }
      var mark = document.createElement('mark');
      mark.className = 'search-highlight';
      mark.textContent = text.substring(matchIndex, matchIndex + term.length);
      parent.appendChild(mark);
      startIndex = matchIndex + term.length;
      matchIndex = lowerText.indexOf(lowerTerm, startIndex);
    }
    if (startIndex < text.length) {
      parent.appendChild(document.createTextNode(text.substring(startIndex)));
    }
  }

  // Line-numbered code block with copy integrity
  function renderCodeBlockWithLines(text) {
    var container = el('div', 'code-block code-block-lines');
    var lines = (text || '').split('\n');
    lines.forEach(function(line, idx) {
      var row = el('div', 'code-line-row');
      var num = el('span', 'code-line-num', idx + 1);
      var content = el('span', 'code-line-text', line || ' ');
      row.appendChild(num);
      row.appendChild(content);
      container.appendChild(row);
    });
    return container;
  }

  // 3. Clipboard Copy Helpers
  function copyText(text, btn) {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function() {
        showCopied(btn);
      }).catch(function() {
        fallbackCopy(text, btn);
      });
    } else {
      fallbackCopy(text, btn);
    }
  }

  function fallbackCopy(text, btn) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try {
      document.execCommand('copy');
      showCopied(btn);
    } catch (err) {}
    document.body.removeChild(ta);
  }

  function showCopied(btn) {
    if (!btn) return;
    var orig = btn.textContent;
    btn.textContent = '✓ Copied';
    btn.classList.add('btn-copied');
    setTimeout(function() {
      btn.textContent = orig;
      btn.classList.remove('btn-copied');
    }, 1800);
  }

  // 4. CSV Export
  function exportCSV() {
    var headers = ["Index", "Severity", "Confidence", "Module", "Rule", "Path", "Reason", "Why", "MITRE", "SHA256", "Timestamp"];
    var rows = [headers];
    allFindings.forEach(function(f, i) {
      var mitreStr = (f.mitre || []).map(function(m) {
        return (m.technique || '') + ' ' + (m.technique_name || '');
      }).join('; ');
      var sha256 = (f.hashes && f.hashes['SHA256']) ? f.hashes['SHA256'] : '';
      var row = [
        String(f.index || (i + 1)),
        f.severity || '',
        f.confidence || '',
        f.module || '',
        f.rule_name || '',
        f.path || '',
        f.reason || '',
        f.why || '',
        mitreStr,
        sha256,
        f.timestamp || ''
      ];
      rows.push(row.map(function(val) {
        var s = String(val).replace(/"/g, '""');
        return '"' + s + '"';
      }));
    });
    var csvStr = rows.map(function(r) { return r.join(','); }).join('\r\n');
    var blob = new Blob([csvStr], { type: 'text/csv;charset=utf-8;' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.setAttribute('href', url);
    var hostStr = (reportData.hostname || 'hunt').replace(/[^a-zA-Z0-9_-]/g, '_');
    a.setAttribute('download', 'aether-threat-dossier-' + hostStr + '.csv');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  if (btnExportCSV) {
    btnExportCSV.addEventListener('click', exportCSV);
  }

  function exportJSON() {
    var jsonStr = JSON.stringify(reportData, null, 2);
    var blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8;' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.setAttribute('href', url);
    var hostStr = (reportData.hostname || 'hunt').replace(/[^a-zA-Z0-9_-]/g, '_');
    a.setAttribute('download', 'aether-threat-dossier-' + hostStr + '.json');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  if (btnExportJSON) {
    btnExportJSON.addEventListener('click', exportJSON);
  }

  // 4b. Triage Script Export
  // Builds a self-contained POSIX shell script that gathers read-only
  // evidence for every finding on the target host (existence, metadata,
  // hashes). Remediation guidance is embedded as comments: the script never
  // deletes, kills or mutates anything on its own.
  function shQuote(s) {
    return "'" + String(s).replace(/'/g, "'\\''") + "'";
  }

  function shellCommentLines(prefix, text) {
    var out = [];
    String(text || '').split('\n').forEach(function(line) {
      out.push(prefix + line);
    });
    return out;
  }

  function exportTriage() {
    var hostStr = (reportData.hostname || 'hunt').replace(/[^a-zA-Z0-9_-]/g, '_');
    var lines = [];
    lines.push('#!/bin/sh');
    lines.push('# -----------------------------------------------------------------');
    lines.push('# aether-triage-' + hostStr + '.sh — evidence-gathering triage script');
    lines.push('# Generated by Aether offline HTML report at ' + new Date().toISOString());
    lines.push('# Host: ' + (reportData.hostname || 'unknown'));
    lines.push('# Findings covered: ' + allFindings.length);
    lines.push('#');
    lines.push('# Scope (IMPORTANT):');
    lines.push('#   * Read-only evidence collection only: file existence checks,');
    lines.push('#     metadata listings, and cryptographic hashes.');
    lines.push('#   * Remediation guidance appears as comments for an analyst to');
    lines.push('#     review — the script NEVER deletes, kills or modifies anything.');
    lines.push('# Run on the scanned host (or an image of it): sh ./this-script.sh');
    lines.push('# -----------------------------------------------------------------');
    lines.push('set -u');
    lines.push('');
    lines.push('echo "[aether-triage] evidence collection started at $(date -u 2>/dev/null)"');
    lines.push('');

    allFindings.forEach(function(f, i) {
      var num = f.index || (i + 1);
      var p = f.path || '';
      lines.push('# -----------------------------------------------------------------');
      lines.push('# Finding ' + num + '  [' + (f.severity || '') + ']  ' + (f.rule_name || ''));
      lines.push('# Target: ' + p);
      lines.push('# Reason: ' + (f.reason || ''));
      if (f.why) {
        Array.prototype.push.apply(lines, shellCommentLines('# Why: ', f.why));
      }
      var mitreStr = (f.mitre || []).map(function(m) {
        return (m.technique || '') + ' ' + (m.technique_name || '');
      }).join('; ');
      if (mitreStr) {
        lines.push('# MITRE: ' + mitreStr);
      }
      var sha256 = (f.hashes && f.hashes.SHA256) ? f.hashes.SHA256 : '';
      if (sha256) {
        lines.push('# Expected SHA256: ' + sha256);
      }
      lines.push('');

      if (p) {
        lines.push('TARGET=' + shQuote(p));
        lines.push('if [ -e "$TARGET" ]; then');
        lines.push('    echo "--- Finding ' + num + ': $TARGET ---"');
        lines.push('    file "$TARGET" 2>/dev/null');
        lines.push('    ls -la "$TARGET" 2>/dev/null');
        lines.push('    sha256sum "$TARGET" 2>/dev/null');
        lines.push('else');
        lines.push('    echo "--- Finding ' + num + ': target MISSING (deleted after scan?) - $TARGET"');
        lines.push('fi');
        lines.push('');
      }

      (f.remediation || []).forEach(function(step) {
        Array.prototype.push.apply(lines, shellCommentLines('# Remediation: ', step));
      });
      lines.push('');
    });

    lines.push('echo "[aether-triage] evidence collection finished."');
    lines.push('');

    var blob = new Blob([lines.join('\n')], { type: 'application/x-shellscript;charset=utf-8;' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.setAttribute('href', url);
    a.setAttribute('download', 'aether-triage-' + hostStr + '.sh');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  if (btnExportTriage) {
    btnExportTriage.addEventListener('click', exportTriage);
  }

  if (btnPrint) {
    btnPrint.addEventListener('click', function() {
      window.print();
    });
  }

  // 5. Render Findings Table

  // Sortable findings table state. Severity first-click sorts worst-first
  // (descending), every other column first-click sorts ascending.
  var currentSortKey = null;
  var currentSortDir = 1;

  var SEVERITY_RANK = {
    CRITICAL: 8,
    ALERT: 7,
    HIGH: 6,
    WARNING: 5,
    MEDIUM: 4,
    NOTICE: 3,
    LOW: 2,
    INFO: 1
  };

  function severityRank(sev) {
    return SEVERITY_RANK[(sev || '').toUpperCase()] || 0;
  }

  function timestampValue(ts) {
    var t = Date.parse(ts || '');
    return isNaN(t) ? 0 : t;
  }

  // sortFindingsList returns a stable sorted copy per the active sort state.
  function sortFindingsList(list) {
    if (!currentSortKey) return list.slice(0);
    var key = currentSortKey;
    var dir = currentSortDir;
    var copy = list.slice(0);
    copy.sort(function(a, b) {
      var va, vb;
      if (key === 'severity') {
        va = severityRank(a.severity);
        vb = severityRank(b.severity);
      } else if (key === 'timestamp') {
        va = timestampValue(a.timestamp);
        vb = timestampValue(b.timestamp);
      } else {
        va = String((a[key] || '').toLowerCase());
        vb = String((b[key] || '').toLowerCase());
      }
      if (va < vb) return -1 * dir;
      if (va > vb) return 1 * dir;
      // Stable fallback keeps severity-equal rows in report order.
      return (a.index || 0) - (b.index || 0);
    });
    return copy;
  }

  function updateSortIndicators() {
    var ths = document.querySelectorAll('#findings-table th.sortable');
    for (var i = 0; i < ths.length; i++) {
      var th = ths[i];
      var ind = th.querySelector('.th-sort-ind');
      var isActive = th.getAttribute('data-key') === currentSortKey;
      th.classList.toggle('sorted-asc', isActive && currentSortDir > 0);
      th.classList.toggle('sorted-desc', isActive && currentSortDir < 0);
      if (ind) {
        if (!isActive) {
          ind.textContent = '\u2195';
          th.setAttribute('aria-sort', 'none');
        } else {
          ind.textContent = currentSortDir > 0 ? '\u2191' : '\u2193';
          th.setAttribute('aria-sort', currentSortDir > 0 ? 'ascending' : 'descending');
        }
      }
    }
  }

  function onSortHeaderClick(th) {
    var key = th.getAttribute('data-key');
    if (!key) return;
    if (currentSortKey === key) {
      currentSortDir = -currentSortDir;
    } else {
      currentSortKey = key;
      currentSortDir = (key === 'severity') ? -1 : 1;
    }
    updateSortIndicators();
    renderTable();
  }

  function bindSortableHeaders() {
    var ths = document.querySelectorAll('#findings-table th.sortable');
    for (var i = 0; i < ths.length; i++) {
      (function(th) {
        th.addEventListener('click', function() {
          onSortHeaderClick(th);
        });
        th.addEventListener('keydown', function(e) {
          if (e.key === 'Enter' || e.key === ' ' || e.keyCode === 13 || e.keyCode === 32) {
            e.preventDefault();
            onSortHeaderClick(th);
          }
        });
      })(ths[i]);
    }
    updateSortIndicators();
  }

  function renderTable() {
    clearChildren(tbody);

    var filtered = allFindings.filter(function(f) {
      if (currentSeverity !== 'ALL' && f.severity !== currentSeverity) {
        return false;
      }
      if (currentModule && f.module !== currentModule) {
        return false;
      }
      if (currentSearch) {
        var term = currentSearch.toLowerCase();
        var matchPath = f.path && f.path.toLowerCase().indexOf(term) !== -1;
        var matchRule = f.rule_name && f.rule_name.toLowerCase().indexOf(term) !== -1;
        var matchReason = f.reason && f.reason.toLowerCase().indexOf(term) !== -1;
        var matchModule = f.module && f.module.toLowerCase().indexOf(term) !== -1;
        var matchWhy = f.why && f.why.toLowerCase().indexOf(term) !== -1;
        var matchMitre = (f.mitre || []).some(function(m) {
          return (m.technique && m.technique.toLowerCase().indexOf(term) !== -1) ||
                 (m.tactic && m.tactic.toLowerCase().indexOf(term) !== -1) ||
                 (m.technique_name && m.technique_name.toLowerCase().indexOf(term) !== -1);
        });
        if (!matchPath && !matchRule && !matchReason && !matchModule && !matchWhy && !matchMitre) {
          return false;
        }
      }
      return true;
    });

    var ordered = sortFindingsList(filtered);

    // Drawer prev/next navigation walks the displayed (sorted) order.
    currentFilteredFindings = ordered;

    if (countSummary) {
      countSummary.textContent = 'Showing ' + filtered.length + ' of ' + allFindings.length + ' items';
    }

    if (ordered.length === 0) {
      if (emptyState) emptyState.style.display = 'block';
      return;
    } else {
      if (emptyState) emptyState.style.display = 'none';
    }

    ordered.forEach(function(f, idx) {
      var tr = document.createElement('tr');
      tr.setAttribute('tabindex', '0');
      tr.setAttribute('role', 'button');
      tr.setAttribute('aria-label', 'View details for finding in ' + (f.path || f.rule_name));

      // Severity column
      var tdSev = document.createElement('td');
      tdSev.appendChild(createBadge(f.severity));
      tr.appendChild(tdSev);

      // Module column
      var tdMod = document.createElement('td');
      var modStrong = document.createElement('strong');
      modStrong.textContent = f.module || '';
      tdMod.appendChild(modStrong);
      tr.appendChild(tdMod);

      // Path column
      var tdPath = document.createElement('td');
      var codePath = document.createElement('code');
      appendHighlightedText(codePath, f.path || '', currentSearch);
      tdPath.appendChild(codePath);
      tr.appendChild(tdPath);

      // Rule Name column
      var tdRule = document.createElement('td');
      var codeRule = document.createElement('code');
      appendHighlightedText(codeRule, f.rule_name || '', currentSearch);
      tdRule.appendChild(codeRule);
      tr.appendChild(tdRule);

      // Reason column
      var tdReason = document.createElement('td');
      appendHighlightedText(tdReason, f.reason || '', currentSearch);
      tr.appendChild(tdReason);

      // Timestamp column
      var tdTime = document.createElement('td');
      var timeStr = f.timestamp || '';
      if (timeStr.length > 19) {
        timeStr = timeStr.substring(11, 19);
      }
      tdTime.textContent = timeStr;
      tr.appendChild(tdTime);

      // Row Interaction
      function onRowSelect() {
        activeRow = tr;
        currentFilteredIndex = idx;
        renderDrawerFinding(f);
        openDrawer();
      }

      tr.addEventListener('click', onRowSelect);
      tr.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' || e.key === ' ' || e.keyCode === 13 || e.keyCode === 32) {
          e.preventDefault();
          onRowSelect();
        }
      });

      tbody.appendChild(tr);
    });
  }

  // 6. Detail Drawer Rendering
  function renderDrawerFinding(f) {
    clearChildren(drawerBody);

    var drawerTitle = document.getElementById('drawer-title');
    var drawerIndexBadge = document.getElementById('drawer-index-badge');

    if (drawerTitle) {
      drawerTitle.textContent = f.title || f.rule_name || 'Finding Details';
    }
    if (drawerIndexBadge) {
      drawerIndexBadge.textContent = (currentFilteredIndex >= 0) ? (currentFilteredIndex + 1) + ' / ' + currentFilteredFindings.length : '';
      drawerIndexBadge.className = 'badge sev-' + (f.severity || 'info').toLowerCase();
    }
    if (drawerPrev) {
      drawerPrev.disabled = (currentFilteredIndex <= 0);
    }
    if (drawerNext) {
      drawerNext.disabled = (currentFilteredIndex >= currentFilteredFindings.length - 1);
    }

    // 1. Threat Assessment Card
    var assessCard = el('div', 'drawer-card');
    assessCard.appendChild(el('h4', 'drawer-card-title', 'Threat Assessment'));

    var badgesWrap = el('div', 'drawer-badges-row');
    badgesWrap.appendChild(createBadge(f.severity));
    if (f.confidence) {
      var confBadge = el('span', 'badge badge-conf', 'CONFIDENCE: ' + f.confidence);
      if (f.confidence_rationale) {
        confBadge.setAttribute('title', f.confidence_rationale);
      }
      badgesWrap.appendChild(confBadge);
    }
    if (f.verdict) {
      badgesWrap.appendChild(el('span', 'badge badge-verd', 'VERDICT: ' + f.verdict));
    }
    assessCard.appendChild(badgesWrap);

    if (f.why) {
      var callout = el('div', 'threat-callout threat-callout-' + (f.severity || 'info').toLowerCase());
      callout.appendChild(el('div', 'callout-title', 'Forensic Rationale (Why Dangerous)'));
      callout.appendChild(el('div', 'callout-text', f.why));
      assessCard.appendChild(callout);
    }
    drawerBody.appendChild(assessCard);

    // 2. Forensic Evidence & Artifacts Card
    var evidCard = el('div', 'drawer-card');
    evidCard.appendChild(el('h4', 'drawer-card-title', 'Forensic Evidence & Artifacts'));

    if (f.path) {
      var pathField = el('div', 'drawer-field');
      var pathHdr = el('div', 'field-header');
      pathHdr.appendChild(el('span', 'drawer-field-label', 'Primary Path / Target'));
      var copyPathBtn = el('button', 'btn-copy-sm', 'Copy Path');
      copyPathBtn.addEventListener('click', function() { copyText(f.path, copyPathBtn); });
      pathHdr.appendChild(copyPathBtn);
      pathField.appendChild(pathHdr);
      pathField.appendChild(el('div', 'code-block', f.path));
      evidCard.appendChild(pathField);
    }

    if (f.paths && f.paths.length > 1) {
      var pathsField = el('div', 'drawer-field');
      var pathsHdr = el('div', 'field-header');
      pathsHdr.appendChild(el('span', 'drawer-field-label', 'All Matched Paths (' + f.paths.length + ')'));
      var copyAllBtn = el('button', 'btn-copy-sm', 'Copy All');
      copyAllBtn.addEventListener('click', function() { copyText(f.paths.join('\n'), copyAllBtn); });
      pathsHdr.appendChild(copyAllBtn);
      pathsField.appendChild(pathsHdr);
      pathsField.appendChild(renderCodeBlockWithLines(f.paths.join('\n')));
      evidCard.appendChild(pathsField);
    }

    if (f.reason) {
      var reasonField = el('div', 'drawer-field');
      reasonField.appendChild(el('span', 'drawer-field-label', 'Detection Details'));
      reasonField.appendChild(el('div', 'drawer-text-block', f.reason));
      evidCard.appendChild(reasonField);
    }

    if (f.evidence) {
      var evField = el('div', 'drawer-field');
      var evHdr = el('div', 'field-header');
      evHdr.appendChild(el('span', 'drawer-field-label', 'Raw Evidence / Matched String'));
      var copyEvBtn = el('button', 'btn-copy-sm', 'Copy Evidence');
      copyEvBtn.addEventListener('click', function() { copyText(f.evidence, copyEvBtn); });
      evHdr.appendChild(copyEvBtn);
      evField.appendChild(evHdr);
      evField.appendChild(renderCodeBlockWithLines(f.evidence));
      evidCard.appendChild(evField);
    }

    if (f.hashes && Object.keys(f.hashes).length > 0) {
      var hashField = el('div', 'drawer-field');
      var hashHdr = el('div', 'field-header');
      hashHdr.appendChild(el('span', 'drawer-field-label', 'Cryptographic Hashes'));
      var allHashStr = [];
      for (var hName in f.hashes) {
        allHashStr.push(hName + ': ' + f.hashes[hName]);
      }
      var copyHashBtn = el('button', 'btn-copy-sm', 'Copy Hashes');
      copyHashBtn.addEventListener('click', function() { copyText(allHashStr.join('\n'), copyHashBtn); });
      hashHdr.appendChild(copyHashBtn);
      hashField.appendChild(hashHdr);

      var hashList = el('div', 'hash-list');
      for (var hKey in f.hashes) {
        (function(key, val) {
          var hRow = el('div', 'hash-row');
          hRow.appendChild(el('code', 'hash-code', key + ': ' + val));
          var cBtn = el('button', 'btn-copy-xs', 'Copy');
          cBtn.addEventListener('click', function() { copyText(val, cBtn); });
          hRow.appendChild(cBtn);
          hashList.appendChild(hRow);
        })(hKey, f.hashes[hKey]);
      }
      hashField.appendChild(hashList);
      evidCard.appendChild(hashField);
    }

    if (f.metadata && Object.keys(f.metadata).length > 0) {
      var metaField = el('div', 'drawer-field');
      metaField.appendChild(el('span', 'drawer-field-label', 'Forensic Metadata'));
      metaField.appendChild(el('div', 'code-block', JSON.stringify(f.metadata, null, 2)));
      evidCard.appendChild(metaField);
    }

    drawerBody.appendChild(evidCard);

    // 3. MITRE ATT&CK Mapping Card
    if (f.mitre && f.mitre.length > 0) {
      var mitreCard = el('div', 'drawer-card');
      mitreCard.appendChild(el('h4', 'drawer-card-title', 'MITRE ATT&CK® Enterprise Alignment'));
      var mitreList = el('div', 'mitre-chips-grid');
      f.mitre.forEach(function(m) {
        var item = el('div', 'mitre-item-card');
        var topRow = el('div', 'mitre-top-row');
        topRow.appendChild(el('span', 'mitre-tech-id', m.technique || ''));
        topRow.appendChild(el('span', 'mitre-tactic-name', m.tactic || ''));
        item.appendChild(topRow);
        item.appendChild(el('div', 'mitre-tech-name', m.technique_name || ''));
        mitreList.appendChild(item);
      });
      mitreCard.appendChild(mitreList);
      drawerBody.appendChild(mitreCard);
    }

    // 4. Actionable Containment & Remediation Card
    if (f.remediation && f.remediation.length > 0) {
      var remCard = el('div', 'drawer-card');
      remCard.appendChild(el('h4', 'drawer-card-title', 'Actionable Containment & Remediation'));
      var remList = el('ol', 'remediation-steps');
      f.remediation.forEach(function(step) {
        var li = el('li', 'remediation-step');
        var trimmed = step.trim();
        var isCommand = trimmed.startsWith('kill ') ||
                        trimmed.startsWith('rm ') ||
                        trimmed.startsWith('systemctl ') ||
                        trimmed.startsWith('chmod ') ||
                        trimmed.startsWith('iptables ') ||
                        trimmed.startsWith('sed ') ||
                        trimmed.startsWith('pkill ') ||
                        trimmed.startsWith('chattr ');
        if (isCommand) {
          var cmdBox = el('div', 'cmd-box');
          cmdBox.appendChild(el('code', '', trimmed));
          var copyCmdBtn = el('button', 'btn-copy-sm', 'Copy Command');
          copyCmdBtn.addEventListener('click', function() { copyText(trimmed, copyCmdBtn); });
          cmdBox.appendChild(copyCmdBtn);
          li.appendChild(cmdBox);
        } else {
          li.appendChild(el('div', 'step-desc', step));
        }
        remList.appendChild(li);
      });
      remCard.appendChild(remList);
      drawerBody.appendChild(remCard);
    }
  }

  function openDrawer() {
    if (drawerOverlay) {
      drawerOverlay.style.display = 'flex';
      drawerOverlay.setAttribute('aria-hidden', 'false');
      drawerOverlay.setAttribute('aria-modal', 'true');
      drawerOverlay.setAttribute('role', 'dialog');
      if (drawerClose) drawerClose.focus();
    }
  }

  function closeDrawer() {
    if (drawerOverlay) {
      drawerOverlay.style.display = 'none';
      drawerOverlay.setAttribute('aria-hidden', 'true');
      if (activeRow) {
        activeRow.focus();
      }
    }
  }

  if (drawerClose) {
    drawerClose.addEventListener('click', closeDrawer);
  }
  if (drawerOverlay) {
    drawerOverlay.addEventListener('click', function(e) {
      if (e.target === drawerOverlay) {
        closeDrawer();
      }
    });
  }

  if (drawerPrev) {
    drawerPrev.addEventListener('click', function() {
      if (currentFilteredIndex > 0) {
        currentFilteredIndex--;
        renderDrawerFinding(currentFilteredFindings[currentFilteredIndex]);
      }
    });
  }

  if (drawerNext) {
    drawerNext.addEventListener('click', function() {
      if (currentFilteredIndex < currentFilteredFindings.length - 1) {
        currentFilteredIndex++;
        renderDrawerFinding(currentFilteredFindings[currentFilteredIndex]);
      }
    });
  }

  window.addEventListener('keydown', function(e) {
    if (drawerOverlay && drawerOverlay.style.display !== 'none') {
      if (e.key === 'Escape' || e.keyCode === 27) {
        closeDrawer();
      } else if (e.key === 'ArrowLeft' && currentFilteredIndex > 0) {
        currentFilteredIndex--;
        renderDrawerFinding(currentFilteredFindings[currentFilteredIndex]);
      } else if (e.key === 'ArrowRight' && currentFilteredIndex < currentFilteredFindings.length - 1) {
        currentFilteredIndex++;
        renderDrawerFinding(currentFilteredFindings[currentFilteredIndex]);
      } else if (e.key === 'Tab' || e.keyCode === 9) {
        var focusables = drawerOverlay.querySelectorAll('button:not([disabled]), [tabindex="0"]:not([disabled])');
        if (focusables.length > 0) {
          var first = focusables[0];
          var last = focusables[focusables.length - 1];
          if (e.shiftKey) {
            if (document.activeElement === first) {
              e.preventDefault();
              last.focus();
            }
          } else {
            if (document.activeElement === last) {
              e.preventDefault();
              first.focus();
            }
          }
        }
      }
      return;
    }

    // Global Command-K / '/' shortcut to focus search input
    var isSearchShortcut = ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) ||
      (e.key === '/' && document.activeElement !== searchInput && document.activeElement &&
       document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA');
    if (isSearchShortcut) {
      e.preventDefault();
      if (searchInput) {
        searchInput.focus();
        searchInput.select();
      }
    }
  });

  // 7. MITRE Technique Chip Click Handling
  var techChips = document.querySelectorAll('.btn-tech-chip');
  techChips.forEach(function(chip) {
    chip.addEventListener('click', function() {
      var techId = chip.getAttribute('data-tech-id') || '';
      if (searchInput) {
        searchInput.value = techId;
        currentSearch = techId;
        renderTable();
        var tableSection = document.getElementById('findings-table');
        if (tableSection) {
          tableSection.scrollIntoView({ behavior: 'smooth' });
        }
      }
    });
  });

  // 8. Search & Filters
  if (searchInput) {
    searchInput.addEventListener('input', function() {
      currentSearch = (searchInput.value || '').trim();
      renderTable();
    });
  }

  if (moduleFilter) {
    moduleFilter.addEventListener('change', function() {
      currentModule = moduleFilter.value || '';
      renderTable();
    });
  }

  pills.forEach(function(btn) {
    btn.addEventListener('click', function() {
      pills.forEach(function(b) {
        b.classList.remove('active');
        b.setAttribute('aria-pressed', 'false');
      });
      btn.classList.add('active');
      btn.setAttribute('aria-pressed', 'true');
      currentSeverity = btn.getAttribute('data-sev') || 'ALL';
      renderTable();
    });
  });

  // Initial table render
  bindSortableHeaders();
  renderTable();

  // 12. Count-up numerals: metric values rise from 0 with ease-out physics.
  // Reduced-motion users get the final value instantly.
  function initCountUp() {
    var els = document.querySelectorAll('.counter-num[data-countup]');
    if (!els.length) return;
    var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    for (var i = 0; i < els.length; i++) {
      (function(node) {
        var target = parseInt(node.getAttribute('data-countup'), 10) || 0;
        if (reduced || target <= 0) { node.textContent = String(target); return; }
        var dur = 850;
        var start = null;
        function step(ts) {
          if (!start) start = ts;
          var t = Math.min((ts - start) / dur, 1);
          var eased = 1 - Math.pow(1 - t, 3);
          node.textContent = String(Math.round(target * eased));
          if (t < 1) requestAnimationFrame(step);
        }
        setTimeout(function() { requestAnimationFrame(step); }, 40);
      })(els[i]);
    }
  }

  // 13. Reveal-on-scroll: sections rise into place as the analyst scrolls.
  function initReveal() {
    var items = document.querySelectorAll('.reveal');
    if (!items.length) return;
    var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced || !('IntersectionObserver' in window)) {
      for (var i = 0; i < items.length; i++) items[i].classList.add('revealed');
      return;
    }
    var io = new IntersectionObserver(function(entries) {
      entries.forEach(function(en) {
        if (en.isIntersecting) {
          en.target.classList.add('revealed');
          io.unobserve(en.target);
        }
      });
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.05 });
    for (var j = 0; j < items.length; j++) io.observe(items[j]);
  }

  // 14. Detection Timeline: severity lanes over the scan window. Built
  // entirely from the embedded JSON payload with createElementNS (DOM-safe,
  // CSP-safe). Markers open the finding drawer.
  function buildTimeline() {
    var wrap = document.getElementById('timeline-wrap');
    if (!wrap || !allFindings.length) {
      if (wrap) wrap.appendChild(el('div', 'timeline-empty',
        allFindings.length ? '' : 'No findings recorded — the timeline populates as detections surface.'));
      return;
    }

    var parseTS = function(s) {
      var d = new Date(s);
      return isNaN(d.getTime()) ? null : d.getTime();
    };
    var times = [];
    for (var i = 0; i < allFindings.length; i++) {
      var t = parseTS(allFindings[i].timestamp);
      if (t !== null) times.push(t);
    }
    if (!times.length) { wrap.appendChild(el('div', 'timeline-empty', 'Finding timestamps unavailable.')); return; }
    times.sort(function(a, b) { return a - b; });
    var t0 = times[0], t1 = times[times.length - 1];
    if (t1 - t0 < 1000) { t0 -= 500; t1 += 500; } // degenerate single-instant window

    var W = 1000, laneH = 34, topPad = 18, botPad = 26, labelW = 64;
    var plotW = W - labelW - 16;
    var lanes = [
      { key: 'ALERT', label: 'ALERT' },
      { key: 'WARNING', label: 'WARN' },
      { key: 'NOTICE', label: 'NOTICE' },
      { key: 'INFO', label: 'INFO' }
    ];
    var laneIndex = function(sev) {
      var s = (sev || '').toUpperCase();
      if (s === 'ALERT' || s === 'CRITICAL') return 0;
      if (s === 'WARNING' || s === 'HIGH') return 1;
      if (s === 'NOTICE' || s === 'MEDIUM') return 2;
      return 3;
    };

    var H = topPad + lanes.length * laneH + botPad;
    var NS = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('class', 'timeline-svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Detection timeline: findings per severity over the scan window');

    var mk = function(tag, attrs, text) {
      var n = document.createElementNS(NS, tag);
      for (var k in attrs) n.setAttribute(k, attrs[k]);
      if (text !== undefined) n.textContent = text;
      return n;
    };
    var fmt = function(ms) {
      var d = new Date(ms);
      var p = function(x) { return (x < 10 ? '0' : '') + x; };
      return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    };
    var xOf = function(ms) { return labelW + ((ms - t0) / (t1 - t0)) * plotW; };

    // Lane backgrounds, labels, and baseline grid.
    for (var li = 0; li < lanes.length; li++) {
      var y = topPad + li * laneH;
      svg.appendChild(mk('rect', { x: labelW, y: y + 4, width: plotW, height: laneH - 8, rx: 6, class: 'tl-lane tl-lane-' + lanes[li].key.toLowerCase() }));
      svg.appendChild(mk('text', { x: labelW - 8, y: y + laneH / 2 + 3, 'text-anchor': 'end', class: 'tl-lane-label' }, lanes[li].label));
    }
    // Time axis: start, middle, end.
    svg.appendChild(mk('line', { x1: labelW, y1: topPad + lanes.length * laneH, x2: labelW + plotW, y2: topPad + lanes.length * laneH, class: 'tl-axis' }));
    svg.appendChild(mk('text', { x: labelW, y: H - 8, class: 'tl-tick' }, fmt(t0)));
    svg.appendChild(mk('text', { x: labelW + plotW / 2, y: H - 8, 'text-anchor': 'middle', class: 'tl-tick' }, fmt((t0 + t1) / 2)));
    svg.appendChild(mk('text', { x: labelW + plotW, y: H - 8, 'text-anchor': 'end', class: 'tl-tick' }, fmt(t1)));

    // Markers: newest last so alerts stack on top; click opens the drawer.
    for (var fi = 0; fi < allFindings.length; fi++) {
      var f = allFindings[fi];
      var ms = parseTS(f.timestamp);
      if (ms === null) continue;
      var lane = laneIndex(f.severity);
      var cx = xOf(ms);
      if (cx < labelW + 4 || cx > labelW + plotW - 4) cx = Math.max(labelW + 4, Math.min(cx, labelW + plotW - 4));
      var cy = topPad + lane * laneH + laneH / 2;
      var sevKey = (f.severity || 'INFO').toLowerCase();

      var g = document.createElementNS(NS, 'g');
      g.setAttribute('class', 'tl-marker');
      g.setAttribute('tabindex', '0');
      g.setAttribute('role', 'button');
      var circle = mk('circle', { cx: cx, cy: cy, r: 5, class: 'tl-dot tl-dot-' + sevKey });
      var halo = mk('circle', { cx: cx, cy: cy, r: 9, class: 'tl-halo tl-halo-' + sevKey });
      var title = mk('title', {}, (f.severity || '') + ' — ' + (f.rule_name || '') + '\n' + (f.path || ''));
      g.appendChild(halo);
      g.appendChild(circle);
      g.appendChild(title);

      (function(finding, idx) {
        var open = function() {
          currentFilteredFindings = allFindings.slice();
          currentFilteredIndex = idx;
          renderDrawerFinding(finding);
          openDrawer();
        };
        g.addEventListener('click', open);
        g.addEventListener('keydown', function(e) {
          if (e.key === 'Enter' || e.key === ' ' || e.keyCode === 13 || e.keyCode === 32) {
            e.preventDefault();
            open();
          }
        });
      })(f, fi);
      svg.appendChild(g);
    }
    wrap.appendChild(svg);
  }

  initCountUp();
  initReveal();
  buildTimeline();
})();
