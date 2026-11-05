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

      // Severity column (+ NEW chip in delta hunting mode)
      var tdSev = document.createElement('td');
      tdSev.appendChild(createBadge(f.severity));
      if (f.metadata && f.metadata.baseline_state === 'new') {
        tdSev.appendChild(el('span', 'chip-new', 'NEW'));
      }
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

  // 5b. Hexdump Byte Formatter
  function formatHexDump(str, maxBytes) {
    if (!str) return '(No payload data captured)';
    var bytes = [];
    for (var i = 0; i < str.length && (!maxBytes || i < maxBytes); i++) {
      bytes.push(str.charCodeAt(i) & 0xff);
    }
    var out = 'OFFSET    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  │ ASCII DECODE\n';
    out += '────────  ───────────────────────  ───────────────────────  │ ────────────────\n';
    for (var o = 0; o < bytes.length; o += 16) {
      var hexPart1 = '', hexPart2 = '', asciiPart = '';
      var offStr = ('00000000' + o.toString(16).toUpperCase()).slice(-8);
      for (var j = 0; j < 8; j++) {
        if (o + j < bytes.length) {
          var b = bytes[o + j];
          hexPart1 += ('0' + b.toString(16).toUpperCase()).slice(-2) + ' ';
          asciiPart += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
        } else {
          hexPart1 += '   ';
        }
      }
      for (var k = 8; k < 16; k++) {
        if (o + k < bytes.length) {
          var b2 = bytes[o + k];
          hexPart2 += ('0' + b2.toString(16).toUpperCase()).slice(-2) + ' ';
          asciiPart += (b2 >= 32 && b2 <= 126) ? String.fromCharCode(b2) : '.';
        } else {
          hexPart2 += '   ';
        }
      }
      out += offStr + '  ' + hexPart1 + ' ' + hexPart2 + ' │ ' + asciiPart + '\n';
    }
    return out;
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

    // Forensic Hexdump / Byte Inspector View
    var rawTextPayload = f.evidence || (f.evidence_record && f.evidence_record.line_content) || '';
    if (rawTextPayload) {
      var hexField = el('div', 'drawer-field');
      var hexHdr = el('div', 'field-header');
      hexHdr.appendChild(el('span', 'drawer-field-label', 'Forensic Byte Dump & Hex Inspector'));
      var hexDumpStr = formatHexDump(rawTextPayload, 512);
      var copyHexBtn = el('button', 'btn-copy-sm', 'Copy Hex');
      copyHexBtn.addEventListener('click', function() { copyText(hexDumpStr, copyHexBtn); });
      hexHdr.appendChild(copyHexBtn);
      hexField.appendChild(hexHdr);
      var hexWrap = el('div', 'hexdump-container');
      hexWrap.appendChild(el('pre', 'hexdump-code', hexDumpStr));
      hexField.appendChild(hexWrap);
      evidCard.appendChild(hexField);
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

  // 8. Threat Entity & Process Topology Graph (HTML5 Canvas)
  function initThreatGraph() {
    var canvas = document.getElementById('threat-graph-canvas');
    if (!canvas || !canvas.getContext) return;
    var ctx = canvas.getContext('2d');
    if (!ctx) return;

    var container = document.getElementById('graph-container');
    function resizeCanvas() {
      if (container) {
        var rect = container.getBoundingClientRect();
        if (rect.width > 200) {
          canvas.width = Math.floor(rect.width);
          canvas.height = 380;
        }
      }
    }
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    // Build Graph Model
    var hostLabel = reportData.hostname || 'Target Host';
    var nodes = [];
    var links = [];
    var nodeMap = {};

    function addNode(id, label, type, severity, queryTerm) {
      if (nodeMap[id]) return nodeMap[id];
      var color = '#8b5cf6';
      var r = 10;
      if (type === 'host') {
        color = '#8b5cf6'; r = 16;
      } else if (type === 'process') {
        color = '#38bdf8'; r = 12;
      } else if (type === 'socket') {
        color = '#22d3ee'; r = 10;
      } else if (type === 'persistence') {
        color = '#fbbf24'; r = 11;
      } else if (type === 'threat') {
        color = (severity === 'ALERT' || severity === 'CRITICAL') ? '#ff3b6b' : '#ffb020';
        r = 13;
      }
      var n = {
        id: id,
        label: label,
        type: type,
        severity: severity,
        queryTerm: queryTerm || label,
        color: color,
        r: r,
        x: canvas.width / 2,
        y: canvas.height / 2,
        vx: 0,
        vy: 0
      };
      nodes.push(n);
      nodeMap[id] = n;
      return n;
    }

    function addLink(sourceId, targetId) {
      links.push({ source: sourceId, target: targetId });
    }

    // Root Host Node
    addNode('host', hostLabel, 'host', 'INFO', hostLabel);

    // Populate Entities from findings
    var procCount = 0, socketCount = 0, persistCount = 0, threatCount = 0;
    allFindings.forEach(function(f, i) {
      var sourceNodeId = 'host';

      // 1. Process entity
      var pid = (f.evidence_record && f.evidence_record.pid) ? f.evidence_record.pid : null;
      var comm = (f.evidence_record && f.evidence_record.comm) ? f.evidence_record.comm : '';
      if (pid && procCount < 12) {
        var procId = 'proc_' + pid;
        var procLbl = (comm ? comm + ' ' : '') + '(PID ' + pid + ')';
        addNode(procId, procLbl, 'process', f.severity, String(pid));
        addLink('host', procId);
        sourceNodeId = procId;
        procCount++;
      }

      // 2. Network Sockets
      var sock = (f.evidence_record && f.evidence_record.socket_info) ? f.evidence_record.socket_info : null;
      if (!sock && f.module === 'network' && f.path && f.path.indexOf(':') !== -1) {
        sock = f.path;
      }
      if (sock && socketCount < 10) {
        var sockId = 'sock_' + i;
        addNode(sockId, sock, 'socket', f.severity, sock);
        addLink(sourceNodeId, sockId);
        socketCount++;
      }

      // 3. Persistence entity
      if (f.module === 'persistence' && persistCount < 12) {
        var persistId = 'persist_' + i;
        var persistLbl = f.path ? f.path.split('/').pop() : f.rule_name;
        addNode(persistId, persistLbl, 'persistence', f.severity, persistLbl);
        addLink(sourceNodeId, persistId);
        persistCount++;
      }

      // 4. Alert / Payload entity
      if ((f.severity === 'ALERT' || f.severity === 'CRITICAL' || f.module === 'filesystem') && threatCount < 16) {
        var threatId = 'threat_' + i;
        var threatLbl = f.path ? f.path.split('/').pop() : f.rule_name;
        addNode(threatId, threatLbl, 'threat', f.severity, f.path || f.rule_name);
        addLink(sourceNodeId, threatId);
        threatCount++;
      }
    });

    // Orbit distribution layout around center
    var cx = canvas.width / 2;
    var cy = canvas.height / 2;
    nodeMap['host'].x = cx;
    nodeMap['host'].y = cy;

    var childNodes = nodes.filter(function(n) { return n.id !== 'host'; });
    var totalChildren = childNodes.length;

    for (var ci = 0; ci < totalChildren; ci++) {
      var angle = (ci / totalChildren) * 2 * Math.PI;
      var dist = 110 + (ci % 3) * 45;
      childNodes[ci].x = cx + Math.cos(angle) * dist;
      childNodes[ci].y = cy + Math.sin(angle) * dist;
    }

    // Animation loop & Particle Render
    var hoveredNode = null;
    var pulseFrame = 0;

    function renderGraph() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      pulseFrame += 0.03;

      if (totalChildren === 0) {
        ctx.fillStyle = '#10b981';
        ctx.font = 'bold 14px monospace';
        ctx.textAlign = 'center';
        ctx.fillText('✔  CLEAN ENDPOINT — ZERO MALICIOUS TOPOLOGY RESIDUE DETECTED', canvas.width / 2, canvas.height / 2);
        return;
      }

      // 1. Draw Links
      links.forEach(function(l) {
        var s = nodeMap[l.source];
        var t = nodeMap[l.target];
        if (!s || !t) return;
        ctx.beginPath();
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(t.x, t.y);
        ctx.strokeStyle = 'rgba(139, 92, 246, 0.22)';
        ctx.lineWidth = 1.2;
        ctx.stroke();

        // Animated packet dot
        var progress = (Math.sin(pulseFrame + (s.x + t.y) * 0.01) + 1) / 2;
        var px = s.x + (t.x - s.x) * progress;
        var py = s.y + (t.y - s.y) * progress;
        ctx.beginPath();
        ctx.arc(px, py, 2, 0, 2 * Math.PI);
        ctx.fillStyle = 'rgba(56, 189, 248, 0.75)';
        ctx.fill();
      });

      // 2. Draw Nodes
      nodes.forEach(function(n) {
        var isHovered = (hoveredNode && hoveredNode.id === n.id);
        var r = isHovered ? n.r + 4 : n.r;

        // Outer Glow
        var grad = ctx.createRadialGradient(n.x, n.y, r * 0.5, n.x, n.y, r * 2.2);
        grad.addColorStop(0, n.color);
        grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(n.x, n.y, r * 2.2, 0, 2 * Math.PI);
        ctx.fill();

        // Node Body
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
        ctx.fillStyle = n.color;
        ctx.fill();
        ctx.strokeStyle = isHovered ? '#ffffff' : 'rgba(255, 255, 255, 0.4)';
        ctx.lineWidth = isHovered ? 2.5 : 1;
        ctx.stroke();

        // Node Label
        ctx.fillStyle = isHovered ? '#ffffff' : '#c7d2fe';
        ctx.font = (isHovered ? 'bold 11px' : '10px') + ' -apple-system, monospace';
        ctx.textAlign = 'center';
        var displayLbl = n.label.length > 20 ? n.label.slice(0, 18) + '…' : n.label;
        ctx.fillText(displayLbl, n.x, n.y + r + 13);
      });

      requestAnimationFrame(renderGraph);
    }
    requestAnimationFrame(renderGraph);

    // Canvas Mouse Interaction
    function getNodeAt(x, y) {
      for (var i = nodes.length - 1; i >= 0; i--) {
        var n = nodes[i];
        var dx = x - n.x;
        var dy = y - n.y;
        if (dx * dx + dy * dy <= (n.r + 6) * (n.r + 6)) {
          return n;
        }
      }
      return null;
    }

    canvas.addEventListener('mousemove', function(e) {
      var rect = canvas.getBoundingClientRect();
      var x = e.clientX - rect.left;
      var y = e.clientY - rect.top;
      hoveredNode = getNodeAt(x, y);
      canvas.style.cursor = hoveredNode ? 'pointer' : 'crosshair';
    });

    canvas.addEventListener('click', function(e) {
      var rect = canvas.getBoundingClientRect();
      var x = e.clientX - rect.left;
      var y = e.clientY - rect.top;
      var clicked = getNodeAt(x, y);
      if (clicked && clicked.queryTerm && searchInput) {
        currentSearch = clicked.queryTerm;
        searchInput.value = clicked.queryTerm;
        renderTable();
        var tbl = document.getElementById('findings-table');
        if (tbl) tbl.scrollIntoView({ behavior: 'smooth' });
      }
    });

    var resetBtn = document.getElementById('btn-graph-reset');
    if (resetBtn) {
      resetBtn.addEventListener('click', function() {
        cx = canvas.width / 2;
        cy = canvas.height / 2;
        nodeMap['host'].x = cx;
        nodeMap['host'].y = cy;
        for (var ci = 0; ci < totalChildren; ci++) {
          var angle = (ci / totalChildren) * 2 * Math.PI;
          var dist = 110 + (ci % 3) * 45;
          childNodes[ci].x = cx + Math.cos(angle) * dist;
          childNodes[ci].y = cy + Math.sin(angle) * dist;
        }
      });
    }
  }

  // 9. Keyboard Shortcuts & Power-User Controls
  function initShortcutsAndNavigation() {
    var shortcutsOverlay = document.getElementById('shortcuts-overlay');
    var btnShortcuts = document.getElementById('btn-shortcuts');
    var shortcutsClose = document.getElementById('shortcuts-close');

    function toggleShortcuts() {
      if (!shortcutsOverlay) return;
      var isHidden = (shortcutsOverlay.style.display === 'none');
      shortcutsOverlay.style.display = isHidden ? 'flex' : 'none';
      shortcutsOverlay.setAttribute('aria-hidden', isHidden ? 'false' : 'true');
    }

    if (btnShortcuts) {
      btnShortcuts.addEventListener('click', toggleShortcuts);
    }
    if (shortcutsClose) {
      shortcutsClose.addEventListener('click', toggleShortcuts);
    }
    if (shortcutsOverlay) {
      shortcutsOverlay.addEventListener('click', function(e) {
        if (e.target === shortcutsOverlay) toggleShortcuts();
      });
    }

    document.addEventListener('keydown', function(e) {
      var tag = (document.activeElement && document.activeElement.tagName) ? document.activeElement.tagName.toLowerCase() : '';
      var isTyping = (tag === 'input' || tag === 'textarea' || tag === 'select');

      // Global Escape
      if (e.key === 'Escape' || e.keyCode === 27) {
        if (shortcutsOverlay && shortcutsOverlay.style.display !== 'none') {
          shortcutsOverlay.style.display = 'none';
          shortcutsOverlay.setAttribute('aria-hidden', 'true');
          return;
        }
        if (drawerOverlay && drawerOverlay.style.display !== 'none') {
          closeDrawer();
          return;
        }
        if (searchInput && searchInput.value) {
          searchInput.value = '';
          currentSearch = '';
          renderTable();
          return;
        }
      }

      if (isTyping) return;

      // Focus Search: '/' or Cmd+K
      if (e.key === '/' || ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K'))) {
        e.preventDefault();
        if (searchInput) {
          searchInput.focus();
          searchInput.select();
        }
        return;
      }

      // Help Modal: '?'
      if (e.key === '?') {
        e.preventDefault();
        toggleShortcuts();
        return;
      }

      // Theme toggle: 't'
      if (e.key === 't' || e.key === 'T') {
        if (themeToggle) themeToggle.click();
        return;
      }

      // Print report: 'p'
      if (e.key === 'p' || e.key === 'P') {
        if (btnPrint) btnPrint.click();
        return;
      }

      // Export CSV: 'e'
      if (e.key === 'e' || e.key === 'E') {
        e.preventDefault();
        exportCSV();
        return;
      }

      // Row Navigation: 'j' (down), 'k' (up)
      if (e.key === 'j' || e.key === 'ArrowDown') {
        if (currentFilteredFindings.length > 0) {
          e.preventDefault();
          var nextIdx = currentFilteredIndex + 1;
          if (nextIdx >= currentFilteredFindings.length) nextIdx = 0;
          currentFilteredIndex = nextIdx;
          renderDrawerFinding(currentFilteredFindings[currentFilteredIndex]);
          if (drawerOverlay && drawerOverlay.style.display !== 'none') {
            openDrawer();
          }
        }
        return;
      }

      if (e.key === 'k' || e.key === 'ArrowUp') {
        if (currentFilteredFindings.length > 0) {
          e.preventDefault();
          var prevIdx = currentFilteredIndex - 1;
          if (prevIdx < 0) prevIdx = currentFilteredFindings.length - 1;
          currentFilteredIndex = prevIdx;
          renderDrawerFinding(currentFilteredFindings[currentFilteredIndex]);
          if (drawerOverlay && drawerOverlay.style.display !== 'none') {
            openDrawer();
          }
        }
        return;
      }

      // Open finding in drawer: 'Enter'
      if (e.key === 'Enter' && currentFilteredIndex >= 0 && currentFilteredIndex < currentFilteredFindings.length) {
        e.preventDefault();
        renderDrawerFinding(currentFilteredFindings[currentFilteredIndex]);
        openDrawer();
      }
    });
  }

  // 10. Clickable Kill-Chain and MITRE Tech Chips
  function bindKillchainAndTechClicks() {
    // Kill-chain tactic nodes
    document.querySelectorAll('.kill-stage').forEach(function(stageEl) {
      stageEl.style.cursor = 'pointer';
      stageEl.addEventListener('click', function() {
        var titleEl = stageEl.querySelector('title');
        if (titleEl && searchInput) {
          var tactic = titleEl.textContent.split(' — ')[0];
          if (tactic) {
            currentSearch = tactic;
            searchInput.value = tactic;
            renderTable();
            var tbl = document.getElementById('findings-table');
            if (tbl) tbl.scrollIntoView({ behavior: 'smooth' });
          }
        }
      });
    });

    // MITRE technique chips
    document.querySelectorAll('.btn-tech-chip').forEach(function(chip) {
      chip.addEventListener('click', function() {
        var techId = chip.getAttribute('data-tech-id') || '';
        if (techId && searchInput) {
          currentSearch = techId;
          searchInput.value = techId;
          renderTable();
          var tbl = document.getElementById('findings-table');
          if (tbl) tbl.scrollIntoView({ behavior: 'smooth' });
        }
      });
    });
  }

  // Command Deck scrollspy mini-nav (DESIGN.md §6): a fixed section index
  // built from the report's own headings — DOM-safe (createElement/textContent
  // only, never markup injection).
  function initCommandDeckNav() {
    var headings = document.querySelectorAll('h2.section-title');
    if (headings.length < 3) return;

    var items = [];
    headings.forEach(function(h) {
      var section = h.closest('section');
      if (!section) return;
      if (!section.id) section.id = 'cd-sec-' + (items.length + 1);
      items.push({ id: section.id, label: (h.textContent || '').trim() });
    });
    if (items.length < 3) return;

    var nav = el('nav', 'cd-mininav');
    nav.setAttribute('aria-label', 'Report sections');
    var links = {};
    items.forEach(function(item) {
      var a = el('a', null, item.label);
      a.href = '#' + item.id;
      a.addEventListener('click', function(ev) {
        ev.preventDefault();
        var target = document.getElementById(item.id);
        if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
      links[item.id] = a;
      nav.appendChild(a);
    });
    document.body.appendChild(nav);

    if (typeof IntersectionObserver === 'undefined') return;
    var activeId = null;
    var observer = new IntersectionObserver(function(entries) {
      entries.forEach(function(entry) {
        if (entry.isIntersecting) {
          var id = entry.target.id;
          if (id === activeId) return;
          activeId = id;
          Object.keys(links).forEach(function(key) {
            if (key === id) links[key].classList.add('active');
            else links[key].classList.remove('active');
          });
        }
      });
    }, { rootMargin: '-35% 0px -55% 0px' });
    items.forEach(function(item) {
      var target = document.getElementById(item.id);
      if (target) observer.observe(target);
    });
  }

  initCountUp();
  initReveal();
  buildTimeline();
  initThreatGraph();
  initShortcutsAndNavigation();
  bindKillchainAndTechClicks();
  initCommandDeckNav();
})();
