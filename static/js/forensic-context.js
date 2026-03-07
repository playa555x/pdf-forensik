/**
 * forensic-context.js — Kontextbezogene forensische Interpretationen
 * Generiert einfache, verständliche Erklärungen basierend auf den tatsächlichen Daten.
 * Zweisprachig (DE/EN) mit getLang() aus i18n.js.
 */

// ─── Helper ──────────────────────────────────────────────────────────────────

function _interpBox(level, headerText, bodyHtml) {
  const icons = { safe: '✅', note: '💡', warn: '⚠️', info: 'ℹ️' };
  const icon = icons[level] || icons.info;
  return `<div class="forensic-interp interp-${level}">
    <div class="forensic-interp-header" onclick="this.parentElement.classList.toggle('collapsed')">
      <span class="interp-icon">${icon}</span>
      <span class="interp-header-text">${headerText}</span>
      <span class="interp-toggle">▼</span>
    </div>
    <div class="forensic-interp-body interp-body">${bodyHtml}</div>
  </div>`;
}

function _verdict(level, text) {
  return `<span class="interp-verdict">${text}</span>`;
}

function _de() { return getLang() !== 'en'; }


// ─── Metadata Interpretation ─────────────────────────────────────────────────

function interpMetadata(meta) {
  if (!meta) return '';
  const de = _de();
  let parts = [];
  let level = 'safe';

  // Creator/Producer analysis
  if (meta.creator && meta.producer) {
    if (meta.creator === meta.producer) {
      parts.push(de
        ? `<p><strong>Creator und Producer sind identisch</strong> ("${meta.creator}"). Das bedeutet, dass die Software die das Dokument erstellt hat auch direkt das PDF erzeugt hat — kein Zwischenschritt, keine Konvertierung. Das ist <strong>normal und unauffällig</strong>.</p>`
        : `<p><strong>Creator and Producer are identical</strong> ("${meta.creator}"). This means the software that created the document also directly generated the PDF — no intermediate step, no conversion. This is <strong>normal and unremarkable</strong>.</p>`
      );
    } else {
      parts.push(de
        ? `<p><strong>Creator ("${meta.creator}") und Producer ("${meta.producer}") unterscheiden sich.</strong> Das ist an sich nicht verdächtig — z.B. erstellt Microsoft Word das Dokument (Creator), und eine PDF-Engine exportiert es (Producer). Es kann aber auch bedeuten, dass das PDF nachträglich konvertiert oder bearbeitet wurde.</p>`
        : `<p><strong>Creator ("${meta.creator}") and Producer ("${meta.producer}") differ.</strong> This is not necessarily suspicious — e.g. Microsoft Word creates the document (Creator), and a PDF engine exports it (Producer). However, it could also mean the PDF was converted or edited after initial creation.</p>`
      );
      level = 'info';
    }
  }

  // Date analysis
  if (meta.creation_date_parsed && meta.mod_date_parsed) {
    const created = new Date(meta.creation_date_parsed);
    const modified = new Date(meta.mod_date_parsed);
    if (modified < created) {
      parts.push(de
        ? `<p><strong>🚨 Das Änderungsdatum liegt VOR dem Erstelldatum!</strong> Das ist physisch unmöglich und ein starkes Zeichen für Manipulation. Jemand hat wahrscheinlich die Metadaten manuell geändert, um das Dokument älter oder neuer erscheinen zu lassen, als es wirklich ist.</p>`
        : `<p><strong>🚨 The modification date is BEFORE the creation date!</strong> This is physically impossible and a strong indicator of manipulation. Someone likely manually altered the metadata to make the document appear older or newer than it actually is.</p>`
      );
      level = 'warn';
    } else {
      const diffMs = modified - created;
      const diffMin = diffMs / 60000;
      if (diffMin < 1) {
        parts.push(de
          ? `<p><strong>Erstellt und geändert fast gleichzeitig</strong> (Differenz < 1 Minute). Das bedeutet, das PDF wurde erstellt und sofort gespeichert, ohne spätere Bearbeitung. <strong>Typisch für einen direkten Export</strong> aus Word, Chrome "Print to PDF" o.ä.</p>`
          : `<p><strong>Created and modified nearly simultaneously</strong> (difference < 1 minute). This means the PDF was created and saved immediately, without later editing. <strong>Typical for a direct export</strong> from Word, Chrome "Print to PDF", etc.</p>`
        );
      }
    }
  }

  // Author
  if (meta.author) {
    parts.push(de
      ? `<p><strong>Autor:</strong> "${meta.author}" — das ist der Name der im Betriebssystem oder in der Anwendung eingetragen war, als das Dokument erstellt wurde. Dieser kann leicht gefälscht werden, ist aber ein nützlicher Hinweis auf den Ersteller.</p>`
      : `<p><strong>Author:</strong> "${meta.author}" — this is the name that was set in the operating system or application when the document was created. This can be easily faked, but is a useful hint about the creator.</p>`
    );
  }

  // Anomalies summary
  const anoms = (meta.anomalies || []);
  const highs = anoms.filter(a => a.severity === 'HIGH');
  if (highs.length > 0) {
    level = 'warn';
    parts.push(de
      ? `<p><strong>${highs.length} kritische Auffälligkeit(en)</strong> in den Metadaten gefunden. Das deutet auf mögliche Manipulation oder Inkonsistenzen hin.</p>`
      : `<p><strong>${highs.length} critical finding(s)</strong> detected in metadata. This suggests possible manipulation or inconsistencies.</p>`
    );
  } else if (anoms.length === 0) {
    parts.push(de
      ? `<p>${_verdict('safe', '✓ Keine Auffälligkeiten')} — Die Metadaten sind konsistent und zeigen keine Zeichen von Manipulation.</p>`
      : `<p>${_verdict('safe', '✓ No findings')} — The metadata is consistent and shows no signs of manipulation.</p>`
    );
  }

  if (parts.length === 0) return '';
  const header = de ? '🔍 Was bedeuten diese Metadaten?' : '🔍 What do these metadata mean?';
  return _interpBox(level, header, parts.join(''));
}


// ─── Hash Interpretation ─────────────────────────────────────────────────────

function interpHashes(hashes) {
  if (!hashes) return '';
  const de = _de();
  const sizeKB = Math.round(hashes.file_size_bytes / 1024);
  const sizeMB = (hashes.file_size_bytes / (1024*1024)).toFixed(1);

  let body = de
    ? `<p><strong>Was sind Hashes?</strong> Stell dir einen Hash wie einen einzigartigen "digitalen Fingerabdruck" einer Datei vor. Selbst wenn du nur ein einziges Zeichen in der Datei änderst, sieht der Hash komplett anders aus. Deshalb eignen sich Hashes perfekt um zu beweisen, dass eine Datei nicht verändert wurde.</p>
       <p><strong>Dateigröße:</strong> ${sizeKB > 1024 ? sizeMB + ' MB' : sizeKB + ' KB'}. ${sizeKB < 50 ? 'Sehr klein — könnte ein fast leeres oder stark komprimiertes Dokument sein.' : sizeKB > 10000 ? 'Relativ groß — enthält wahrscheinlich viele Bilder oder eingebettete Dateien.' : 'Normale Größe für ein PDF-Dokument.'}</p>
       <p><strong>So verwendest du die Hashes:</strong> Kopiere den <strong>SHA-256 Hash</strong> und vergleiche ihn mit dem Hash aus einer vertrauenswürdigen Quelle (z.B. vom Absender, aus einer Behörden-Datenbank oder von VirusTotal). Wenn die Hashes übereinstimmen, ist die Datei byte-genau identisch — sie wurde definitiv nicht verändert.</p>`
    : `<p><strong>What are hashes?</strong> Think of a hash as a unique "digital fingerprint" of a file. Even if you change just a single character in the file, the hash looks completely different. That's why hashes are perfect for proving that a file has not been modified.</p>
       <p><strong>File size:</strong> ${sizeKB > 1024 ? sizeMB + ' MB' : sizeKB + ' KB'}. ${sizeKB < 50 ? 'Very small — could be a nearly empty or heavily compressed document.' : sizeKB > 10000 ? 'Relatively large — probably contains many images or embedded files.' : 'Normal size for a PDF document.'}</p>
       <p><strong>How to use:</strong> Copy the <strong>SHA-256 hash</strong> and compare it with the hash from a trusted source (e.g. the sender, an official database, or VirusTotal). If the hashes match, the file is byte-identical — it definitely has not been modified.</p>`;

  const header = de ? '🔍 Was bedeuten die Hashes?' : '🔍 What do these hashes mean?';
  return _interpBox('info', header, body);
}


// ─── Software Fingerprint Interpretation ─────────────────────────────────────

function interpSoftware(sw) {
  if (!sw) return '';
  const de = _de();
  let parts = [];
  let level = 'safe';

  const tool = sw.identified_tool || sw.producer_raw || '';
  const cat = sw.tool_category || '';

  if (tool) {
    const toolLower = tool.toLowerCase();
    if (toolLower.includes('word') || toolLower.includes('libreoffice') || toolLower.includes('pages')) {
      parts.push(de
        ? `<p><strong>Erstellt mit: ${tool}</strong> — Das ist ein normales Textverarbeitungsprogramm. Die meisten legitimen Dokumente (Briefe, Verträge, Berichte) werden so erstellt. <strong>Kein Grund zur Sorge.</strong></p>`
        : `<p><strong>Created with: ${tool}</strong> — This is a normal word processing program. Most legitimate documents (letters, contracts, reports) are created this way. <strong>No reason for concern.</strong></p>`
      );
    } else if (toolLower.includes('adobe') || toolLower.includes('acrobat')) {
      parts.push(de
        ? `<p><strong>Erstellt mit: ${tool}</strong> — Adobe Acrobat ist die Referenz-Software für PDFs. Kann aber auch zum Bearbeiten existierender PDFs verwendet werden. Prüfe die Revisions-Analyse um zu sehen ob das Dokument nachträglich verändert wurde.</p>`
        : `<p><strong>Created with: ${tool}</strong> — Adobe Acrobat is the reference software for PDFs. However, it can also be used to edit existing PDFs. Check the revision analysis to see if the document was modified afterwards.</p>`
      );
      level = 'info';
    } else if (toolLower.includes('ghostscript') || toolLower.includes('gs')) {
      parts.push(de
        ? `<p><strong>Erstellt/verarbeitet mit: ${tool}</strong> — Ghostscript ist ein Kommandozeilen-Tool zur PDF-Konvertierung. Es wird oft verwendet um PDFs zu komprimieren, konvertieren oder nachzubearbeiten. <strong>Wenn das Originaldokument angeblich aus Word oder einem Scanner stammt, ist Ghostscript verdächtig</strong> — es deutet darauf hin, dass das PDF nachträglich verarbeitet wurde.</p>`
        : `<p><strong>Created/processed with: ${tool}</strong> — Ghostscript is a command-line PDF conversion tool. It's often used to compress, convert or post-process PDFs. <strong>If the original document supposedly came from Word or a scanner, Ghostscript is suspicious</strong> — it suggests the PDF was post-processed.</p>`
      );
      level = 'note';
    } else if (toolLower.includes('fpdf') || toolLower.includes('reportlab') || toolLower.includes('wkhtmltopdf') || toolLower.includes('itext')) {
      parts.push(de
        ? `<p><strong>Erstellt mit: ${tool}</strong> — Das ist eine <strong>Programmier-Bibliothek</strong> zur PDF-Erzeugung. Solche PDFs werden oft automatisch generiert (Rechnungen, Berichte, Formulare). Aber: Sie können auch verwendet werden um gefälschte Dokumente zu erstellen, da man damit jedes Detail im PDF kontrollieren kann.</p>`
        : `<p><strong>Created with: ${tool}</strong> — This is a <strong>programming library</strong> for PDF generation. Such PDFs are often automatically generated (invoices, reports, forms). However, they can also be used to create forged documents, as you can control every detail in the PDF.</p>`
      );
      level = 'note';
    } else {
      parts.push(de
        ? `<p><strong>Erstellt mit: ${tool}</strong> (Kategorie: ${cat || 'unbekannt'}). Das ist die Software die dieses PDF erzeugt hat.</p>`
        : `<p><strong>Created with: ${tool}</strong> (category: ${cat || 'unknown'}). This is the software that generated this PDF.</p>`
      );
    }
  }

  const anoms = (sw.anomalies || []);
  if (anoms.length > 0) {
    level = anoms.some(a => a.severity === 'HIGH') ? 'warn' : 'note';
  }

  if (parts.length === 0) return '';
  const header = de ? '🔍 Was sagt die Software aus?' : '🔍 What does the software tell us?';
  return _interpBox(level, header, parts.join(''));
}


// ─── Encryption Interpretation ───────────────────────────────────────────────

function interpEncryption(enc) {
  if (!enc) return '';
  const de = _de();
  let body, level;

  if (!enc.is_encrypted) {
    level = 'safe';
    body = de
      ? `<p><strong>Dieses PDF ist nicht verschlüsselt.</strong> Das bedeutet, jeder kann es öffnen, kopieren und bearbeiten. Das ist bei den meisten Dokumenten normal. Verschlüsselung allein sagt nichts über die Echtheit eines Dokuments aus — ein gefälschtes Dokument kann genauso verschlüsselt sein wie ein echtes.</p>`
      : `<p><strong>This PDF is not encrypted.</strong> This means anyone can open, copy, and edit it. This is normal for most documents. Encryption alone says nothing about a document's authenticity — a forged document can be encrypted just like a genuine one.</p>`;
  } else {
    const algo = enc.algorithm || '';
    const strength = enc.strength || '';
    if (algo.includes('RC4') || strength === 'SCHWACH' || strength === 'WEAK') {
      level = 'warn';
      body = de
        ? `<p><strong>⚠️ Dieses PDF verwendet eine <u>schwache</u> Verschlüsselung (${algo}).</strong> RC4-Verschlüsselung, besonders mit kurzen Schlüsseln, kann mit frei verfügbaren Tools in Sekunden geknackt werden. Die Verschlüsselung bietet keinen echten Schutz.</p>
           <p>Wenn du ein Passwort brauchst um die Datei zu öffnen, kann die Analyse trotzdem eingeschränkt sein. Aber der Schutz ist <strong>nur eine Illusion</strong>.</p>`
        : `<p><strong>⚠️ This PDF uses <u>weak</u> encryption (${algo}).</strong> RC4 encryption, especially with short keys, can be cracked in seconds with freely available tools. The encryption provides no real protection.</p>
           <p>If you need a password to open the file, the analysis may still be limited. But the protection is <strong>just an illusion</strong>.</p>`;
    } else {
      level = 'info';
      body = de
        ? `<p><strong>Dieses PDF ist verschlüsselt (${algo}, ${enc.key_length_bits || '?'}-bit).</strong> Die Verschlüsselung schützt den Inhalt vor unbefugtem Zugriff. ${strength === 'STARK' || strength === 'SEHR STARK' ? 'Die Verschlüsselungsstärke ist <strong>gut</strong>.' : ''}</p>
           <p><strong>Wichtig:</strong> Verschlüsselung beweist <strong>nicht</strong>, dass ein Dokument echt ist. Es bedeutet nur, dass es passwortgeschützt ist.</p>`
        : `<p><strong>This PDF is encrypted (${algo}, ${enc.key_length_bits || '?'}-bit).</strong> Encryption protects the content from unauthorized access. ${strength === 'STRONG' || strength === 'VERY STRONG' ? 'The encryption strength is <strong>good</strong>.' : ''}</p>
           <p><strong>Important:</strong> Encryption does <strong>not</strong> prove a document is genuine. It only means it's password-protected.</p>`;
    }
  }

  const header = de ? '🔍 Was bedeutet die Verschlüsselung?' : '🔍 What does encryption mean?';
  return _interpBox(level, header, body);
}


// ─── JavaScript / Actions Interpretation ─────────────────────────────────────

function interpJavaScript(js) {
  if (!js) return '';
  const de = _de();

  if (!js.has_javascript && !js.has_auto_execute && (!js.found_actions || js.found_actions.length === 0)) {
    const body = de
      ? `<p><strong>Kein JavaScript, keine Auto-Aktionen gefunden.</strong> ${_verdict('safe', '✓ Unbedenklich')} — Legitime Dokumente (Briefe, Rechnungen, Verträge) enthalten normalerweise kein JavaScript. Das Fehlen von JavaScript ist ein gutes Zeichen.</p>`
      : `<p><strong>No JavaScript, no auto-actions found.</strong> ${_verdict('safe', '✓ Safe')} — Legitimate documents (letters, invoices, contracts) normally don't contain JavaScript. The absence of JavaScript is a good sign.</p>`;
    return _interpBox('safe', de ? '🔍 Gibt es aktive Inhalte?' : '🔍 Are there active contents?', body);
  }

  let body = de
    ? `<p><strong>⚠️ Dieses PDF enthält aktive Inhalte!</strong></p>`
    : `<p><strong>⚠️ This PDF contains active content!</strong></p>`;

  if (js.has_javascript) {
    body += de
      ? `<p><strong>JavaScript gefunden:</strong> Das PDF enthält eingebetteten Programmcode. In normalen Dokumenten (Briefe, Verträge, Rechnungen) ist das <strong>extrem ungewöhnlich</strong> und ein Warnsignal. JavaScript in PDFs wird oft für Schadsoftware verwendet — es kann z.B. Sicherheitslücken in PDF-Readern ausnutzen.</p>`
      : `<p><strong>JavaScript found:</strong> The PDF contains embedded program code. In normal documents (letters, contracts, invoices) this is <strong>extremely unusual</strong> and a warning sign. JavaScript in PDFs is often used for malware — it can exploit security vulnerabilities in PDF readers.</p>`;
  }

  if (js.has_auto_execute) {
    body += de
      ? `<p><strong>🚨 Auto-Ausführung aktiv!</strong> Das PDF führt beim Öffnen automatisch Code aus. Das ist ein <strong>klassisches Merkmal von Schadsoftware</strong>. Öffne diese Datei nur in einer sicheren Umgebung (Sandbox, virtueller Computer).</p>`
      : `<p><strong>🚨 Auto-execution active!</strong> The PDF automatically runs code when opened. This is a <strong>classic characteristic of malware</strong>. Only open this file in a safe environment (sandbox, virtual machine).</p>`;
  }

  return _interpBox('warn', de ? '🔍 Gibt es aktive Inhalte?' : '🔍 Are there active contents?', body);
}


// ─── Embedded Files Interpretation ───────────────────────────────────────────

function interpEmbeddedFiles(ef) {
  if (!ef) return '';
  const de = _de();

  if (ef.embedded_file_count === 0 && ef.annotation_count === 0) {
    const body = de
      ? `<p>${_verdict('safe', '✓ Keine eingebetteten Dateien')} — Es sind keine versteckten Dateien oder Anhänge im PDF eingebettet. Das ist normal für Standard-Dokumente.</p>`
      : `<p>${_verdict('safe', '✓ No embedded files')} — No hidden files or attachments are embedded in the PDF. This is normal for standard documents.</p>`;
    return _interpBox('safe', de ? '🔍 Sind Dateien versteckt?' : '🔍 Are files hidden?', body);
  }

  let level = 'note';
  let body = de
    ? `<p><strong>${ef.embedded_file_count} eingebettete Datei(en)</strong> gefunden. Das bedeutet, in diesem PDF sind andere Dateien "versteckt" — ähnlich wie E-Mail-Anhänge. Das ist bei manchen Dokumenten normal (z.B. PDF/A-3 mit XML-Anhängen), kann aber auch gefährlich sein wenn es sich um ausführbare Dateien (.exe, .bat, .js) handelt.</p>`
    : `<p><strong>${ef.embedded_file_count} embedded file(s)</strong> found. This means other files are "hidden" inside this PDF — similar to email attachments. This is normal for some documents (e.g. PDF/A-3 with XML attachments), but can be dangerous if they are executable files (.exe, .bat, .js).</p>`;

  const anoms = (ef.anomalies || []);
  if (anoms.some(a => a.severity === 'HIGH')) level = 'warn';

  const header = de ? '🔍 Sind Dateien versteckt?' : '🔍 Are files hidden?';
  return _interpBox(level, header, body);
}


// ─── Object Streams Interpretation ───────────────────────────────────────────

function interpObjectStreams(os) {
  if (!os) return '';
  const de = _de();
  let level = 'safe';
  let body;

  if (os.obj_stream_count === 0) {
    body = de
      ? `<p>${_verdict('safe', '✓ Keine Object Streams')} — Dieses PDF verwendet keine komprimierten Object Streams. Es nutzt das ältere, einfacher lesbare Format.</p>`
      : `<p>${_verdict('safe', '✓ No Object Streams')} — This PDF doesn't use compressed Object Streams. It uses the older, more easily readable format.</p>`;
  } else {
    body = de
      ? `<p><strong>${os.obj_stream_count} Object Stream(s)</strong> mit komprimierten Objekten gefunden.</p>
         <p><strong>Was ist das?</strong> Seit PDF 1.5 können mehrere PDF-Objekte zusammen in einem komprimierten Container ("Object Stream") verpackt werden. Das spart Platz und ist <strong>Standard-Verhalten</strong> bei moderner Software wie Microsoft Word, Chrome, und Adobe Acrobat.</p>
         <p><strong>Warum ist es trotzdem relevant?</strong> In seltenen Fällen können Object Streams verwendet werden um Inhalte zu <strong>verschleiern</strong> — z.B. verstecktes JavaScript oder doppelte Objekt-IDs (Shadow-Attack-Technik). Darum schauen wir genau rein.</p>
         <p>${_verdict('safe', '✓ Unbedenklich wenn keine Anomalien gemeldet')}</p>`
      : `<p><strong>${os.obj_stream_count} Object Stream(s)</strong> with compressed objects found.</p>
         <p><strong>What is this?</strong> Since PDF 1.5, multiple PDF objects can be packed together in a compressed container ("Object Stream"). This saves space and is <strong>standard behavior</strong> for modern software like Microsoft Word, Chrome, and Adobe Acrobat.</p>
         <p><strong>Why is it still relevant?</strong> In rare cases, Object Streams can be used to <strong>obfuscate</strong> content — e.g. hidden JavaScript or duplicate object IDs (Shadow Attack technique). That's why we examine them closely.</p>
         <p>${_verdict('safe', '✓ Safe if no anomalies reported')}</p>`;
  }

  const anoms = (os.anomalies || []);
  if (anoms.some(a => a.severity === 'HIGH')) level = 'warn';
  else if (anoms.some(a => a.severity === 'MEDIUM')) level = 'note';

  const header = de ? '🔍 Was sind Object Streams?' : '🔍 What are Object Streams?';
  return _interpBox(level, header, body);
}


// ─── Residual Objects Interpretation ─────────────────────────────────────────

function interpResidualObjects(ro) {
  if (!ro) return '';
  const de = _de();
  let level = 'safe';

  let body = de
    ? `<p><strong>Was sind verwaiste Objekte?</strong> Wenn ein PDF bearbeitet wird, werden alte Versionen von Text, Bildern oder Metadaten nicht immer vollständig gelöscht. Sie bleiben als "Geister-Daten" in der Datei zurück — unsichtbar für den Betrachter, aber mit forensischen Tools auffindbar.</p>`
    : `<p><strong>What are residual objects?</strong> When a PDF is edited, old versions of text, images, or metadata are not always fully deleted. They remain as "ghost data" in the file — invisible to the viewer, but discoverable with forensic tools.</p>`;

  if (ro.orphaned_count === 0) {
    body += de
      ? `<p>${_verdict('safe', '✓ Keine verwaisten Objekte')} — Es wurden keine Reste früherer Bearbeitungen gefunden. Das ist ein gutes Zeichen.</p>`
      : `<p>${_verdict('safe', '✓ No orphaned objects')} — No remnants of previous edits were found. This is a good sign.</p>`;
  } else {
    body += de
      ? `<p><strong>${ro.orphaned_count} verwaiste(s) Objekt(e)</strong> gefunden. Das können sein:</p>
         <p>• <strong>Gelöschter Text</strong> — frühere Versionen die jemand "entfernt" hat, die aber noch in den Rohdaten stecken<br>
         • <strong>Alte Metadaten</strong> — z.B. ein früherer Autor oder ein anderes Erstelldatum<br>
         • <strong>Linearisierungsdaten</strong> — technische Optimierungsdaten, harmlos<br>
         • <strong>Entfernte Bilder</strong> — Bilder die aus dem Dokument gelöscht wurden</p>
         <p><strong>Forensisch wichtig:</strong> Diese Daten können Aufschluss über die <strong>Geschichte des Dokuments</strong> geben — wer hat was wann geändert?</p>`
      : `<p><strong>${ro.orphaned_count} orphaned object(s)</strong> found. These could be:</p>
         <p>• <strong>Deleted text</strong> — earlier versions that someone "removed" but still remain in raw data<br>
         • <strong>Old metadata</strong> — e.g. a previous author or different creation date<br>
         • <strong>Linearization data</strong> — technical optimization data, harmless<br>
         • <strong>Removed images</strong> — images deleted from the document</p>
         <p><strong>Forensically important:</strong> This data can reveal the <strong>history of the document</strong> — who changed what and when?</p>`;
    level = 'note';
  }

  const anoms = (ro.anomalies || []);
  if (anoms.some(a => a.severity === 'HIGH')) level = 'warn';

  const header = de ? '🔍 Gibt es versteckte Überreste?' : '🔍 Are there hidden remnants?';
  return _interpBox(level, header, body);
}


// ─── Author Artifacts Interpretation ─────────────────────────────────────────

function interpAuthorArtifacts(aa) {
  if (!aa) return '';
  const de = _de();
  let level = 'info';
  let parts = [];

  // Font prefixes
  const fonts = aa.font_prefixes || [];
  if (fonts.length > 0) {
    parts.push(de
      ? `<p><strong>${fonts.length} Font-Subset-Präfix(e)</strong> gefunden (z.B. "${fonts[0]?.prefix || 'BCDHEE'}+Calibri").</p>
         <p><strong>Was ist das?</strong> Wenn Word oder eine andere Software ein PDF erstellt, werden Schriftarten "eingebettet" — aber nur die Zeichen die im Dokument verwendet werden (="Subset"). Jedes Subset bekommt einen zufälligen 6-Buchstaben-Code (z.B. BCDHEE). Dieser Code ist <strong>wie ein Fingerabdruck der Export-Session</strong> — er ist einzigartig für genau diesen Export-Vorgang.</p>
         <p><strong>Warum ist das wichtig?</strong> Wenn zwei verschiedene PDFs die <strong>gleichen Subset-Präfixe</strong> haben, wurden sie höchstwahrscheinlich in der gleichen Session erstellt — starker Beweis für einen Zusammenhang zwischen den Dokumenten!</p>`
      : `<p><strong>${fonts.length} font subset prefix(es)</strong> found (e.g. "${fonts[0]?.prefix || 'BCDHEE'}+Calibri").</p>
         <p><strong>What is this?</strong> When Word or other software creates a PDF, fonts are "embedded" — but only the characters used in the document (="subset"). Each subset gets a random 6-letter code (e.g. BCDHEE). This code is <strong>like a fingerprint of the export session</strong> — it's unique to exactly this export operation.</p>
         <p><strong>Why does this matter?</strong> If two different PDFs have the <strong>same subset prefixes</strong>, they were most likely created in the same session — strong evidence of a connection between documents!</p>`
    );
  }

  // Cross-matches
  const crossMatches = (aa.all_artifacts || []).filter(a => (a.source || '').includes('cross'));
  if (crossMatches.length > 0) {
    level = 'warn';
    parts.push(de
      ? `<p><strong>🔗 Cross-Document-Match gefunden!</strong> Dieses Dokument teilt forensische Merkmale mit anderen analysierten Dokumenten. Das bedeutet die Dokumente haben einen <strong>gemeinsamen Ursprung</strong> — sie wurden wahrscheinlich auf dem gleichen Computer, in der gleichen Session oder von der gleichen Person erstellt.</p>`
      : `<p><strong>🔗 Cross-document match found!</strong> This document shares forensic characteristics with other analyzed documents. This means the documents have a <strong>common origin</strong> — they were probably created on the same computer, in the same session, or by the same person.</p>`
    );
  }

  if (parts.length === 0) return '';
  const header = de ? '🔍 Wer hat dieses Dokument erstellt?' : '🔍 Who created this document?';
  return _interpBox(level, header, parts.join(''));
}


// ─── Signature Interpretation ────────────────────────────────────────────────

function interpSignature(sig) {
  if (!sig) return '';
  const de = _de();

  if (!sig.has_sig_field && !sig.has_acroform) {
    const body = de
      ? `<p><strong>Keine digitale Signatur vorhanden.</strong> Das bedeutet: Niemand hat dieses PDF kryptografisch "unterschrieben". Das Dokument hat also <strong>keinen mathematischen Beweis</strong> für seine Echtheit oder Unverändertheit.</p>
         <p>Das ist bei den meisten Dokumenten normal — nur Verträge, behördliche Dokumente oder zertifizierte Formulare werden typischerweise digital signiert.</p>`
      : `<p><strong>No digital signature present.</strong> This means: Nobody has cryptographically "signed" this PDF. The document therefore has <strong>no mathematical proof</strong> of its authenticity or integrity.</p>
         <p>This is normal for most documents — only contracts, government documents, or certified forms are typically digitally signed.</p>`;
    return _interpBox('info', de ? '🔍 Ist das Dokument signiert?' : '🔍 Is the document signed?', body);
  }

  let level = 'info';
  let body = de
    ? `<p><strong>Dieses PDF enthält eine digitale Signatur.</strong> Eine digitale Signatur ist wie ein Siegel — sie beweist wer das Dokument unterschrieben hat und ob es seitdem verändert wurde.</p>`
    : `<p><strong>This PDF contains a digital signature.</strong> A digital signature is like a seal — it proves who signed the document and whether it has been modified since.</p>`;

  if (sig.has_doc_mdp) {
    body += de
      ? `<p><strong>DocMDP vorhanden:</strong> Das Dokument hat Regeln definiert, welche Änderungen nach der Signatur erlaubt sind. Wurden diese Regeln verletzt, ist die Signatur ungültig.</p>`
      : `<p><strong>DocMDP present:</strong> The document has defined rules for which changes are allowed after signing. If these rules were violated, the signature is invalid.</p>`;
  }

  const anoms = (sig.anomalies || []);
  if (anoms.some(a => a.severity === 'HIGH')) {
    level = 'warn';
    body += de
      ? `<p><strong>⚠️ Auffälligkeiten bei der Signatur gefunden!</strong> Das kann bedeuten, dass das Dokument nach der Signatur verändert wurde (Shadow Attack) oder die Signatur technisch inkonsistent ist.</p>`
      : `<p><strong>⚠️ Issues found with the signature!</strong> This could mean the document was modified after signing (Shadow Attack) or the signature is technically inconsistent.</p>`;
  }

  const header = de ? '🔍 Ist das Dokument signiert?' : '🔍 Is the document signed?';
  return _interpBox(level, header, body);
}


// ─── Incremental Updates Interpretation ──────────────────────────────────────

function interpIncrementalUpdates(inc) {
  if (!inc) return '';
  const de = _de();

  if (inc.revision_count <= 1) {
    const body = de
      ? `<p>${_verdict('safe', '✓ Nur 1 Revision')} — Dieses PDF wurde in einem Stück erstellt und nicht nachträglich bearbeitet (zumindest nicht durch Incremental Updates). Das ist ein gutes Zeichen für Unverändertheit.</p>`
      : `<p>${_verdict('safe', '✓ Only 1 revision')} — This PDF was created in one piece and not subsequently edited (at least not through Incremental Updates). This is a good sign of integrity.</p>`;
    return _interpBox('safe', de ? '🔍 Wurde das PDF nachträglich bearbeitet?' : '🔍 Was the PDF edited afterwards?', body);
  }

  const body = de
    ? `<p><strong>${inc.revision_count} Revisionen gefunden!</strong></p>
       <p><strong>Was bedeutet das?</strong> Stell dir ein PDF wie ein Buch vor. Statt das ganze Buch neu zu drucken wenn sich eine Seite ändert, wird einfach ein neues Blatt hinten angehängt ("Incremental Update"). Das Original bleibt erhalten — das neue Blatt überschreibt nur den geänderten Teil.</p>
       <p><strong>Ist das verdächtig?</strong> ${inc.revision_count <= 2 ? 'Bei 2 Revisionen nicht unbedingt — Adobe Acrobat und andere Tools fügen manchmal automatisch eine Revision hinzu (z.B. beim Speichern von Formulardaten).' : 'Mehr als 2 Revisionen können auf <strong>nachträgliche Bearbeitung</strong> hinweisen. Jemand könnte das Dokument nach der Erstellung verändert haben.'}</p>
       <p><strong>Forensischer Hinweis:</strong> Die früheren Revisionen können mit speziellen Tools wiederhergestellt werden — so kann man sehen was vorher im Dokument stand!</p>
       ${inc.has_trailing_data ? '<p><strong>⚠️ Daten nach dem EOF-Marker!</strong> Am Ende des PDFs befinden sich Daten die nicht zum offiziellen Dokument gehören. Das kann auf versteckte Informationen oder eine fehlerhafte Manipulation hinweisen.</p>' : ''}`
    : `<p><strong>${inc.revision_count} revisions found!</strong></p>
       <p><strong>What does this mean?</strong> Think of a PDF like a book. Instead of reprinting the whole book when a page changes, a new sheet is simply appended at the end ("Incremental Update"). The original stays intact — the new sheet only overwrites the changed part.</p>
       <p><strong>Is this suspicious?</strong> ${inc.revision_count <= 2 ? 'With 2 revisions, not necessarily — Adobe Acrobat and other tools sometimes automatically add a revision (e.g. when saving form data).' : 'More than 2 revisions can indicate <strong>post-creation editing</strong>. Someone may have modified the document after it was created.'}</p>
       <p><strong>Forensic note:</strong> Previous revisions can be recovered with special tools — allowing you to see what was in the document before!</p>
       ${inc.has_trailing_data ? '<p><strong>⚠️ Data after EOF marker!</strong> At the end of the PDF there is data that doesn\'t belong to the official document. This can indicate hidden information or a faulty manipulation.</p>' : ''}`;

  const level = inc.revision_count > 2 || inc.has_trailing_data ? 'note' : 'info';
  const header = de ? '🔍 Wurde das PDF nachträglich bearbeitet?' : '🔍 Was the PDF edited afterwards?';
  return _interpBox(level, header, body);
}


// ─── Virus Scan Interpretation ───────────────────────────────────────────────

function interpVirusScan(vs) {
  if (!vs) return '';
  const de = _de();

  if (vs.is_clean) {
    const body = de
      ? `<p>${_verdict('safe', '✓ Keine Malware erkannt')} — Die Datei wurde gegen bekannte Viren, Trojaner und Exploits geprüft. <strong>Kein Treffer.</strong></p>
         <p><strong>Aber Vorsicht:</strong> Ein sauberer Virus-Scan bedeutet nicht, dass die Datei sicher ist. Neue ("Zero-Day") Schadsoftware wird von Virenscannern nicht erkannt. Der Scan ist ein wichtiger Baustein, aber nur einer von vielen.</p>`
      : `<p>${_verdict('safe', '✓ No malware detected')} — The file was checked against known viruses, trojans, and exploits. <strong>No matches.</strong></p>
         <p><strong>However:</strong> A clean virus scan doesn't guarantee the file is safe. New ("zero-day") malware is not detected by virus scanners. The scan is an important building block, but just one of many.</p>`;
    return _interpBox('safe', de ? '🔍 Ist die Datei sicher?' : '🔍 Is the file safe?', body);
  }

  const body = de
    ? `<p><strong>🚨 MALWARE ERKANNT!</strong> Der Virenscanner hat ${vs.total_detections} Treffer gemeldet. <strong>Diese Datei sollte NICHT geöffnet werden</strong> es sei denn in einer sicheren Umgebung (Sandbox, virtueller Computer).</p>
       <p>Die Datei könnte versuchen Sicherheitslücken in PDF-Readern auszunutzen, Schadsoftware herunterzuladen oder dein System zu kompromittieren.</p>`
    : `<p><strong>🚨 MALWARE DETECTED!</strong> The virus scanner reported ${vs.total_detections} detection(s). <strong>This file should NOT be opened</strong> unless in a safe environment (sandbox, virtual machine).</p>
       <p>The file could attempt to exploit security vulnerabilities in PDF readers, download malware, or compromise your system.</p>`;
  return _interpBox('warn', de ? '🔍 Ist die Datei sicher?' : '🔍 Is the file safe?', body);
}


// ─── UUID Interpretation ─────────────────────────────────────────────────────

function interpUUID(uuid) {
  if (!uuid) return '';
  const de = _de();

  if (!uuid.found_uuids || uuid.found_uuids.length === 0) {
    const body = de
      ? `<p>Keine UUID Version 1 im Dokument gefunden. Ohne UUIDs fehlt uns ein Zeitstempel-Vergleich, aber das ist bei vielen PDFs normal.</p>`
      : `<p>No UUID version 1 found in the document. Without UUIDs we lack a timestamp comparison, but this is normal for many PDFs.</p>`;
    return _interpBox('info', de ? '🔍 UUID-Zeitstempel' : '🔍 UUID Timestamps', body);
  }

  let level = 'safe';
  let body = de
    ? `<p><strong>${uuid.found_uuids.length} UUID(s) gefunden.</strong></p>
       <p><strong>Was ist eine UUID?</strong> Eine UUID (Universally Unique Identifier) Version 1 enthält einen <strong>hochpräzisen Zeitstempel</strong> (auf die 100-Nanosekunde genau!) und eine Geräte-ID. Dieser Zeitstempel wird von der Software automatisch generiert und ist <strong>viel schwerer zu fälschen</strong> als die Metadaten-Daten.</p>
       <p><strong>Warum ist das wertvoll?</strong> Wenn das Datum im UUID stark vom Erstelldatum in den Metadaten abweicht, ist das ein starkes Zeichen für Fälschung — jemand hat die Metadaten manuell geändert, aber vergessen die UUIDs anzupassen.</p>`
    : `<p><strong>${uuid.found_uuids.length} UUID(s) found.</strong></p>
       <p><strong>What is a UUID?</strong> A UUID (Universally Unique Identifier) version 1 contains a <strong>high-precision timestamp</strong> (accurate to 100 nanoseconds!) and a device ID. This timestamp is automatically generated by the software and is <strong>much harder to forge</strong> than metadata dates.</p>
       <p><strong>Why is this valuable?</strong> If the UUID date strongly deviates from the creation date in metadata, it's a strong sign of forgery — someone manually changed the metadata but forgot to adjust the UUIDs.</p>`;

  const anoms = (uuid.anomalies || []);
  if (anoms.some(a => a.severity === 'HIGH')) level = 'warn';
  else if (anoms.some(a => a.severity === 'MEDIUM')) level = 'note';

  const header = de ? '🔍 UUID-Zeitstempel-Analyse' : '🔍 UUID Timestamp Analysis';
  return _interpBox(level, header, body);
}


// ─── IOC Interpretation ──────────────────────────────────────────────────────

function interpIOC(ioc) {
  if (!ioc) return '';
  const de = _de();

  if (ioc.total_count === 0) {
    const body = de
      ? `<p>${_verdict('safe', '✓ Keine Netzwerk-Indikatoren')} — Es wurden keine URLs, IP-Adressen oder E-Mail-Adressen im PDF gefunden.</p>`
      : `<p>${_verdict('safe', '✓ No network indicators')} — No URLs, IP addresses, or email addresses were found in the PDF.</p>`;
    return _interpBox('safe', de ? '🔍 Verbindungen zum Internet?' : '🔍 Internet connections?', body);
  }

  let level = 'info';
  let body = de
    ? `<p><strong>Was sind IOCs?</strong> "Indicators of Compromise" sind Netzwerkhinweise in der Datei — URLs, IP-Adressen, E-Mails und Domains die in den PDF-Daten stecken. Nicht alle sind böswillig, aber manche können auf Phishing, Tracking oder Malware-Server hinweisen.</p>`
    : `<p><strong>What are IOCs?</strong> "Indicators of Compromise" are network hints in the file — URLs, IP addresses, emails, and domains embedded in the PDF data. Not all are malicious, but some can point to phishing, tracking, or malware servers.</p>`;

  if (ioc.suspicious_iocs && ioc.suspicious_iocs.length > 0) {
    level = 'warn';
    body += de
      ? `<p><strong>⚠️ ${ioc.suspicious_iocs.length} verdächtige IOC(s)!</strong> Diese könnten auf Phishing-Seiten, URL-Shortener oder bekannte bösartige Domains verweisen.</p>`
      : `<p><strong>⚠️ ${ioc.suspicious_iocs.length} suspicious IOC(s)!</strong> These could point to phishing sites, URL shorteners, or known malicious domains.</p>`;
  }

  const header = de ? '🔍 Verbindungen zum Internet?' : '🔍 Internet connections?';
  return _interpBox(level, header, body);
}


// ─── Hidden Text Interpretation ──────────────────────────────────────────────

function interpHiddenText(ht) {
  if (!ht) return '';
  const de = _de();
  const total = (ht.invisible_text_count || 0) + (ht.white_text_count || 0) + (ht.tiny_text_count || 0) + (ht.rendering_mode_3_count || 0);

  if (total === 0) {
    const body = de
      ? `<p>${_verdict('safe', '✓ Kein versteckter Text')} — Alle Textinhalte im PDF sind sichtbar. Es gibt keinen unsichtbaren, weißen oder mikroskopisch kleinen Text.</p>`
      : `<p>${_verdict('safe', '✓ No hidden text')} — All text content in the PDF is visible. There is no invisible, white, or microscopically small text.</p>`;
    return _interpBox('safe', de ? '🔍 Gibt es versteckten Text?' : '🔍 Is there hidden text?', body);
  }

  const body = de
    ? `<p><strong>⚠️ Versteckter Text gefunden!</strong></p>
       <p><strong>Was bedeutet das?</strong> Im PDF gibt es Text den du nicht sehen kannst wenn du das Dokument normal öffnest. Das können sein:</p>
       <p>• <strong>Weißer Text auf weißem Hintergrund</strong> (${ht.white_text_count || 0}x) — Text der da ist aber die gleiche Farbe wie der Hintergrund hat<br>
       • <strong>Mikroskopisch kleiner Text</strong> (${ht.tiny_text_count || 0}x) — Text kleiner als 1 Punkt, mit bloßem Auge nicht lesbar<br>
       • <strong>Transparenter Text</strong> (${ht.rendering_mode_3_count || 0}x) — Text der technisch vorhanden aber auf "unsichtbar" gestellt ist</p>
       <p><strong>Warum ist das verdächtig?</strong> Versteckter Text kann zur Informations-Verschleierung dienen, für SEO-Manipulation, oder um Text zu verstecken der bei Copy&Paste sichtbar wird. Es kann aber auch harmlos sein (z.B. OCR-Layer über gescannten Dokumenten).</p>`
    : `<p><strong>⚠️ Hidden text found!</strong></p>
       <p><strong>What does this mean?</strong> The PDF contains text that you can't see when opening the document normally. This could be:</p>
       <p>• <strong>White text on white background</strong> (${ht.white_text_count || 0}x) — text that exists but has the same color as the background<br>
       • <strong>Microscopically small text</strong> (${ht.tiny_text_count || 0}x) — text smaller than 1 point, not readable to the naked eye<br>
       • <strong>Transparent text</strong> (${ht.rendering_mode_3_count || 0}x) — text that technically exists but is set to "invisible"</p>
       <p><strong>Why is this suspicious?</strong> Hidden text can be used for information concealment, SEO manipulation, or to hide text that becomes visible on copy&paste. However, it can also be harmless (e.g. OCR layer over scanned documents).</p>`;

  const header = de ? '🔍 Gibt es versteckten Text?' : '🔍 Is there hidden text?';
  return _interpBox('warn', header, body);
}


// ─── Yellow Dots Interpretation ──────────────────────────────────────────────

function interpYellowDots(yd) {
  if (!yd) return '';
  const de = _de();

  if (!yd.dots_found) {
    const body = de
      ? `<p>${_verdict('safe', '✓ Keine Yellow Dots')} — Es wurden keine Drucker-Identifikationsmuster gefunden. Das Dokument wurde wahrscheinlich nicht ausgedruckt und wieder eingescannt, oder der Drucker hinterlässt keine MIC-Muster.</p>`
      : `<p>${_verdict('safe', '✓ No Yellow Dots')} — No printer identification patterns were found. The document was probably not printed and rescanned, or the printer doesn't leave MIC patterns.</p>`;
    return _interpBox('safe', de ? '🔍 Drucker-Tracking (Yellow Dots)' : '🔍 Printer Tracking (Yellow Dots)', body);
  }

  const body = de
    ? `<p><strong>Yellow Dots / MIC erkannt!</strong></p>
       <p><strong>Was ist das?</strong> Viele Farblaserdrucker drucken auf jede Seite ein winziges Muster aus gelben Punkten — so klein dass man es mit bloßem Auge kaum sieht. Dieses "Machine Identification Code" (MIC) Muster enthält die <strong>Seriennummer des Druckers</strong> und das <strong>Druckdatum</strong>.</p>
       <p><strong>Was bedeutet das für dieses Dokument?</strong> Das PDF enthält Bilder die dieses Muster zeigen. Das bedeutet das Dokument (oder Teile davon) wurde irgendwann auf einem Farblaserdrucker <strong>ausgedruckt</strong> und dann <strong>wieder eingescannt</strong>. Der Drucker könnte damit identifiziert werden.</p>`
    : `<p><strong>Yellow Dots / MIC detected!</strong></p>
       <p><strong>What is this?</strong> Many color laser printers print a tiny pattern of yellow dots on every page — so small you can barely see it with the naked eye. This "Machine Identification Code" (MIC) pattern contains the <strong>printer's serial number</strong> and the <strong>print date</strong>.</p>
       <p><strong>What does this mean for this document?</strong> The PDF contains images showing this pattern. This means the document (or parts of it) was at some point <strong>printed</strong> on a color laser printer and then <strong>scanned back in</strong>. The printer could potentially be identified.</p>`;

  const header = de ? '🔍 Drucker-Tracking (Yellow Dots)' : '🔍 Printer Tracking (Yellow Dots)';
  return _interpBox('note', header, body);
}


// ─── Shadow Attack Interpretation ────────────────────────────────────────────

function interpShadowAttack(sa) {
  if (!sa) return '';
  const de = _de();

  const anoms = (sa.anomalies || []);
  if (anoms.length === 0) {
    const body = de
      ? `<p>${_verdict('safe', '✓ Kein Shadow-Attack erkannt')} — Die Signatur (falls vorhanden) deckt das gesamte Dokument ab und es wurden keine verdächtigen Muster gefunden.</p>`
      : `<p>${_verdict('safe', '✓ No Shadow Attack detected')} — The signature (if present) covers the entire document and no suspicious patterns were found.</p>`;
    return _interpBox('safe', de ? '🔍 Shadow-Attack-Analyse' : '🔍 Shadow Attack Analysis', body);
  }

  const body = de
    ? `<p><strong>⚠️ Verdacht auf Shadow-Attack!</strong></p>
       <p><strong>Was ist ein Shadow-Attack?</strong> Stell dir vor, jemand unterschreibt einen Vertrag (= digitale Signatur). Dann versteckt jemand NEUEN Inhalt im Dokument — aber die Signatur sieht immer noch "gültig" aus! Das ist ein Shadow-Attack: Das was du siehst ist nicht das was signiert wurde.</p>
       <p><strong>Drei Varianten:</strong></p>
       <p>• <strong>Hide:</strong> Nach der Signatur wird Inhalt unsichtbar gemacht<br>
       • <strong>Replace:</strong> Nach der Signatur wird sichtbarer Inhalt ausgetauscht<br>
       • <strong>ISA (Incremental Saving Attack):</strong> Nach der Signatur werden Objekte hinzugefügt</p>
       <p>Dies ist ein <strong>ernstes Sicherheitsproblem</strong> wenn das Dokument als signiert und vertrauenswürdig gilt!</p>`
    : `<p><strong>⚠️ Possible Shadow Attack!</strong></p>
       <p><strong>What is a Shadow Attack?</strong> Imagine someone signs a contract (= digital signature). Then someone hides NEW content in the document — but the signature still looks "valid"! That's a Shadow Attack: what you see is not what was signed.</p>
       <p><strong>Three variants:</strong></p>
       <p>• <strong>Hide:</strong> Content is made invisible after signing<br>
       • <strong>Replace:</strong> Visible content is swapped after signing<br>
       • <strong>ISA (Incremental Saving Attack):</strong> Objects are added after signing</p>
       <p>This is a <strong>serious security issue</strong> if the document is considered signed and trustworthy!</p>`;

  const header = de ? '🔍 Shadow-Attack-Analyse' : '🔍 Shadow Attack Analysis';
  return _interpBox('warn', header, body);
}


// ─── Cross-Analyzer Interpretation ───────────────────────────────────────────

function interpCrossAnalyzer(ca) {
  if (!ca) return '';
  const de = _de();
  const score = ca.manipulation_score || 0;
  let level, body;

  if (score <= 20) {
    level = 'safe';
    body = de
      ? `<p><strong>Manipulations-Score: ${score}/100</strong> ${_verdict('safe', '✓ Unauffällig')}</p>
         <p>Der Cross-Analyzer hat die Ergebnisse aller ${ca.correlations ? ca.correlations.length : 0} einzelnen Analysen verglichen und kreuzreferenziert. Bei einem Score unter 20 gibt es <strong>keine starken Anzeichen für Manipulation</strong>. Die verschiedenen Datenquellen im Dokument (Metadaten, Zeitstempel, Fonts, UUIDs) erzählen eine <strong>konsistente Geschichte</strong>.</p>`
      : `<p><strong>Manipulation Score: ${score}/100</strong> ${_verdict('safe', '✓ Unremarkable')}</p>
         <p>The Cross-Analyzer compared and cross-referenced results from all ${ca.correlations ? ca.correlations.length : 0} individual analyses. With a score below 20, there are <strong>no strong indications of manipulation</strong>. The various data sources in the document (metadata, timestamps, fonts, UUIDs) tell a <strong>consistent story</strong>.</p>`;
  } else if (score <= 50) {
    level = 'note';
    body = de
      ? `<p><strong>Manipulations-Score: ${score}/100</strong> ${_verdict('note', '⚡ Einige Auffälligkeiten')}</p>
         <p>Der Cross-Analyzer hat einige Inkonsistenzen zwischen den verschiedenen Datenquellen gefunden. Das muss nicht zwingend Manipulation bedeuten — es kann auch an Software-Eigenheiten oder Konvertierungen liegen. Aber die markierten Korrelationen sollten <strong>manuell überprüft</strong> werden.</p>`
      : `<p><strong>Manipulation Score: ${score}/100</strong> ${_verdict('note', '⚡ Some findings')}</p>
         <p>The Cross-Analyzer found some inconsistencies between different data sources. This doesn't necessarily mean manipulation — it could also be due to software quirks or conversions. However, the flagged correlations should be <strong>manually reviewed</strong>.</p>`;
  } else {
    level = 'warn';
    body = de
      ? `<p><strong>Manipulations-Score: ${score}/100</strong> ${_verdict('warn', '🚨 Hohes Manipulationsrisiko')}</p>
         <p>Mehrere unabhängige Analysen zeigen <strong>widersprüchliche Ergebnisse</strong>. Die Zeitstempel passen nicht zusammen, die Software-Fingerprints sind inkonsistent, oder es gibt andere starke Anzeichen dafür, dass dieses Dokument <strong>nachträglich verändert</strong> wurde.</p>
         <p>Prüfe die einzelnen Korrelationen unten im Detail und vergleiche das Dokument wenn möglich mit dem Original.</p>`
      : `<p><strong>Manipulation Score: ${score}/100</strong> ${_verdict('warn', '🚨 High manipulation risk')}</p>
         <p>Multiple independent analyses show <strong>contradictory results</strong>. Timestamps don't match, software fingerprints are inconsistent, or there are other strong indications that this document was <strong>subsequently modified</strong>.</p>
         <p>Check the individual correlations below in detail and compare the document with the original if possible.</p>`;
  }

  const header = de ? '🔍 Gesamtbewertung: Manipulation?' : '🔍 Overall Assessment: Manipulation?';
  return _interpBox(level, header, body);
}
