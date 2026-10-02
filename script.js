"use strict";
/* Network Traffic Triage Tool — 100% local, no network calls, no storage.
   All CSV content is untrusted: never use innerHTML with it. Build DOM with textContent. */

const DEFAULTS = { volume: 50, dests: 10, ports: 10, icmp: 30, dns: 30, repeated: 40, syn: 20 };

const ALIASES = {
  src: ["source", "sourceip", "src", "ipsrc", "sourceaddress", "sourceaddr", "srcip", "srcaddr", "sourcemac"],
  dst: ["destination", "destinationip", "dst", "ipdst", "destinationaddress", "dest", "destip", "dstip", "dstaddr", "destinationaddr"],
  proto: ["protocol", "proto", "frameprotocols", "protocolname"],
  length: ["length", "len", "framelength", "framelen", "packetlength", "bytes", "size", "frame_len"],
  info: ["info", "information", "details", "summary", "packetinfo"],
  time: ["time", "timestamp", "arrivaltime", "framearrivaltime", "datetime", "frame_time"]
};

const state = { packets: [], fileName: "", isDemo: false, missing: [], thresholds: { ...DEFAULTS }, allAlerts: [] };

const $ = (id) => document.getElementById(id);
const els = {
  drop: $("dropzone"), file: $("fileInput"), status: $("fileStatus"), demo: $("demoBadge"),
  dash: $("dashboard"), empty: $("emptyState"), cards: $("summaryCards"), score: $("scorePanel"),
  topSrc: $("topSources"), topDst: $("topDests"), proto: $("protoDist"),
  alerts: $("alertsList"), count: $("alertCount"),
  fSrc: $("fSrc"), fDst: $("fDst"), fProto: $("fProto"), fSev: $("fSev"), fSearch: $("fSearch")
};

function norm(h) { return String(h || "").toLowerCase().replace(/[^a-z0-9]/g, ""); }

function findCol(headers, key) {
  const normalized = headers.map(norm);
  for (const alias of ALIASES[key]) {
    const i = normalized.indexOf(alias);
    if (i !== -1) return i;
  }
  return -1;
}

// Minimal robust CSV parser: handles quotes, escaped quotes, commas, newlines.
function parseCSV(text) {
  const rows = [];
  let row = [], field = "", inQ = false, i = 0;
  while (i < text.length) {
    const c = text[i];
    if (inQ) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
        inQ = false; i++; continue;
      }
      field += c; i++; continue;
    }
    if (c === '"') { inQ = true; i++; continue; }
    if (c === ",") { row.push(field); field = ""; i++; continue; }
    if (c === "\r") { i++; continue; }
    if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; i++; continue; }
    field += c; i++;
  }
  row.push(field); rows.push(row);
  // Drop trailing empty rows
  while (rows.length && rows[rows.length - 1].every((v) => String(v).trim() === "")) rows.pop();
  return rows;
}

function categorizeProto(p) {
  const s = String(p || "").toUpperCase();
  if (!s.trim()) return "Other";
  if (s.includes("DNS")) return "DNS";
  if (s.includes("ICMP")) return "ICMP";
  if (s.includes("ARP")) return "ARP";
  if (s.includes("TLS") || s.includes("SSL") || s.includes("HTTPS")) return "HTTPS/TLS";
  if (s.includes("HTTP") && !s.includes("HTTPS")) return "HTTP";
  if (s.includes("TCP")) return "TCP";
  if (s.includes("UDP")) return "UDP";
  if (s.includes("DHCP") || s.includes("NBNS") || s.includes("SSDP") || s.includes("MDNS")) return s.split(/[^A-Z]/)[0] || "Other";
  return "Other";
}

function extractDstPort(info) {
  const s = String(info || "");
  let m = s.match(/(?:Dst Port|DPort|Destination port|dstport)\s*[:=]\s*(\d{1,5})/i);
  if (m) return parseInt(m[1], 10);
  m = s.match(/(\d{1,5})\s*(?:\u2192|->|>)\s*(\d{1,5})/); // e.g. "52341 → 443 [SYN]"
  if (m) return parseInt(m[2], 10);
  m = s.match(/\bport\s+(\d{1,5})/i);
  if (m) return parseInt(m[1], 10);
  return null;
}

function isSynPacket(proto, info) {
  const s = String(info || "").toUpperCase();
  const p = String(proto || "").toUpperCase();
  if (!/\bSYN\b/.test(s)) return false;
  if (p.includes("TCP") || s.includes("TCP") || /\[SYN/.test(s)) return true;
  return true; // Info says SYN explicitly — count it, evidence shown to user
}

function esc(s) { return String(s ?? ""); }

function setText(parent, text) { parent.textContent = text; }

function analyse() {
  const t = state.thresholds;
  const packets = state.packets;
  const bySrc = new Map(), byDst = new Map(), byProto = new Map();
  const pairCount = new Map(), pairProto = new Map();
  const srcDests = new Map(), srcPortsByDst = new Map();
  const icmpBySrc = new Map(), dnsBySrc = new Map(), synBySrc = new Map();
  let lenSum = 0, lenN = 0;

  for (const p of packets) {
    if (p.src) bySrc.set(p.src, (bySrc.get(p.src) || 0) + 1);
    if (p.dst) byDst.set(p.dst, (byDst.get(p.dst) || 0) + 1);
    const cat = categorizeProto(p.proto);
    p._cat = cat;
    byProto.set(cat, (byProto.get(cat) || 0) + 1);
    if (p.src && p.dst) {
      const k = p.src + "\u0000" + p.dst;
      pairCount.set(k, (pairCount.get(k) || 0) + 1);
      if (!pairProto.has(k)) pairProto.set(k, new Map());
      const m = pairProto.get(k);
      m.set(cat, (m.get(cat) || 0) + 1);
      if (!srcDests.has(p.src)) srcDests.set(p.src, new Set());
      srcDests.get(p.src).add(p.dst);
      if (p.dport != null) {
        if (!srcPortsByDst.has(p.src)) srcPortsByDst.set(p.src, new Map());
        const dm = srcPortsByDst.get(p.src);
        if (!dm.has(p.dst)) dm.set(p.dst, new Set());
        dm.get(p.dst).add(p.dport);
      }
    }
    if (cat === "ICMP" && p.src) icmpBySrc.set(p.src, (icmpBySrc.get(p.src) || 0) + 1);
    if (cat === "DNS" && p.src) dnsBySrc.set(p.src, (dnsBySrc.get(p.src) || 0) + 1);
    if (isSynPacket(p.proto, p.info) && p.src) synBySrc.set(p.src, (synBySrc.get(p.src) || 0) + 1);
    const L = parseFloat(p.len);
    if (Number.isFinite(L)) { lenSum += L; lenN++; }
  }

  const top = (m, n) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  const alerts = [];
  const add = (a) => alerts.push(a);

  // Rule 1 — high packet volume
  for (const [src, n] of bySrc) {
    if (n > t.volume) add({
      name: "High activity host", severity: n > t.volume * 3 ? "High" : "Medium",
      src, dst: null, proto: null, observed: `${n} packets from one source`, threshold: `> ${t.volume} packets per source`,
      why: "A host generating significantly more traffic than expected may warrant investigation.",
      benign: ["Legitimate file transfer", "Software updates or backups", "Misconfigured or chatty application", "Automated scripts"],
      steps: ["Identify the source device and its normal role.", "Check protocols, destinations and timing in the table below.", "Ask whether a transfer, update or backup was scheduled.", "If unexplained, review endpoint and firewall logs."],
      score: 20, evidence: { packets: n }
    });
  }
  // Rule 2 — possible host scanning (many unique destinations)
  for (const [src, set] of srcDests) {
    if (set.size > t.dests) add({
      name: "Possible network scanning (many destinations)", severity: "Medium",
      src, dst: null, proto: null, observed: `${set.size} unique destinations contacted`, threshold: `> ${t.dests} unique destinations`,
      why: "A single host communicating with many destination systems in one capture may indicate host discovery or scanning behaviour.",
      benign: ["Network management or monitoring software", "Authorised vulnerability scanner", "Asset discovery system"],
      steps: ["Identify the source device.", "Determine whether the behaviour is expected or authorised.", "Review protocols and destination ports.", "Check whether the source is an approved scanner.", "Review endpoint telemetry if available."],
      score: 15, evidence: { uniqueDests: set.size }
    });
  }
  // Rule 3 — possible port scanning
  let portDataAvailable = false;
  for (const [, dm] of srcPortsByDst) for (const [, s] of dm) if (s.size > 0) portDataAvailable = true;
  if (portDataAvailable) {
    for (const [src, dm] of srcPortsByDst) {
      for (const [dst, ports] of dm) {
        if (ports.size > t.ports) add({
          name: "Possible port scanning (many destination ports)", severity: "Medium",
          src, dst, proto: null, observed: `${ports.size} unique destination ports on ${dst} (ports: ${[...ports].sort((a, b) => a - b).slice(0, 12).join(", ")}${ports.size > 12 ? "…" : ""})`,
          threshold: `> ${t.ports} unique ports on one destination`,
          why: "Contacting many ports on a single host can indicate port scanning, but also occurs during legitimate service discovery or application behaviour.",
          benign: ["Service discovery", "Application probing multiple services", "Admin troubleshooting"],
          steps: ["Check which ports were contacted and whether services listen there.", "See if the source is an authorised scanner.", "Correlate with host and firewall logs."],
          score: 10, evidence: { uniquePorts: ports.size }
        });
      }
    }
  }
  // Rule 4 — high ICMP
  for (const [src, n] of icmpBySrc) {
    if (n > t.icmp) add({
      name: "High ICMP activity", severity: n > t.icmp * 2 ? "Medium" : "Low",
      src, dst: null, proto: "ICMP", observed: `${n} ICMP packets`, threshold: `> ${t.icmp} ICMP packets per source`,
      why: "Unusually high ICMP traffic can reflect troubleshooting, monitoring, ping sweeps, network discovery, or denial-of-service activity.",
      benign: ["Ping troubleshooting", "Monitoring system", "Misconfigured health checks"],
      steps: ["Identify the source and its targets.", "Check ICMP types (echo request/reply) in Wireshark.", "Ask whether anyone was troubleshooting the network."],
      score: 15, evidence: { icmp: n }
    });
  }
  // Rule 5 — high DNS
  for (const [src, n] of dnsBySrc) {
    if (n > t.dns) add({
      name: "High DNS query activity", severity: "Low",
      src, dst: null, proto: "DNS", observed: `${n} DNS packets`, threshold: `> ${t.dns} DNS packets per source`,
      why: "High DNS activity can be normal, but large numbers of automated lookups sometimes deserve a closer look (e.g. misconfiguration or beaconing).",
      benign: ["Normal browsing", "Software updates", "Automated applications", "Misconfigured system retrying lookups"],
      steps: ["Review queried names in Wireshark (apply display filter dns).", "Check whether the volume matches user/app activity.", "Look for repeated queries to rare or random-looking domains."],
      score: 10, evidence: { dns: n }
    });
  }
  // Rule 6 — repeated src→dst
  for (const [k, n] of pairCount) {
    if (n > t.repeated) {
      const [src, dst] = k.split("\u0000");
      const pm = pairProto.get(k);
      const topProto = [...pm.entries()].sort((a, b) => b[1] - a[1])[0][0];
      add({
        name: "Repeated source-to-destination communication", severity: "Informational",
        src, dst, proto: topProto, observed: `${n} packets from ${src} to ${dst} (mostly ${topProto})`, threshold: `> ${t.repeated} packets for one pair`,
        why: "Repeated communication might be normal application traffic — or unusual automated activity. Volume alone does not prove anything.",
        benign: ["Streaming, file transfer or backup", "Long-lived app session", "Monitoring heartbeat"],
        steps: ["Check the protocol and Info column for context.", "Compare against the host's normal baseline.", "Confirm with the application or host owner."],
        score: 10, evidence: { pairPackets: n }
      });
    }
  }
  // Rule 7 — TCP SYN heavy
  for (const [src, n] of synBySrc) {
    if (n > t.syn) add({
      name: "Repeated TCP SYN activity", severity: n > t.syn * 3 ? "High" : "Medium",
      src, dst: null, proto: "TCP", observed: `${n} packets with SYN flag`, threshold: `> ${t.syn} SYN packets per source`,
      why: "Repeated SYN packets may reflect normal connection attempts, unavailable services, network scanning, or SYN-flood-like behaviour. Do not label it a SYN flood from CSV alone.",
      benign: ["Retries to an unavailable service", "Application reconnect loop", "Admin scan"],
      steps: ["Filter tcp.flags.syn==1 in Wireshark to inspect.", "Check SYN vs SYN-ACK balance and targets.", "Correlate with server availability and firewall logs."],
      score: 10, evidence: { syn: n }
    });
  }

  const sevRank = { Informational: 0, Low: 1, Medium: 2, High: 3 };
  alerts.sort((a, b) => sevRank[b.severity] - sevRank[a.severity] || b.score - a.score);

  // Explainable investigation score (global, no fake precision)
  const parts = [];
  if (alerts.some((a) => a.name === "High activity host")) parts.push({ label: "High packet volume", pts: 20 });
  if (alerts.some((a) => a.name.startsWith("Possible network scanning"))) parts.push({ label: "Large number of destinations", pts: 15 });
  if (alerts.some((a) => a.name === "High ICMP activity")) parts.push({ label: "High ICMP activity", pts: 15 });
  if (alerts.some((a) => a.name === "High DNS query activity")) parts.push({ label: "High DNS activity", pts: 10 });
  if (alerts.some((a) => a.name.startsWith("Possible port scanning"))) parts.push({ label: "Many destination ports", pts: 10 });
  if (alerts.some((a) => a.name.startsWith("Repeated source"))) parts.push({ label: "Repeated src→dst traffic", pts: 10 });
  if (alerts.some((a) => a.name.startsWith("Repeated TCP SYN"))) parts.push({ label: "Repeated SYN activity", pts: 10 });
  const total = parts.reduce((s, p) => s + p.pts, 0);
  const label = total === 0 ? "Quiet" : total < 20 ? "Minor activity" : total < 40 ? "Notable activity" : total < 70 ? "Elevated activity" : "High activity — prioritise review";

  return {
    total: packets.length, uniqSrc: bySrc.size, uniqDst: byDst.size,
    topSrc: top(bySrc, 10), topDst: top(byDst, 10), byProto,
    mostActive: top(bySrc, 1)[0] || null, mostContacted: top(byDst, 1)[0] || null,
    mostProto: top(byProto, 1)[0] || null,
    avgLen: lenN ? lenSum / lenN : null,
    alerts, scoreParts: parts, scoreTotal: total, scoreLabel: label,
    portDataAvailable
  };
}

function handleRows(rows, fileName, isDemo) {
  if (!rows.length) throw new Error("The CSV appears to be empty.");
  const headers = rows[0].map((h) => String(h).trim());
  const ci = {
    src: findCol(headers, "src"), dst: findCol(headers, "dst"),
    proto: findCol(headers, "proto"), len: findCol(headers, "length"),
    info: findCol(headers, "info"), time: findCol(headers, "time")
  };
  const missing = [];
  if (ci.src === -1) missing.push("Source — e.g. “This CSV does not appear to contain a Source address column.” Analysis of per-host rules will be limited.");
  if (ci.dst === -1) missing.push("Destination — destination-based rules (scanning, repeated pairs) will be limited.");
  if (ci.proto === -1) missing.push("Protocol — protocol distribution and ICMP/DNS rules will be limited.");
  if (ci.len === -1) missing.push("Length — average packet length cannot be computed.");
  if (ci.info === -1) missing.push("Info — port-scan and SYN detection (which rely on the Info field) will be limited.");
  if (ci.src === -1 && ci.dst === -1 && ci.proto === -1) {
    throw new Error("Could not find Source, Destination or Protocol columns. Expected Wireshark CSV headers like: No., Time, Source, Destination, Protocol, Length, Info.");
  }
  const packets = [];
  for (let r = 1; r < rows.length; r++) {
    const row = rows[r];
    if (row.every((v) => String(v).trim() === "")) continue;
    packets.push({
      src: ci.src >= 0 ? String(row[ci.src] ?? "").trim() : "",
      dst: ci.dst >= 0 ? String(row[ci.dst] ?? "").trim() : "",
      proto: ci.proto >= 0 ? String(row[ci.proto] ?? "").trim() : "",
      len: ci.len >= 0 ? String(row[ci.len] ?? "").trim() : "",
      info: ci.info >= 0 ? String(row[ci.info] ?? "").trim() : "",
      time: ci.time >= 0 ? String(row[ci.time] ?? "").trim() : "",
      dport: ci.info >= 0 ? extractDstPort(row[ci.info]) : null
    });
  }
  if (!packets.length) throw new Error("No packet rows found after the header row.");
  state.packets = packets;
  state.fileName = fileName;
  state.isDemo = isDemo;
  state.missing = missing;
  renderAll();
}

function renderAll() {
  const res = analyse();
  state.allAlerts = res.alerts;
  renderStatus(res);
  renderDashboard(res);
  populateFilters(res);
  renderAlerts();
}

function renderStatus(res) {
  els.status.innerHTML = "";
  const dl = document.createElement("dl");
  const items = [
    ["File", state.fileName + (state.isDemo ? " (demo)" : "")],
    ["Packets loaded", String(res.total)],
    ["Parsed", "Yes — CSV parsed successfully in your browser"]
  ];
  for (const [k, v] of items) {
    const dt = document.createElement("dt"); setText(dt, k);
    const dd = document.createElement("dd"); setText(dd, v);
    dl.append(dt, dd);
  }
  els.status.appendChild(dl);
  if (state.missing.length) {
    const p = document.createElement("p");
    setText(p, "Missing fields affecting analysis:");
    els.status.appendChild(p);
    const ul = document.createElement("ul");
    for (const m of state.missing) { const li = document.createElement("li"); setText(li, m); ul.appendChild(li); }
    els.status.appendChild(ul);
  } else {
    const p = document.createElement("p");
    p.className = "muted small";
    setText(p, "All expected columns found (Source, Destination, Protocol, Length, Info).");
    els.status.appendChild(p);
  }
  els.demo.hidden = !state.isDemo;
}

function statCard(k, v) {
  const d = document.createElement("div");
  d.className = "stat";
  const kk = document.createElement("div"); kk.className = "k"; setText(kk, k);
  const vv = document.createElement("div"); vv.className = "v"; setText(vv, v);
  d.append(kk, vv);
  return d;
}

function renderDashboard(res) {
  els.empty.hidden = true;
  els.dash.hidden = false;
  els.cards.innerHTML = "";
  els.cards.append(
    statCard("Total packets", String(res.total)),
    statCard("Unique sources", String(res.uniqSrc)),
    statCard("Unique destinations", String(res.uniqDst)),
    statCard("Most active source", res.mostActive ? `${res.mostActive[0]} (${res.mostActive[1]})` : "—"),
    statCard("Most contacted dest", res.mostContacted ? `${res.mostContacted[0]} (${res.mostContacted[1]})` : "—"),
    statCard("Most common protocol", res.mostProto ? `${res.mostProto[0]} (${res.mostProto[1]})` : "—"),
    statCard("Avg packet length", res.avgLen != null ? res.avgLen.toFixed(1) : "n/a")
  );

  els.score.innerHTML = "";
  const h = document.createElement("h3"); setText(h, `Investigation score: ${res.scoreTotal} — ${res.scoreLabel}`);
  els.score.appendChild(h);
  const note = document.createElement("p"); note.className = "muted small";
  setText(note, "Explainable triage score, not a probability. Points show exactly what contributed:");
  els.score.appendChild(note);
  if (!res.scoreParts.length) {
    const p = document.createElement("p"); setText(p, "No scoring rules triggered. Nothing here means nothing to learn — review the tables below."); els.score.appendChild(p);
  } else {
    const ul = document.createElement("ul");
    for (const p of res.scoreParts) { const li = document.createElement("li"); setText(li, `+${p.pts} ${p.label}`); ul.appendChild(li); }
    els.score.appendChild(ul);
  }
  if (!res.portDataAvailable) {
    const p = document.createElement("p"); p.className = "muted small";
    setText(p, "Note: destination-port info was not found in the Info column, so port-scan detection was skipped (not an error).");
    els.score.appendChild(p);
  }

  // Top hosts tables with CSS bars
  els.topSrc.innerHTML = ""; els.topDst.innerHTML = "";
  els.topSrc.appendChild(barsTable(res.topSrc));
  els.topDst.appendChild(barsTable(res.topDst));

  els.proto.innerHTML = "";
  const entries = [...res.byProto.entries()].sort((a, b) => b[1] - a[1]);
  const max = entries.length ? entries[0][1] : 1;
  for (const [name, n] of entries) {
    const row = document.createElement("div"); row.className = "bar-row";
    const a = document.createElement("span"); setText(a, name);
    const bar = document.createElement("div"); bar.className = "bar";
    const fill = document.createElement("span"); fill.style.width = Math.max(2, Math.round((n / max) * 100)) + "%";
    bar.appendChild(fill);
    const c = document.createElement("span"); setText(c, String(n));
    row.append(a, bar, c);
    els.proto.appendChild(row);
  }
}

function barsTable(top) {
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const trh = document.createElement("tr");
  const th1 = document.createElement("th"); setText(th1, "Host");
  const th2 = document.createElement("th"); setText(th2, "Packets");
  trh.append(th1, th2); thead.appendChild(trh); table.appendChild(thead);
  const tb = document.createElement("tbody");
  if (!top.length) { const tr = document.createElement("tr"); const td = document.createElement("td"); td.colSpan = 2; setText(td, "—"); tr.appendChild(td); tb.appendChild(tr); }
  for (const [host, n] of top) {
    const tr = document.createElement("tr");
    const td1 = document.createElement("td"); setText(td1, host);
    const td2 = document.createElement("td"); setText(td2, String(n));
    tr.append(td1, td2); tb.appendChild(tr);
  }
  table.appendChild(tb);
  return table;
}

function populateFilters(res) {
  const fill = (sel, values) => {
    const cur = sel.value;
    sel.innerHTML = "";
    const all = document.createElement("option"); all.value = "";
    setText(all, sel === els.fSev ? "All severities" : sel === els.fProto ? "All protocols" : sel === els.fSrc ? "All sources" : "All destinations");
    if (sel === els.fSev) { ["Informational", "Low", "Medium", "High"].forEach((s) => { const o = document.createElement("option"); setText(o, s); sel.appendChild(o); }); sel.value = cur; return; }
    sel.appendChild(all);
    for (const v of values) { const o = document.createElement("option"); setText(o, v); o.value = v; sel.appendChild(o); }
    sel.value = cur;
  };
  fill(els.fSrc, [...new Set(state.packets.map((p) => p.src).filter(Boolean))].sort().slice(0, 200));
  fill(els.fDst, [...new Set(state.packets.map((p) => p.dst).filter(Boolean))].sort().slice(0, 200));
  fill(els.fProto, [...new Set(state.packets.map((p) => p._cat || categorizeProto(p.proto)).filter(Boolean))].sort());
}

function renderAlerts() {
  const fs = els.fSearch.value.trim().toLowerCase();
  const list = state.allAlerts.filter((a) =>
    (!els.fSrc.value || a.src === els.fSrc.value) &&
    (!els.fDst.value || a.dst === els.fDst.value) &&
    (!els.fProto.value || a.proto === els.fProto.value) &&
    (!els.fSev.value || a.severity === els.fSev.value) &&
    (!fs || JSON.stringify(a).toLowerCase().includes(fs))
  );
  setText(els.count, list.length + " of " + state.allAlerts.length + " alerts shown.");
  els.alerts.innerHTML = "";
  if (!state.allAlerts.length) {
    const p = document.createElement("p"); p.className = "muted";
    setText(p, "No alerts — traffic looks routine against current thresholds. That does not prove it is benign; it means nothing crossed your investigation thresholds.");
    els.alerts.appendChild(p);
    return;
  }
  if (!list.length) {
    const p = document.createElement("p"); p.className = "muted";
    setText(p, "No alerts match the current filters.");
    els.alerts.appendChild(p);
    return;
  }
  for (const a of list) els.alerts.appendChild(alertCard(a));
}

function alertCard(a) {
  const d = document.createElement("article");
  d.className = "alert sev-" + a.severity;
  const pill = document.createElement("span"); pill.className = "sev-pill"; setText(pill, a.severity);
  const h = document.createElement("h3"); setText(h, a.name);
  d.append(pill, h);
  const dl = document.createElement("dl");
  const rows = [
    ["Source host", a.src || "—"],
    ["Destination host", a.dst || "—"],
    ["Observed activity", a.observed],
    ["Configured threshold", a.threshold],
    ["Why this could matter", a.why]
  ];
  for (const [k, v] of rows) {
    const dt = document.createElement("dt"); setText(dt, k);
    const dd = document.createElement("dd"); setText(dd, v);
    dl.append(dt, dd);
  }
  d.appendChild(dl);
  const b1 = document.createElement("p"); setText(b1, "Possible benign explanations:");
  const u1 = document.createElement("ul");
  for (const b of a.benign) { const li = document.createElement("li"); setText(li, b); u1.appendChild(li); }
  const b2 = document.createElement("p"); setText(b2, "Suggested investigation:");
  const o = document.createElement("ol");
  for (const s of a.steps) { const li = document.createElement("li"); setText(li, s); o.appendChild(li); }
  d.append(b1, u1, b2, o);
  return d;
}

function loadText(text, name, isDemo) {
  try {
    const rows = parseCSV(text);
    handleRows(rows, name, isDemo);
  } catch (e) {
    els.status.innerHTML = "";
    const p = document.createElement("p");
    setText(p, "Could not analyse “" + name + "”: " + e.message);
    els.status.appendChild(p);
  }
}

function loadFile(file, isDemo) {
  if (!/\.csv$/i.test(file.name) && file.type && !file.type.includes("csv") && !file.type.includes("text")) {
    els.status.textContent = "Please choose a .csv file exported from Wireshark.";
    return;
  }
  if (file.size > 15 * 1024 * 1024) {
    els.status.textContent = "File is very large (>15 MB). Try a smaller capture slice first.";
    return;
  }
  const r = new FileReader();
  r.onload = () => loadText(String(r.result || ""), file.name, isDemo);
  r.onerror = () => { els.status.textContent = "Could not read the file. Please try again."; };
  r.readAsText(file);
}

// Events
els.file.addEventListener("change", (e) => { if (e.target.files[0]) loadFile(e.target.files[0], false); });
["dragover", "dragenter"].forEach((ev) => els.drop.addEventListener(ev, (e) => { e.preventDefault(); els.drop.classList.add("drag"); }));
["dragleave", "drop"].forEach((ev) => els.drop.addEventListener(ev, (e) => { e.preventDefault(); els.drop.classList.remove("drag"); }));
els.drop.addEventListener("drop", (e) => {
  const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if (f) loadFile(f, false);
});
els.drop.addEventListener("click", (e) => { if (e.target.tagName !== "BUTTON" && e.target.tagName !== "LABEL") els.file.click(); });
els.drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); els.file.click(); } });

document.querySelectorAll("[data-sample]").forEach((b) => b.addEventListener("click", async () => {
  const url = b.getAttribute("data-sample");
  // Embedded fallback: works on file:// where fetch is blocked. No server needed.
  try {
    if (window.EMBEDDED_SAMPLES && window.EMBEDDED_SAMPLES[url]) {
      loadText(window.EMBEDDED_SAMPLES[url], url.split("/").pop(), true);
      return;
    }
    const res = await fetch(url);
    if (!res.ok) throw new Error("HTTP " + res.status);
    loadText(await res.text(), url.split("/").pop(), true);
  } catch (e) {
    els.status.textContent = "Could not load sample (" + url + "). " + e.message;
  }
}));

function readThresholds() {
  const g = (id, dflt) => {
    const v = parseInt($(id).value, 10);
    return Number.isFinite(v) && v > 0 ? v : dflt;
  };
  state.thresholds = {
    volume: g("thrVolume", DEFAULTS.volume), dests: g("thrDests", DEFAULTS.dests),
    ports: g("thrPorts", DEFAULTS.ports), icmp: g("thrIcmp", DEFAULTS.icmp),
    dns: g("thrDns", DEFAULTS.dns), repeated: g("thrRepeated", DEFAULTS.repeated),
    syn: g("thrSyn", DEFAULTS.syn)
  };
}
$("thresholdForm").addEventListener("submit", (e) => { e.preventDefault(); readThresholds(); if (state.packets.length) renderAll(); });
$("resetThr").addEventListener("click", () => {
  $("thrVolume").value = DEFAULTS.volume; $("thrDests").value = DEFAULTS.dests;
  $("thrPorts").value = DEFAULTS.ports; $("thrIcmp").value = DEFAULTS.icmp;
  $("thrDns").value = DEFAULTS.dns; $("thrRepeated").value = DEFAULTS.repeated;
  $("thrSyn").value = DEFAULTS.syn;
  readThresholds(); if (state.packets.length) renderAll();
});
["fSrc", "fDst", "fProto", "fSev"].forEach((id) => $(id).addEventListener("change", renderAlerts));
$("fSearch").addEventListener("input", renderAlerts);
$("clearFilters").addEventListener("click", () => {
  els.fSrc.value = ""; els.fDst.value = ""; els.fProto.value = ""; els.fSev.value = ""; els.fSearch.value = "";
  renderAlerts();
});
