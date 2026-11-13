/* fortidoc report script. No framework, no network access.
 * Every text from the backup is written with textContent, never as HTML. */
(function () {
  "use strict";

  const DATA = JSON.parse(document.getElementById("report-data").textContent);
  const VALUES = DATA.values; // [kind, text, note, reason, fromDefault, intervals, ipVersion]
  const SVCS = DATA.svcs; // [kind, text, note, protocol, [lo, hi] | null, srcRestricted, protocolNumber]
  const POLICIES = DATA.policies;
  const LOCAL_IN = DATA.localIn;
  const INSPECTION = DATA.inspection;
  const MULTI = DATA.multiVdom;
  const PAGE_SIZES = [50, 100, 250, 500];
  const VALUE_PREVIEW = 6;

  const V_KIND = 0, V_TEXT = 1, V_NOTE = 2, V_REASON = 3, V_DEFAULT = 4, V_IV = 5, V_VER = 6;
  const S_KIND = 0, S_TEXT = 1, S_NOTE = 2, S_PROTO = 3, S_PORTS = 4, S_SRCPORT = 5, S_PNUM = 6;

  const REASONS = {
    geo: "Geo-Adresse",
    dynamic: "dynamische Adresse",
    isdb: "Internet Service",
    mac: "MAC-Adresse",
    "not-found": "Objekt nicht gefunden",
    circular: "Zirkelbezug",
    wildcard: "Wildcard",
    interface: "Interface-Netz unbekannt",
    "unknown-type": "unbekannter Adresstyp",
    exclude: "Ausschluss nicht berechenbar",
    invalid: "nicht auflösbar",
  };
  const PROTOCOL_NUMBERS = { TCP: 6, UDP: 17, SCTP: 132 };

  // ---------------------------------------------------------------------------
  // DOM helpers: text only
  // ---------------------------------------------------------------------------

  function h(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function append(parent, children) {
    for (const child of children) {
      if (child === null || child === undefined || child === "") continue;
      parent.appendChild(typeof child === "string" || typeof child === "number" ? document.createTextNode(String(child)) : child);
    }
    return parent;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function option(value, label) {
    const node = h("option", null, label);
    node.value = value;
    return node;
  }

  function debounce(fn, ms) {
    let timer = null;
    return function () {
      clearTimeout(timer);
      timer = setTimeout(fn, ms);
    };
  }

  function $(id) {
    return document.getElementById(id);
  }

  // ---------------------------------------------------------------------------
  // Paged table: only the rows of the current page are in the DOM
  // ---------------------------------------------------------------------------

  class PagedTable {
    constructor(container, columns, options) {
      this.container = container;
      this.columns = columns;
      this.rowClass = (options && options.rowClass) || null;
      this.rowKey = (options && options.rowKey) || null;
      this.emptyText = (options && options.emptyText) || "Keine Einträge.";
      this.pageSize = 100;
      this.page = 0;
      this.rows = [];
      this.all = false;
    }

    setRows(rows, keepPage) {
      this.rows = rows;
      if (!keepPage) this.page = 0;
      this.render();
    }

    pages() {
      return Math.max(1, Math.ceil(this.rows.length / this.pageSize));
    }

    render() {
      const container = this.container;
      clear(container);
      if (!this.rows.length) {
        container.appendChild(h("p", "empty", this.emptyText));
        return;
      }
      if (this.page >= this.pages()) this.page = this.pages() - 1;
      const start = this.all ? 0 : this.page * this.pageSize;
      const end = this.all ? this.rows.length : Math.min(this.rows.length, start + this.pageSize);
      if (!this.all) container.appendChild(this.pager(start, end));
      const wrap = h("div", "scroll");
      const table = h("table", "data");
      const head = h("thead");
      const headRow = h("tr");
      for (const col of this.columns) headRow.appendChild(h("th", null, col.title));
      head.appendChild(headRow);
      table.appendChild(head);
      const body = h("tbody");
      for (let i = start; i < end; i++) {
        const row = this.rows[i];
        const tr = h("tr", this.rowClass ? this.rowClass(row) : null);
        if (this.rowKey) tr.dataset.key = this.rowKey(row);
        for (const col of this.columns) {
          const td = h("td", col.cls || null);
          const content = col.cell(row, this);
          if (content instanceof Node) td.appendChild(content);
          else if (content !== null && content !== undefined) td.textContent = String(content);
          tr.appendChild(td);
        }
        body.appendChild(tr);
      }
      table.appendChild(body);
      wrap.appendChild(table);
      container.appendChild(wrap);
      if (!this.all && this.pages() > 1) container.appendChild(this.pager(start, end));
    }

    pager(start, end) {
      const bar = h("div", "pager");
      const info = h("span", "page-info", "Einträge " + (start + 1) + "–" + end + " von " + this.rows.length + " · Seite " + (this.page + 1) + " von " + this.pages());
      const go = (page) => () => {
        this.page = Math.max(0, Math.min(this.pages() - 1, page));
        this.render();
      };
      const button = (label, page, disabled, cls) => {
        const b = h("button", cls, label);
        b.type = "button";
        b.disabled = disabled;
        b.addEventListener("click", go(page));
        return b;
      };
      const first = this.page === 0;
      const last = this.page >= this.pages() - 1;
      const size = h("select");
      for (const n of PAGE_SIZES) size.appendChild(option(String(n), n + " je Seite"));
      size.value = String(this.pageSize);
      size.addEventListener("change", () => {
        this.pageSize = Number(size.value);
        this.page = 0;
        this.render();
      });
      append(bar, [
        button("« Erste", 0, first, "first"),
        button("‹ Zurück", this.page - 1, first, "prev"),
        info,
        button("Weiter ›", this.page + 1, last, "next"),
        button("Letzte »", this.pages() - 1, last, "last"),
        size,
      ]);
      return bar;
    }
  }

  // ---------------------------------------------------------------------------
  // Rule cells
  // ---------------------------------------------------------------------------

  const expanded = new Set();

  function policyKey(p) {
    return p.vdom + "|" + p.sec + "|" + p.pos;
  }

  function valueNode(v) {
    const line = h("span", "val");
    line.appendChild(document.createTextNode(v[V_TEXT]));
    const kind = v[V_KIND];
    if (kind === "range") line.appendChild(h("span", "badge", "Bereich"));
    else if (kind === "fqdn") line.appendChild(h("span", "badge", "FQDN"));
    else if (kind === "vip") line.appendChild(h("span", "badge", "VIP"));
    else if (kind === "unresolvable") line.appendChild(h("span", "badge unres", "nicht auflösbar"));
    if (v[V_NOTE]) {
      line.appendChild(document.createTextNode(" "));
      line.appendChild(h("span", "note", "(" + v[V_NOTE] + ")"));
    }
    return line;
  }

  function serviceNode(s) {
    const line = h("span", "val");
    line.appendChild(document.createTextNode(s[S_TEXT]));
    if (s[S_KIND] === "unresolvable") {
      line.appendChild(h("span", "badge unres", "nicht auflösbar"));
      if (s[S_NOTE]) {
        line.appendChild(document.createTextNode(" "));
        line.appendChild(h("span", "note", "(" + s[S_NOTE] + ")"));
      }
    }
    return line;
  }

  function valueList(items, render, key, table) {
    const box = h("div", "vals");
    const showAll = !table || table.all || expanded.has(key) || items.length <= VALUE_PREVIEW + 1;
    const shown = showAll ? items : items.slice(0, VALUE_PREVIEW);
    for (const item of shown) box.appendChild(render(item));
    if (items.length > VALUE_PREVIEW + 1 && table && !table.all) {
      const more = h("button", "more", showAll ? "weniger anzeigen" : "… und " + (items.length - VALUE_PREVIEW) + " weitere anzeigen");
      more.type = "button";
      more.addEventListener("click", () => {
        if (expanded.has(key)) expanded.delete(key);
        else expanded.add(key);
        table.render();
      });
      box.appendChild(more);
    }
    return box;
  }

  function addressCell(p, sideName, table) {
    const side = p[sideName];
    const cell = h("div");
    if (side.neg) cell.appendChild(h("div", "neg", "NICHT (alles außer):"));
    for (const name of side.o) cell.appendChild(h("div", "obj", name));
    for (const name of side.o6) cell.appendChild(h("div", "obj", name + " (IPv6)"));
    for (const name of side.isdb) cell.appendChild(h("div", "obj", "Internet Service: " + name));
    if (side.v.length) {
      const values = side.v.map((i) => VALUES[i]);
      const list = valueList(values, valueNode, policyKey(p) + "|" + sideName, table);
      if (side.neg) list.insertBefore(h("div", "neg", "alles außer:"), list.firstChild);
      cell.appendChild(list);
    }
    return cell;
  }

  function serviceCell(p, table) {
    const svc = p.svc;
    const cell = h("div");
    if (svc.neg) cell.appendChild(h("div", "neg", "NICHT (alles außer):"));
    for (const name of svc.o) cell.appendChild(h("div", "obj", name));
    for (const name of p.apps) cell.appendChild(h("div", "obj app", name));
    if (svc.v.length) {
      const list = valueList(svc.v.map((i) => SVCS[i]), serviceNode, policyKey(p) + "|svc", table);
      if (svc.neg) list.insertBefore(h("div", "neg", "alles außer:"), list.firstChild);
      cell.appendChild(list);
    }
    return cell;
  }

  function lines(items) {
    return items && items.length ? items.join("\n") : "";
  }

  function zoneText(zones, refs) {
    const unknown = new Set(refs.filter((r) => r[1] === "unknown").map((r) => r[0]));
    return zones.map((z) => (unknown.has(z) ? z + " (unbekannt)" : z)).join("\n");
  }

  function ruleColumns(reasonTitle) {
    const cols = [];
    if (MULTI) cols.push({ title: "VDOM", cls: "narrow", cell: (r) => r.p.vdom });
    cols.push(
      { title: "Pos.", cls: "narrow num", cell: (r) => r.p.pos },
      { title: "ID", cls: "narrow num", cell: (r) => r.p.id },
      { title: "Name", cls: "wide", cell: (r) => r.p.name || "" },
      { title: "Status", cls: "narrow", cell: (r) => r.p.status },
      { title: "Action", cls: "narrow", cell: (r) => r.p.action.toUpperCase() },
      { title: "Quellzone", cls: "narrow", cell: (r) => zoneText(r.p.sz, r.p.si) },
      { title: "Zielzone", cls: "narrow", cell: (r) => zoneText(r.p.dz, r.p.di) }
    );
    if (reasonTitle) cols.push({ title: reasonTitle, cls: "wide reason", cell: (r) => lines(r.reasons) });
    cols.push(
      { title: "Quelle", cls: "wide", cell: (r, t) => addressCell(r.p, "src", t) },
      { title: "Ziel", cls: "wide", cell: (r, t) => addressCell(r.p, "dst", t) },
      { title: "Dienst", cls: "wide", cell: (r, t) => serviceCell(r.p, t) },
      { title: "NAT", cell: (r) => r.p.nat },
      { title: "Benutzer und Gruppen", cell: (r) => lines(r.p.users) },
      { title: "Schedule", cls: "narrow", cell: (r) => r.p.sched || "" },
      { title: "Logging", cls: "narrow", cell: (r) => r.p.log || "" },
      { title: "Profile", cell: (r) => lines(r.p.prof) },
      { title: "Kommentar", cls: "wide", cell: (r) => r.p.comment || "" },
      { title: "Hinweise", cls: "wide", cell: (r) => lines(r.p.notes) }
    );
    return cols;
  }

  function ruleClass(r) {
    const p = r.p;
    let cls = !p.en ? "disabled" : p.action === "accept" ? "accept" : p.action === "deny" ? "deny" : "other";
    if (p.implicit) cls += " implicit";
    return cls;
  }

  function ruleTable(container, reasonTitle, emptyText) {
    return new PagedTable(container, ruleColumns(reasonTitle), {
      rowClass: ruleClass,
      rowKey: (r) => policyKey(r.p) + "|" + r.p.id,
      emptyText: emptyText,
    });
  }

  // ---------------------------------------------------------------------------
  // Search: IP/network and port against the resolved values
  // ---------------------------------------------------------------------------

  function parseIPv4(text) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
    if (!m) return null;
    let n = 0n;
    for (let i = 1; i <= 4; i++) {
      const octet = Number(m[i]);
      if (octet > 255) return null;
      n = (n << 8n) + BigInt(octet);
    }
    return n;
  }

  function parseIPv6(text) {
    let s = text.toLowerCase();
    if (!/^[0-9a-f:.]+$/.test(s) || s.indexOf(":") < 0) return null;
    const lastColon = s.lastIndexOf(":");
    if (s.indexOf(".", lastColon) >= 0) {
      // Embedded IPv4 address in the last 32 bits, e.g. ::ffff:192.0.2.1
      const v4 = parseIPv4(s.slice(lastColon + 1));
      if (v4 === null) return null;
      s = s.slice(0, lastColon + 1) + (v4 >> 16n).toString(16) + ":" + (v4 & 0xffffn).toString(16);
    }
    const halves = s.split("::");
    if (halves.length > 2) return null;
    const parse = (part) => (part === "" ? [] : part.split(":"));
    const head = parse(halves[0]);
    const rest = halves.length === 2 ? parse(halves[1]) : [];
    for (const g of head.concat(rest)) if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    let groups = head;
    if (halves.length === 2) {
      const missing = 8 - head.length - rest.length;
      if (missing < 1) return null;
      groups = head.concat(new Array(missing).fill("0"), rest);
    }
    if (groups.length !== 8) return null;
    let n = 0n;
    for (const g of groups) n = (n << 16n) + BigInt(parseInt(g, 16));
    return n;
  }

  function parseQuery(text) {
    const raw = text.trim();
    if (!raw) return null;
    const slash = raw.indexOf("/");
    const addr = slash >= 0 ? raw.slice(0, slash) : raw;
    let version = 4;
    let value = parseIPv4(addr);
    if (value === null) {
      version = 6;
      value = parseIPv6(addr);
    }
    if (value === null) return { error: "Keine gültige IP-Adresse oder kein gültiges Netz: " + raw };
    const bits = version === 4 ? 32 : 128;
    let prefix = bits;
    if (slash >= 0) {
      const p = raw.slice(slash + 1);
      if (!/^\d{1,3}$/.test(p) || Number(p) > bits) return { error: "Ungültige Präfixlänge: " + raw };
      prefix = Number(p);
    }
    const hostBits = BigInt(bits - prefix);
    const size = 1n << hostBits;
    const lo = (value >> hostBits) << hostBits;
    return { version: version, lo: lo, hi: lo + size - 1n, isNet: prefix < bits, text: raw };
  }

  function parsePort(text, proto) {
    const raw = text.trim();
    if (!raw) return null;
    if (!/^\d{1,5}$/.test(raw) || Number(raw) > 65535) return { error: "Ungültiger Port: " + raw };
    return { port: Number(raw), proto: proto };
  }

  const bigIntervals = new Map(); // value index -> [[version, lo, hi]] as BigInt

  function intervalsOf(index) {
    let iv = bigIntervals.get(index);
    if (!iv) {
      iv = VALUES[index][V_IV].map((x) => [x[0], BigInt(x[1]), BigInt(x[2]), x[3] || null]);
      bigIntervals.set(index, iv);
    }
    return iv;
  }

  function uncertainReason(v) {
    if (v[V_DEFAULT]) return "ohne subnet im Backup, Inhalt nur auf dem Gerät: " + v[V_TEXT];
    if (v[V_KIND] === "fqdn") return "FQDN " + v[V_TEXT];
    if (v[V_KIND] === "unresolvable") return (REASONS[v[V_REASON]] || "nicht auflösbar") + ": " + v[V_TEXT];
    return null;
  }

  function vipSide(tag) {
    return tag === "extern" ? "externe Adresse der VIP " : "interne Adresse der VIP ";
  }

  // Returns {state: "sure" | "possible" | "none", reasons: [...]}. For a sure
  // hit, reasons holds notes such as which address of a VIP matched.
  function matchSide(side, q) {
    let sure = false;
    let relevant = false;
    const reasons = [];
    const notes = [];
    for (const index of side.v) {
      const v = VALUES[index];
      if (v[V_VER] !== null && v[V_VER] !== q.version) continue;
      relevant = true;
      const uncertain = uncertainReason(v);
      if (uncertain) {
        reasons.push(uncertain);
        continue;
      }
      for (const iv of intervalsOf(index)) {
        if (iv[0] !== q.version) continue;
        if (iv[1] <= q.lo && q.hi <= iv[2]) {
          sure = true;
          if (iv[3]) notes.push(vipSide(iv[3]) + v[V_TEXT]);
        } else if (iv[1] <= q.hi && q.lo <= iv[2]) {
          reasons.push("Netz überschneidet sich teilweise mit " + (iv[3] ? "der " + vipSide(iv[3]) : "") + v[V_TEXT]);
        }
      }
    }
    if (side.neg) {
      return relevant ? { state: "possible", reasons: ["Negation: alles außer den aufgelösten Werten"] } : { state: "none", reasons: [] };
    }
    if (sure) return { state: "sure", reasons: notes.filter((n, i) => notes.indexOf(n) === i) };
    if (reasons.length) return { state: "possible", reasons: reasons };
    return { state: "none", reasons: [] };
  }

  function matchService(p, q) {
    const svc = p.svc;
    const reasons = [];
    let sure = false;
    if (!svc.o.length && !svc.v.length && (p.src.isdb.length || p.dst.isdb.length)) {
      return { state: "possible", reasons: ["Dienst wird durch den Internet Service bestimmt"] };
    }
    for (const index of svc.v) {
      const s = SVCS[index];
      const kind = s[S_KIND];
      if (kind === "ports") {
        if (q.proto !== "any" && s[S_PROTO] !== q.proto) continue;
        const range = s[S_PORTS];
        if (!range || q.port < range[0] || q.port > range[1]) continue;
        if (s[S_SRCPORT]) reasons.push("nur bestimmte Quellports: " + s[S_TEXT]);
        else sure = true;
      } else if (kind === "ip") {
        const number = s[S_PNUM];
        if (number === 0) sure = true;
        else if (q.proto === "any" ? [6, 17, 132].indexOf(number) >= 0 : PROTOCOL_NUMBERS[q.proto] === number) sure = true;
      } else if (kind === "unresolvable") {
        reasons.push("Dienst nicht auflösbar: " + s[S_TEXT]);
      }
    }
    if (svc.neg) return { state: "possible", reasons: ["Negation: alle Dienste außer den aufgelösten"] };
    if (sure) return { state: "sure", reasons: [] };
    if (reasons.length) return { state: "possible", reasons: reasons };
    return { state: "none", reasons: [] };
  }

  const RANK = { none: 0, possible: 1, sure: 2 };

  function classify(p, ipQuery, side, portQuery) {
    const parts = [];
    if (ipQuery) {
      if (side === "both") {
        const a = matchSide(p.src, ipQuery);
        const b = matchSide(p.dst, ipQuery);
        const best = RANK[a.state] >= RANK[b.state] ? a.state : b.state;
        const reasons = [];
        if (best !== "none") {
          if (a.state === best) for (const r of a.reasons) reasons.push("Quelle: " + r);
          if (b.state === best) for (const r of b.reasons) reasons.push("Ziel: " + r);
        }
        parts.push({ state: best, reasons: reasons });
      } else {
        const m = matchSide(side === "src" ? p.src : p.dst, ipQuery);
        const label = side === "src" ? "Quelle: " : "Ziel: ";
        parts.push({ state: m.state, reasons: m.reasons.map((r) => label + r) });
      }
    }
    if (portQuery) {
      const m = matchService(p, portQuery);
      parts.push({ state: m.state, reasons: m.reasons.map((r) => "Dienst: " + r) });
    }
    let state = "sure";
    const reasons = [];
    for (const part of parts) {
      if (part.state === "none") return { state: "none", reasons: [] };
      if (part.state === "possible") state = "possible";
      for (const r of part.reasons) reasons.push(r);
    }
    if (p.apps.length) {
      // ASSUMPTION(N4): the rule also depends on application control, which only the device evaluates.
      state = "possible";
      reasons.push("Anwendung/Kategorie: " + p.apps.join(", ") + " (nur auf dem Gerät auswertbar)");
    }
    return { state: state, reasons: reasons };
  }

  // ---------------------------------------------------------------------------
  // Rules view: filters, search, cell filter
  // ---------------------------------------------------------------------------

  const zonesByVdom = new Map();
  for (const m of DATA.matrices) {
    const set = new Set(m.rows.concat(m.cols));
    zonesByVdom.set(m.vdom, Array.from(set));
  }

  let cellFilter = null; // {vdom, src, dst, positions: Set}
  const haystacks = new Map();

  function haystack(p) {
    const key = policyKey(p);
    let text = haystacks.get(key);
    if (text === undefined) {
      const parts = [p.id, p.name || "", p.comment || "", p.action, p.status, p.nat, p.sched || "", p.log || ""];
      for (const side of [p.src, p.dst]) {
        parts.push(side.o.join(" "), side.o6.join(" "), side.isdb.join(" "));
        for (const i of side.v) parts.push(VALUES[i][V_TEXT]);
      }
      parts.push(p.svc.o.join(" "), p.apps.join(" "));
      for (const i of p.svc.v) parts.push(SVCS[i][S_TEXT]);
      parts.push(p.sz.join(" "), p.dz.join(" "), p.users.join(" "), p.prof.join(" "), p.notes.join(" "));
      text = parts.join("\n").toLowerCase();
      haystacks.set(key, text);
    }
    return text;
  }

  const rules = {
    built: false,
    list: null, // all filtered rules (no search)
    sure: null, // sure hits, same container as list
    possible: null,
  };

  function fillZoneSelect(select, vdom) {
    const current = select.value;
    clear(select);
    select.appendChild(option("", "alle"));
    let zones = [];
    if (vdom) zones = zonesByVdom.get(vdom) || [];
    else {
      const all = new Set();
      for (const list of zonesByVdom.values()) for (const z of list) all.add(z);
      zones = Array.from(all);
    }
    for (const z of zones) select.appendChild(option(z, z));
    select.value = zones.indexOf(current) >= 0 ? current : "";
  }

  function buildRules() {
    if (rules.built) return;
    rules.built = true;
    const vdomSelect = $("f-vdom");
    vdomSelect.appendChild(option("", "alle"));
    for (const name of DATA.vdoms) vdomSelect.appendChild(option(name, name));
    if (!MULTI) vdomSelect.closest("label").hidden = true;
    fillZoneSelect($("f-srczone"), "");
    fillZoneSelect($("f-dstzone"), "");
    rules.list = ruleTable($("rules-main"), null, "Keine Regel passt zu den Filtern.");
    rules.sure = ruleTable($("rules-main"), "Hinweis zum Treffer", "Keine Regel mit sicherem Treffer.");
    rules.possible = ruleTable($("rules-possible"), "Grund", "Keine Regel mit möglichem Treffer.");
    const refresh = debounce(updateRules, 150);
    vdomSelect.addEventListener("change", () => {
      fillZoneSelect($("f-srczone"), vdomSelect.value);
      fillZoneSelect($("f-dstzone"), vdomSelect.value);
      updateRules();
    });
    for (const id of ["f-srczone", "f-dstzone", "f-action", "f-status", "s-side", "s-proto"]) {
      $(id).addEventListener("change", updateRules);
    }
    for (const id of ["f-text", "s-ip", "s-port"]) $(id).addEventListener("input", refresh);
    for (const id of ["rule-filters", "rule-search"]) {
      $(id).addEventListener("submit", (event) => {
        event.preventDefault();
        updateRules();
      });
    }
    $("s-reset").addEventListener("click", () => {
      $("s-ip").value = "";
      $("s-port").value = "";
      updateRules();
    });
    updateRules();
  }

  function setCellFilter(filter) {
    cellFilter = filter;
    const box = $("cell-filter");
    clear(box);
    if (!filter) return;
    const chip = h("span", "chip");
    append(chip, [
      "Matrix-Zelle: " + (MULTI ? "VDOM " + filter.vdom + ", " : "") + filter.src + " → " + filter.dst + " (" + filter.positions.size + " Regeln)",
    ]);
    const remove = h("button", null, "✕");
    remove.type = "button";
    remove.title = "Zellenfilter entfernen";
    remove.addEventListener("click", () => {
      setCellFilter(null);
      updateRules();
    });
    chip.appendChild(remove);
    box.appendChild(chip);
  }

  function filteredPolicies() {
    const vdom = $("f-vdom").value;
    const srcZone = $("f-srczone").value;
    const dstZone = $("f-dstzone").value;
    const actionFilter = $("f-action").value;
    const status = $("f-status").value;
    const text = $("f-text").value.trim().toLowerCase();
    return POLICIES.filter((p) => {
      if (cellFilter && (p.vdom !== cellFilter.vdom || !cellFilter.positions.has(p.pos))) return false;
      if (vdom && p.vdom !== vdom) return false;
      if (srcZone && p.sz.indexOf(srcZone) < 0) return false;
      if (dstZone && p.dz.indexOf(dstZone) < 0) return false;
      if (actionFilter === "accept" && p.action !== "accept") return false;
      if (actionFilter === "deny" && p.action !== "deny") return false;
      if (actionFilter === "other" && (p.action === "accept" || p.action === "deny")) return false;
      if (status === "enabled" && !p.en) return false;
      if (status === "disabled" && p.en) return false;
      if (text && haystack(p).indexOf(text) < 0) return false;
      return true;
    });
  }

  function updateRules() {
    const error = $("s-error");
    error.textContent = "";
    const ipQuery = parseQuery($("s-ip").value);
    const portQuery = parsePort($("s-port").value, $("s-proto").value);
    const errors = [ipQuery, portQuery].filter((q) => q && q.error).map((q) => q.error);
    const policies = filteredPolicies();
    const searching = (ipQuery && !ipQuery.error) || (portQuery && !portQuery.error);
    if (errors.length) error.textContent = errors.join(" · ");
    if (!searching || errors.length) {
      $("rules-main-title").textContent = "Regeln (" + policies.length + " von " + POLICIES.length + ")";
      $("rules-possible-block").hidden = true;
      rules.sure.rows = [];
      rules.list.setRows(policies.map((p) => ({ p: p, reasons: [] })));
      rules.possible.setRows([]);
      return;
    }
    const sure = [];
    const possible = [];
    const side = $("s-side").value;
    const ip = ipQuery && !ipQuery.error ? ipQuery : null;
    const port = portQuery && !portQuery.error ? portQuery : null;
    for (const p of policies) {
      const result = classify(p, ip, side, port);
      if (result.state === "sure") sure.push({ p: p, reasons: result.reasons });
      else if (result.state === "possible") possible.push({ p: p, reasons: result.reasons });
    }
    $("rules-main-title").textContent = "Sichere Treffer (" + sure.length + ")";
    $("rules-possible-title").textContent = "Möglicherweise (" + possible.length + ")";
    $("rules-possible-block").hidden = false;
    rules.list.rows = [];
    rules.sure.setRows(sure);
    rules.possible.setRows(possible);
  }

  // ---------------------------------------------------------------------------
  // Zone matrix
  // ---------------------------------------------------------------------------

  const matrixState = { built: false, table: null, selected: null };

  function buildMatrix() {
    if (matrixState.built) return;
    matrixState.built = true;
    const select = $("matrix-vdom");
    for (const m of DATA.matrices) select.appendChild(option(m.vdom, m.vdom));
    if (!MULTI) select.closest("label").hidden = true;
    select.addEventListener("change", () => renderMatrix(select.value));
    matrixState.table = ruleTable($("matrix-rules"), null, "Keine Regeln.");
    renderMatrix(select.value);
  }

  function countSpans(cell, target) {
    const accept = cell[2], deny = cell[3], other = cell[4], disabled = cell[5];
    const add = (n, cls, title) => {
      if (!n) return;
      if (target.firstChild) target.appendChild(document.createTextNode(" "));
      const span = h("span", cls, String(n));
      span.title = title;
      target.appendChild(span);
    };
    add(accept, "n-accept", "Accept (aktiv)");
    add(deny, "n-deny", "Deny (aktiv)");
    add(other, "n-other", "sonstige Action (aktiv)");
    if (disabled) {
      if (target.firstChild) target.appendChild(document.createTextNode(" "));
      const span = h("span", "n-disabled", "(" + disabled + ")");
      span.title = "deaktiviert";
      target.appendChild(span);
    }
  }

  function matrixTable(m, interactive) {
    const lookup = new Map();
    for (const c of m.cells) lookup.set(c[0] + "\u0000" + c[1], c);
    const known = new Set(zonesKnown(m.vdom));
    const table = h("table", "matrix");
    const head = h("thead");
    const headRow = h("tr");
    headRow.appendChild(h("th", "corner", "Quelle ↓ / Ziel →"));
    for (const col of m.cols) headRow.appendChild(h("th", known.has(col) ? null : "unknown", col));
    head.appendChild(headRow);
    table.appendChild(head);
    const body = h("tbody");
    for (const row of m.rows) {
      const tr = h("tr");
      tr.appendChild(h("th", known.has(row) ? null : "unknown", row));
      for (const col of m.cols) {
        const cell = lookup.get(row + "\u0000" + col);
        const td = h("td", cell ? "cell" : "blank");
        if (cell) {
          td.dataset.srcZone = row;
          td.dataset.dstZone = col;
          countSpans(cell, td);
          if (interactive) {
            td.tabIndex = 0;
            const open = () => selectCell(m, cell, td);
            td.addEventListener("click", open);
            td.addEventListener("keydown", (event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                open();
              }
            });
          }
        }
        tr.appendChild(td);
      }
      body.appendChild(tr);
    }
    table.appendChild(body);
    return table;
  }

  function zonesKnown(vdom) {
    const zones = DATA.tables.zones.rows.filter((r) => r[0] === vdom).map((r) => r[1]);
    zones.push("any");
    return zones;
  }

  function renderMatrix(vdom) {
    const m = DATA.matrices.find((x) => x.vdom === vdom) || DATA.matrices[0];
    const box = $("matrix");
    clear(box);
    matrixState.selected = null;
    matrixState.table.setRows([]);
    clear($("matrix-rules"));
    if (!m || !m.cells.length) {
      box.appendChild(h("p", "empty", "Keine Regeln in diesem VDOM."));
      return;
    }
    box.appendChild(matrixTable(m, true));
  }

  function selectCell(m, cell, td) {
    if (matrixState.selected) matrixState.selected.classList.remove("selected");
    td.classList.add("selected");
    matrixState.selected = td;
    const positions = new Set(cell[6]);
    const policies = POLICIES.filter((p) => p.vdom === m.vdom && positions.has(p.pos));
    const box = $("matrix-rules");
    matrixState.table.setRows(policies.map((p) => ({ p: p, reasons: [] })));
    const title = h("h3", null, "Regeln der Zelle " + cell[0] + " → " + cell[1] + " (" + policies.length + ")");
    const link = h("button", "more", "In der Regeltabelle öffnen");
    link.type = "button";
    link.addEventListener("click", () => {
      showView("rules");
      $("f-vdom").value = MULTI ? m.vdom : "";
      fillZoneSelect($("f-srczone"), $("f-vdom").value);
      fillZoneSelect($("f-dstzone"), $("f-vdom").value);
      $("f-srczone").value = "";
      $("f-dstzone").value = "";
      setCellFilter({ vdom: m.vdom, src: cell[0], dst: cell[1], positions: positions });
      updateRules();
    });
    const flowLink = h("button", "more", "Als Regel-Fluss zeigen");
    flowLink.type = "button";
    flowLink.addEventListener("click", () => openFlow(m.vdom, cell[0], cell[1]));
    title.appendChild(document.createTextNode(" "));
    title.appendChild(link);
    title.appendChild(document.createTextNode(" · "));
    title.appendChild(flowLink);
    box.insertBefore(title, box.firstChild);
  }

  // ---------------------------------------------------------------------------
  // Generic tables (objects, NAT, interfaces, findings, coverage)
  // ---------------------------------------------------------------------------

  const generic = new Map();

  function genericColumns(headers) {
    return headers.map((title, i) => ({
      title: title,
      cls: title === "Detail" || title === "Aufgelöst" || title === "Hinweise" ? "wide" : null,
      cell: (row) => (row[i] === null || row[i] === undefined ? "" : row[i]),
    }));
  }

  function buildGeneric(container) {
    if (generic.has(container)) return;
    const name = container.dataset.table;
    const source = DATA.tables[name];
    const toolbar = h("form", "toolbar");
    toolbar.autocomplete = "off";
    toolbar.addEventListener("submit", (event) => event.preventDefault());
    const label = h("label", null, "Filter");
    const input = h("input");
    input.type = "search";
    input.placeholder = "Text …";
    label.appendChild(input);
    toolbar.appendChild(label);
    let select = null;
    const filterColumn = container.dataset.filterColumn;
    if (filterColumn !== undefined) {
      const col = Number(filterColumn);
      const selectLabel = h("label", null, source.headers[col]);
      select = h("select");
      select.appendChild(option("", "alle"));
      const values = name === "findings" ? DATA.categories : Array.from(new Set(source.rows.map((r) => r[col])));
      for (const v of values) select.appendChild(option(v, v + (name === "findings" ? " (" + (DATA.counts[v] || 0) + ")" : "")));
      selectLabel.appendChild(select);
      toolbar.appendChild(selectLabel);
    }
    const count = h("span", "hint");
    toolbar.appendChild(count);
    const holder = h("div");
    container.appendChild(toolbar);
    container.appendChild(holder);
    const table = new PagedTable(holder, genericColumns(source.headers), {});
    const lower = source.rows.map((r) => r.map((v) => (v === null ? "" : String(v))).join("\n").toLowerCase());
    const update = () => {
      const text = input.value.trim().toLowerCase();
      const col = select ? Number(filterColumn) : -1;
      const wanted = select ? select.value : "";
      const rows = [];
      for (let i = 0; i < source.rows.length; i++) {
        if (wanted && source.rows[i][col] !== wanted) continue;
        if (text && lower[i].indexOf(text) < 0) continue;
        rows.push(source.rows[i]);
      }
      count.textContent = rows.length + " von " + source.rows.length;
      table.setRows(rows);
    };
    input.addEventListener("input", debounce(update, 150));
    if (select) select.addEventListener("change", update);
    generic.set(container, table);
    update();
  }

  // ---------------------------------------------------------------------------
  // Local-in rules
  // ---------------------------------------------------------------------------

  const ownTables = new Set();

  function buildOwnTable(containerId, policies, emptyText) {
    if (ownTables.has(containerId)) return;
    ownTables.add(containerId);
    const table = ruleTable($(containerId), null, emptyText);
    table.setRows(policies.map((p) => ({ p: p, reasons: [] })));
  }

  // ---------------------------------------------------------------------------
  // Rule flows: source zone | FortiGate | destination zone, one band per rule
  // ---------------------------------------------------------------------------

  // The SVG namespace comes from an inline <svg> of the page, so the script holds no URL.
  const SVG_NS = $("svg-ns").namespaceURI;
  const FLOW = {
    width: 1100,
    srcX: 20,
    boxW: 270,
    fwX: 550,
    dstX: 810,
    head: 96,
    lineH: 15,
    arrowGap: 26,
    pageSize: 20,
    maxObjects: 6,
    maxAddrs: 6,
    maxArrows: 8,
    labelChars: 38,
  };
  const flowState = { built: false, page: 0, rules: [], svg: null };

  function s(tag, attrs, text) {
    const node = document.createElementNS(SVG_NS, tag);
    if (attrs) for (const name of Object.keys(attrs)) node.setAttribute(name, String(attrs[name]));
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function tooltip(node, text) {
    node.appendChild(s("title", null, text));
    return node;
  }

  function cut(text, n) {
    text = String(text);
    return text.length > n ? text.slice(0, n - 1) + "…" : text;
  }

  const PROTO_CLASS = { 6: "tcp", 17: "udp", 132: "sctp", 1: "icmp", 58: "icmp" };

  function protoClass(svc) {
    const kind = svc[S_KIND];
    if (kind === "ports") return (svc[S_PROTO] || "TCP").toLowerCase();
    if (kind === "icmp") return "icmp";
    if (kind === "ip") return PROTO_CLASS[svc[S_PNUM]] || "ip";
    return "ip";
  }

  // Objects of one side, each with its resolved addresses: [{name, addrs: [..], title}]
  function sideObjects(side) {
    const groups = new Map();
    const order = [];
    const add = (name) => {
      if (!groups.has(name)) {
        groups.set(name, []);
        order.push(name);
      }
      return groups.get(name);
    };
    for (const name of side.o) add(name);
    for (const name of side.o6) add(name);
    for (const name of side.isdb) add(name);
    const owners = [];
    for (const [name, count] of side.g) for (let k = 0; k < count; k++) owners.push(name);
    side.v.forEach((i, n) => {
      const v = VALUES[i];
      const owner = owners[n] || v[V_TEXT];
      let text = v[V_TEXT];
      if (v[V_KIND] === "unresolvable") text += " (" + (REASONS[v[V_REASON]] || "nicht auflösbar") + ")";
      else if (v[V_KIND] === "fqdn") text += " (FQDN)";
      else if (v[V_KIND] === "vip") text += " (VIP)";
      else if (v[V_DEFAULT]) text += " (kein subnet im Backup)";
      add(owner).push(text);
    });
    const objects = order.map((name) => ({ name: name, addrs: groups.get(name) }));
    if (side.neg && objects.length) objects[0].name = "NICHT: " + objects[0].name;
    return objects;
  }

  function serviceArrows(p) {
    const arrows = [];
    const owners = [];
    for (const [name, count] of p.svc.g) for (let k = 0; k < count; k++) owners.push(name);
    p.svc.v.forEach((i, n) => {
      const svc = SVCS[i];
      const owner = owners[n];
      const text = svc[S_TEXT].replace("/", " ");
      const label = owner && owner !== svc[S_TEXT] ? owner + " · " + text : text;
      arrows.push({ label: label, cls: protoClass(svc), dashed: svc[S_KIND] === "unresolvable" });
    });
    if (!arrows.length) {
      const isdb = p.src.isdb.length || p.dst.isdb.length;
      arrows.push({ label: isdb ? "Dienste des Internet Service" : "kein Dienst", cls: "ip", dashed: true });
    }
    if (p.svc.neg) for (const a of arrows) a.label = "alle außer " + a.label;
    for (const app of p.apps) arrows.push({ label: app, cls: "ip", dashed: true });
    return arrows;
  }

  // Height of a column of object boxes and a function that draws it.
  function objectColumn(objects, x) {
    const shown = objects.slice(0, FLOW.maxObjects);
    let height = 0;
    const items = shown.map((o) => {
      const addrs = o.addrs.slice(0, FLOW.maxAddrs);
      const extra = o.addrs.length - addrs.length;
      const lines = 1 + addrs.length + (extra > 0 ? 1 : 0);
      const boxH = lines * FLOW.lineH + 10;
      const item = { o: o, addrs: addrs, extra: extra, y: height, h: boxH };
      height += boxH + 6;
      return item;
    });
    const rest = objects.length - shown.length;
    if (rest > 0) height += FLOW.lineH;
    height = Math.max(height - 6, FLOW.lineH + 10);
    return {
      height: height,
      draw(group, top) {
        for (const item of items) {
          const g = s("g", { class: "obj" });
          tooltip(g, item.o.name + (item.o.addrs.length ? "\n" + item.o.addrs.join("\n") : ""));
          g.appendChild(s("rect", { x: x, y: top + item.y, width: FLOW.boxW, height: item.h, rx: 4 }));
          let ty = top + item.y + FLOW.lineH;
          g.appendChild(s("text", { class: "name", x: x + 8, y: ty }, cut(item.o.name, 40)));
          for (const a of item.addrs) {
            ty += FLOW.lineH;
            g.appendChild(s("text", { class: "addr mono", x: x + 8, y: ty }, cut(a, 44)));
          }
          if (item.extra > 0) {
            ty += FLOW.lineH;
            g.appendChild(s("text", { class: "more-addr", x: x + 8, y: ty }, "+ " + item.extra + " weitere"));
          }
          group.appendChild(g);
        }
        if (rest > 0) {
          group.appendChild(s("text", { class: "more-text", x: x + 8, y: top + height - 3 }, "+ " + rest + " weitere Objekte"));
        }
      },
    };
  }

  function drawArrow(group, a, y, verdict, off) {
    const cls = off ? "off" : a.cls;
    const x1 = FLOW.srcX + FLOW.boxW + 6;
    const x2 = FLOW.dstX - 8;
    const g = s("g", { class: "arrow" + (a.dashed ? " dashed" : "") });
    tooltip(g, a.label);
    g.appendChild(s("line", { class: cls, x1: x1, y1: y, x2: x2 - 6, y2: y }));
    g.appendChild(s("polygon", { class: cls, points: x2 + "," + y + " " + (x2 - 10) + "," + (y - 5) + " " + (x2 - 10) + "," + (y + 5) }));
    g.appendChild(s("text", { class: "label " + cls, x: (x1 + FLOW.fwX) / 2, y: y - 5, "text-anchor": "middle" }, cut(a.label, FLOW.labelChars)));
    group.appendChild(g);
    const mark = s("g", { class: "verdict " + verdict });
    mark.appendChild(s("circle", { cx: FLOW.fwX, cy: y, r: 8 }));
    mark.appendChild(s("text", { x: FLOW.fwX, y: y + 4, "text-anchor": "middle" }, verdict === "accept" ? "✓" : verdict === "deny" ? "✕" : "?"));
    group.appendChild(mark);
  }

  function flowBand(p) {
    const left = objectColumn(sideObjects(p.src), FLOW.srcX);
    const right = objectColumn(sideObjects(p.dst), FLOW.dstX);
    const arrows = serviceArrows(p);
    const shownArrows = arrows.slice(0, FLOW.maxArrows);
    const moreArrows = arrows.length - shownArrows.length;
    const arrowsH = shownArrows.length * FLOW.arrowGap + (moreArrows > 0 ? FLOW.lineH : 0);
    const inner = Math.max(left.height, right.height, arrowsH);
    return { p: p, left: left, right: right, arrows: shownArrows, moreArrows: moreArrows, inner: inner, height: inner + 40 };
  }

  function drawBand(svg, band, top) {
    const p = band.p;
    const off = !p.en;
    const verdict = off ? "off" : p.action === "accept" ? "accept" : p.action === "deny" ? "deny" : "other";
    const g = s("g", { class: "rule", "data-pos": p.pos });
    g.appendChild(s("rect", { class: "band" + (off ? " disabled" : ""), x: 8, y: top, width: FLOW.width - 16, height: band.height - 8, rx: 3 }));
    let title = "Regel ID " + p.id + " (Position " + p.pos + ")";
    if (p.name) title += " · " + p.name;
    title += " · " + p.action.toUpperCase() + (off ? " · deaktiviert" : "");
    g.appendChild(s("text", { class: "band-title" + (off ? " disabled" : ""), x: 16, y: top + 16 }, cut(title, 120)));
    const bodyTop = top + 26;
    band.left.draw(g, bodyTop + (band.inner - band.left.height) / 2);
    band.right.draw(g, bodyTop + (band.inner - band.right.height) / 2);
    const arrowsH = band.arrows.length * FLOW.arrowGap;
    let y = bodyTop + (band.inner - arrowsH) / 2 + FLOW.arrowGap / 2 + 4;
    for (const a of band.arrows) {
      drawArrow(g, a, y, verdict, off);
      y += FLOW.arrowGap;
    }
    if (band.moreArrows > 0) {
      g.appendChild(s("text", { class: "more-text", x: FLOW.fwX + 20, y: y - 6 }, "+ " + band.moreArrows + " weitere Dienste"));
    }
    svg.appendChild(g);
  }

  function zoneLines(vdom, zone) {
    return (DATA.zoneInfo[vdom] || {})[zone] || (zone === "any" ? ["alle Interfaces"] : []);
  }

  function laneHead(svg, x, anchor, label, zone, vdom) {
    svg.appendChild(s("text", { class: "lane-head", x: x, y: 18, "text-anchor": anchor }, label + ": " + cut(zone, 40)));
    const info = zoneLines(vdom, zone);
    info.slice(0, 4).forEach((line, i) => {
      svg.appendChild(s("text", { class: "lane-sub mono", x: x, y: 34 + i * 13, "text-anchor": anchor }, cut(line, 44)));
    });
    if (info.length > 4) svg.appendChild(s("text", { class: "lane-sub", x: x, y: 34 + 4 * 13, "text-anchor": anchor }, "+ " + (info.length - 4) + " weitere Interfaces"));
  }

  function firewallIcon(svg) {
    const w = 36, hgt = 24, x = FLOW.fwX - w / 2, y = 8;
    const g = s("g", { class: "fw" });
    tooltip(g, "FortiGate");
    for (let row = 0; row < 3; row++) {
      const shift = row % 2 ? 6 : 0;
      for (let col = -1; col < 3; col++) {
        const bx = Math.max(x, x + shift + col * 12);
        const bw = Math.min(x + w, x + shift + col * 12 + 12) - bx;
        if (bw > 1) g.appendChild(s("rect", { class: "fw-brick", x: bx, y: y + row * 8, width: bw, height: 8 }));
      }
    }
    svg.appendChild(g);
    svg.appendChild(s("text", { class: "lane-sub", x: FLOW.fwX, y: y + hgt + 14, "text-anchor": "middle" }, "FortiGate"));
  }

  function renderFlow(vdom, src, dst, policies) {
    const bands = policies.map(flowBand);
    const infoLines = Math.max(zoneLines(vdom, src).length, zoneLines(vdom, dst).length);
    const head = Math.max(FLOW.head, 34 + Math.min(infoLines, 5) * 13 + 22);
    let height = head;
    for (const b of bands) height += b.height;
    height += 10;
    const svg = s("svg", {
      class: "diagram flow",
      viewBox: "0 0 " + FLOW.width + " " + height,
      width: FLOW.width,
      height: height,
      role: "img",
      "aria-label": "Regel-Flüsse " + src + " nach " + dst,
    });
    laneHead(svg, FLOW.srcX, "start", "Quellzone", src, vdom);
    laneHead(svg, FLOW.dstX + FLOW.boxW, "end", "Zielzone", dst, vdom);
    firewallIcon(svg);
    svg.appendChild(s("line", { class: "lane-line", x1: 0, y1: head - 14, x2: FLOW.width, y2: head - 14 }));
    svg.appendChild(s("line", { class: "fw-line", x1: FLOW.fwX, y1: 56, x2: FLOW.fwX, y2: height }));
    let top = head - 4;
    for (const b of bands) {
      drawBand(svg, b, top);
      top += b.height;
    }
    return svg;
  }

  function flowMatrix(vdom) {
    return DATA.matrices.find((m) => m.vdom === vdom);
  }

  function fillFlowZones() {
    const m = flowMatrix($("fl-vdom").value);
    const srcSel = $("fl-src");
    const current = srcSel.value;
    clear(srcSel);
    const sources = m ? m.rows.filter((z) => m.cells.some((c) => c[0] === z)) : [];
    for (const z of sources) srcSel.appendChild(option(z, z));
    if (sources.indexOf(current) >= 0) srcSel.value = current;
    fillFlowTargets();
  }

  function fillFlowTargets() {
    const m = flowMatrix($("fl-vdom").value);
    const dstSel = $("fl-dst");
    const current = dstSel.value;
    clear(dstSel);
    const srcZone = $("fl-src").value;
    const targets = m ? m.cols.filter((z) => m.cells.some((c) => c[0] === srcZone && c[1] === z)) : [];
    for (const z of targets) dstSel.appendChild(option(z, z));
    if (targets.indexOf(current) >= 0) dstSel.value = current;
    fillFlowRules();
  }

  function fillFlowRules() {
    const m = flowMatrix($("fl-vdom").value);
    const srcZone = $("fl-src").value;
    const dstZone = $("fl-dst").value;
    const cell = m ? m.cells.find((c) => c[0] === srcZone && c[1] === dstZone) : null;
    const positions = new Set(cell ? cell[6] : []);
    flowState.rules = POLICIES.filter((p) => m && p.vdom === m.vdom && positions.has(p.pos));
    const ruleSel = $("fl-rule");
    clear(ruleSel);
    ruleSel.appendChild(option("", "alle (" + flowState.rules.length + ")"));
    for (const p of flowState.rules) ruleSel.appendChild(option(String(p.pos), "ID " + p.id + (p.name ? " · " + cut(p.name, 30) : "")));
    flowState.page = 0;
    updateFlow();
  }

  function updateFlow() {
    const box = $("flow");
    clear(box);
    flowState.svg = null;
    const vdom = $("fl-vdom").value;
    const srcZone = $("fl-src").value;
    const dstZone = $("fl-dst").value;
    const pos = $("fl-rule").value;
    let rules = flowState.rules;
    if (pos) rules = rules.filter((p) => String(p.pos) === pos);
    if (!rules.length) {
      box.appendChild(h("p", "empty", "Keine Regeln für diese Auswahl."));
      return;
    }
    const pages = Math.max(1, Math.ceil(rules.length / FLOW.pageSize));
    flowState.page = Math.min(flowState.page, pages - 1);
    const start = flowState.page * FLOW.pageSize;
    const shown = rules.slice(start, start + FLOW.pageSize);
    if (pages > 1) {
      const bar = h("div", "pager");
      const nav = (label, page, disabled, cls) => {
        const b = h("button", cls, label);
        b.type = "button";
        b.disabled = disabled;
        b.addEventListener("click", () => {
          flowState.page = page;
          updateFlow();
        });
        return b;
      };
      append(bar, [
        nav("‹ Zurück", flowState.page - 1, flowState.page === 0, "prev"),
        h("span", "page-info", "Regeln " + (start + 1) + "–" + (start + shown.length) + " von " + rules.length),
        nav("Weiter ›", flowState.page + 1, flowState.page >= pages - 1, "next"),
      ]);
      box.appendChild(bar);
    }
    const wrap = h("div", "scroll");
    flowState.svg = renderFlow(vdom, srcZone, dstZone, shown);
    wrap.appendChild(flowState.svg);
    box.appendChild(wrap);
  }

  function buildFlows() {
    if (flowState.built) return;
    flowState.built = true;
    const vdomSel = $("fl-vdom");
    for (const m of DATA.matrices) vdomSel.appendChild(option(m.vdom, m.vdom));
    if (!MULTI) vdomSel.closest("label").hidden = true;
    vdomSel.addEventListener("change", fillFlowZones);
    $("fl-src").addEventListener("change", fillFlowTargets);
    $("fl-dst").addEventListener("change", fillFlowRules);
    $("fl-rule").addEventListener("change", () => {
      flowState.page = 0;
      updateFlow();
    });
    $("flow-filters").addEventListener("submit", (event) => event.preventDefault());
    fillFlowZones();
  }

  function openFlow(vdom, src, dst) {
    showView("flows");
    $("fl-vdom").value = vdom;
    fillFlowZones();
    $("fl-src").value = src;
    fillFlowTargets();
    $("fl-dst").value = dst;
    fillFlowRules();
  }

  // ---------------------------------------------------------------------------
  // Views
  // ---------------------------------------------------------------------------

  function showView(name) {
    for (const button of document.querySelectorAll(".tabs button")) {
      button.setAttribute("aria-selected", button.dataset.view === name ? "true" : "false");
    }
    for (const section of document.querySelectorAll("main > .view")) {
      section.hidden = section.id !== "view-" + name;
    }
    if (name === "rules") buildRules();
    if (name === "matrix") buildMatrix();
    if (name === "flows") buildFlows();
    if (name === "localin") buildOwnTable("localin-rules", LOCAL_IN, "Das Backup enthält keine Local-In-Regeln.");
    if (name === "inspection") buildOwnTable("inspection-rules", INSPECTION, "Keine SSL-Inspection-Regeln.");
    const section = $("view-" + name);
    if (section) for (const container of section.querySelectorAll(".generic")) buildGeneric(container);
  }

  for (const button of document.querySelectorAll(".tabs button")) {
    button.addEventListener("click", () => showView(button.dataset.view));
  }

  // ---------------------------------------------------------------------------
  // Print: the complete document, independent of filters and pages
  // ---------------------------------------------------------------------------

  function printSection(area, title, content) {
    const section = h("section", "pr-section");
    section.appendChild(h("h2", null, title));
    for (const node of content) section.appendChild(node);
    area.appendChild(section);
  }

  function fullTable(columns, rows, rowClass) {
    const holder = h("div");
    const table = new PagedTable(holder, columns, { rowClass: rowClass });
    table.all = true;
    table.setRows(rows);
    return holder;
  }

  function buildPrint() {
    const area = $("print-area");
    clear(area);
    for (const m of DATA.matrices) {
      printSection(area, "Zonen-Matrix" + (MULTI ? " – VDOM " + m.vdom : ""), [
        h("p", "hint", "Zeilen: Quellzonen, Spalten: Zielzonen. Grün Accept, rot Deny, grau in Klammern deaktivierte Regeln."),
        m.cells.length ? matrixTable(m, false) : h("p", "empty", "Keine Regeln."),
      ]);
    }
    printSection(area, "Regeln", [
      fullTable(ruleColumns(null), POLICIES.map((p) => ({ p: p, reasons: [] })), ruleClass),
    ]);
    if (LOCAL_IN.length) {
      printSection(area, "Local-In-Regeln", [
        h("p", "hint", "Verkehr zur FortiGate selbst; eigene Tabelle mit eigener Reihenfolge."),
        fullTable(ruleColumns(null), LOCAL_IN.map((p) => ({ p: p, reasons: [] })), ruleClass),
      ]);
    }
    if (INSPECTION.length) {
      printSection(area, "SSL-Inspection- und Authentifizierungsregeln", [
        h("p", "hint", "NGFW-Modus richtlinienbasiert: firewall policy steuert SSL-Inspection und Authentifizierung; eigene Tabelle."),
        fullTable(ruleColumns(null), INSPECTION.map((p) => ({ p: p, reasons: [] })), ruleClass),
      ]);
    }
    if (flowState.svg) {
      printSection(area, "Regel-Flüsse: " + $("fl-src").value + " → " + $("fl-dst").value, [flowState.svg.cloneNode(true)]);
    }
    const tables = [
      ["Adressen", "addresses"],
      ["Dienste", "services"],
      ["Interfaces", "interfaces"],
      ["Zonen", "zones"],
      ["NAT", "nat"],
      ["Auffälligkeiten", "findings"],
      ["Nicht verarbeitet", "coverage"],
    ];
    for (const [title, name] of tables) {
      const source = DATA.tables[name];
      printSection(area, title, [fullTable(genericColumns(source.headers), source.rows, null)]);
    }
  }

  window.addEventListener("beforeprint", buildPrint);
  window.addEventListener("afterprint", () => clear($("print-area")));
  $("print-button").addEventListener("click", () => window.print());

  showView("overview");
  document.body.setAttribute("data-ready", "1");
})();
