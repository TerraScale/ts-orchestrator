// TerraScale orchestrator dashboard elements. No build step: this file is
// served as-is from the binary. Datastar owns every update: the server
// patches element attributes (data-spec, datetime, data-values) and these
// elements only render what the attributes say. Rendering happens inside a
// shadow root so a Datastar morph of the light DOM never removes a chart.
//
// Elements: <ts-time>, <ts-sparkline>, <ts-chart>, <ts-timeline>,
// <ts-topology>, <ts-map>, <ts-palette>. Plus toasts, the attention badge
// bump, opt-in browser notifications and copy buttons.

const root = document.documentElement;

function css(name) {
  return getComputedStyle(root).getPropertyValue(name).trim();
}

function theme() {
  const series = css("--ts-series").split(/\s+/).filter(Boolean);
  return {
    ink: css("--ts-ink"), ink2: css("--ts-ink-2"), ink3: css("--ts-ink-3"),
    hairline: css("--ts-hairline"), axis: css("--ts-axis"), surface: css("--ts-surface"),
    series: series.length ? series : ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"],
    seq: css("--ts-seq").split(/\s+/).filter(Boolean),
    status: {
      ok: css("--ts-ok"), warn: css("--ts-warn"), serious: css("--ts-serious"), bad: css("--ts-bad"),
      info: css("--ts-info"), run: css("--ts-run"), idle: css("--ts-idle"),
    },
  };
}

// ---- formatting ----

const units = {
  percent: (v) => (v * 100).toFixed(v < 0.1 ? 1 : 0) + "%",
  bytes: (v) => bytes(v),
  bytes_rate: (v) => bytes(v) + "/s",
  rate: (v) => compact(v) + "/s",
  seconds: (v) => duration(v),
  count: (v) => compact(v),
  score: (v) => Math.round(v).toString(),
};

function compact(v) {
  const a = Math.abs(v);
  if (a >= 1e9) return (v / 1e9).toFixed(1) + "G";
  if (a >= 1e6) return (v / 1e6).toFixed(1) + "M";
  if (a >= 1e3) return (v / 1e3).toFixed(1) + "k";
  if (a >= 10 || v === 0) return Math.round(v).toString();
  return v.toFixed(a < 1 ? 3 : 2);
}

function bytes(v) {
  const names = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let i = 0;
  while (Math.abs(v) >= 1024 && i < names.length - 1) { v /= 1024; i++; }
  return (i === 0 ? Math.round(v) : v.toFixed(1)) + " " + names[i];
}

function duration(seconds) {
  if (seconds < 1) return Math.round(seconds * 1000) + "ms";
  if (seconds < 60) return seconds.toFixed(1) + "s";
  if (seconds < 3600) return Math.round(seconds / 60) + "m";
  if (seconds < 172800) return Math.floor(seconds / 3600) + "h" + Math.round((seconds % 3600) / 60) + "m";
  return Math.round(seconds / 86400) + "d";
}

function fmt(unit) { return units[unit] || compact; }

function relative(date, now = Date.now()) {
  const seconds = Math.round((now - date.getTime()) / 1000);
  const future = seconds < 0;
  const s = Math.abs(seconds);
  let text;
  if (s < 45) text = s + "s";
  else if (s < 3600) text = Math.round(s / 60) + "m";
  else if (s < 86400) text = Math.floor(s / 3600) + "h " + Math.round((s % 3600) / 60) + "m";
  else text = Math.round(s / 86400) + "d";
  return future ? "in " + text : text + " ago";
}

function absolute(date) {
  return date.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

// ---- <ts-time datetime="RFC 3339">: relative text, absolute on hover ----

const clocks = new Set();
setInterval(() => clocks.forEach((element) => element.render()), 15000);

class TsTime extends HTMLElement {
  static observedAttributes = ["datetime"];
  connectedCallback() {
    if (!this.shadowRoot) this.attachShadow({ mode: "open" });
    clocks.add(this);
    this.render();
  }
  disconnectedCallback() { clocks.delete(this); }
  attributeChangedCallback() { if (this.shadowRoot) this.render(); }
  render() {
    const date = new Date(this.getAttribute("datetime"));
    if (isNaN(date)) { this.shadowRoot.textContent = this.textContent; return; }
    this.shadowRoot.textContent = relative(date);
    this.title = absolute(date) + " (" + date.toLocaleString() + " local)";
  }
}
customElements.define("ts-time", TsTime);

// ---- <ts-sparkline data-values="1,2,3" data-status="ok"> ----

class TsSparkline extends HTMLElement {
  static observedAttributes = ["data-values", "data-status"];
  connectedCallback() {
    if (!this.shadowRoot) this.attachShadow({ mode: "open" });
    this.render();
  }
  attributeChangedCallback() { if (this.shadowRoot) this.render(); }
  render() {
    const values = (this.dataset.values || "").split(",").map(Number).filter((v) => !isNaN(v));
    if (values.length < 2) { this.shadowRoot.innerHTML = ""; return; }
    const status = this.dataset.status;
    const color = status ? theme().status[status] : "currentColor";
    const lo = Math.min(...values), hi = Math.max(...values);
    const span = hi - lo || 1;
    const w = 100, h = 28;
    const pts = values.map((v, i) => [(i / (values.length - 1)) * w, h - 2 - ((v - lo) / span) * (h - 4)]);
    const line = pts.map((p) => p[0].toFixed(1) + "," + p[1].toFixed(1)).join(" ");
    const area = "0," + h + " " + line + " " + w + "," + h;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
    svg.setAttribute("preserveAspectRatio", "none");
    svg.setAttribute("width", "100%");
    svg.setAttribute("height", "100%");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "trend " + values[0] + " to " + values[values.length - 1]);
    const fill = document.createElementNS(svg.namespaceURI, "polygon");
    fill.setAttribute("points", area);
    fill.setAttribute("fill", color);
    fill.setAttribute("fill-opacity", "0.12");
    const stroke = document.createElementNS(svg.namespaceURI, "polyline");
    stroke.setAttribute("points", line);
    stroke.setAttribute("fill", "none");
    stroke.setAttribute("stroke", color);
    stroke.setAttribute("stroke-width", "1.6");
    stroke.setAttribute("vector-effect", "non-scaling-stroke");
    svg.append(fill, stroke);
    this.shadowRoot.replaceChildren(svg);
  }
}
customElements.define("ts-sparkline", TsSparkline);

// ---- ECharts base element ----

const charts = new Set();
function rerenderAll() { charts.forEach((element) => element.render(true)); }
new MutationObserver(rerenderAll).observe(root, { attributes: true, attributeFilter: ["data-theme"] });
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", rerenderAll);

class EChartElement extends HTMLElement {
  static observedAttributes = ["data-spec"];
  connectedCallback() {
    if (!this.shadowRoot) {
      const shadow = this.attachShadow({ mode: "open" });
      this.box = document.createElement("div");
      this.box.style.width = "100%";
      this.box.style.height = "100%";
      this.empty = document.createElement("div");
      this.empty.part = "empty";
      this.empty.style.cssText = "position:absolute;inset:0;display:none;align-items:center;justify-content:center;" +
        "border:1px dashed var(--ts-axis);border-radius:.5rem;color:var(--ts-ink-2);font-size:.88rem;padding:1rem;text-align:center";
      shadow.append(this.box, this.empty);
    }
    charts.add(this);
    this.resizer = new ResizeObserver(() => this.chart && this.chart.resize());
    this.resizer.observe(this);
    this.render(true);
  }
  disconnectedCallback() {
    charts.delete(this);
    if (this.resizer) this.resizer.disconnect();
    if (this.chart) { this.chart.dispose(); this.chart = null; }
  }
  attributeChangedCallback() { if (this.shadowRoot) this.render(false); }
  spec() {
    try { return JSON.parse(this.dataset.spec || "{}"); } catch { return { empty: "chart data unreadable" }; }
  }
  async render(fresh) {
    if (!window.echarts) return;
    const spec = this.spec();
    const t = theme();
    if (spec.empty) {
      this.empty.textContent = spec.empty;
      this.empty.style.display = "flex";
      this.box.style.visibility = "hidden";
      return;
    }
    this.empty.style.display = "none";
    this.box.style.visibility = "visible";
    if (!this.chart) {
      this.chart = echarts.init(this.box, null, { renderer: "canvas" });
      this.chart.on("click", (event) => this.clicked(event));
    }
    // option() may await (the map's GeoJSON): the element can be detached,
    // its chart disposed or replaced, or a newer render started meanwhile.
    const chart = this.chart;
    const generation = (this.generation = (this.generation || 0) + 1);
    const option = await this.option(spec, t);
    if (!option || !this.isConnected || this.chart !== chart || this.generation !== generation) return;
    option.animationDuration = fresh ? 300 : 0;
    option.animationDurationUpdate = 250;
    chart.setOption(option, { notMerge: fresh, replaceMerge: ["series", "xAxis", "yAxis", "visualMap"] });
  }
  clicked(event) {
    const data = event.data || {};
    if (data.href) { location.href = data.href; return; }
    const spec = this.spec();
    if (spec.click && Array.isArray(event.value) && typeof event.value[0] === "number") {
      location.href = spec.click + encodeURIComponent(new Date(event.value[0]).toISOString().replace(/\.\d+Z$/, "Z"));
    }
  }
}

function baseText(t) {
  return { color: t.ink2, fontFamily: getComputedStyle(document.body).fontFamily, fontSize: 11 };
}

function tooltip(t, extra = {}) {
  return Object.assign({
    backgroundColor: t.surface, borderColor: t.hairline, textStyle: { color: t.ink, fontSize: 12 },
    confine: true, extraCssText: "box-shadow:0 6px 18px rgba(0,0,0,.18);border-radius:8px",
  }, extra);
}

function timeAxis(spec, t) {
  return {
    type: "time", min: spec.start || null, max: spec.end || null,
    axisLine: { lineStyle: { color: t.axis } }, axisTick: { show: false },
    axisLabel: { color: t.ink3, hideOverlap: true }, splitLine: { show: false },
  };
}

function valueAxis(spec, t) {
  return {
    type: "value", min: spec.min ?? null, max: spec.max ?? null, splitNumber: 3,
    minInterval: spec.unit === "count" ? 1 : undefined,
    axisLabel: { color: t.ink3, formatter: (v) => fmt(spec.unit)(v) },
    splitLine: { lineStyle: { color: t.hairline } },
  };
}

function seriesColor(t, s, index) {
  return s.status ? t.status[s.status] : t.series[index % t.series.length];
}

function thresholdLines(spec, t) {
  if (!spec.thresholds || !spec.thresholds.length) return undefined;
  return {
    silent: true, symbol: "none",
    label: { color: t.ink2, formatter: (p) => p.name, position: "insideEndTop", fontSize: 10 },
    data: spec.thresholds.map((th) => ({
      yAxis: th.value, name: th.label,
      lineStyle: { color: th.status ? t.status[th.status] : t.ink3, type: "dashed", width: 1 },
    })),
  };
}

EChartElement.prototype.option = async function (spec, t) {
  const f = fmt(spec.unit);
  const many = (spec.series || []).length > 1;
  switch (spec.kind) {
    case "line": case "area": case "stacked": {
      return {
        textStyle: baseText(t),
        grid: { left: 8, right: 12, top: many ? 30 : 12, bottom: 4, containLabel: true },
        legend: many ? { top: 0, type: "scroll", textStyle: { color: t.ink2, lineHeight: 14 }, icon: "roundRect", itemWidth: 12, itemHeight: 8,
          pageIconSize: 10, pageIconColor: t.ink2, pageIconInactiveColor: t.axis, pageTextStyle: { color: t.ink3 } } : undefined,
        tooltip: tooltip(t, { trigger: "axis", valueFormatter: f, axisPointer: { type: "line", lineStyle: { color: t.axis } } }),
        xAxis: timeAxis(spec, t), yAxis: valueAxis(spec, t),
        series: (spec.series || []).map((s, i) => ({
          name: s.name, type: "line", data: s.points, showSymbol: false, symbolSize: 8, smooth: 0.15,
          stack: spec.kind === "stacked" ? "all" : undefined,
          lineStyle: { width: 2, type: s.dashed ? "dashed" : "solid" },
          areaStyle: spec.kind === "line" || s.dashed ? undefined : { opacity: spec.kind === "stacked" ? 0.55 : 0.12 },
          color: seriesColor(t, s, i), emphasis: { focus: "series" },
          markLine: i === 0 ? thresholdLines(spec, t) : undefined,
        })),
      };
    }
    case "bar": case "hbar": {
      const horizontal = spec.kind === "hbar";
      const cat = { type: "category", data: spec.categories, axisLabel: { color: t.ink2, hideOverlap: true },
        axisLine: { lineStyle: { color: t.axis } }, axisTick: { show: false } };
      const val = valueAxis(spec, t);
      const bars = spec.bars || [];
      return {
        textStyle: baseText(t),
        grid: { left: 8, right: 16, top: bars.length > 1 ? 30 : 10, bottom: 4, containLabel: true },
        legend: bars.length > 1 ? { top: 0, textStyle: { color: t.ink2 }, itemWidth: 10, itemHeight: 10 } : undefined,
        tooltip: tooltip(t, { trigger: "axis", valueFormatter: f, axisPointer: { type: "shadow" } }),
        xAxis: horizontal ? val : cat, yAxis: horizontal ? cat : val,
        series: bars.map((b, i) => ({
          name: b.name, type: "bar", data: b.values, stack: "all", barMaxWidth: 26,
          itemStyle: { color: seriesColor(t, b, i), borderRadius: horizontal ? [0, 4, 4, 0] : [4, 4, 0, 0], borderColor: t.surface, borderWidth: 1 },
          markLine: i === 0 ? thresholdLines(spec, t) : undefined,
        })),
      };
    }
    case "heatmap": {
      const values = (spec.heat || []).map((c) => c[2]);
      const hi = spec.max ?? Math.max(...values, 0);
      const step = spec.step || Math.max(10000, ((spec.end - spec.start) / 90) | 0);
      return {
        textStyle: baseText(t),
        grid: { left: 8, right: 12, top: 8, bottom: 36, containLabel: true },
        tooltip: tooltip(t, { formatter: (p) => `${escapeHTML(spec.categories[p.value[1]])}<br>${absolute(new Date(p.value[0]))}<br><b>${f(p.value[2])}</b>` }),
        xAxis: timeAxis(spec, t),
        yAxis: { type: "category", data: spec.categories, axisLabel: { color: t.ink2 }, axisLine: { show: false }, axisTick: { show: false } },
        visualMap: { min: spec.min ?? 0, max: hi || 1, orient: "horizontal", left: "center", bottom: 0, itemHeight: 120, itemWidth: 10,
          calculable: false, inRange: { color: t.seq }, textStyle: { color: t.ink3 }, formatter: (v) => f(v) },
        series: [{ type: "custom", data: spec.heat, encode: { x: 0, y: 1 },
          renderItem: (params, api) => {
            const start = api.coord([api.value(0), api.value(1)]);
            const end = api.coord([api.value(0) + step, api.value(1)]);
            const height = api.size([0, 1])[1];
            return { type: "rect", shape: { x: start[0], y: start[1] - height / 2 + 1, width: Math.max(1, end[0] - start[0]), height: height - 2 },
              style: { fill: api.visual("color") } };
          } }],
      };
    }
    case "gauge": {
      const color = spec.series && spec.series[0] && spec.series[0].status ? t.status[spec.series[0].status] : t.status.info;
      return {
        series: [{
          type: "gauge", startAngle: 210, endAngle: -30, min: spec.min ?? 0, max: spec.max ?? 100, radius: "95%", center: ["50%", "58%"],
          progress: { show: true, width: 10, roundCap: true, itemStyle: { color } },
          axisLine: { roundCap: true, lineStyle: { width: 10, color: [[1, t.hairline]] } },
          axisTick: { show: false }, splitLine: { show: false }, axisLabel: { show: false }, pointer: { show: false }, anchor: { show: false },
          title: { offsetCenter: [0, "45%"], color: t.ink3, fontSize: 11 },
          detail: { offsetCenter: [0, "0%"], color: t.ink, fontSize: 20, fontWeight: 700, formatter: (v) => f(v) },
          data: [{ value: spec.value, name: spec.label || "" }],
        }],
      };
    }
    case "treemap": {
      const color = (node) => node.status ? t.status[node.status] : undefined;
      const map = (node) => ({ name: node.name, value: node.value, href: node.href,
        itemStyle: color(node) ? { color: color(node) } : undefined,
        children: node.children ? node.children.map(map) : undefined });
      return {
        tooltip: tooltip(t, { formatter: (p) => `${escapeHTML(p.treePathInfo.map((x) => x.name).filter(Boolean).join(" / "))}<br><b>${f(p.value)}</b>` }),
        series: [{
          type: "treemap", data: (spec.tree || []).map(map), roam: false, nodeClick: false, breadcrumb: { show: false },
          width: "100%", height: "100%", top: 0, left: 0, color: t.series,
          label: { color: "#fff", fontSize: 11, lineHeight: 15, overflow: "truncate", formatter: (p) => `${p.name}\n${f(p.value)}` },
          upperLabel: { show: true, height: 20, color: t.ink, fontSize: 11, backgroundColor: "transparent", overflow: "truncate",
            formatter: (p) => `${p.name || "total"} · ${f(p.value)}` },
          itemStyle: { borderColor: t.surface, borderWidth: 2, gapWidth: 2 },
          levels: [{ itemStyle: { borderColor: t.hairline, borderWidth: 2, gapWidth: 3 } }, { colorSaturation: [0.35, 0.6] }],
        }],
      };
    }
    case "timeline": return timelineOption(spec, t);
    default: return null;
  }
};

function timelineOption(spec, t) {
  const lanes = spec.lanes || [];
  const data = (spec.items || []).map((item) => ({
    value: [item.t, lanes.indexOf(item.lane)], name: item.label, detail: item.detail, href: item.href,
    itemStyle: { color: t.status[item.status] || t.status.info, borderColor: t.surface, borderWidth: 2 },
  }));
  return {
    textStyle: baseText(t),
    grid: { left: 8, right: 16, top: 10, bottom: 4, containLabel: true },
    tooltip: tooltip(t, { trigger: "item", formatter: (p) => `<b>${escapeHTML(p.data.name)}</b><br>${escapeHTML(p.data.detail || "")}<br><span style="opacity:.7">${absolute(new Date(p.value[0]))}</span>` }),
    xAxis: timeAxis(spec, t),
    yAxis: { type: "category", data: lanes, inverse: true, axisLabel: { color: t.ink2, fontWeight: 600 },
      axisLine: { show: false }, axisTick: { show: false }, splitLine: { show: true, lineStyle: { color: t.hairline } } },
    dataZoom: [{ type: "inside", filterMode: "weakFilter" }],
    series: [{ type: "scatter", data, symbolSize: 13, cursor: "pointer", emphasis: { scale: 1.4 } }],
  };
}

function escapeHTML(text) {
  return String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

customElements.define("ts-chart", class extends EChartElement {});
customElements.define("ts-timeline", class extends EChartElement {});

// ---- <ts-topology data-spec='{"nodes":[...],"links":[...]}'> ----
//
// Regions are drawn as labeled groups: the region node in the middle, its
// controllers on an inner ring (with the NATS route mesh), its hosts on an
// outer ring and each host's TerraBase seats fanned outwards. The layout is
// computed here, not by a force simulation, so the graph is always fit to
// the element, centered, and stable across live updates. The toolbar
// collapses and expands regions, filters node kinds and refits the view;
// clicking a node opens a details panel docked on the right (an overlay on
// narrow screens).

const kindSize = { region: 44, controller: 24, host: 18, seat: 8 };
const kindShape = { region: "circle", controller: "roundRect", host: "rect", seat: "circle" };
const kindOrder = ["region", "controller", "host", "seat"];
const kindIcon = {
  region: '<circle cx="6" cy="6" r="5"/>', controller: '<rect x="1" y="1" width="10" height="10" rx="3"/>',
  host: '<rect x="1.5" y="1.5" width="9" height="9"/>', seat: '<circle cx="6" cy="6" r="3"/>',
};

const topologyCSS = `
:host { --gap: .4rem; }
.bar { position: absolute; top: 0; left: 0; right: 0; display: flex; flex-wrap: wrap; gap: var(--gap); align-items: center;
  font: 12px/1.2 system-ui, sans-serif; color: var(--ts-ink-2); z-index: 2; pointer-events: none; }
.bar > * { pointer-events: auto; }
.group { display: inline-flex; flex-wrap: wrap; gap: 2px; padding: 2px; border: 1px solid var(--ts-hairline); border-radius: .45rem;
  background: var(--ts-surface); }
@media (max-width: 640px) { .bar { font-size: 11px; --gap: .25rem; } button { padding: .18rem .35rem; } }
button { all: unset; box-sizing: border-box; cursor: pointer; display: inline-flex; align-items: center; gap: .35rem;
  padding: .22rem .5rem; border-radius: .32rem; color: var(--ts-ink-2); white-space: nowrap; }
button:hover { background: var(--ts-hairline); color: var(--ts-ink); }
button:focus-visible { outline: 2px solid var(--ts-info); outline-offset: 1px; }
button[aria-pressed="false"] { opacity: .45; text-decoration: line-through; }
button.region[aria-expanded="true"] { color: var(--ts-ink); font-weight: 600; }
button svg { width: 11px; height: 11px; fill: currentColor; flex: none; }
.dot { width: .55rem; height: .55rem; border-radius: 50%; flex: none; }
.count { color: var(--ts-ink-3); font-variant-numeric: tabular-nums; }
.chev { color: var(--ts-ink-3); font-size: 10px; }
.panel { position: absolute; display: none; overflow: auto; background: var(--ts-surface); color: var(--ts-ink);
  border: 1px solid var(--ts-hairline); border-radius: .6rem; padding: .75rem .9rem; font: 13px/1.45 system-ui, sans-serif;
  box-shadow: 0 8px 24px rgba(0,0,0,.18); z-index: 3; box-sizing: border-box; }
.panel.open { display: block; }
.panel.docked { box-shadow: none; }
.panel header { display: flex; justify-content: space-between; gap: .5rem; align-items: center; }
.panel h4 { margin: 0; font-size: 15px; }
.panel .state { margin: .2rem 0 .6rem; color: var(--ts-ink-2); display: flex; gap: .4rem; align-items: center; }
.panel table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
.panel td { padding: .15rem 0; vertical-align: top; }
.panel td:first-child { color: var(--ts-ink-3); padding-right: .75rem; white-space: nowrap; }
.panel .actions { margin-top: .7rem; display: flex; flex-wrap: wrap; gap: .4rem; }
.panel .actions a, .panel .actions button { color: var(--ts-info); text-decoration: none; padding: .2rem .45rem;
  border: 1px solid var(--ts-hairline); border-radius: .35rem; }
.panel .neighbors { margin: .6rem 0 0; padding: 0; list-style: none; font-size: 12.5px; color: var(--ts-ink-2); }
.panel .neighbors li { display: flex; gap: .4rem; align-items: center; }
`;

let topologySheet = null;

function alpha(color, a) {
  return /^#[0-9a-f]{6}$/i.test(color) ? color + Math.round(a * 255).toString(16).padStart(2, "0") : color;
}

function shortKind(kind, count) {
  const names = { region: "region", controller: "controller", host: "host", seat: "seat" };
  return count + " " + (names[kind] || kind) + (count === 1 ? "" : "s");
}

class TsTopology extends EChartElement {
  connectedCallback() {
    super.connectedCallback();
    if (!this.bar) {
      this.hiddenKinds = new Set();
      // A constructed sheet: the page CSP forbids inline <style> elements.
      if (!topologySheet) {
        topologySheet = new CSSStyleSheet();
        topologySheet.replaceSync(topologyCSS);
      }
      this.shadowRoot.adoptedStyleSheets = [topologySheet];
      this.bar = document.createElement("div");
      this.bar.className = "bar";
      this.bar.setAttribute("role", "toolbar");
      this.bar.setAttribute("aria-label", "Topology view controls");
      this.panel = document.createElement("aside");
      this.panel.className = "panel";
      this.panel.setAttribute("aria-live", "polite");
      this.box.style.position = "absolute";
      this.box.style.left = "0";
      this.box.style.bottom = "0";
      this.shadowRoot.append(this.bar, this.panel);
      this.bar.addEventListener("click", (event) => this.toolbar(event));
    }
    // Refit (not only resize) when the element changes size, so the graph
    // always fills the canvas.
    this.resizer.disconnect();
    this.resizer = new ResizeObserver(() => {
      cancelAnimationFrame(this.frame);
      this.frame = requestAnimationFrame(() => this.chart && this.render(true, true));
    });
    this.resizer.observe(this);
    this.render(true);
  }
  disconnectedCallback() {
    cancelAnimationFrame(this.frame);
    super.disconnectedCallback();
  }
  // A patch that only changes node details (load, memory) must not redraw;
  // only a change of nodes, links or states does. The open panel follows.
  render(fresh, quiet) {
    if (!this.bar) return Promise.resolve();
    const spec = this.spec();
    const shape = JSON.stringify([(spec.nodes || []).map((n) => [n.id, n.state]), (spec.links || []).map((l) => [l.source, l.target, l.state])]);
    if (this.selected) this.showPanel(this.selected);
    if (!fresh && this.chart && shape === this.shape) return Promise.resolve();
    this.shape = shape;
    this.quiet = quiet;
    return super.render(fresh);
  }
  regions(spec) {
    return (spec.nodes || []).filter((n) => n.kind === "region").map((n) => n.region || n.id.slice("region:".length));
  }
  toolbar(event) {
    const button = event.target.closest("button");
    if (!button) return;
    const spec = this.spec();
    if (button.dataset.region) {
      const region = button.dataset.region;
      if (this.collapsed.has(region)) this.collapsed.delete(region); else this.collapsed.add(region);
    } else if (button.dataset.kind) {
      const kind = button.dataset.kind;
      if (this.hiddenKinds.has(kind)) this.hiddenKinds.delete(kind); else this.hiddenKinds.add(kind);
    } else if (button.dataset.action === "expand") {
      this.collapsed.clear();
    } else if (button.dataset.action === "collapse") {
      this.collapsed = new Set(this.regions(spec));
    }
    // "Fit" only redraws: a fresh render resets zoom and pan.
    this.render(true);
  }
  drawBar(spec, t, regionNodes, counts) {
    const regions = regionNodes.map((n) => {
      const region = n.region || n.id.slice("region:".length);
      const open = !this.collapsed.has(region);
      return `<button type="button" class="region" data-region="${escapeHTML(region)}" aria-expanded="${open}"
        title="${open ? "Collapse" : "Expand"} ${escapeHTML(n.name)}"><span class="dot" style="background:${t.status[n.state] || t.status.idle}"></span>${escapeHTML(n.name)}<span class="chev">${open ? "▾" : "▸"}</span></button>`;
    }).join("");
    const kinds = kindOrder.filter((k) => counts[k]).map((k) =>
      `<button type="button" data-kind="${k}" aria-pressed="${!this.hiddenKinds.has(k)}" title="Show or hide ${k}s">
        <svg viewBox="0 0 12 12" aria-hidden="true">${kindIcon[k]}</svg>${k}<span class="count">${counts[k]}</span></button>`).join("");
    const anyOpen = regionNodes.some((n) => !this.collapsed.has(n.region || n.id.slice("region:".length)));
    const all = regionNodes.length > 1 ? `<button type="button" data-action="${anyOpen ? "collapse" : "expand"}">${anyOpen ? "Collapse" : "Expand"} all</button>` : "";
    this.bar.innerHTML = `<span class="group" aria-label="Regions">${regions}${all}</span>
      <span class="group" aria-label="Node kinds">${kinds}</span>
      <span class="group"><button type="button" data-action="fit" title="Reset zoom and fit the graph">Fit</button></span>`;
  }
  layoutPanel() {
    const docked = this.selected && this.clientWidth >= 860;
    const top = this.bar.offsetHeight + 6;
    this.panel.classList.toggle("docked", !!docked);
    if (docked) {
      Object.assign(this.panel.style, { top: top + "px", right: "0", bottom: "0", left: "auto", width: "19rem", maxHeight: "" });
    } else {
      Object.assign(this.panel.style, { top: "auto", right: ".25rem", bottom: ".25rem", left: ".25rem", width: "auto", maxHeight: "55%" });
    }
    this.box.style.top = top + "px";
    this.box.style.right = docked ? "calc(19rem + .75rem)" : "0";
    this.box.style.width = "auto";
    this.box.style.height = "auto";
  }
  clicked(event) {
    if (event.dataType !== "node" || !event.data.node) return;
    this.selected = event.data.node.id;
    this.showPanel(this.selected);
    this.render(true, true);
  }
  showPanel(id) {
    const spec = this.spec();
    const node = (spec.nodes || []).find((n) => n.id === id);
    if (!node) { this.closePanel(); return; }
    const t = theme();
    const rows = Object.entries(node.details || {}).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) =>
      `<tr><td>${escapeHTML(k)}</td><td>${escapeHTML(v)}</td></tr>`).join("");
    const byId = new Map((spec.nodes || []).map((n) => [n.id, n]));
    const neighbors = (spec.links || []).filter((l) => l.source === id || l.target === id).map((l) => {
      const other = byId.get(l.source === id ? l.target : l.source);
      return other ? `<li><span class="dot" style="background:${t.status[l.state || other.state] || t.status.idle}"></span>${escapeHTML(other.name)}
        <span class="count">${escapeHTML(l.label || other.kind)}</span></li>` : "";
    });
    const region = node.kind === "region" ? (node.region || node.id.slice("region:".length)) : "";
    const toggle = region ? `<button type="button" data-toggle>${this.collapsed.has(region) ? "Expand" : "Collapse"} region</button>` : "";
    this.panel.innerHTML = `<header><h4>${escapeHTML(node.name)}</h4><button type="button" data-close aria-label="Close details">✕</button></header>
      <div class="state"><span class="dot" style="background:${t.status[node.state] || t.status.idle}"></span>${escapeHTML(node.kind)} · ${escapeHTML(node.stateLabel || node.state)}</div>
      ${rows ? `<table>${rows}</table>` : ""}
      ${neighbors.length ? `<ul class="neighbors" aria-label="Connected">${neighbors.slice(0, 12).join("")}${neighbors.length > 12 ? `<li class="count">and ${neighbors.length - 12} more</li>` : ""}</ul>` : ""}
      <div class="actions">${node.href ? `<a href="${escapeHTML(node.href)}">Open ${escapeHTML(node.kind)} →</a>` : ""}${toggle}</div>`;
    this.panel.querySelector("[data-close]").addEventListener("click", () => this.closePanel());
    const button = this.panel.querySelector("[data-toggle]");
    if (button) {
      button.dataset.region = region;
      button.addEventListener("click", () => this.toolbar({ target: button }));
    }
    this.panel.classList.add("open");
  }
  closePanel() {
    this.selected = null;
    this.panel.classList.remove("open");
    this.render(true, true);
  }
}

// layoutTopology places every region group in a grid that best matches the
// canvas aspect ratio and returns node positions in layout units plus each
// group's radius.
function layoutTopology(spec, collapsed, hidden, width, height) {
  const nodes = spec.nodes || [];
  const links = spec.links || [];
  const regionOf = (n) => n.region || (n.id.split(":")[1] || "");
  const groups = [];
  const byRegion = new Map();
  for (const n of nodes) {
    if (n.kind !== "region") continue;
    const group = { region: regionOf(n), node: n, controllers: [], hosts: [], seats: new Map(), r: 60 };
    groups.push(group);
    byRegion.set(group.region, group);
  }
  const seatHost = new Map();
  for (const l of links) if (l.kind === "seat") seatHost.set(l.target, l.source);
  for (const n of nodes) {
    const group = byRegion.get(regionOf(n));
    if (!group || n.kind === "region") continue;
    if (n.kind === "controller") group.controllers.push(n);
    else if (n.kind === "host") group.hosts.push(n);
    else if (n.kind === "seat") {
      const host = seatHost.get(n.id) || "";
      if (!group.seats.has(host)) group.seats.set(host, []);
      group.seats.get(host).push(n);
    }
  }
  const pos = new Map();
  const labelSide = new Map();
  for (const g of groups) {
    g.counts = { controller: g.controllers.length, host: g.hosts.length,
      seat: [...g.seats.values()].reduce((sum, list) => sum + list.length, 0) };
    g.open = !collapsed.has(g.region);
    const local = new Map([[g.node.id, [0, 0]]]);
    if (g.open) {
      const ctl = hidden.has("controller") ? [] : g.controllers;
      const hosts = hidden.has("host") ? [] : g.hosts;
      const r1 = ctl.length ? Math.max(62, (ctl.length * 52) / (2 * Math.PI)) : 0;
      ctl.forEach((n, i) => {
        const a = -Math.PI / 2 + (2 * Math.PI * i) / ctl.length + (ctl.length === 2 ? Math.PI / 2 : 0);
        local.set(n.id, [r1 * Math.cos(a), r1 * Math.sin(a)]);
      });
      const seatsShown = !hidden.has("seat");
      const maxSeats = Math.max(0, ...g.hosts.map((h) => (g.seats.get(h.id) || []).length));
      const r2 = hosts.length ? Math.max(r1 + 78, 112, (hosts.length * (seatsShown && maxSeats ? 74 : 54)) / (2 * Math.PI)) : r1;
      hosts.forEach((n, i) => {
        const a = -Math.PI / 2 + (2 * Math.PI * (i + 0.5)) / hosts.length;
        const hx = r2 * Math.cos(a), hy = r2 * Math.sin(a);
        local.set(n.id, [hx, hy]);
        // Seats fan outwards; the label goes across the fan, not into it:
        // above hosts left or right of the region, right of the others.
        labelSide.set(n.id, Math.abs(Math.cos(a)) > Math.abs(Math.sin(a)) ? "top" : "right");
        const seats = seatsShown ? (g.seats.get(n.id) || []) : [];
        const spread = Math.min(Math.PI * 0.9, Math.max(0.5, seats.length * 0.22));
        seats.forEach((s, j) => {
          const ring = 24 + 12 * Math.floor(j / 12);
          const inRing = Math.min(12, seats.length - 12 * Math.floor(j / 12));
          const k = j % 12;
          const b = a + (inRing > 1 ? -spread / 2 + (spread * k) / (inRing - 1) : 0);
          local.set(s.id, [hx + ring * Math.cos(b), hy + ring * Math.sin(b)]);
        });
      });
      g.r = Math.max(70, r2 + (seatsShown && maxSeats ? 24 + 12 * Math.floor((maxSeats - 1) / 12) : 0) + 34);
    } else {
      // A collapsed region sits high in its cell so the counts listed under
      // it stay inside the canvas.
      g.r = 76;
      local.set(g.node.id, [0, -30]);
    }
    g.local = local;
  }
  // Pick the column count whose grid fits the canvas at the largest scale.
  const pad = 14;
  let best = null;
  for (let cols = 1; cols <= Math.max(1, groups.length); cols++) {
    const rows = Math.ceil(groups.length / cols);
    const colW = Array(cols).fill(0), rowH = Array(rows).fill(0);
    groups.forEach((g, i) => {
      colW[i % cols] = Math.max(colW[i % cols], 2 * g.r + pad);
      rowH[Math.floor(i / cols)] = Math.max(rowH[Math.floor(i / cols)], 2 * g.r + pad + 18);
    });
    const w = colW.reduce((a, b) => a + b, 0), h = rowH.reduce((a, b) => a + b, 0);
    const scale = Math.min(width / w, height / h);
    if (!best || scale > best.scale * 1.02) best = { cols, colW, rowH, w, h, scale };
  }
  if (!best) best = { cols: 1, colW: [1], rowH: [1], w: 1, h: 1, scale: 1 };
  groups.forEach((g, i) => {
    const col = i % best.cols, row = Math.floor(i / best.cols);
    const cx = best.colW.slice(0, col).reduce((a, b) => a + b, 0) + best.colW[col] / 2;
    // Leave room for the group title above the halo.
    const cy = best.rowH.slice(0, row).reduce((a, b) => a + b, 0) + 18 + (best.rowH[row] - 18) / 2;
    g.center = [cx, cy];
    for (const [id, [x, y]] of g.local) pos.set(id, [cx + x, cy + y]);
  });
  return { groups, pos, labelSide, width: best.w, height: best.h, scale: best.scale };
}

TsTopology.prototype.option = async function (spec, t) {
  if (!this.collapsed) {
    // Start with everything open unless the graph would be crowded (many
    // nodes or a phone-sized canvas); then only this member's region (the
    // first one) starts open.
    const regions = this.regions(spec);
    const crowded = (spec.nodes || []).length > 260 || this.clientWidth < 560;
    this.collapsed = new Set(crowded ? regions.slice(1) : []);
  }
  const counts = {};
  for (const n of spec.nodes || []) counts[n.kind] = (counts[n.kind] || 0) + 1;
  const regionNodes = (spec.nodes || []).filter((n) => n.kind === "region");
  this.drawBar(spec, t, regionNodes, counts);
  if (!this.selected) this.panel.classList.remove("open");
  this.layoutPanel();
  // The stylesheet's max-height is the most the canvas may use (most of the
  // viewport); the element then shrinks to the fitted graph so a wide,
  // short graph does not leave empty bands above and below it.
  const margin = 12;
  const rem = parseFloat(getComputedStyle(root).fontSize) || 14;
  const top = this.bar.offsetHeight + 6;
  const maxHeight = parseFloat(getComputedStyle(this).maxHeight) || 40 * rem;
  const boxW = this.box.clientWidth;
  const width = Math.max(120, boxW - 2 * margin), height = Math.max(120, maxHeight - top - 2 * margin);
  const layout = layoutTopology(spec, this.collapsed, this.hiddenKinds, width, height);
  const scale = layout.scale;
  const fitted = Math.ceil(layout.height * scale + 2 * margin + top);
  const docked = this.panel.classList.contains("docked");
  const elementHeight = Math.min(maxHeight, Math.max(docked ? 30 * rem : 22 * rem, fitted));
  if (Math.abs(this.offsetHeight - elementHeight) > 1) this.style.height = elementHeight + "px";
  this.chart.resize();
  const boxH = this.box.clientHeight;
  // The graph view stretches its bounding box to the series rectangle, so
  // give it exactly the layout's aspect ratio, centered: circles stay round
  // and nothing is clipped.
  const viewW = layout.width * scale, viewH = layout.height * scale;
  // Symbols shrink with the fit on small canvases and never grow huge.
  const s = Math.max(0.55, Math.min(1.25, scale));
  const labelsFor = { controller: s >= 0.6, host: s >= 0.75 };
  const data = [];
  const shown = new Set();
  for (const g of layout.groups) {
    const status = t.status[g.node.state] || t.status.idle;
    const summary = ["controller", "host", "seat"].filter((k) => g.counts[k]).map((k) => shortKind(k, g.counts[k])).join(" · ");
    if (g.open) {
      data.push({ id: "halo:" + g.region, name: g.node.name, node: g.node, x: g.center[0], y: g.center[1],
        symbol: "circle", symbolSize: Math.max(10, 2 * g.r * scale - 6), z: 0, cursor: "default",
        itemStyle: { color: alpha(status, 0.07), borderColor: alpha(status, 0.55), borderWidth: 1.5, borderType: "dashed" },
        label: { show: true, position: "top", distance: 2, color: t.ink, fontWeight: 700, fontSize: 13,
          formatter: `${g.node.name}  {m|${summary}}`, rich: { m: { color: t.ink3, fontSize: 11, fontWeight: 400 } } },
        emphasis: { disabled: true }, tooltip: { show: false } });
    }
    for (const [id] of g.local) shown.add(id);
  }
  const visible = (n) => shown.has(n.id) && !(this.hiddenKinds.has(n.kind) && n.kind !== "region");
  for (const n of spec.nodes || []) {
    if (!visible(n)) continue;
    const [x, y] = layout.pos.get(n.id);
    const g = layout.groups.find((group) => group.node.id === n.id);
    const size = (kindSize[n.kind] || 14) * s;
    const color = t.status[n.state] || t.status.idle;
    const item = { id: n.id, name: n.name, node: n, x, y, symbol: kindShape[n.kind] || "circle", symbolSize: size,
      itemStyle: { color, borderColor: t.surface, borderWidth: n.kind === "seat" ? 1 : 2 } };
    if (n.id === this.selected) Object.assign(item.itemStyle, { borderColor: t.ink, borderWidth: 3 });
    if (n.kind === "region") {
      item.itemStyle = Object.assign(item.itemStyle, { color: t.surface, borderColor: color, borderWidth: n.id === this.selected ? 5 : 3 });
      item.label = { show: true, position: "inside", color: t.ink, fontWeight: 700, fontSize: Math.round(12 * Math.max(s, 0.85)) };
      if (g && !g.open) {
        const summary = ["controller", "host", "seat"].filter((k) => g.counts[k]).map((k) => shortKind(k, g.counts[k]));
        item.label = { show: true, position: "bottom", distance: 6, color: t.ink, fontWeight: 700, fontSize: 13, align: "center",
          formatter: `${n.name} ▸\n{m|${summary.join("\n")}}`, lineHeight: 16,
          rich: { m: { color: t.ink3, fontSize: 11, fontWeight: 400, lineHeight: 15, align: "center" } } };
        item.symbolSize = 2 * 30 * s;
        item.itemStyle.color = color;
        item.itemStyle.opacity = 0.9;
      }
    } else if (n.kind === "seat") {
      item.label = { show: false };
    } else {
      const side = layout.labelSide.get(n.id) || "right";
      item.label = { show: labelsFor[n.kind], position: side, distance: 4, color: t.ink2, fontSize: 10.5 };
    }
    data.push(item);
  }
  // Two invisible corner anchors pin the fitted bounding box to the whole
  // grid, so halos and titles at the edges are never clipped.
  for (const [id, x, y] of [["anchor:0", 0, 0], ["anchor:1", layout.width, layout.height]]) {
    data.push({ id, name: "", x, y, symbolSize: 0, itemStyle: { opacity: 0 }, label: { show: false },
      emphasis: { disabled: true }, tooltip: { show: false }, cursor: "default" });
  }
  const ids = new Set(data.map((d) => d.id));
  const groupIndex = new Map(layout.groups.map((g, i) => [g.node.id, i]));
  const links = (spec.links || []).filter((l) => ids.has(l.source) && ids.has(l.target)).map((l) => ({
    source: l.source, target: l.target, label: l.label, kind: l.kind,
    lineStyle: { color: l.state ? t.status[l.state] : l.kind === "leaf" ? t.ink3 : t.axis,
      width: l.kind === "region" ? 2.5 : l.kind === "route" ? 1.8 : 1,
      type: l.kind === "leaf" ? "dashed" : l.kind === "region" && l.state === "idle" ? "dotted" : "solid",
      curveness: l.kind === "route" ? 0.25 : l.kind === "region" ? 0.2 * Math.abs((groupIndex.get(l.source) ?? 0) - (groupIndex.get(l.target) ?? 0)) : 0, opacity: l.kind === "seat" || l.kind === "leaf" ? 0.5 : l.kind === "region" ? 0.55 : 0.85 },
  }));
  const tip = (p) => {
    if (p.dataType === "node") {
      // Resolve by id from the current spec: a patch that changes only a
      // node's details or stage label keeps the drawn graph (and its stored
      // node objects) to preserve the layout.
      const n = (this.spec().nodes || []).find((node) => node.id === p.data.id) || p.data.node;
      return n ? `<b>${escapeHTML(n.name)}</b><br>${escapeHTML(n.kind)} · ${escapeHTML(n.stateLabel || n.state)}<br><span style="opacity:.65">click for details</span>` : "";
    }
    const name = (id) => (spec.nodes || []).find((n) => n.id === id)?.name || id;
    return `${escapeHTML(p.data.label || p.data.kind || "")}<br>${escapeHTML(name(p.data.source))} — ${escapeHTML(name(p.data.target))}`;
  };
  return {
    animation: !this.quiet,
    textStyle: baseText(t),
    tooltip: tooltip(t, { formatter: tip }),
    series: [{
      type: "graph", layout: "none", roam: true, draggable: false, nodeScaleRatio: 1,
      left: (boxW - viewW) / 2, top: (boxH - viewH) / 2, width: viewW, height: viewH, scaleLimit: { min: 0.3, max: 6 },
      labelLayout: { hideOverlap: true },
      emphasis: { focus: "adjacency", lineStyle: { width: 3, opacity: 1 }, label: { show: true } },
      blur: { itemStyle: { opacity: 0.18 }, lineStyle: { opacity: 0.08 }, label: { opacity: 0.25 } },
      data, links,
    }],
  };
};

customElements.define("ts-topology", TsTopology);

// ---- <ts-map data-spec='{"regions":[...],"links":[...]}' data-geo="url"> ----

let geoLoading = null;
function loadGeo(url) {
  if (!geoLoading) {
    const attempt = fetch(url, { credentials: "same-origin" }).then((r) => {
      if (!r.ok) throw new Error("GeoJSON " + r.status);
      return r.json();
    }).then((geo) => {
      echarts.registerMap("world", geo);
      return true;
    }).catch(() => {
      // Only success is cached: the next render retries.
      if (geoLoading === attempt) geoLoading = null;
      return false;
    });
    geoLoading = attempt;
  }
  return geoLoading;
}

class TsMap extends EChartElement {}
TsMap.prototype.option = async function (spec, t) {
  const ready = await loadGeo(this.dataset.geo);
  const regions = spec.regions || [];
  const byID = Object.fromEntries(regions.map((r) => [r.id, r]));
  const points = regions.map((r) => ({
    name: r.name, value: [r.lon, r.lat, r.score], href: r.href, detail: r.detail,
    itemStyle: { color: t.status[r.status] || t.status.idle, borderColor: t.surface, borderWidth: 2,
      shadowBlur: r.current ? 14 : 0, shadowColor: t.status.info },
    symbolSize: r.current ? 22 : 17,
  }));
  const lines = (spec.links || []).filter((l) => byID[l.from] && byID[l.to]).map((l) => ({
    coords: [[byID[l.from].lon, byID[l.from].lat], [byID[l.to].lon, byID[l.to].lat]], label: l.label,
    lineStyle: { color: t.status[l.state] || t.axis, type: l.state === "idle" ? "dashed" : "solid" },
  }));
  // Initial zoom and center only: streamed updates keep the operator's pan
  // and zoom (ECharts writes them back into the geo option on roam).
  let current;
  try { current = ((this.chart && this.chart.getOption()) || {}).geo; } catch { current = undefined; }
  current = current && current[0];
  const geo = ready ? {
    map: "world", roam: true, zoom: current && current.zoom ? current.zoom : 1.15,
    center: current && current.center ? current.center : [-35, 20],
    itemStyle: { areaColor: t.hairline, borderColor: t.surface, borderWidth: 0.6 },
    emphasis: { disabled: true }, silent: true,
  } : undefined;
  const series = [
    { type: "lines", coordinateSystem: ready ? "geo" : "cartesian2d", data: lines, zlevel: 1,
      effect: { show: true, period: 5, trailLength: 0.25, symbolSize: 4, color: t.status.info },
      lineStyle: { width: 2, curveness: 0.25, opacity: 0.8 } },
    { type: "effectScatter", coordinateSystem: ready ? "geo" : "cartesian2d", data: points, zlevel: 2, cursor: "pointer",
      rippleEffect: { scale: 2.6, brushType: "stroke" }, showEffectOn: "render",
      label: { show: true, position: "right", formatter: (p) => `${p.name}  ${Math.round(p.value[2])}`, color: t.ink, fontWeight: 700,
        backgroundColor: t.surface, padding: [2, 5], borderRadius: 4 } },
  ];
  return {
    textStyle: baseText(t),
    tooltip: tooltip(t, { trigger: "item", formatter: (p) => p.seriesType === "lines" ? escapeHTML(p.data.label || "") :
      `<b>${escapeHTML(p.name)}</b> · health ${Math.round(p.value[2])}<br>${escapeHTML(p.data.detail || "")}` }),
    geo,
    xAxis: ready ? undefined : { type: "value", min: -180, max: 180, show: false },
    yAxis: ready ? undefined : { type: "value", min: -60, max: 80, show: false },
    series,
  };
};
customElements.define("ts-map", TsMap);

// ---- <ts-palette data-items='[{"label","href","group","action"}]'>: Ctrl/⌘+K ----

class TsPalette extends HTMLElement {
  connectedCallback() {
    if (this.shadowRoot) return;
    const shadow = this.attachShadow({ mode: "open" });
    // A constructed sheet, not a <style> element: the page CSP allows no
    // inline style elements.
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(`
      :host{position:fixed;inset:0;z-index:80;display:none;background:rgba(0,0,0,.35);align-items:flex-start;justify-content:center;padding-top:12vh}
      :host([open]){display:flex}
      .box{width:min(36rem,92vw);background:var(--ts-surface);color:var(--ts-ink);border:1px solid var(--ts-hairline);border-radius:.75rem;box-shadow:0 18px 48px rgba(0,0,0,.35);overflow:hidden;font:inherit}
      input{all:unset;box-sizing:border-box;width:100%;padding:.85rem 1rem;font-size:1rem;border-bottom:1px solid var(--ts-hairline)}
      ul{list-style:none;margin:0;padding:.35rem;max-height:50vh;overflow:auto}
      li{display:flex;justify-content:space-between;gap:1rem;padding:.45rem .7rem;border-radius:.45rem;cursor:pointer;font-size:.9rem}
      li small{color:var(--ts-ink-3)} li[aria-selected=true]{background:var(--ts-plane);box-shadow:inset 3px 0 0 var(--ts-info)}
      .hint{padding:.4rem .9rem;font-size:.75rem;color:var(--ts-ink-3);border-top:1px solid var(--ts-hairline)}`);
    shadow.adoptedStyleSheets = [sheet];
    shadow.innerHTML = `<div class="box" role="dialog" aria-label="Command palette"><input placeholder="Jump to a page, region or action…" aria-label="Command">
      <ul role="listbox"></ul><div class="hint">↑↓ to move · Enter to open · Esc to close · Ctrl/⌘+K or / to open</div></div>`;
    this.input = shadow.querySelector("input");
    this.list = shadow.querySelector("ul");
    this.input.addEventListener("input", () => this.filter());
    this.input.addEventListener("keydown", (e) => this.key(e));
    // Clicks inside the shadow root are retargeted to the host; only a click
    // whose original target is the host itself is on the backdrop.
    this.addEventListener("click", (e) => { if (e.composedPath()[0] === this) this.close(); });
    document.addEventListener("keydown", (e) => {
      const typing = /^(INPUT|SELECT|TEXTAREA)$/.test((e.target && e.target.tagName) || "");
      if ((e.key === "k" && (e.ctrlKey || e.metaKey)) || (e.key === "/" && !typing && !this.hasAttribute("open"))) {
        e.preventDefault();
        this.open();
      }
    });
    document.addEventListener("ts-palette-open", () => this.open());
  }
  items() { try { return JSON.parse(this.dataset.items || "[]"); } catch { return []; } }
  open() { this.setAttribute("open", ""); this.input.value = ""; this.filter(); this.input.focus(); }
  close() { this.removeAttribute("open"); }
  filter() {
    const q = this.input.value.toLowerCase().trim();
    this.matches = this.items().filter((item) => !q || (item.label + " " + item.group).toLowerCase().includes(q)).slice(0, 40);
    this.selected = 0;
    this.list.replaceChildren(...this.matches.map((item, index) => {
      const li = document.createElement("li");
      li.setAttribute("role", "option");
      li.innerHTML = `<span>${escapeHTML(item.label)}</span><small>${escapeHTML(item.group || "")}</small>`;
      li.addEventListener("click", () => this.run(index));
      return li;
    }));
    this.mark();
  }
  mark() { [...this.list.children].forEach((li, i) => li.setAttribute("aria-selected", String(i === this.selected))); }
  key(e) {
    if (e.key === "Escape") { this.close(); return; }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const n = this.matches.length;
      this.selected = (this.selected + (e.key === "ArrowDown" ? 1 : n - 1)) % Math.max(n, 1);
      this.mark();
      const li = this.list.children[this.selected];
      if (li) li.scrollIntoView({ block: "nearest" });
    }
    if (e.key === "Enter") { e.preventDefault(); this.run(this.selected); }
  }
  run(index) {
    const item = this.matches[index];
    if (!item) return;
    this.close();
    if (item.action === "theme") toggleTheme();
    else if (item.action === "notify") enableNotifications();
    else if (item.href) location.href = item.href;
  }
}
customElements.define("ts-palette", TsPalette);

// ---- theme, notifications, toasts, badge, copy ----

function toggleTheme() {
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  localStorage.setItem("ts-orch-theme", root.dataset.theme);
}

function notificationsOn() {
  return "Notification" in window && Notification.permission === "granted" && localStorage.getItem("ts-orch-notify") === "1";
}

async function enableNotifications() {
  if (!("Notification" in window)) return;
  if (notificationsOn()) {
    localStorage.removeItem("ts-orch-notify");
  } else if ((await Notification.requestPermission()) === "granted") {
    localStorage.setItem("ts-orch-notify", "1");
    new Notification("TerraScale orchestrator", { body: "Notifications are on for new insights while this tab is open." });
  }
  syncNotifyButtons();
}

// syncNotifyButtons runs from the body MutationObserver, so it must not
// mutate the DOM when nothing changed: replacing the text node even with the
// same label queues another childList record and loops forever.
function syncNotifyButtons() {
  const on = notificationsOn();
  const label = on ? "Notifications on" : "Notify me";
  document.querySelectorAll("[data-notify-toggle]").forEach((button) => {
    if (button.textContent !== label) button.textContent = label;
    if (button.getAttribute("aria-pressed") !== String(on)) button.setAttribute("aria-pressed", String(on));
  });
}

function wire() {
  document.querySelectorAll("[data-theme-toggle]").forEach((b) => { b.onclick = toggleTheme; });
  document.querySelectorAll("[data-notify-toggle]").forEach((b) => { b.onclick = enableNotifications; });
  document.querySelectorAll("[data-palette-open]").forEach((b) => { b.onclick = () => document.dispatchEvent(new Event("ts-palette-open")); });
  syncNotifyButtons();
}

document.addEventListener("click", (event) => {
  const button = event.target.closest && event.target.closest("[data-copy]");
  if (!button || button.dataset.copyState) return;
  const flash = (text) => {
    const label = button.textContent;
    button.dataset.copyState = "1";
    button.textContent = text;
    setTimeout(() => { button.textContent = label; delete button.dataset.copyState; }, 1600);
  };
  // Select the command so it can be copied by hand when the API is missing
  // (plain HTTP outside localhost) or the browser refuses.
  const manual = () => {
    const code = button.parentElement && button.parentElement.querySelector("code");
    if (code) {
      const range = document.createRange();
      range.selectNodeContents(code);
      const selection = getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
    }
    flash("Press Ctrl+C");
  };
  if (!navigator.clipboard || !navigator.clipboard.writeText) { manual(); return; }
  navigator.clipboard.writeText(button.dataset.copy).then(() => flash("Copied"), manual);
});

function watchToasts() {
  const box = document.getElementById("toasts");
  if (!box) return;
  new MutationObserver((records) => {
    for (const record of records) {
      for (const node of record.addedNodes) {
        if (!(node instanceof HTMLElement) || !node.classList.contains("toast")) continue;
        setTimeout(() => node.remove(), 12000);
        if (notificationsOn() && document.visibilityState !== "visible") {
          const n = new Notification(node.dataset.title || "New insight", { body: node.dataset.body || "", tag: node.dataset.key });
          n.onclick = () => { window.focus(); if (node.dataset.href) location.href = node.dataset.href; };
        }
        const badge = document.querySelector("#attention-badge .badge");
        if (badge) { badge.classList.remove("bump"); void badge.offsetWidth; badge.classList.add("bump"); }
      }
    }
  }).observe(box, { childList: true });
}

function start() {
  wire();
  watchToasts();
  // Datastar morphs replace buttons inside patched regions; rewire them.
  new MutationObserver(() => wire()).observe(document.body, { childList: true, subtree: true });
  if (!window.echarts) {
    const wait = setInterval(() => { if (window.echarts) { clearInterval(wait); rerenderAll(); } }, 50);
  }
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
else start();
