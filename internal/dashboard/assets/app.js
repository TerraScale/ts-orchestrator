// TerraScale orchestrator dashboard elements. No build step: this file is
// served as-is from the binary. Datastar owns every update: the server
// patches element attributes (data-spec, datetime, data-values) and these
// elements only render what the attributes say. Rendering happens inside a
// shadow root so a Datastar morph of the light DOM never removes a chart.
//
// Elements: <ts-time>, <ts-sparkline>, <ts-chart>, <ts-timeline>,
// <ts-map>, <ts-palette>. Plus toasts, the attention badge
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
