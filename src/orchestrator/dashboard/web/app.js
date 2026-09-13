/* Progressive enhancement only: every page is complete without JavaScript. */
(function () {
  const connection = document.querySelector('#connection');
  const setConnection = (label, state) => {
    if (!connection) return;
    connection.textContent = label;
    connection.className = 'connection ' + state;
  };
  const parse = (node) => {
    try { return JSON.parse(node.dataset.values || '[]'); } catch (_) { return []; }
  };
  const renderChart = (node) => {
    if (!window.ApexCharts) return;
    const rows = parse(node), kind = node.dataset.chart;
    let categories = [], series = [];
    if (kind === 'capacity' || kind === 'regions') {
      const valid = rows.filter(x => x && x.code && Number.isFinite(Number(x.capacityPct)));
      categories = valid.map(x => x.code);
      series = [{ name: 'Capacity %', data: valid.map(x => Number(x.capacityPct)) }];
    } else if (kind === 'nodes') {
      const valid = rows.filter(x => x && x.id && (Number.isFinite(Number(x.cpuPercent)) || Number.isFinite(Number(x.memoryPercent))));
      categories = valid.map(x => x.id);
      series = [
        { name: 'CPU %', data: valid.map(x => Number.isFinite(Number(x.cpuPercent)) ? Number(x.cpuPercent) : null) },
        { name: 'Memory %', data: valid.map(x => Number.isFinite(Number(x.memoryPercent)) ? Number(x.memoryPercent) : null) }
      ];
    } else if (kind === 'rollouts') {
      const valid = rows.filter(x => x && (x.id || x.version) && Number.isFinite(Number(x.progress)));
      categories = valid.map(x => x.id || x.version);
      series = [{ name: 'Complete %', data: valid.map(x => Number(x.progress)) }];
    }
    if (!categories.length || !series.length) return;
    node.textContent = '';
    new ApexCharts(node, {
      chart: { type: 'bar', height: 220, toolbar: { show: false }, animations: { enabled: false }, foreColor: '#8f9aae' },
      series, xaxis: { categories, labels: { style: { colors: '#8f9aae' } } },
      yaxis: { max: 100, min: 0 }, theme: { mode: 'dark' },
      colors: ['#6ea8fe', '#58d6b0'], dataLabels: { enabled: false },
      grid: { borderColor: '#293142' }, legend: { labels: { colors: '#a4adbe' } }
    }).render();
  };
  document.querySelectorAll('[data-chart]').forEach(renderChart);
  if (window.lucide) window.lucide.createIcons();
  if (window.EventSource) {
    const source = new EventSource('/api/events');
    source.onopen = () => setConnection('LIVE', 'live');
    source.onerror = () => setConnection('RECONNECTING', '');
  }
})();
