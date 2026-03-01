import { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import Chart from 'react-apexcharts';
import { HiOutlineChartBar, HiOutlineGlobeAlt, HiOutlineArrowLeft, HiOutlineDownload } from 'react-icons/hi';
import { getAnalysis, exportFilteredPcap } from '../services/api';
import PacketTable from '../components/PacketTable';
import './Dashboard.css';

function Dashboard() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!id) {
      setLoading(false);
      return;
    }
    fetchAnalysis();
  }, [id]);

  const fetchAnalysis = async () => {
    try {
      setLoading(true);
      const res = await getAnalysis(id);
      setAnalysis(res.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load analysis');
    } finally {
      setLoading(false);
    }
  };

  // No ID — show empty state
  if (!id) {
    return (
      <div className="animate-in">
        <div className="page-header">
          <h2>Dashboard</h2>
          <p>Visualize your network traffic analysis results</p>
        </div>
        <div className="empty-state">
          <div className="empty-icon"><HiOutlineChartBar /></div>
          <h3>No Analysis Selected</h3>
          <p>Upload a .pcap file to see traffic analysis, application breakdown, and protocol distribution charts.</p>
          <Link to="/" className="btn btn-primary" style={{ marginTop: '16px' }}>
            Upload a File
          </Link>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="animate-in">
        <div className="page-header"><h2>Loading...</h2></div>
        <div className="stats-grid">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className="stat-card"><div className="skeleton" style={{ height: 80 }} /></div>
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="animate-in">
        <div className="page-header"><h2>Error</h2><p>{error}</p></div>
      </div>
    );
  }

  const { stats, appBreakdown, protocolBreakdown, detectedDomains } = analysis;

  // -- Chart Data --
  const appData = appBreakdown ? Object.entries(appBreakdown).filter(([k]) => k !== 'Unknown').sort((a, b) => b[1] - a[1]).slice(0, 12) : [];
  const protocolData = protocolBreakdown ? Object.entries(protocolBreakdown).sort((a, b) => b[1] - a[1]) : [];

  const chartColors = ['#06d6a0', '#22d3ee', '#a78bfa', '#f472b6', '#fb923c', '#eab308', '#3b82f6', '#ef4444', '#22c55e', '#818cf8', '#f97316', '#14b8a6'];

  const appChartOptions = {
    chart: { type: 'donut', background: 'transparent' },
    labels: appData.map(([name]) => name),
    colors: chartColors.slice(0, appData.length),
    legend: { position: 'bottom', labels: { colors: '#94a3b8' }, fontSize: '12px' },
    plotOptions: { pie: { donut: { size: '55%', labels: { show: true, total: { show: true, label: 'Applications', color: '#94a3b8', fontSize: '12px', formatter: () => appData.length } } } } },
    dataLabels: { enabled: false },
    stroke: { width: 0 },
    theme: { mode: 'dark' },
    tooltip: { theme: 'dark' },
  };

  const protocolChartOptions = {
    chart: { type: 'bar', background: 'transparent', toolbar: { show: false } },
    xaxis: { categories: protocolData.map(([name]) => name), labels: { style: { colors: '#94a3b8', fontSize: '12px' } } },
    yaxis: { labels: { style: { colors: '#94a3b8' } } },
    colors: ['#22d3ee'],
    plotOptions: { bar: { borderRadius: 6, columnWidth: '60%' } },
    dataLabels: { enabled: false },
    grid: { borderColor: '#1e293b', strokeDashArray: 4 },
    theme: { mode: 'dark' },
    tooltip: { theme: 'dark' },
  };

  const trafficChartOptions = {
    chart: { type: 'area', background: 'transparent', toolbar: { show: false }, sparkline: { enabled: false } },
    xaxis: { labels: { show: false }, axisBorder: { show: false }, axisTicks: { show: false } },
    yaxis: { labels: { style: { colors: '#94a3b8' } } },
    colors: ['#06d6a0'],
    fill: { type: 'gradient', gradient: { shade: 'dark', type: 'vertical', shadeIntensity: 0.5, opacityFrom: 0.5, opacityTo: 0.05 } },
    stroke: { curve: 'smooth', width: 2 },
    dataLabels: { enabled: false },
    grid: { borderColor: '#1e293b', strokeDashArray: 4 },
    theme: { mode: 'dark' },
    tooltip: { theme: 'dark' },
  };

  // Build traffic timeline from packets (group by second)
  const packetsBySecond = {};
  (analysis.packets || []).forEach((pkt) => {
    if (!pkt.timestamp) return;
    const sec = pkt.timestamp.substring(0, 19);
    packetsBySecond[sec] = (packetsBySecond[sec] || 0) + 1;
  });
  const timelineData = Object.values(packetsBySecond);

  return (
    <div className="animate-in">
      <div className="page-header dashboard-header">
        <div>
          <button className="btn btn-secondary btn-sm" onClick={() => navigate('/')} style={{ marginBottom: 12 }}>
            <HiOutlineArrowLeft /> Back
          </button>
          <h2>Analysis: {analysis.originalName}</h2>
          <p>PCAP v{analysis.pcapVersion} • {analysis.linkType} • {new Date(analysis.createdAt).toLocaleString()}</p>
        </div>
        <button className="btn btn-primary" onClick={() => exportFilteredPcap(id)}>
          <HiOutlineDownload /> Download Filtered PCAP
        </button>
      </div>

      {/* Stat Cards */}
      <div className="stats-grid">
        <div className="stat-card accent">
          <div className="stat-label">Total Packets</div>
          <div className="stat-value">{stats.totalPackets.toLocaleString()}</div>
          <div className="stat-sub">{stats.parsedPackets} parsed</div>
        </div>
        <div className="stat-card cyan">
          <div className="stat-label">Total Flows</div>
          <div className="stat-value">{stats.totalFlows.toLocaleString()}</div>
          <div className="stat-sub">unique connections</div>
        </div>
        <div className="stat-card purple">
          <div className="stat-label">Data Volume</div>
          <div className="stat-value">{(stats.totalBytes / 1024).toFixed(1)}</div>
          <div className="stat-sub">KB transferred</div>
        </div>
        <div className="stat-card pink">
          <div className="stat-label">Forwarded / Dropped</div>
          <div className="stat-value">{stats.forwarded} / {stats.dropped}</div>
          <div className="stat-sub">{stats.dropped > 0 ? `${((stats.dropped / stats.parsedPackets) * 100).toFixed(1)}% blocked` : 'none blocked'}</div>
        </div>
      </div>

      {/* Charts */}
      <div className="chart-grid">
        {/* App Distribution */}
        <div className="card chart-card">
          <div className="card-header">
            <h3><HiOutlineGlobeAlt /> Application Distribution</h3>
          </div>
          {appData.length > 0 ? (
            <Chart options={appChartOptions} series={appData.map(([, v]) => v)} type="donut" height={320} />
          ) : (
            <div className="empty-state"><p>No application data detected</p></div>
          )}
        </div>

        {/* Protocol Breakdown */}
        <div className="card chart-card">
          <div className="card-header">
            <h3><HiOutlineChartBar /> Protocol Breakdown</h3>
          </div>
          {protocolData.length > 0 ? (
            <Chart options={protocolChartOptions} series={[{ name: 'Packets', data: protocolData.map(([, v]) => v) }]} type="bar" height={320} />
          ) : (
            <div className="empty-state"><p>No protocol data</p></div>
          )}
        </div>
      </div>

      {/* Traffic Timeline */}
      {timelineData.length > 1 && (
        <div className="card chart-card" style={{ marginTop: 16 }}>
          <div className="card-header">
            <h3>📈 Traffic Timeline</h3>
          </div>
          <Chart options={trafficChartOptions} series={[{ name: 'Packets/sec', data: timelineData }]} type="area" height={200} />
        </div>
      )}

      {/* Detected Domains */}
      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-header">
          <h3><HiOutlineGlobeAlt /> Detected Domains ({detectedDomains?.length || 0})</h3>
        </div>
        {detectedDomains && detectedDomains.length > 0 ? (
          <div className="domain-grid">
            {detectedDomains.map((d, i) => (
              <div key={i} className="domain-chip">
                <span className="domain-name">{d.domain}</span>
                <span className={`badge badge-${badgeColor(d.appType)}`}>{d.appType}</span>
              </div>
            ))}
          </div>
        ) : (
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No domains detected</p>
        )}
      </div>

      {/* Packet Table */}
      {analysis.packets && analysis.packets.length > 0 && (
        <PacketTable packets={analysis.packets} />
      )}
    </div>
  );
}

function badgeColor(appType) {
  const colors = {
    Google: 'blue', YouTube: 'red', Facebook: 'blue', Instagram: 'purple',
    'Twitter/X': 'cyan', Amazon: 'orange', Netflix: 'red', GitHub: 'green',
    Discord: 'purple', Zoom: 'blue', Telegram: 'cyan', TikTok: 'pink',
    Spotify: 'green', Cloudflare: 'orange', Microsoft: 'blue', Apple: 'cyan',
    HTTP: 'green', HTTPS: 'blue', DNS: 'purple',
  };
  return colors[appType] || 'cyan';
}

export default Dashboard;
