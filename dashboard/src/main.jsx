import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

// Base API configuration with trailing slash stripping
const rawApi = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api';
const API = rawApi.replace(/\/+$/, '');

// Side Navigation Items
const SIDEBAR_ITEMS = [
  { id: 'dashboard', label: 'Overview', icon: '📊' },
  { id: 'incidents', label: 'Incidents', icon: '🚨' },
  { id: 'analytics', label: 'Analytics', icon: '📈' },
  { id: 'queue', label: 'Triage Queue', icon: '🎯', badgeKey: 'queue' },
  { id: 'users', label: 'User Directory', icon: '👥' }
];

// SVG Security Risk Trend Chart Component
function SecurityRiskTrendChart({ chartType = 'line', riskData = [] }) {
  const width = 640;
  const height = 190;
  const padding = { top: 25, right: 30, bottom: 35, left: 35 };

  let chartPoints = [
    { label: '24 Aug', val: 140 },
    { label: '31 Aug', val: 190 },
    { label: '7 Sept', val: 318, active: true },
    { label: '14 Sept', val: 210 },
    { label: '21 Sept', val: 285 },
    { label: '28 Sept', val: 230 }
  ];

  if (riskData && riskData.length >= 4) {
    const sorted = [...riskData].sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
    chartPoints = sorted.slice(0, 7).map((r, i) => ({
      label: r.user_id || `EMP ${i + 1}`,
      val: Math.round(Number(r.risk_score || 50) * 3.2),
      active: i === 0
    }));
  }

  const values = chartPoints.map(d => d.val);
  const maxVal = Math.max(...values, 350);
  const minVal = Math.min(...values, 50);

  const innerW = width - padding.left - padding.right;
  const innerH = height - padding.top - padding.bottom;

  const coords = chartPoints.map((d, i) => {
    const x = padding.left + (i / Math.max(chartPoints.length - 1, 1)) * innerW;
    const y = padding.top + innerH - ((d.val - minVal) / Math.max(maxVal - minVal, 1)) * innerH;
    return { ...d, x, y };
  });

  const linePath = coords.reduce((acc, pt, i, arr) => {
    if (i === 0) return `M ${pt.x.toFixed(1)} ${pt.y.toFixed(1)}`;
    const prev = arr[i - 1];
    const cx1 = prev.x + (pt.x - prev.x) / 2;
    const cy1 = prev.y;
    const cx2 = prev.x + (pt.x - prev.x) / 2;
    const cy2 = pt.y;
    return `${acc} C ${cx1.toFixed(1)} ${cy1.toFixed(1)}, ${cx2.toFixed(1)} ${cy2.toFixed(1)}, ${pt.x.toFixed(1)} ${pt.y.toFixed(1)}`;
  }, '');

  const activePt = coords.find(c => c.active) || coords[0];

  return (
    <div style={{ width: '100%', overflow: 'hidden' }}>
      <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height: 'auto' }}>
        <defs>
          <linearGradient id="lineGradient" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#6366F1" />
            <stop offset="100%" stopColor="#8B5CF6" />
          </linearGradient>
        </defs>

        {[0, 0.33, 0.66, 1].map((ratio, idx) => {
          const y = padding.top + innerH * ratio;
          return (
            <line key={idx} x1={padding.left} y1={y} x2={width - padding.right} y2={y} stroke="#E2E8F0" strokeWidth="1" strokeDasharray="4 4" />
          );
        })}

        {chartType === 'bar' ? (
          coords.map((pt, idx) => {
            const barW = 28;
            const bH = (height - padding.bottom) - pt.y;
            return (
              <rect
                key={idx}
                x={pt.x - barW / 2}
                y={pt.y}
                width={barW}
                height={bH}
                rx="6"
                fill={pt.active ? '#6366F1' : '#CBD5E1'}
              />
            );
          })
        ) : (
          <path d={linePath} fill="none" stroke="url(#lineGradient)" strokeWidth="3.5" />
        )}

        {coords.map((pt, idx) => (
          <text
            key={idx}
            x={pt.x}
            y={height - 10}
            fill={pt.active ? '#0F172A' : '#64748B'}
            fontSize="11"
            fontWeight={pt.active ? '700' : '500'}
            textAnchor="middle"
          >
            {pt.label}
          </text>
        ))}

        {chartType === 'line' && activePt && (
          <g transform={`translate(${activePt.x}, ${activePt.y})`}>
            <circle cx="0" cy="0" r="6" fill="#6366F1" stroke="#FFF" strokeWidth="2.5" />
            <g transform="translate(-35, -30)">
              <rect width="70" height="22" rx="11" fill="#0F172A" />
              <text x="35" y="15" fill="#FFF" fontSize="10" fontWeight="700" textAnchor="middle">
                Risk: {activePt.val}
              </text>
            </g>
          </g>
        )}
      </svg>
    </div>
  );
}

// Donut Chart Component
function ThreatDonutChart({ threats = [] }) {
  const total = threats.length || 1;
  let malwareCount = 0;
  let postTermCount = 0;
  let identityCount = 0;

  threats.forEach(t => {
    const type = String(t.threat_type || t.threat_name || '').toLowerCase();
    if (type.includes('malware') || type.includes('powershell') || type.includes('lateral')) {
      malwareCount++;
    } else if (type.includes('termination') || type.includes('disabled') || type.includes('inactive')) {
      postTermCount++;
    } else {
      identityCount++;
    }
  });

  if (threats.length === 0) {
    malwareCount = 8;
    postTermCount = 3;
    identityCount = 1;
  }

  const radius = 62;
  const circumference = 2 * Math.PI * radius;
  const pct1 = (malwareCount / total);
  const pct2 = (postTermCount / total);
  const pct3 = (identityCount / total);

  const dash1 = `${Math.round(pct1 * circumference)} ${Math.round(circumference)}`;
  const dash2 = `${Math.round(pct2 * circumference)} ${Math.round(circumference)}`;
  const dash3 = `${Math.round(pct3 * circumference)} ${Math.round(circumference)}`;

  const offset2 = -Math.round(pct1 * circumference);
  const offset3 = -Math.round((pct1 + pct2) * circumference);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', position: 'relative', padding: '16px 0' }}>
      <svg viewBox="0 0 180 180" style={{ width: '160px', height: '160px', transform: 'rotate(-90deg)' }}>
        <circle cx="90" cy="90" r={radius} fill="none" stroke="#F1F5F9" strokeWidth="14" />
        <circle cx="90" cy="90" r={radius} fill="none" stroke="#6366F1" strokeWidth="14" strokeDasharray={dash1} strokeDashoffset="0" strokeLinecap="round" />
        <circle cx="90" cy="90" r={radius} fill="none" stroke="#EF4444" strokeWidth="14" strokeDasharray={dash2} strokeDashoffset={offset2} strokeLinecap="round" />
        <circle cx="90" cy="90" r={radius} fill="none" stroke="#06B6D4" strokeWidth="14" strokeDasharray={dash3} strokeDashoffset={offset3} strokeLinecap="round" />
      </svg>

      <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', textAlign: 'center', width: '90px', pointerEvents: 'none' }}>
        <div style={{ fontSize: '24px', fontWeight: '800', color: '#0F172A', lineHeight: '1' }}>{threats.length}</div>
        <div style={{ fontSize: '10px', color: '#64748B', fontWeight: '700', marginTop: '4px', textTransform: 'uppercase', letterSpacing: '0.3px' }}>
          Active Detections
        </div>
      </div>
    </div>
  );
}

// Account Inspector Modal
function AccountInspectorModal({ user, onClose, onOpenAi }) {
  if (!user) return null;
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" style={{ maxWidth: '480px', height: 'auto', padding: '24px' }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
          <div>
            <div style={{ fontSize: '11px', color: '#6366F1', fontWeight: '700', textTransform: 'uppercase' }}>ACCOUNT INSPECTOR</div>
            <h3 style={{ fontSize: '22px', fontWeight: '800', color: '#0F172A' }}>{user.user_id}</h3>
          </div>
          <button type="button" className="btn-pill-action" onClick={onClose}>✕</button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ background: '#F8FAFC', padding: '12px', borderRadius: '10px' }}>
            <div style={{ fontSize: '11px', color: '#64748B', fontWeight: '700' }}>DEPARTMENT &amp; STATUS</div>
            <div style={{ fontWeight: '700', marginTop: '2px', color: '#0F172A' }}>{user.department || 'Operations'} • {user.status || 'Active'}</div>
          </div>

          <div style={{ background: '#F8FAFC', padding: '12px', borderRadius: '10px' }}>
            <div style={{ fontSize: '11px', color: '#64748B', fontWeight: '700' }}>RISK SCORE &amp; LEVEL</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
              <span style={{ fontSize: '20px', fontWeight: '800' }}>{user.risk_score}</span>
              <span className={`pill-badge ${(user.risk_level || 'low').toLowerCase()}`}>● {user.risk_level || 'LOW'}</span>
            </div>
          </div>

          <div style={{ background: '#F8FAFC', padding: '12px', borderRadius: '10px' }}>
            <div style={{ fontSize: '11px', color: '#64748B', fontWeight: '700' }}>FLAGGED RISK DRIVERS</div>
            <div style={{ color: '#475569', fontSize: '12.5px', marginTop: '4px', lineHeight: '1.4' }}>
              {user.risk_drivers || 'No critical drivers flagged.'}
            </div>
          </div>

          <button
            type="button"
            className="btn-send"
            style={{ width: '100%', marginTop: '8px' }}
            onClick={() => { onClose(); onOpenAi(`Investigate ${user.user_id}`); }}
          >
            ✦ Deep Dive with Sentinel AI
          </button>
        </div>
      </div>
    </div>
  );
}

// Main App Component
function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [aiModalOpen, setAiModalOpen] = useState(false);
  const [quickAiInput, setQuickAiInput] = useState('');
  const [inspectedUser, setInspectedUser] = useState(null);

  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [chartType, setChartType] = useState('line');

  const fetchTelemetry = () => {
    fetch(`${API}/snapshot`)
      .then(res => {
        if (!res.ok) throw new Error(`API returned HTTP ${res.status}`);
        return res.json();
      })
      .then(resData => {
        setData(resData);
        setError('');
      })
      .catch(err => {
        setError(`Failed to connect to ${API}: ${err.message}`);
      });
  };

  useEffect(() => {
    fetchTelemetry();
  }, []);

  if (error && !data) {
    return (
      <div className="app-container" style={{ alignItems: 'center', justifyContent: 'center' }}>
        <div className="card" style={{ maxWidth: '440px', textAlign: 'center' }}>
          <div style={{ fontSize: '36px', marginBottom: '12px' }}>⚠️</div>
          <h2 style={{ fontSize: '20px', fontWeight: '800' }}>Telemetry Offline</h2>
          <p style={{ color: '#64748B', fontSize: '13px', margin: '8px 0 16px' }}>{error}</p>
          <button type="button" className="btn-send" style={{ width: '100%' }} onClick={() => window.location.reload()}>
            Retry Connection 🔄
          </button>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="app-container" style={{ alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
          <div style={{ width: '44px', height: '44px', border: '3px solid #E2E8F0', borderTopColor: '#6366F1', borderRadius: '50%', animation: 'spin 1s linear infinite' }}></div>
          <div style={{ fontSize: '16px', fontWeight: '800', color: '#0F172A' }}>
            Loading Sentinel Telemetry...
          </div>
        </div>
      </div>
    );
  }

  const queue = data.queue || [];
  const threats = data.threats || [];
  const risk = data.risk || [];

  const criticalCount = risk.filter(r => String(r.risk_level || '').toLowerCase() === 'critical').length;
  const highCount = risk.filter(r => String(r.risk_level || '').toLowerCase() === 'high').length;
  const stats = data.meta || {
    users: risk.length,
    threats: threats.length,
    queue: queue.length,
    critical: criticalCount
  };

  const filteredThreats = threats.filter(t => {
    const matchesSearch = !searchTerm || String(t.user_id || '').toLowerCase().includes(searchTerm.toLowerCase()) || String(t.threat_type || '').toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSev = severityFilter === 'ALL' || String(t.severity || '').toUpperCase() === severityFilter;
    return matchesSearch && matchesSev;
  });

  const filteredUsers = risk.filter(u => {
    return !searchTerm || String(u.user_id || '').toLowerCase().includes(searchTerm.toLowerCase()) || String(u.department || '').toLowerCase().includes(searchTerm.toLowerCase());
  });

  return (
    <div className="app-container">

      {/* SIDEBAR NAVIGATION */}
      <aside className="sidebar-nav">
        <div>
          <div className="sidebar-brand-group">
            <div className="brand-icon-box">✦</div>
            <div>
              <div className="brand-title-text">SENTINEL</div>
              <div className="brand-subtitle-text">SECURITY PLATFORM</div>
            </div>
          </div>

          <nav className="sidebar-menu-list">
            {SIDEBAR_ITEMS.map((item) => (
              <button
                key={item.id}
                type="button"
                className={`sidebar-btn ${activeTab === item.id ? 'active' : ''}`}
                onClick={() => setActiveTab(item.id)}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span>{item.icon}</span>
                  <span>{item.label}</span>
                </div>
                {item.badgeKey && stats[item.badgeKey] > 0 && (
                  <span className="sidebar-badge">{stats[item.badgeKey]}</span>
                )}
              </button>
            ))}

            <button
              type="button"
              className="sidebar-btn sidebar-ai-btn"
              onClick={() => { setQuickAiInput(''); setAiModalOpen(true); }}
            >
              <span>✦ Sentinel AI Assistant</span>
              <span>→</span>
            </button>
          </nav>
        </div>

        <div style={{ paddingTop: '16px', borderTop: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: '#10B981', fontWeight: '700' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10B981' }}></span>
            <span>Telemetry Live</span>
          </div>
        </div>
      </aside>

      {/* MAIN WORKSPACE AREA */}
      <main className="main-workspace">

        {/* Workspace Header Row */}
        <div className="workspace-header-row">
          <div>
            <h1 className="page-title">
              {activeTab === 'dashboard' && 'Security Intelligence Overview'}
              {activeTab === 'incidents' && 'Active Threat Incidents'}
              {activeTab === 'analytics' && 'Risk Analytics & Security Metrics'}
              {activeTab === 'queue' && 'Triage Queue'}
              {activeTab === 'users' && 'User Accounts Directory'}
            </h1>
            <p className="page-subtitle">Real-time Identity &amp; Threat Intelligence (ITDR)</p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div className="search-bar-container">
              <input
                type="text"
                className="search-input"
                placeholder="Search EMP ID, threat type, dept..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' && searchTerm.trim()) {
                    setQuickAiInput(`Investigate ${searchTerm}`);
                    setAiModalOpen(true);
                  }
                }}
              />
              <button
                type="button"
                className="search-btn-circle"
                onClick={() => {
                  if (searchTerm.trim()) {
                    setQuickAiInput(`Investigate ${searchTerm}`);
                    setAiModalOpen(true);
                  }
                }}
              >
                🔍
              </button>
            </div>
          </div>
        </div>

        {/* --------------------------------------------------------------------------
            TAB 1: OVERVIEW DASHBOARD
            -------------------------------------------------------------------------- */}
        {activeTab === 'dashboard' && (
          <>
            {/* KPI Cards Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
              <div className="card" style={{ borderLeft: '4px solid #EF4444' }}>
                <span style={{ fontSize: '11px', fontWeight: '700', color: '#64748B', textTransform: 'uppercase' }}>Active Threats</span>
                <div style={{ fontSize: '28px', fontWeight: '800', color: '#0F172A', margin: '4px 0' }}>{stats.threats}</div>
                <div style={{ fontSize: '12px', color: '#EF4444', fontWeight: '700' }}>EDR &amp; IAM Alert Stream</div>
              </div>

              <div className="card" style={{ borderLeft: '4px solid #F97316' }}>
                <span style={{ fontSize: '11px', fontWeight: '700', color: '#64748B', textTransform: 'uppercase' }}>Critical Accounts</span>
                <div style={{ fontSize: '28px', fontWeight: '800', color: '#EF4444', margin: '4px 0' }}>{criticalCount}</div>
                <div style={{ fontSize: '12px', color: '#64748B' }}>Risk Score &gt; 75 / 100</div>
              </div>

              <div className="card" style={{ borderLeft: '4px solid #6366F1' }}>
                <span style={{ fontSize: '11px', fontWeight: '700', color: '#64748B', textTransform: 'uppercase' }}>Monitored Identities</span>
                <div style={{ fontSize: '28px', fontWeight: '800', color: '#0F172A', margin: '4px 0' }}>{stats.users}</div>
                <div style={{ fontSize: '12px', color: '#6366F1', fontWeight: '700' }}>{highCount} High Risk Accounts</div>
              </div>

              <div className="card" style={{ borderLeft: '4px solid #10B981' }}>
                <span style={{ fontSize: '11px', fontWeight: '700', color: '#64748B', textTransform: 'uppercase' }}>Triage Cases</span>
                <div style={{ fontSize: '28px', fontWeight: '800', color: '#0F172A', margin: '4px 0' }}>{stats.queue}</div>
                <div style={{ fontSize: '12px', color: '#10B981', fontWeight: '700' }}>Priority Score &gt; 80</div>
              </div>
            </div>

            {/* Main Overview Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '20px', marginTop: '4px' }}>

              {/* Left Column */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div className="card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <h3 style={{ fontSize: '16px', fontWeight: '800', color: '#0F172A' }}>Security Risk Index Trend</h3>
                    <button type="button" className="btn-pill-action" onClick={() => setChartType(prev => prev === 'line' ? 'bar' : 'line')}>
                      {chartType === 'line' ? '📈 Line' : '📊 Bar'}
                    </button>
                  </div>
                  <SecurityRiskTrendChart chartType={chartType} riskData={risk} />
                </div>

                <div className="card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <h3 style={{ fontSize: '16px', fontWeight: '800', color: '#0F172A' }}>Priority Account Triage Matrix</h3>
                    <button type="button" className="btn-pill-action" onClick={() => setActiveTab('queue')}>View All Queue →</button>
                  </div>

                  <div className="table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Account ID</th>
                          <th>Risk Score</th>
                          <th>Level</th>
                          <th>Risk Drivers</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {risk.slice(0, 5).map((u) => (
                          <tr key={u.user_id} style={{ cursor: 'pointer' }} onClick={() => setInspectedUser(u)}>
                            <td>
                              <strong>{u.user_id}</strong>
                              <div style={{ fontSize: '11px', color: '#64748B' }}>{u.department || 'Operations'}</div>
                            </td>
                            <td style={{ fontWeight: '800' }}>{u.risk_score}</td>
                            <td>
                              <span className={`pill-badge ${(u.risk_level || 'low').toLowerCase()}`}>
                                ● {u.risk_level || 'LOW'}
                              </span>
                            </td>
                            <td style={{ color: '#64748B', fontSize: '12px', maxWidth: '200px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                              {u.risk_drivers || 'Telemetry active'}
                            </td>
                            <td>
                              <button
                                type="button"
                                className="btn-pill-action"
                                onClick={(e) => { e.stopPropagation(); setQuickAiInput(`Investigate ${u.user_id}`); setAiModalOpen(true); }}
                              >
                                Investigate ✦
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* Right Column */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div className="card">
                  <h3 style={{ fontSize: '16px', fontWeight: '800', color: '#0F172A', marginBottom: '8px' }}>Threat Vectors Breakdown</h3>
                  <ThreatDonutChart threats={threats} />
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px', marginTop: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: '#6366F1', fontWeight: '700' }}>● Malware &amp; Execution</span>
                      <strong>EDR Alerts</strong>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: '#EF4444', fontWeight: '700' }}>● Post-Termination</span>
                      <strong>Identity Risk</strong>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: '#06B6D4', fontWeight: '700' }}>● IAM &amp; MFA Anomaly</span>
                      <strong>Auth Logs</strong>
                    </div>
                  </div>
                </div>

                <div className="card" style={{ background: 'linear-gradient(135deg, #EEF2FF 0%, #E0E7FF 100%)', border: '1px solid rgba(99, 102, 241, 0.3)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                    <div style={{ width: '32px', height: '32px', borderRadius: '10px', background: '#6366F1', color: 'white', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: '800', fontSize: '16px' }}>✦</div>
                    <div>
                      <div style={{ fontSize: '14px', fontWeight: '800', color: '#0F172A' }}>Sentinel AI Assistant</div>
                      <div style={{ fontSize: '11px', color: '#6366F1', fontWeight: '600' }}>Instant Telemetry AI Search</div>
                    </div>
                  </div>
                  <p style={{ fontSize: '12px', color: '#475569', lineHeight: '1.4', marginBottom: '12px' }}>
                    Ask Sentinel AI to analyze MFA failures, inspect EDR payload alerts, or compare critical EMP risk profiles.
                  </p>
                  <button
                    type="button"
                    className="btn-send"
                    style={{ width: '100%', padding: '10px' }}
                    onClick={() => { setQuickAiInput("Summarize active threats"); setAiModalOpen(true); }}
                  >
                    Launch AI Investigation ✦
                  </button>
                </div>



              </div>

            </div>
          </>
        )}

        {/* --------------------------------------------------------------------------
            TAB 2: INCIDENTS (ACTIVE THREATS VIEW)
            -------------------------------------------------------------------------- */}
        {activeTab === 'incidents' && (
          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div>
                <h3 style={{ fontSize: '18px', fontWeight: '800' }}>Active Threat Incidents ({filteredThreats.length})</h3>
                <p style={{ fontSize: '13px', color: '#64748B' }}>Correlated telemetry detections across IAM, EDR, and Firewall</p>
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
                  <button
                    key={sev}
                    type="button"
                    className={`btn-pill-action ${severityFilter === sev ? 'active' : ''}`}
                    onClick={() => setSeverityFilter(sev)}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '16px' }}>
              {filteredThreats.map((t, idx) => (
                <div key={idx} className="card" style={{ borderLeft: `4px solid ${String(t.severity).toLowerCase() === 'critical' ? '#EF4444' : '#F97316'}` }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className={`pill-badge ${(t.severity || 'high').toLowerCase()}`}>{t.severity || 'HIGH'}</span>
                    <span style={{ fontSize: '11px', color: '#64748B' }}>Confidence: {t.confidence || 'High'}</span>
                  </div>

                  <div style={{ margin: '10px 0' }}>
                    <h4 style={{ fontSize: '15px', fontWeight: '800' }}>{t.threat_type || t.threat_name}</h4>
                    <div style={{ fontSize: '12px', color: '#6366F1', marginTop: '2px' }}>Target: <strong>{t.user_id}</strong> {t.hostname && `• Host: ${t.hostname}`}</div>
                  </div>

                  <p style={{ fontSize: '12.5px', color: '#64748B', lineHeight: '1.4' }}>
                    {t.reason || t.detection_reason || 'Correlated telemetry alert flagged by Sentinel AI.'}
                  </p>

                  <button
                    type="button"
                    className="btn-pill-action"
                    style={{ marginTop: '12px' }}
                    onClick={() => { setQuickAiInput(`Investigate threat ${t.threat_type} for ${t.user_id}`); setAiModalOpen(true); }}
                  >
                    Investigate Threat ✦
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* --------------------------------------------------------------------------
            TAB 3: ANALYTICS (RISK ANALYTICS & SECURITY METRICS)
            -------------------------------------------------------------------------- */}
        {activeTab === 'analytics' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {/* Analytics Overview Summary Row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
              <div className="card" style={{ borderLeft: '4px solid #6366F1' }}>
                <span style={{ fontSize: '11px', fontWeight: '700', color: '#64748B', textTransform: 'uppercase' }}>Avg Risk Score</span>
                <div style={{ fontSize: '28px', fontWeight: '800', color: '#0F172A', margin: '4px 0' }}>
                  {risk.length > 0 ? (risk.reduce((acc, u) => acc + (Number(u.risk_score) || 0), 0) / risk.length).toFixed(1) : 0}
                </div>
                <div style={{ fontSize: '12px', color: '#6366F1', fontWeight: '700' }}>Across {risk.length} Accounts</div>
              </div>

              <div className="card" style={{ borderLeft: '4px solid #EF4444' }}>
                <span style={{ fontSize: '11px', fontWeight: '700', color: '#64748B', textTransform: 'uppercase' }}>Critical Risk Users</span>
                <div style={{ fontSize: '28px', fontWeight: '800', color: '#EF4444', margin: '4px 0' }}>
                  {risk.filter(u => String(u.risk_level).toLowerCase() === 'critical').length}
                </div>
                <div style={{ fontSize: '12px', color: '#EF4444', fontWeight: '700' }}>Immediate Action Required</div>
              </div>

              <div className="card" style={{ borderLeft: '4px solid #F97316' }}>
                <span style={{ fontSize: '11px', fontWeight: '700', color: '#64748B', textTransform: 'uppercase' }}>High Risk Users</span>
                <div style={{ fontSize: '28px', fontWeight: '800', color: '#F97316', margin: '4px 0' }}>
                  {risk.filter(u => String(u.risk_level).toLowerCase() === 'high').length}
                </div>
                <div style={{ fontSize: '12px', color: '#64748B' }}>Score 50 - 75 Range</div>
              </div>

              <div className="card" style={{ borderLeft: '4px solid #10B981' }}>
                <span style={{ fontSize: '11px', fontWeight: '700', color: '#64748B', textTransform: 'uppercase' }}>Total Active Threat Alerts</span>
                <div style={{ fontSize: '28px', fontWeight: '800', color: '#0F172A', margin: '4px 0' }}>
                  {threats.length}
                </div>
                <div style={{ fontSize: '12px', color: '#10B981', fontWeight: '700' }}>Correlated Detections</div>
              </div>
            </div>

            {/* Department Risk Breakdown & Top Risky Users */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
              
              {/* Department Breakdown */}
              <div className="card">
                <h3 style={{ fontSize: '16px', fontWeight: '800', color: '#0F172A', marginBottom: '16px' }}>Department Risk Breakdown</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {(() => {
                    const depts = {};
                    risk.forEach(u => {
                      const d = u.department || 'Other';
                      if (!depts[d]) depts[d] = { count: 0, totalScore: 0 };
                      depts[d].count += 1;
                      depts[d].totalScore += (Number(u.risk_score) || 0);
                    });
                    const deptList = Object.keys(depts).map(d => ({
                      dept: d,
                      count: depts[d].count,
                      avgScore: (depts[d].totalScore / depts[d].count).toFixed(1)
                    })).sort((a, b) => b.avgScore - a.avgScore);

                    return deptList.map(item => (
                      <div key={item.dept} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', background: '#F8FAFC', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                        <div>
                          <strong style={{ fontSize: '14px', color: '#0F172A' }}>{item.dept}</strong>
                          <div style={{ fontSize: '11px', color: '#64748B' }}>{item.count} Monitored Users</div>
                        </div>
                        <div style={{ textAlign: 'right' }}>
                          <span style={{ fontSize: '16px', fontWeight: '800', color: item.avgScore > 60 ? '#EF4444' : item.avgScore > 40 ? '#F97316' : '#10B981' }}>
                            {item.avgScore}
                          </span>
                          <div style={{ fontSize: '10px', color: '#64748B', fontWeight: '600' }}>Avg Risk Index</div>
                        </div>
                      </div>
                    ));
                  })()}
                </div>
              </div>

              {/* Top Highest Risk Accounts */}
              <div className="card">
                <h3 style={{ fontSize: '16px', fontWeight: '800', color: '#0F172A', marginBottom: '16px' }}>Highest Risk Monitored Accounts</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {risk.slice().sort((a, b) => (Number(b.risk_score) || 0) - (Number(a.risk_score) || 0)).slice(0, 5).map(u => (
                    <div
                      key={u.user_id}
                      style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', background: '#F8FAFC', borderRadius: '8px', border: '1px solid var(--border-subtle)', cursor: 'pointer' }}
                      onClick={() => setInspectedUser(u)}
                    >
                      <div>
                        <strong style={{ fontSize: '14px', color: '#0F172A' }}>{u.user_id}</strong>
                        <div style={{ fontSize: '11px', color: '#64748B' }}>{u.department || 'Operations'} • Status: {u.status || 'Active'}</div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <span className={`pill-badge ${(u.risk_level || 'low').toLowerCase()}`}>
                          {u.risk_level || 'LOW'}
                        </span>
                        <strong style={{ fontSize: '16px', color: '#0F172A' }}>{u.risk_score}</strong>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          </div>
        )}

        {/* --------------------------------------------------------------------------
            TAB 4: TRIAGE QUEUE VIEW
            -------------------------------------------------------------------------- */}
        {activeTab === 'queue' && (
          <div className="card">
            <h3 style={{ fontSize: '18px', fontWeight: '800', marginBottom: '4px' }}>Prioritized Triage Queue ({queue.length})</h3>
            <p style={{ fontSize: '13px', color: '#64748B', marginBottom: '16px' }}>Ranked by Investigation Priority Score for instant analyst triage</p>

            <div className="table-wrapper">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>User ID &amp; Name</th>
                    <th>Department</th>
                    <th>Risk Score</th>
                    <th>Detections</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {queue.map((item, idx) => (
                    <tr key={idx} style={{ cursor: 'pointer' }} onClick={() => setInspectedUser(item)}>
                      <td>
                        <span style={{ fontWeight: '800', color: idx < 3 ? '#EF4444' : '#0F172A' }}>
                          #{item.priority_rank || idx + 1}
                        </span>
                      </td>
                      <td>
                        <strong>{item.user_id}</strong>
                        <div style={{ fontSize: '11px', color: '#64748B' }}>{item.full_name || 'Account'}</div>
                      </td>
                      <td>{item.department || 'IT'}</td>
                      <td style={{ fontWeight: '800' }}>{item.risk_score}</td>
                      <td>
                        <span className="pill-badge critical">{item.threat_detection_count || 1} Threats</span>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn-pill-action"
                          onClick={(e) => { e.stopPropagation(); setQuickAiInput(`Investigate queue item ${item.user_id}`); setAiModalOpen(true); }}
                        >
                          Start Triage ✦
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* --------------------------------------------------------------------------
            TAB 5: USER DIRECTORY VIEW
            -------------------------------------------------------------------------- */}
        {activeTab === 'users' && (
          <div className="card">
            <h3 style={{ fontSize: '18px', fontWeight: '800', marginBottom: '4px' }}>User Accounts Directory ({filteredUsers.length})</h3>
            <p style={{ fontSize: '13px', color: '#64748B', marginBottom: '16px' }}>Monitored identity records and telemetry risk state</p>

            <div className="table-wrapper">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>User ID</th>
                    <th>Department</th>
                    <th>Status</th>
                    <th>Risk Score</th>
                    <th>Risk Level</th>
                    <th>Auth Failures</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map((u) => (
                    <tr key={u.user_id} style={{ cursor: 'pointer' }} onClick={() => setInspectedUser(u)}>
                      <td><strong>{u.user_id}</strong></td>
                      <td>{u.department || 'Operations'}</td>
                      <td>
                        <span style={{ color: String(u.status).toLowerCase() === 'disabled' ? '#EF4444' : '#10B981', fontWeight: '700' }}>
                          {u.status || 'Active'}
                        </span>
                      </td>
                      <td style={{ fontWeight: '800' }}>{u.risk_score}</td>
                      <td>
                        <span className={`pill-badge ${(u.risk_level || 'low').toLowerCase()}`}>
                          ● {u.risk_level || 'LOW'}
                        </span>
                      </td>
                      <td>{u.iam_failed_auth || 0}</td>
                      <td>
                        <button
                          type="button"
                          className="btn-pill-action"
                          onClick={(e) => { e.stopPropagation(); setQuickAiInput(`Investigate ${u.user_id}`); setAiModalOpen(true); }}
                        >
                          Inspect ✦
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

      </main>

      {/* ACCOUNT INSPECTOR MODAL */}
      {inspectedUser && (
        <AccountInspectorModal
          user={inspectedUser}
          onClose={() => setInspectedUser(null)}
          onOpenAi={(prompt) => { setQuickAiInput(prompt); setAiModalOpen(true); }}
        />
      )}

      {/* SENTINEL AI MODAL CHATBOT */}
      {aiModalOpen && (
        <SentinelAiModal
          initialQuery={quickAiInput}
          userList={risk}
          onClose={() => setAiModalOpen(false)}
        />
      )}
    </div>
  );
}

// Sentinel AI Chatbot Modal
function SentinelAiModal({ initialQuery = '', userList = [], onClose }) {
  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: "Hello! I am **Sentinel AI**, your Security Assistant connected to live enterprise telemetry streams. Ask me to investigate any EMP account, analyze threats, review MFA failures, or explain security concepts.",
      actions: ["Summarize active threats", "Which accounts are critical?", "Explain MFA"]
    }
  ]);
  const [input, setInput] = useState(initialQuery);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (initialQuery.trim()) {
      setInput(initialQuery);
    }
  }, [initialQuery]);

  const sendQuery = async (queryText) => {
    const q = (queryText || input).trim();
    if (!q || loading) return;

    setMessages(prev => [...prev, { sender: 'user', text: q }]);
    setInput('');
    setLoading(true);

    const historyPayload = messages.map(m => ({
      sender: m.sender,
      text: m.text
    }));

    try {
      const res = await fetch(`${API}/analyst/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: q, history: historyPayload })
      });
      if (!res.ok) throw new Error('Agent API query failed');
      const resData = await res.json();

      let answerStr = 'Investigation complete.';
      let quickActions = [];

      if (typeof resData === 'string') {
        answerStr = resData;
      } else if (resData && typeof resData === 'object') {
        answerStr = resData.answer || resData.text || 'Investigation complete.';
        quickActions = resData.suggested_actions || resData.quick_actions || [];
      }

      setMessages(prev => [
        ...prev,
        {
          sender: 'ai',
          text: answerStr,
          actions: quickActions
        }
      ]);
    } catch (e) {
      setMessages(prev => [
        ...prev,
        {
          sender: 'ai',
          text: `⚠️ Error reaching Sentinel AI agent: ${e.message}`
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const formatMarkdown = (txt) => {
    if (!txt) return '';
    let html = txt;
    html = html.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    html = html.replace(/^### (.*$)/gim, '<h4 style="margin: 10px 0 4px; font-size: 14px; font-weight: 700; color: #6366F1;">$1</h4>');
    html = html.replace(/^#### (.*$)/gim, '<h5 style="margin: 8px 0 2px; font-size: 13px; font-weight: 600; color: #0F172A;">$1</h5>');
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    html = html.replace(/`([^`]+)`/g, '<code style="background: #F1F5F9; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.9em; color: #6366F1;">$1</code>');
    html = html.replace(/\n/g, '<br/>');
    return html;
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div className="brand-icon-box" style={{ width: '32px', height: '32px', fontSize: '16px' }}>✦</div>
            <div>
              <div style={{ fontSize: '16px', fontWeight: '800', color: '#0F172A' }}>Sentinel AI Assistant</div>
              <div style={{ fontSize: '12px', color: '#64748B' }}>Connected to live security telemetry &amp; identity dataset</div>
            </div>
          </div>
          <button type="button" className="btn-pill-action" onClick={onClose} style={{ padding: '6px 12px' }}>✕ Close</button>
        </div>

        {/* Quick Starter Bar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '10px 24px', background: '#F8FAFC', borderBottom: '1px solid var(--border-subtle)', overflowX: 'auto' }}>
          <span style={{ fontSize: '12px', fontWeight: '700', color: '#64748B', whiteSpace: 'nowrap' }}>Quick Prompts:</span>
          <button type="button" className="btn-pill-action" style={{ fontSize: '11px', padding: '4px 10px' }} onClick={() => sendQuery("Show summary of threats")}>
            Threat Summary
          </button>
          <button type="button" className="btn-pill-action" style={{ fontSize: '11px', padding: '4px 10px' }} onClick={() => sendQuery("Which accounts have critical risk?")}>
            Critical Accounts
          </button>
          <button type="button" className="btn-pill-action" style={{ fontSize: '11px', padding: '4px 10px' }} onClick={() => sendQuery("Explain MFA")}>
            Explain MFA
          </button>
          {userList.length > 0 && (
            <button type="button" className="btn-pill-action" style={{ fontSize: '11px', padding: '4px 10px' }} onClick={() => sendQuery(`Investigate ${userList[0].user_id}`)}>
              Investigate {userList[0].user_id}
            </button>
          )}
        </div>

        {/* Chat Body */}
        <div className="modal-body">
          {messages.map((m, idx) => (
            <div key={idx} className={`chat-bubble-row ${m.sender}`}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <div className="chat-bubble" dangerouslySetInnerHTML={{ __html: formatMarkdown(m.text) }} />

                {/* Action Suggestion Chips */}
                {m.actions && m.actions.length > 0 && (
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '4px' }}>
                    {m.actions.map((act, aIdx) => (
                      <button
                        key={aIdx}
                        type="button"
                        className="btn-pill-action"
                        onClick={() => sendQuery(act)}
                      >
                        {act} →
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
          {loading && (
            <div className="chat-bubble-row ai">
              <div className="chat-bubble" style={{ color: '#64748B', fontSize: '13px' }}>
                <em>Analyzing live telemetry streams...</em>
              </div>
            </div>
          )}
        </div>

        {/* Chat Input Row */}
        <div className="modal-input-row">
          <input
            type="text"
            className="chat-input-field"
            placeholder="Ask Sentinel AI to investigate EMP11218, explain MFA, or summarize threats..."
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && sendQuery()}
          />
          <button
            type="button"
            className="btn-send"
            onClick={() => sendQuery()}
            disabled={loading}
          >
            Send ✦
          </button>
        </div>
      </div>
    </div>
  );
}

// Render React Root
const container = document.getElementById('root');
const root = createRoot(container);
root.render(<App />);
