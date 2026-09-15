import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api';
const NAV = [
  ['overview', 'Overview', '⌂'], ['risk', 'Risk posture', '◈'], ['threats', 'Threat detections', '⚠'],
  ['queue', 'Investigation queue', '☷'], ['users', 'User investigations', '◎'], ['quality', 'Data quality', '◌'], ['analyst', 'Analyst workspace', '✦']
];
const fallback = {
  meta: { users: 0, threats: 0, queue: 0, critical: 0 },
  queue: [], threats: [], risk: [],
  quality: [{ source: 'Identity master', status: 'Healthy', coverage: '100%', issues: 0 }, { source: 'IAM audit trail', status: 'Reviewed', coverage: '100%', issues: 'Validated' }, { source: 'Endpoint alerts', status: 'Reviewed', coverage: '100%', issues: 'Validated' }, { source: 'Firewall logs', status: 'Reviewed', coverage: '100%', issues: 'Validated' }]
};

function App() {
  const [page, setPage] = useState('overview'), [data, setData] = useState(null), [error, setError] = useState(''), [selected, setSelected] = useState(null), [query, setQuery] = useState('');
  useEffect(() => { fetch(`${API}/snapshot`).then(r => { if (!r.ok) throw Error('Snapshot unavailable'); return r.json(); }).then(setData).catch(e => { setError(e.message); setData(fallback); }); }, []);
  const d = data || fallback, queue = d.queue || [], threats = d.threats || [], risk = d.risk || [];
  const stats = d.meta || { users: risk.length, threats: threats.length, queue: queue.length, critical: risk.filter(x => x.risk_level === 'Critical').length };
  const title = NAV.find(n => n[0] === page)?.[1] || 'Overview';
  const openUser = u => { setSelected(risk.find(r => r.user_id === u?.user_id) || queue.find(r => r.user_id === u?.user_id) || u); setPage('users'); };
  const investigateWithAI = u => { setSelected(risk.find(r => r.user_id === u?.user_id) || queue.find(r => r.user_id === u?.user_id) || u); setPage('analyst'); };

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">D</span><div><strong>DEFEND</strong><small>SECURITY OPERATIONS</small></div></div>
      <div className="environment"><span className="status-dot" />LIVE TELEMETRY</div>
      <nav aria-label="Primary navigation">{NAV.map(([id, label, icon]) => <button type="button" key={id} className={page === id ? 'nav-item active' : 'nav-item'} onClick={() => setPage(id)} aria-current={page === id ? 'page' : undefined} aria-label={label}><span aria-hidden="true">{icon}</span><label>{label}</label>{id === 'queue' && stats.queue > 0 && <em>{stats.queue}</em>}</button>)}</nav>
      <div className="sidebar-user"><span className="avatar">SA</span><div><strong>SOC Analyst</strong><small>Demo operator</small></div><span className="more">•••</span></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div className="page-heading"><span className="kicker">DEFEND / SECURITY OPERATIONS</span><h1>{title}</h1></div><div className="top-actions"><button type="button" className="top-button" aria-label="Open investigation search" onClick={() => setPage('queue')}>⌕</button><button type="button" className="avatar" aria-label="Analyst profile">SA</button></div></header>
      {error && <div className="notice" role="status">Using the local shell while the API reconnects · {error}</div>}
      {page === 'overview' && <Overview stats={stats} risk={risk} threats={threats} queue={queue} onOpen={setPage} onSelect={openUser} />}
      {page === 'risk' && <Risk risk={risk} onSelect={openUser} onAISelect={investigateWithAI} />}
      {page === 'threats' && <Threats threats={threats} onSelect={openUser} />}
      {page === 'queue' && <Queue rows={queue.filter(x => `${x.user_id} ${x.full_name} ${x.department}`.toLowerCase().includes(query.toLowerCase()))} query={query} setQuery={setQuery} onSelect={openUser} />}
      {page === 'users' && <Investigation user={selected || queue[0] || risk[0]} threats={threats} risk={risk} onAIInvestigate={investigateWithAI} />}
      {page === 'quality' && <Quality quality={d.quality} />}
      {page === 'analyst' && <AnalystWorkspace selectedUser={selected || queue[0] || risk[0]} riskUsers={risk} onOpenUser={openUser} />}
    </main>
  </div>;
}

const MiniBars = ({ values, tone = 'teal' }) => { const max = Math.max(...values, 1); return <div className={`mini-bars ${tone}`} aria-hidden="true">{values.map((v, i) => <i key={i} style={{ height: `${Math.max(10, v / max * 100)}%` }} />)}</div>; };
const Stat = ({ label, value, detail, tone = 'teal', values, onClick }) => <button type="button" className={`stat-card ${tone}`} onClick={onClick} aria-label={`${label}: ${value}. Open related view`}><div className="stat-label">{label}<span aria-hidden="true">↗</span></div><div className="stat-value">{value}</div><div className="stat-detail">{detail}</div>{values && <MiniBars values={values} tone={tone} />}</button>;
const SectionHead = ({ title, detail, action, onAction }) => <div className="section-head"><div><h3>{title}</h3>{detail && <p>{detail}</p>}</div>{action && <button className="text-button" onClick={onAction}>{action} <span>→</span></button>}</div>;
function Overview({ stats, risk, threats, queue, onOpen, onSelect }) {
  const bands = ['Critical', 'High', 'Medium', 'Low'], posture = Math.max(0, 100 - stats.critical * 3);
  const priority = [...risk].sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0)).slice(0, 5);
  return <div className="page-stack">
    <section className="hero-panel"><div><span className="kicker teal-text">LIVE SECURITY POSTURE</span><h2>Know what needs attention<br /><span>before it becomes impact.</span></h2><p>Prioritized signals across identity, endpoint and network telemetry.</p><button type="button" className="primary-button" onClick={() => onOpen('queue')}>Open investigation queue <span>→</span></button></div><div className="posture-visual" title="Posture score derived from critical user count"><div className="posture-orb" role="img" aria-label={`Posture score ${posture} out of 100`}><div><strong>{posture}</strong><small>/100</small></div></div><div><b>Posture score</b><small>{stats.critical ? 'Needs attention' : 'Within guardrails'}</small><span className="orb-caption">CRITICAL USERS <strong>{stats.critical}</strong></span></div></div></section>
    <div className="stats-grid"><Stat onClick={() => onOpen('risk')} label="USERS MONITORED" value={stats.users.toLocaleString()} detail="Risk-band population" values={bands.map(b => risk.filter(r => r.risk_level === b).length)} /><Stat onClick={() => onOpen('risk')} label="CRITICAL USERS" value={stats.critical} detail="Require immediate review" tone="coral" values={risk.filter(r => r.risk_level === 'Critical').map(r => Number(r.risk_score) || 0)} /><Stat onClick={() => onOpen('threats')} label="ACTIVE THREATS" value={stats.threats} detail="Correlated detections" tone="amber" values={bands.map(b => threats.filter(t => t.severity === b).length)} /><Stat onClick={() => onOpen('queue')} label="INVESTIGATION QUEUE" value={stats.queue} detail="Priority distribution" tone="violet" values={bands.map(b => queue.filter(q => q.investigation_priority === b).length)} /></div>
    <div className="content-grid"><section className="panel"><SectionHead title="Priority investigations" detail="Highest-risk users requiring analyst action" action="View queue" onAction={() => onOpen('queue')} /><div className="priority-list">{priority.length ? priority.map((r, i) => <button type="button" className="priority-row" key={r.user_id} onClick={() => onSelect(r)}><span className="row-index">0{i + 1}</span><div className="person"><b>{r.full_name || r.username || r.user_id}</b><small>{r.department || 'Unknown'} · {r.role || 'User'}</small></div><div className="risk-track"><i style={{ width: `${Math.min(100, Number(r.risk_score) || 0)}%` }} /></div><strong>{r.risk_score}</strong></button>) : <Empty text="No risk records available." />}</div></section><section className="panel"><SectionHead title="Threat activity" detail="Recent correlated detections" action="All threats" onAction={() => onOpen('threats')} /><div className="activity-list">{threats.slice(0, 5).map(t => <button type="button" className="activity-row" key={t.threat_id} onClick={() => onOpen('threats')}><span className={`severity-dot ${String(t.severity).toLowerCase()}`} /><div><b>{t.threat_type}</b><small>{t.user_id} · {t.related_hostname || 'No host'}</small></div><span className={`badge ${String(t.severity).toLowerCase()}`}>{t.severity}</span></button>)}{!threats.length && <Empty text="No threat detections available." />}</div></section></div>
  </div>;
}

function Risk({ risk, onSelect, onAISelect }) { const [band, setBand] = useState('All'); const bands = ['All', 'Critical', 'High', 'Medium', 'Low']; const ranked = [...risk].filter(r => band === 'All' || r.risk_level === band).sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0)); return <div className="page-stack"><div className="page-intro split"><div><span className="kicker">RISK REGISTER</span><h2>Risk posture</h2><p>User-level risk scores generated from trusted cross-source signals. Select a ranked user to inspect evidence.</p></div><div className="segmented"><span>FILTER BY BAND</span>{bands.map(b => <button type="button" key={b} className={band === b ? 'selected' : ''} onClick={() => setBand(b)}>{b}{b !== 'All' && <em>{risk.filter(r => r.risk_level === b).length}</em>}</button>)}</div></div><DataTable headers={['Rank', 'User', 'Department', 'Status', 'Risk / threats', 'Score', 'Band', 'AI Action']} rows={ranked} empty="No users match the selected risk band." rowClick={onSelect} render={(r, i) => <><td><span className="queue-number">#{String(i + 1).padStart(2, '0')}</span></td><td><b>{r.full_name || r.username || r.user_id}</b><small>{r.user_id}</small></td><td>{r.department || '—'}</td><td><span className="status-label">{r.status || 'Active'}</span></td><td className="muted">{r.risk_drivers || `${r.endpoint_alerts || 0} endpoint alerts · ${r.iam_events || 0} IAM events`}</td><td><strong className="score">{r.risk_score}</strong></td><td><span className={`badge ${String(r.risk_level).toLowerCase()}`}>{r.risk_level}</span></td><td><button type="button" className="chip-btn" onClick={(e) => { e.stopPropagation(); onAISelect(r); }}><span>✦</span> AI Brief</button></td></>} /></div>; }
function Threats({ threats, onSelect }) { return <div className="page-stack"><div className="page-intro"><span className="kicker">DETECTION FEED</span><h2>Threat detections</h2><p>Correlated detections from endpoint, IAM and network evidence. Select a detection to investigate its user.</p></div><DataTable headers={['Detection', 'User', 'Type', 'Observed', 'Confidence', 'Severity']} rows={threats} empty="No threat detections available." rowClick={onSelect} render={t => <><td><b>{t.threat_id}</b><small>{t.related_hostname || 'No host'}</small></td><td>{t.user_id}</td><td>{t.threat_type}</td><td>{t.first_observed || '—'}</td><td><span className="badge high">{t.confidence || '—'}</span></td><td><span className={`badge ${String(t.severity).toLowerCase()}`}>{t.severity}</span></td></>} /></div>; }
function Queue({ rows, query, setQuery, onSelect }) { return <div className="page-stack"><div className="page-intro split"><div><span className="kicker">WORK QUEUE</span><h2>Investigation queue</h2><p>Start with the highest-confidence, highest-impact cases.</p></div><input className="search-input" aria-label="Search users or departments" value={query} onChange={e => setQuery(e.target.value)} placeholder="⌕  Search users or departments" /></div><DataTable headers={['Priority', 'User', 'Risk', 'Threats', 'Reason', 'Recommended action']} rows={rows} empty="No cases match your search." rowClick={onSelect} render={(r, i) => <><td><span className="queue-number">{String(i + 1).padStart(2, '0')}</span></td><td><b>{r.full_name || r.user_id}</b><small>{r.user_id} · {r.role || 'User'}</small></td><td><strong className="score">{r.risk_score}</strong><small>{r.risk_level}</small></td><td>{r.threat_detection_count || 0}</td><td className="muted">{r.investigation_reason || 'Review correlated telemetry'}</td><td className="action-text">{r.recommended_action || 'Open investigation'}</td></>} /></div>; }
function Investigation({ user, threats, risk, onAIInvestigate }) { const related = threats.filter(t => t.user_id === user?.user_id); const source = risk.find(r => r.user_id === user?.user_id) || user || {}; return <div className="page-stack"><div className="profile-header"><span className="profile-block">{(user?.full_name || user?.user_id || 'U').slice(0, 2).toUpperCase()}</span><div><span className="kicker">USER INVESTIGATION / {user?.user_id || 'UNAVAILABLE'}</span><h2>{user?.full_name || user?.username || user?.user_id || 'No user selected'}</h2><p>{user?.department || 'Unknown department'} · {user?.role || 'User'} · {user?.status || 'Status unavailable'}</p></div><div style={{ display: 'flex', gap: '8px', marginLeft: 'auto' }}><button className="primary-button" style={{ marginTop: 0 }} onClick={() => onAIInvestigate(user)}>✦ Investigate with AI Analyst</button><button className="primary-button" style={{ marginTop: 0, background: '#202b40', borderColor: '#3b4d70' }}>Create case</button></div></div><div className="content-grid"><section className="panel"><SectionHead title="Evidence timeline" detail="Observed threat timestamps from committed analytics" /><div className="timeline">{(related.length ? related : [{ threat_type: 'Risk score elevated', severity: user?.risk_level || 'Medium', first_observed: 'Latest telemetry stream', evidence: user?.risk_drivers || 'No additional evidence available.' }]).map((e, i) => <div className="timeline-row" key={i}><span className="timeline-dot" /><div><small>{e.first_observed}</small><b>{e.threat_type}</b><p>{e.evidence}</p></div><span className={`badge ${String(e.severity).toLowerCase()}`}>{e.severity}</span></div>)}</div></section><section className="panel"><SectionHead title="Investigation brief" detail="Analyst checklist" /><div className="brief-score"><strong>{user?.risk_score || '—'}</strong><span>risk score<br /><em>{user?.risk_level || 'Unknown'} band</em></span></div><ul className="checklist"><li>Validate identity and account status <small>OPEN</small></li><li>Correlate endpoint and IAM evidence <small>OPEN</small></li><li>Record disposition and owner <small>OPEN</small></li></ul></section></div></div>; }

function Quality({ quality }) { const rows = quality || fallback.quality; return <div className="page-stack"><div className="page-intro"><span className="kicker">TRUST & GOVERNANCE</span><h2>Data quality</h2><p>Know the reliability and coverage behind every investigation.</p></div><div className="stats-grid quality-grid"><Stat label="PIPELINES CHECKED" value={rows.length} detail="Read-only sources" /><Stat label="RELATIONSHIPS" value="Validated" detail="Identity ↔ telemetry" tone="teal" /><Stat label="WRITE ACCESS" value="None" detail="Committed inputs protected" tone="violet" /></div><DataTable headers={['Source', 'Status', 'Coverage', 'Quality notes']} rows={rows} render={r => <><td><b>{r.source}</b></td><td><span className="badge high">{r.status}</span></td><td>{r.coverage}</td><td className="muted">{r.issues || 'No blocking issues reported'}</td></>} /></div>; }

function MarkdownText({ text }) {
  if (!text) return null;
  const lines = text.split('\n');
  const elements = [];
  let listItems = [];
  let tableRows = [];

  const flushList = (key) => {
    if (listItems.length > 0) {
      elements.push(<ul key={`ul-${key}`}>{listItems}</ul>);
      listItems = [];
    }
  };

  const flushTable = (key) => {
    if (tableRows.length > 0) {
      const headers = tableRows[0];
      const rows = tableRows.slice(1);
      elements.push(
        <div className="table-wrap" key={`tbl-${key}`} style={{ margin: '14px 0' }}>
          <table>
            <thead>
              <tr>{headers.map((h, i) => <th key={i}>{formatInline(h)}</th>)}</tr>
            </thead>
            <tbody>
              {rows.map((row, ri) => (
                <tr key={ri}>
                  {row.map((cell, ci) => <td key={ci}>{formatInline(cell)}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
      tableRows = [];
    }
  };

  const formatInline = (str) => {
    if (!str) return '';
    const parts = str.split(/(\*\*.*?\*\*|`.*?`)/g);
    return parts.map((p, i) => {
      if (p.startsWith('**') && p.endsWith('**')) return <strong key={i}>{p.slice(2, -2)}</strong>;
      if (p.startsWith('`') && p.endsWith('`')) return <code key={i}>{p.slice(1, -1)}</code>;
      return p;
    });
  };

  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed) {
      flushList(idx);
      flushTable(idx);
      return;
    }

    if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
      flushList(idx);
      const cells = trimmed.split('|').map(c => c.trim()).filter((c, i, a) => i > 0 && i < a.length - 1);
      if (!cells.every(c => /^:?-+:?$/.test(c))) {
        tableRows.push(cells);
      }
      return;
    } else if (tableRows.length > 0) {
      flushTable(idx);
    }

    if (trimmed.startsWith('### ')) {
      flushList(idx);
      elements.push(<h3 key={idx}>{formatInline(trimmed.slice(4))}</h3>);
    } else if (trimmed.startsWith('#### ')) {
      flushList(idx);
      elements.push(<h4 key={idx}>{formatInline(trimmed.slice(5))}</h4>);
    } else if (trimmed.startsWith('• ') || trimmed.startsWith('- ')) {
      listItems.push(<li key={idx}>{formatInline(trimmed.slice(2))}</li>);
    } else if (/^\d+\.\s/.test(trimmed)) {
      listItems.push(<li key={idx}>{formatInline(trimmed.replace(/^\d+\.\s/, ''))}</li>);
    } else {
      flushList(idx);
      elements.push(<p key={idx}>{formatInline(trimmed)}</p>);
    }
  });

  flushList('end');
  flushTable('end');

  return <div className="ai-markdown-content">{elements}</div>;
}

function AnalystWorkspace({ selectedUser, riskUsers, onOpenUser }) {
  const defaultUser = selectedUser?.user_id || riskUsers?.[0]?.user_id || '';
  const [activeUser, setActiveUser] = useState(defaultUser);
  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: "### SOC AI Security Analyst Initialized\n\nI am connected directly to the cleaned telemetry datasets (Identity, IAM, Endpoint, Firewall, Risk Scores, Threat Detections).\n\nAsk any question or select a target user to run a full multi-signal investigation brief.",
      quick_actions: ["Investigate target user", "Why this risk?", "Show timeline", "Show evidence"],
      data_sources: ["Identity Asset Master", "IAM Audit Trail", "Endpoint Alerts", "Firewall Logs", "User Risk Scores"]
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (selectedUser?.user_id) {
      setActiveUser(selectedUser.user_id);
    } else if (!activeUser && riskUsers?.[0]?.user_id) {
      setActiveUser(riskUsers[0].user_id);
    }
  }, [selectedUser, riskUsers]);

  const sendQuery = async (queryText) => {
    const q = (queryText || input).trim();
    if (!q || loading) return;

    const userMsg = { sender: 'user', text: q };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const res = await fetch(`${API}/analyst/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: q, context: { user_id: activeUser } })
      });
      if (!res.ok) throw new Error('Agent API query failed');
      const data = await res.json();

      if (data.active_user_id) {
        setActiveUser(data.active_user_id);
      }

      setMessages(prev => [
        ...prev,
        {
          sender: 'ai',
          text: data.answer,
          investigation: data.investigation,
          quick_actions: data.quick_actions || [],
          data_sources: data.data_sources || []
        }
      ]);
    } catch (err) {
      setMessages(prev => [
        ...prev,
        {
          sender: 'ai',
          text: `### ⚠️ API Notice\n\nCould not communicate with local AI Agent endpoint: ${err.message}.\n\nPlease ensure backend server is running.`,
          quick_actions: ["Try again", "Who is the highest risk user?"],
          data_sources: ["Local Engine"]
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="analyst-workspace">
      <div className="analyst-hero">
        <div className="analyst-hero-text">
          <span className="kicker teal-text">NATURAL-LANGUAGE AI ANALYST ✦</span>
          <h2>SOC AI Investigation Assistant</h2>
          <p>Ask questions, inspect cross-source evidence, analyze post-termination anomalies, and receive recommended containment steps.</p>
        </div>
        <div className="active-user-badge">
          <span>TARGET USER:</span>
          <select value={activeUser} onChange={e => setActiveUser(e.target.value)}>
            <option value={activeUser}>{activeUser}</option>
            {riskUsers && riskUsers.map(r => r.user_id !== activeUser && (
              <option key={r.user_id} value={r.user_id}>
                {r.user_id} — {r.full_name || r.username || r.user_id} ({r.risk_level || 'Risk'})
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="quick-prompts-bar">
        <label>SUGGESTED ACTIONS:</label>
        {["Investigate " + activeUser, "Why is " + activeUser + " critical?", "Who is the highest risk user?", "Show timeline", "Show evidence", "What network traffic occurred?"].map((prompt, i) => (
          <button key={i} type="button" className="chip-btn" onClick={() => sendQuery(prompt)}>
            <span>✦</span> {prompt}
          </button>
        ))}
      </div>

      <div className="chat-history">
        {messages.map((msg, idx) => (
          <div key={idx} className={`chat-message ${msg.sender}`}>
            <div className="chat-bubble">
              {msg.sender === 'ai' && (
                <div className="ai-message-meta">
                  <div className="ai-agent-label"><span>✦</span> DEFEND AI ANALYST ENGINE</div>
                  {msg.data_sources && (
                    <div className="data-sources-tags">
                      {msg.data_sources.map((ds, i) => <span key={i} className="ds-tag">{ds}</span>)}
                    </div>
                  )}
                </div>
              )}

              {msg.sender === 'user' ? (
                <p style={{ margin: 0 }}>{msg.text}</p>
              ) : (
                <>
                  <MarkdownText text={msg.text} />

                  {msg.investigation && (
                    <div className="report-embed-card">
                      <div className="report-embed-header">
                        <div className="report-user-info">
                          <h4>{msg.investigation.user_name} ({msg.investigation.user_id})</h4>
                          <p>Employment Status: <strong>{msg.investigation.employment_status}</strong></p>
                        </div>
                        <span className={`badge ${String(msg.investigation.overall_risk?.band || 'Medium').toLowerCase()}`}>
                          {msg.investigation.overall_risk?.score}/100 {msg.investigation.overall_risk?.band} RISK
                        </span>
                      </div>

                      {msg.investigation.overall_risk?.breakdown && (
                        <div className="risk-breakdown-grid">
                          {Object.entries(msg.investigation.overall_risk.breakdown).map(([dim, score]) => (
                            <div key={dim} className="rb-item">
                              <label><span>{dim.replace('_', ' ')}</span><strong>{score}/100</strong></label>
                              <div className="rb-bar"><i style={{ width: `${Math.min(100, score)}%` }} /></div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {msg.quick_actions && msg.quick_actions.length > 0 && (
                    <div className="quick-prompts-bar" style={{ marginTop: '16px', paddingTop: '12px', borderTop: '1px solid #1c2742' }}>
                      <label>FOLLOW-UP PROMPTS:</label>
                      {msg.quick_actions.map((act, i) => (
                        <button key={i} type="button" className="chip-btn" onClick={() => sendQuery(act)}>
                          <span>→</span> {act}
                        </button>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div className="thinking-indicator">
            <div className="thinking-dot" />
            <span>AI Agent is correlating telemetry logs and building evidence brief...</span>
          </div>
        )}
      </div>

      <form className="chat-input-panel" onSubmit={e => { e.preventDefault(); sendQuery(); }}>
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder={`✦ Ask AI Analyst about ${activeUser} or telemetry... (e.g. 'Show timeline', 'Why this risk?')`}
          disabled={loading}
        />
        <button type="submit" className="send-btn" disabled={loading || !input.trim()}>
          <span>✦</span> Send Query
        </button>
      </form>
    </div>
  );
}

function DataTable({ title, detail, headers, rows, render, rowClick, empty }) { return <section className="panel table-panel">{title && <SectionHead title={title} detail={detail} />}<div className="table-wrap"><table><thead><tr>{headers.map(h => <th key={h}>{h}</th>)}</tr></thead><tbody>{rows.length ? rows.map((r, i) => <tr key={i} tabIndex={rowClick ? 0 : undefined} role={rowClick ? 'button' : undefined} aria-label={rowClick ? `Open investigation for ${r.full_name || r.username || r.user_id || r.threat_id}` : undefined} onClick={() => rowClick?.(r)} onKeyDown={e => e.key === 'Enter' && rowClick?.(r)}>{render(r, i)}</tr>) : <tr><td className="empty-cell" colSpan={headers.length}><Empty text={empty} /></td></tr>}</tbody></table></div></section>; }
const Empty = ({ text }) => <div className="empty-state"><span>◌</span>{text}</div>;
createRoot(document.getElementById('root')).render(<App />);

