import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { Activity, Ban, Database, LogIn, RadioTower, Send, ShieldAlert, ShieldCheck, Zap } from "lucide-react";
import "./styles.css";

const API = import.meta.env.VITE_API_URL || "";

async function api(path, options = {}) {
  const token = localStorage.getItem("xpulse_token");
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${API}${path}`, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || data.message || "Request failed");
  return data;
}

function App() {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("analyst");
  const [password, setPassword] = useState("securepass");
  const [content, setContent] = useState("Watching the perimeter light up in real time.");
  const [posts, setPosts] = useState([]);
  const [dashboard, setDashboard] = useState({ stats: {}, events: [], blocked_ips: [] });
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const isAuthed = Boolean(localStorage.getItem("xpulse_token"));
  const riskTone = useMemo(() => {
    const top = dashboard.events?.[0]?.risk_score || 0;
    if (top > 80) return "critical";
    if (top > 60) return "warn";
    return "calm";
  }, [dashboard.events]);

  async function refresh() {
    const [feed, dash] = await Promise.all([api("/api/feed"), api("/cyberagent/dashboard")]);
    setPosts(feed.posts);
    setDashboard(dash);
  }

  useEffect(() => {
    refresh().catch(() => {});
    const id = setInterval(() => refresh().catch(() => {}), 2500);
    return () => clearInterval(id);
  }, []);

  async function submitAuth(event) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      const data = await api(`/api/${mode}`, {
        method: "POST",
        body: JSON.stringify({ username, password })
      });
      localStorage.setItem("xpulse_token", data.token);
      setMessage(`${mode === "login" ? "Logged in" : "Signed up"} as ${data.user.username}`);
      await refresh();
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function createPost(event) {
    event.preventDefault();
    setBusy(true);
    try {
      await api("/api/posts", { method: "POST", body: JSON.stringify({ content }) });
      setContent("");
      setMessage("Post published");
      await refresh();
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function simulate(kind) {
    setBusy(true);
    setMessage("");
    try {
      if (kind === "sql") {
        await api("/simulate/sql-injection?q=%27%20OR%201%3D1%20--");
      }
      if (kind === "xss") {
        await api("/simulate/xss", { method: "POST", body: JSON.stringify({ post: "<script>alert('xss')</script>" }) });
      }
      if (kind === "rapid") {
        await Promise.all(Array.from({ length: 16 }, () => api("/simulate/ping").catch((error) => ({ blocked: true, error: error.message }))));
      }
      setMessage(`Simulation sent: ${kind}`);
    } catch (error) {
      setMessage(error.message);
    } finally {
      await refresh().catch(() => {});
      setBusy(false);
    }
  }

  return (
    <main className={`app ${riskTone}`}>
      <section className="topbar">
        <div>
          <span className="eyebrow"><ShieldCheck size={16} /> CyberAgent Middleware</span>
          <h1>XPulse Security Operations Demo</h1>
        </div>
        <div className="status">
          <RadioTower size={18} />
          <span>Live polling</span>
        </div>
      </section>

      <section className="grid">
        <div className="panel xpulse">
          <div className="panel-title">
            <Activity size={20} />
            <h2>XPulse Feed</h2>
          </div>
          {!isAuthed && (
            <form className="auth" onSubmit={submitAuth}>
              <div className="segmented">
                <button type="button" className={mode === "login" ? "active" : ""} onClick={() => setMode("login")}>Login</button>
                <button type="button" className={mode === "signup" ? "active" : ""} onClick={() => setMode("signup")}>Signup</button>
              </div>
              <input value={username} onChange={(event) => setUsername(event.target.value)} placeholder="Username" />
              <input value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Password" type="password" />
              <button className="primary" disabled={busy}><LogIn size={16} /> Continue</button>
            </form>
          )}
          {isAuthed && (
            <form className="composer" onSubmit={createPost}>
              <textarea value={content} onChange={(event) => setContent(event.target.value)} maxLength="280" />
              <button className="primary" disabled={busy}><Send size={16} /> Post</button>
            </form>
          )}
          {message && <p className="message">{message}</p>}
          <div className="feed">
            {posts.map((post) => (
              <article className="post" key={post.id}>
                <strong>@{post.username}</strong>
                <p>{post.content}</p>
                <time>{new Date(post.created_at * 1000).toLocaleString()}</time>
              </article>
            ))}
          </div>
        </div>

        <div className="panel controls">
          <div className="panel-title">
            <Zap size={20} />
            <h2>Attack Simulation</h2>
          </div>
          <button onClick={() => simulate("sql")} disabled={busy}>SQL Injection</button>
          <button onClick={() => simulate("xss")} disabled={busy}>XSS Payload</button>
          <button onClick={() => simulate("rapid")} disabled={busy}>Rapid Requests</button>
        </div>

        <div className="panel metrics">
          <div className="metric">
            <ShieldAlert size={22} />
            <span>{dashboard.stats?.total_events || 0}</span>
            <label>Total events</label>
          </div>
          <div className="metric">
            <Database size={22} />
            <span>{dashboard.stats?.events_last_hour || 0}</span>
            <label>Last hour</label>
          </div>
          <div className="metric">
            <Ban size={22} />
            <span>{dashboard.blocked_ips?.length || 0}</span>
            <label>Banned IPs</label>
          </div>
        </div>

        <div className="panel dashboard">
          <div className="panel-title">
            <ShieldAlert size={20} />
            <h2>CyberAgent Events</h2>
          </div>
          <div className="table">
            <div className="row head">
              <span>Time</span><span>IP</span><span>Route</span><span>Attack</span><span>Risk</span><span>Action</span>
            </div>
            {(dashboard.events || []).map((event) => (
              <div className="row" key={event.id}>
                <span>{new Date(event.timestamp * 1000).toLocaleTimeString()}</span>
                <span>{event.ip}</span>
                <span>{event.route}</span>
                <span>{event.attack_type}</span>
                <span className="risk">{event.risk_score}</span>
                <span className={`action ${event.action}`}>{event.action}</span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);

