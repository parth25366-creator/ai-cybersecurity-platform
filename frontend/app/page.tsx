"use client";
import { useState } from "react";
import ReactMarkdown from "react-markdown";

type Msg = { role: "user" | "ai"; text: string; tools?: string[] };
type Session = { token: string; role: string };

const box = { padding: 10, borderRadius: 8, border: "1px solid #334155", background: "#1e293b", color: "inherit" };
const btn = { ...box, background: "#2563eb", cursor: "pointer" };
const EXAMPLES = ["Summarize CVE-2021-44228 and is it actively exploited?", "What are the first steps in our ransomware playbook?"];

const errText = (d: unknown) => (typeof d === "string" ? d : JSON.stringify(d));

export default function Home() {
  const [session, setSession] = useState<Session | null>(null); // memory only: safer against XSS, lost on refresh
  const [register, setRegister] = useState(false);
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");

  async function auth(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    if (register) {
      const r = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: form.get("username"), password: form.get("password") }),
      });
      if (!r.ok) return setNote(`Registration failed: ${errText((await r.json()).detail)}`);
    }
    const res = await fetch("/api/auth/login", { method: "POST", body: form });
    const data = await res.json();
    if (!res.ok) return setNote(`Login failed: ${errText(data.detail)}`);
    setNote("");
    setSession({ token: data.access_token, role: data.role });
  }

  async function send(question = input) {
    const q = question.trim();
    if (!q || busy || !session) return;
    setMsgs((m) => [...m, { role: "user", text: q }]);
    setInput("");
    setBusy(true);
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.token}` },
      body: JSON.stringify({ question: q }),
    });
    const data = await res.json();
    setMsgs((m) => [...m, { role: "ai", text: res.ok ? data.answer : `Error: ${errText(data.detail)}`, tools: data.tools_used }]);
    setBusy(false);
  }

  async function upload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file || !session) return;
    const body = new FormData();
    body.append("file", file);
    setNote(`Indexing ${file.name}…`);
    const res = await fetch("/api/kb/upload", { method: "POST", headers: { Authorization: `Bearer ${session.token}` }, body });
    const data = await res.json();
    setNote(res.ok ? `Indexed ${file.name} (${data.chunks} chunks)` : `Upload failed: ${errText(data.detail)}`);
    e.target.value = "";
  }

  if (!session)
    return (
      <form onSubmit={auth} style={{ maxWidth: 320, margin: "18vh auto", display: "grid", gap: 10 }}>
        <h2>AI Cybersecurity Platform</h2>
        <input name="username" type="email" placeholder="Email" required style={box} />
        <input name="password" type="password" placeholder="Password (10+ characters)" minLength={10} required style={box} />
        <button style={btn}>{register ? "Create account" : "Sign in"}</button>
        <a onClick={() => setRegister(!register)} style={{ cursor: "pointer", color: "#93c5fd", fontSize: 14 }}>
          {register ? "Have an account? Sign in" : "New here? Create an account"}
        </a>
        {note && <small style={{ color: "#fca5a5" }}>{note}</small>}
      </form>
    );

  const canUpload = session.role !== "viewer";
  return (
    <main style={{ maxWidth: 800, margin: "0 auto", padding: 20, display: "grid", gap: 12 }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h2>Security Assistant</h2>
        <span style={{ fontSize: 14 }}>
          role: <b>{session.role}</b>{" "}
          <a onClick={() => { setSession(null); setMsgs([]); }} style={{ cursor: "pointer", color: "#93c5fd" }}>sign out</a>
        </span>
      </header>
      {canUpload && (
        <label style={{ ...box, cursor: "pointer", fontSize: 14 }}>
          Add to knowledge base (.pdf, .txt, .md): <input type="file" accept=".pdf,.txt,.md" onChange={upload} />
        </label>
      )}
      {note && <small>{note}</small>}
      {!msgs.length && EXAMPLES.map((ex) => (
        <button key={ex} onClick={() => send(ex)} style={{ ...box, cursor: "pointer", textAlign: "left" }}>{ex}</button>
      ))}
      {msgs.map((m, i) => (
        <div key={i} style={{ ...box, background: m.role === "user" ? "#1d4ed8" : "#1e293b" }}>
          <ReactMarkdown>{m.text}</ReactMarkdown>
          {!!m.tools?.length && <small style={{ opacity: 0.7 }}>tools used: {[...new Set(m.tools)].join(", ")}</small>}
        </div>
      ))}
      {busy && <em>Investigating…</em>}
      <div style={{ display: "flex", gap: 8 }}>
        <input value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === "Enter" && send()}
          placeholder="Ask about a CVE, an incident, or your playbooks" maxLength={2000} style={{ ...box, flex: 1 }} />
        <button onClick={() => send()} style={btn}>Send</button>
      </div>
    </main>
  );
}
