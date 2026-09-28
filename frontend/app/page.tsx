"use client";
import { useState } from "react";
import ReactMarkdown from "react-markdown";

type Msg = { role: "user" | "ai"; text: string };
const box = { padding: 10, borderRadius: 8, border: "1px solid #334155", background: "#1e293b", color: "inherit" };

export default function Home() {
  const [token, setToken] = useState<string | null>(null); // memory only: safer against XSS, lost on refresh
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);

  async function login(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const res = await fetch("/api/auth/login", { method: "POST", body: new FormData(e.currentTarget) });
    if (!res.ok) return alert("Login failed");
    setToken((await res.json()).access_token);
  }

  async function send() {
    const q = input.trim();
    if (!q || busy) return;
    setMsgs((m) => [...m, { role: "user", text: q }]);
    setInput("");
    setBusy(true);
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ question: q }),
    });
    const data = await res.json();
    setMsgs((m) => [...m, { role: "ai", text: res.ok ? data.answer : `Error: ${JSON.stringify(data.detail)}` }]);
    setBusy(false);
  }

  if (!token)
    return (
      <form onSubmit={login} style={{ maxWidth: 320, margin: "20vh auto", display: "grid", gap: 10 }}>
        <h2>AI Cybersecurity Platform</h2>
        <input name="username" placeholder="Email" required style={box} />
        <input name="password" type="password" placeholder="Password" required style={box} />
        <button style={{ ...box, background: "#2563eb", cursor: "pointer" }}>Sign in</button>
      </form>
    );

  return (
    <main style={{ maxWidth: 800, margin: "0 auto", padding: 20, display: "grid", gap: 12 }}>
      <h2>Security Assistant</h2>
      {msgs.map((m, i) => (
        <div key={i} style={{ ...box, background: m.role === "user" ? "#1d4ed8" : "#1e293b" }}>
          <ReactMarkdown>{m.text}</ReactMarkdown>
        </div>
      ))}
      {busy && <em>Investigating…</em>}
      <div style={{ display: "flex", gap: 8 }}>
        <input value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === "Enter" && send()}
          placeholder="e.g. Summarize CVE-2021-44228 and our playbook for it" style={{ ...box, flex: 1 }} />
        <button onClick={send} style={{ ...box, background: "#2563eb", cursor: "pointer" }}>Send</button>
      </div>
    </main>
  );
}
