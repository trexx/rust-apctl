import { useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { announceUnauthorized, terminalSocket } from "../api";
import type { Mac } from "../api";

type State =
  | { at: "connecting" }
  | { at: "connected" }
  | { at: "closed"; why: string; failed: boolean };

/** The page's colours, as the terminal takes them (read when it opens). */
function theme() {
  const css = getComputedStyle(document.documentElement);
  const v = (name: string) => css.getPropertyValue(name).trim();
  return {
    background: v("--panel"),
    foreground: v("--text"),
    cursor: v("--accent"),
    selectionBackground: v("--grid"),
  };
}

/**
 * A shell on the AP over SSH, through apctl. What is typed goes as binary
 * frames, the size as JSON; the server says `{"connected":true}` once the
 * shell runs, or `{"error":…}` before it closes.
 */
export function Terminal({
  mac,
  name,
  onClose,
}: {
  mac: Mac;
  name: string;
  onClose: () => void;
}) {
  const box = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<State>({ at: "connecting" });
  // A new one opens the terminal again.
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const term = new XTerm({
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
      fontSize: 13,
      cursorBlink: true,
      theme: theme(),
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(el);
    fit.fit();
    const socket = terminalSocket(mac, term.cols, term.rows);
    socket.binaryType = "arraybuffer";
    const encoder = new TextEncoder();
    const send = (data: Uint8Array<ArrayBuffer> | string) => {
      if (socket.readyState === WebSocket.OPEN) socket.send(data);
    };
    let error: string | null = null;
    socket.onmessage = (e: MessageEvent<ArrayBuffer | string>) => {
      if (typeof e.data !== "string") {
        term.write(new Uint8Array(e.data));
        return;
      }
      const msg = JSON.parse(e.data) as { connected?: boolean; error?: string };
      if (msg.connected) {
        setState({ at: "connected" });
        term.focus();
      }
      if (msg.error) error = msg.error;
    };
    socket.onclose = (e) => {
      // 1008: the session ended (logged out or expired).
      if (e.code === 1008) announceUnauthorized();
      setState({
        at: "closed",
        why: error ?? (e.reason || "the connection to apctl was lost"),
        // 1000: the shell exited, or was idle too long.
        failed: error !== null || e.code !== 1000,
      });
    };
    const subscriptions = [
      term.onData((d) => send(encoder.encode(d))),
      // Mouse reports in the legacy encoding: one byte per character.
      term.onBinary((d) => send(Uint8Array.from(d, (c) => c.charCodeAt(0)))),
      term.onResize(({ cols, rows }) => send(JSON.stringify({ cols, rows }))),
    ];
    const resized = new ResizeObserver(() => fit.fit());
    resized.observe(el);
    return () => {
      resized.disconnect();
      subscriptions.forEach((s) => s.dispose());
      socket.onclose = null;
      socket.close();
      term.dispose();
    };
  }, [mac, attempt]);

  return (
    <div className="panel terminal">
      <div className="panel-head">
        <b>Terminal</b>
        <span className="muted small">
          {state.at === "connecting"
            ? `connecting to ${name}…`
            : state.at === "connected"
              ? `${name} over SSH`
              : null}
        </span>
        {state.at === "closed" && (
          <span className={`small ${state.failed ? "error" : "muted"}`}>
            Closed: {state.why}
          </span>
        )}
        <span className="spacer" />
        {state.at === "closed" && (
          <button
            className="btn small"
            onClick={() => {
              setState({ at: "connecting" });
              setAttempt((a) => a + 1);
            }}
          >
            Reconnect
          </button>
        )}
        <button className="btn small" onClick={onClose}>
          Close
        </button>
      </div>
      <div className="terminal-screen" ref={box} />
    </div>
  );
}
