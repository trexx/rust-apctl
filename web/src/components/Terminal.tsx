import { useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { announceUnauthorized, terminalSocket } from "../api";
import type { Mac } from "../api";

/** The most one frame of input holds: a paste goes in pieces (the server takes 64 KiB at most). */
const CHUNK = 16 << 10;
/** Flow control: with this much output written but not yet shown, the server is asked to pause the AP's… */
const HIGH = 128 << 10;
/** …and below this, to go on. */
const LOW = 16 << 10;

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
 * frames, the size and `{"pause":…}` as JSON; the server says
 * `{"connected":true}` once the shell runs, or `{"error":…}` before it
 * closes (a refusal before the socket opens has no words: the browser hides
 * it). Nothing is sent before the shell runs.
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
    const initial = { cols: term.cols, rows: term.rows };
    const socket = terminalSocket(mac, initial.cols, initial.rows);
    socket.binaryType = "arraybuffer";
    const encoder = new TextEncoder();
    let connected = false;
    const send = (data: Uint8Array<ArrayBuffer> | string) => {
      if (connected && socket.readyState === WebSocket.OPEN) socket.send(data);
    };
    const sendBytes = (bytes: Uint8Array<ArrayBuffer>) => {
      for (let at = 0; at < bytes.length; at += CHUNK)
        send(bytes.subarray(at, at + CHUNK));
    };
    const sendSize = ({ cols, rows }: { cols: number; rows: number }) =>
      send(JSON.stringify({ cols, rows }));
    // Output written to the terminal but not yet shown, and whether the AP's is paused for it.
    let backlog = 0;
    let paused = false;
    const pause = (on: boolean) => {
      paused = on;
      send(JSON.stringify({ pause: on }));
    };
    let error: string | null = null;
    let opened = false;
    socket.onopen = () => {
      opened = true;
    };
    socket.onmessage = (e: MessageEvent<ArrayBuffer | string>) => {
      if (typeof e.data !== "string") {
        const n = e.data.byteLength;
        backlog += n;
        term.write(new Uint8Array(e.data), () => {
          backlog -= n;
          if (paused && backlog < LOW) pause(false);
        });
        if (!paused && backlog > HIGH) pause(true);
        return;
      }
      const msg = JSON.parse(e.data) as { connected?: boolean; error?: string };
      if (msg.connected) {
        connected = true;
        // Resized while it connected: the shell started at the size it opened with.
        if (term.cols !== initial.cols || term.rows !== initial.rows)
          sendSize(term);
        setState({ at: "connected" });
        term.focus();
      }
      if (msg.error) error = msg.error;
    };
    socket.onclose = (e) => {
      // 1008: the session ended (logged out or expired). One that never opened
      // was refused before the upgrade, maybe for a session that ended (the
      // browser hides the 401): /api/me tells, as for the live socket.
      if (e.code === 1008 || !opened) announceUnauthorized();
      const lost = opened
        ? "the connection to apctl was lost"
        : "apctl refused the terminal, or could not be reached";
      setState({
        at: "closed",
        why: error ?? (e.reason || lost),
        // 1000: the shell exited, or was idle too long.
        failed: error !== null || e.code !== 1000,
      });
    };
    const subscriptions = [
      term.onData((d) => sendBytes(encoder.encode(d))),
      // Mouse reports in the legacy encoding: one byte per character.
      term.onBinary((d) =>
        sendBytes(Uint8Array.from(d, (c) => c.charCodeAt(0))),
      ),
      term.onResize(sendSize),
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
