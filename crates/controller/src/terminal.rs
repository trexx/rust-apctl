//! A terminal on an AP, in the browser: a WebSocket carried to a shell over SSH.
//!
//! The page sends what is typed as binary frames, and its size as text ones
//! (`{"cols":80,"rows":24}`; the first in the query); apctl sends what the
//! shell prints as binary frames, `{"connected":true}` once it runs, and
//! `{"error":"…"}` before closing when it cannot. What went wrong goes over the
//! socket rather than as an HTTP status, which a browser hides from the page.
//!
//! The login is the site's device one, else the factory ones, as for adoption
//! over SSH. Unlike adoption, the AP's host key must be known already (from its
//! informs or its record): no password goes to, and no root shell is opened
//! on, a host taken on trust. Each terminal opened is an event naming the user.

use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade, close_code};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use inform::Mac;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{ApiError, AppState, MacPath};
use crate::auth::SessionId;
use crate::clock;
use crate::engine::{Event, EventKind};
use crate::ssh::{self, Failure};

/// How long a terminal stays open with nothing typed.
const IDLE: Duration = Duration::from_secs(30 * 60);
/// How many terminals may be open at once, over all APs and users.
static OPEN: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
/// The most a frame from the page may hold: keystrokes, or a paste.
const MAX_FRAME: usize = 64 << 10;

/// A terminal's size in characters, as the page measures it.
#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct Size {
    cols: Option<u32>,
    rows: Option<u32>,
}

impl Size {
    /// Within bounds, and 80×24 for what the page left out.
    fn clamped(&self) -> (u32, u32) {
        (self.cols.unwrap_or(80).clamp(1, 500), self.rows.unwrap_or(24).clamp(1, 200))
    }
}

/// GET /api/devices/{mac}/terminal?cols=&rows= (a WebSocket, for pages of
/// this server: see the socket router).
pub async fn open(
    State(s): State<AppState>,
    MacPath(mac): MacPath,
    uri: axum::http::Uri,
    session: Option<axum::Extension<SessionId>>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let size = match Query::<Size>::try_from_uri(&uri) {
        Ok(Query(size)) => size,
        Err(e) => return ApiError::from(e).into_response(),
    };
    // Always there: the route is withheld in read-only mode, which has no sessions.
    let Some(axum::Extension(session)) = session else { return ApiError::forbidden("a terminal needs a login").into_response() };
    upgrade.max_message_size(MAX_FRAME).on_upgrade(move |socket| terminal(socket, s, mac, size, session))
}

/// Where and how to log in to an AP for its terminal.
#[derive(Debug)]
struct Target {
    ip: String,
    port: u16,
    /// The host key's fingerprint: always known (see the module's doc).
    expected: String,
    logins: Vec<(String, String)>,
}

/// Whether a terminal can be opened on the AP, and how.
fn target(s: &AppState, mac: &Mac) -> Result<Target, String> {
    crate::api::require_active(s, "a terminal needs").map_err(|e| e.1)?;
    let live = s.live.read().unwrap();
    let d = live.devices.get(mac).ok_or("unknown AP (or it hasn't reported since apctl started)")?;
    if !d.online {
        return Err("the AP is offline".into());
    }
    let ip = d.snapshot.ap.ip.clone().ok_or("the AP hasn't reported its address")?;
    let state = live.state.as_deref();
    let expected = crate::ssh::expected_host_key(&live, state.unwrap_or(&Value::Null), mac)
        .ok_or("apctl doesn't know the AP's SSH host key yet: it learns it from the AP's reports")?;
    Ok(Target { ip, port: 22, expected, logins: crate::ssh::logins(state, None) })
}

/// What ended a terminal.
#[derive(Debug, PartialEq)]
enum End {
    /// The page closed it, or went away.
    Gone,
    /// The shell exited, or the AP ended the session.
    Exited,
    LoggedOut,
    Idle,
}

/// Runs a terminal, then tells the page why it ended.
async fn terminal(mut socket: WebSocket, s: AppState, mac: Mac, size: Size, session: SessionId) {
    let end = match (OPEN.try_acquire(), target(&s, &mac)) {
        (Err(_), _) => Err("too many terminals are open: close one first".into()),
        (Ok(_open), Ok(t)) => bridge(&mut socket, &s, mac, t, &size, &session).await,
        (Ok(_), Err(e)) => Err(e),
    };
    finish(socket, end).await;
}

/// Tells the page why its terminal ended (unless it went away), and closes the socket.
async fn finish(mut socket: WebSocket, end: Result<End, String>) {
    let close = |code, reason| Message::Close(Some(CloseFrame { code, reason: Utf8Bytes::from_static(reason) }));
    let last = match end {
        Ok(End::Gone) => return,
        Ok(End::Exited) => close(close_code::NORMAL, "the shell ended"),
        Ok(End::Idle) => close(close_code::NORMAL, "closed after 30 minutes without input"),
        Ok(End::LoggedOut) => crate::api::logged_out(),
        Err(e) => {
            let _ = socket.send(Message::Text(json!({ "error": e }).to_string().into())).await;
            close(close_code::ERROR, "failed")
        }
    };
    let _ = socket.send(last).await;
}

/// Logs in to the AP, starts its shell, and carries the terminal both ways
/// until one side ends it.
async fn bridge(socket: &mut WebSocket, s: &AppState, mac: Mac, t: Target, size: &Size, session: &SessionId) -> Result<End, String> {
    let ssh = match ssh::connect(ssh::shell_config(), &t.ip, t.port, &t.logins, Some(t.expected)).await {
        Err(Failure::HostKey) => return Err(ssh::host_key_mismatch(s, mac, &t.ip).await.to_string()),
        r => r.map_err(|f| f.to_string())?,
    };
    let (cols, rows) = size.clamped();
    let ch = ssh.shell(cols, rows).await.map_err(|f| f.to_string())?;
    s.note(Event::device(clock::now_ts(), EventKind::ApTerminalOpened, mac, json!({ "user": session.user }))).await;
    tracing::info!("{mac}: terminal opened by {}", session.user);
    if socket.send(Message::Text(Utf8Bytes::from_static(r#"{"connected":true}"#))).await.is_err() {
        return Ok(End::Gone);
    }
    let (mut output, input) = ch.split();
    let ended = crate::api::session_ends(&s.auth, Some(&session.hash));
    let idle = tokio::time::sleep(IDLE);
    tokio::pin!(ended, idle);
    let end = loop {
        tokio::select! {
            _ = &mut ended => break End::LoggedOut,
            _ = &mut idle => break End::Idle,
            msg = output.wait() => match msg {
                Some(russh::ChannelMsg::Data { data } | russh::ChannelMsg::ExtendedData { data, .. }) => {
                    if socket.send(Message::Binary(data)).await.is_err() {
                        break End::Gone;
                    }
                }
                Some(russh::ChannelMsg::Close) | None => break End::Exited,
                _ => {}
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Binary(typed))) => {
                    idle.as_mut().reset(tokio::time::Instant::now() + IDLE);
                    if input.data_bytes(typed).await.is_err() {
                        break End::Exited;
                    }
                }
                Some(Ok(Message::Text(text))) => {
                    if let Ok(size) = serde_json::from_str::<Size>(&text) {
                        let (cols, rows) = size.clamped();
                        let _ = input.window_change(cols, rows, 0, 0).await;
                    }
                }
                Some(Ok(Message::Close(_)) | Err(_)) | None => break End::Gone,
                _ => {}
            },
        }
    };
    ssh.close().await;
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn sizes_are_kept_within_bounds() {
        let size = |text: &str| serde_json::from_str::<Size>(text).unwrap().clamped();
        assert_eq!(size(r#"{"cols":120,"rows":40}"#), (120, 40));
        assert_eq!(size("{}"), (80, 24), "left out: the usual size");
        assert_eq!(size(r#"{"cols":0,"rows":100000}"#), (1, 200));
        assert!(serde_json::from_str::<Size>(r#"{"cols":-1}"#).is_err());
    }

    /// An AP's SSH server, as far as a terminal needs one: `ubnt`/`ubnt` logs
    /// in, the shell echoes what is typed in capitals and exits at `exit`, and
    /// the sizes it was given are kept.
    #[derive(Clone, Default)]
    struct Shell {
        sizes: Arc<std::sync::Mutex<Vec<(u32, u32)>>>,
    }

    impl russh::server::Handler for Shell {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<russh::server::Auth, Self::Error> {
            Ok(if (user, password) == ("ubnt", "ubnt") { russh::server::Auth::Accept } else { russh::server::Auth::reject() })
        }

        async fn channel_open_session(&mut self, _: russh::Channel<russh::server::Msg>, reply: russh::server::ChannelOpenHandle, _: &mut russh::server::Session) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn pty_request(&mut self, _: russh::ChannelId, term: &str, cols: u32, rows: u32, _: u32, _: u32, _: &[(russh::Pty, u32)], _: &mut russh::server::Session) -> Result<(), Self::Error> {
            assert_eq!(term, "xterm-256color");
            self.sizes.lock().unwrap().push((cols, rows));
            Ok(())
        }

        async fn window_change_request(&mut self, _: russh::ChannelId, cols: u32, rows: u32, _: u32, _: u32, _: &mut russh::server::Session) -> Result<(), Self::Error> {
            self.sizes.lock().unwrap().push((cols, rows));
            Ok(())
        }

        async fn data(&mut self, ch: russh::ChannelId, data: &[u8], session: &mut russh::server::Session) -> Result<(), Self::Error> {
            if data == b"exit\r" {
                session.exit_status_request(ch, 0)?;
                return session.close(ch);
            }
            session.data(ch, data.to_ascii_uppercase())
        }
    }

    /// A frame from the page: masked, as a browser sends it (with a zero mask, so as it is).
    async fn send(tcp: &mut tokio::net::TcpStream, op: u8, payload: &[u8]) {
        use tokio::io::AsyncWriteExt;
        assert!(payload.len() < 126);
        let mut f = vec![0x80 | op, 0x80 | payload.len() as u8, 0, 0, 0, 0];
        f.extend_from_slice(payload);
        tcp.write_all(&f).await.unwrap();
    }

    #[tokio::test]
    async fn a_terminal_carries_keystrokes_output_and_sizes_and_checks_the_host_key() {
        use crate::api::tests::{frame, handshake, serve};
        use axum::routing::get;
        let key = russh::keys::PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]));
        let fingerprint = key.public_key().fingerprint(russh::keys::HashAlg::Sha256).to_string();
        let config = Arc::new(russh::server::Config { keys: vec![key], ..Default::default() });
        let shell = Shell::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = shell.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (config, shell) = (config.clone(), server.clone());
                tokio::spawn(async move {
                    if let Ok(session) = russh::server::run_stream(config, tcp, shell).await {
                        let _ = session.await;
                    }
                });
            }
        });

        let (s, mut engine, _dir) = crate::api::tests::state();
        let mac: Mac = "02:00:00:00:00:01".parse().unwrap();
        let logins = vec![("ubnt".to_string(), "wrong".to_string()), ("ubnt".to_string(), "ubnt".to_string())];
        let session = s.auth.session_of(&s.auth.create("admin")).unwrap();
        let app = axum::Router::new()
            .route(
                "/t/{key}",
                get(move |State(s): State<AppState>, axum::extract::Path(key): axum::extract::Path<String>, upgrade: WebSocketUpgrade| async move {
                    let expected = if key == "known" { fingerprint } else { "SHA256:other".into() };
                    let t = Target { ip: "127.0.0.1".into(), port, expected, logins };
                    upgrade.on_upgrade(move |mut socket| async move {
                        let end = bridge(&mut socket, &s, mac, t, &Size { cols: Some(100), rows: Some(30) }, &session).await;
                        finish(socket, end).await;
                    })
                }),
            )
            .with_state(s);
        let addr = serve(app).await;

        let (status, mut tcp) = handshake(addr, "/t/known", "", None).await;
        assert_eq!(status, "101");
        assert_eq!(frame(&mut tcp).await, (1, br#"{"connected":true}"#.to_vec()));
        let Some(crate::engine::Input::Note(e)) = engine.recv().await else { panic!("no event") };
        assert_eq!(e.kind, EventKind::ApTerminalOpened);
        send(&mut tcp, 2, b"uptime").await;
        assert_eq!(frame(&mut tcp).await, (2, b"UPTIME".to_vec()));
        // A resize, then a keystroke: the shell has the size by the time it echoes.
        send(&mut tcp, 1, br#"{"cols":120,"rows":40}"#).await;
        send(&mut tcp, 2, b"x").await;
        assert_eq!(frame(&mut tcp).await, (2, b"X".to_vec()));
        assert_eq!(*shell.sizes.lock().unwrap(), [(100, 30), (120, 40)]);
        // The shell exits: a normal close, saying so.
        send(&mut tcp, 2, b"exit\r").await;
        let (op, close) = frame(&mut tcp).await;
        assert_eq!((op, &close[..2], &close[2..]), (8, &1000u16.to_be_bytes()[..], &b"the shell ended"[..]));

        // A host key other than the one expected: no login, and an event.
        let (_, mut tcp) = handshake(addr, "/t/changed", "", None).await;
        let (op, text) = frame(&mut tcp).await;
        assert_eq!((op, serde_json::from_slice::<Value>(&text).unwrap()["error"].as_str()), (1, Some("the AP's SSH host key isn't the one apctl knows for it")));
        let Some(crate::engine::Input::Note(e)) = engine.recv().await else { panic!("no event") };
        assert_eq!(e.kind, EventKind::ApHostKeyMismatch);
    }
}
