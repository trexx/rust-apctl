//! A terminal on an AP, in the browser: a WebSocket carried to a shell over SSH.
//!
//! The page sends what is typed as binary frames, and its size (`{"cols":80,"rows":24}`;
//! the first in the query) and `{"pause":…}` (see [`Said`]) as text ones, once
//! it is told the shell runs; apctl sends what the shell prints as binary frames, `{"connected":true}`
//! once it runs, `{"error":"…"}` before closing when it cannot, and pings (a
//! page that answers none of a few has gone). What went wrong goes over the
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

/// How many terminals may be open at once, over all APs and users.
static OPEN: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
/// The most a frame from the page may hold: keystrokes, or a paste.
const MAX_FRAME: usize = 64 << 10;
/// How many of the page's frames may wait for the AP to take them in: then
/// the page's are read no further until it does (TCP holds the page back).
const QUEUED: usize = 16;
/// How long the page may take to take in a frame: one that takes in nothing
/// for that long has gone.
const SEND_TIMEOUT: Duration = Duration::from_secs(20);

/// How many pings in a row the page may leave unanswered (while its frames
/// are read): then it has gone (a laptop asleep, a network change, a proxy
/// that dropped the connection).
const UNANSWERED: u32 = 3;

/// A terminal's timers.
struct Pace {
    /// How long a terminal stays open with nothing typed.
    idle: Duration,
    /// How often the page is pinged.
    ping: Duration,
}

const PACE: Pace = Pace { idle: Duration::from_secs(30 * 60), ping: Duration::from_secs(30) };

/// A terminal's size in characters, as the page measures it.
#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct Size {
    cols: Option<u32>,
    rows: Option<u32>,
}

/// A text frame from the page: its size, or `{"pause":true}` while it shows
/// what it was sent so far (the AP's output then waits, held back by SSH's
/// flow control) and `{"pause":false}` once it has.
#[derive(Deserialize)]
struct Said {
    pause: Option<bool>,
    #[serde(flatten)]
    size: Size,
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

/// Where and how to log in to an AP for its terminal. No Debug: it holds passwords.
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
#[derive(Clone, Copy, Debug, PartialEq)]
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
        (Ok(_open), Ok(t)) => bridge(&mut socket, &s, mac, t, &size, &session, &PACE).await,
        (Ok(_), Err(e)) => Err(e),
    };
    finish(socket, end).await;
}

/// Tells the page why its terminal ended (unless it went away), and closes the socket.
async fn finish(mut socket: WebSocket, end: Result<End, String>) {
    /// How long the page has to answer the close.
    const CLOSING: Duration = Duration::from_secs(2);
    let close = |code, reason| Message::Close(Some(CloseFrame { code, reason: Utf8Bytes::from_static(reason) }));
    let last = match end {
        Ok(End::Gone) => return,
        Ok(End::Exited) => close(close_code::NORMAL, "the shell ended"),
        Ok(End::Idle) => close(close_code::NORMAL, "closed after 30 minutes without input"),
        Ok(End::LoggedOut) => crate::api::logged_out(),
        Err(e) => {
            send(&mut socket, Message::Text(json!({ "error": e }).to_string().into())).await;
            close(close_code::ERROR, "failed")
        }
    };
    if send(&mut socket, last).await {
        // Until the page answers, dropping what it sent meanwhile: closing with its frames
        // unread would reset the connection, and the page could miss why it closed.
        let answered = async { while let Some(Ok(m)) = socket.recv().await && !matches!(m, Message::Close(_)) {} };
        let _ = tokio::time::timeout(CLOSING, answered).await;
    }
}

/// Sends the page a frame; false when it has gone, or took in nothing for [`SEND_TIMEOUT`].
async fn send(socket: &mut WebSocket, msg: Message) -> bool {
    matches!(tokio::time::timeout(SEND_TIMEOUT, socket.send(msg)).await, Ok(Ok(())))
}

/// What goes to the AP, in the order the page sent it.
enum ToAp {
    Typed(axum::body::Bytes),
    Size(u32, u32),
}

/// Hands the AP what the page sent, as fast as the AP takes it in: on a task
/// of its own, since an AP that takes in nothing (a program that prints but
/// reads nothing, once its input buffers are full) never lets a write finish.
/// Ends when the session does.
async fn to_ap(input: russh::ChannelWriteHalf<russh::client::Msg>, mut queue: tokio::sync::mpsc::Receiver<ToAp>) {
    while let Some(m) = queue.recv().await {
        let sent = match m {
            ToAp::Typed(typed) => input.data_bytes(typed).await,
            ToAp::Size(cols, rows) => input.window_change(cols, rows, 0, 0).await,
        };
        if sent.is_err() {
            return;
        }
    }
}

/// Logs in to the AP and starts its shell (unless the page goes or its
/// session ends meanwhile), and carries the terminal both ways until one side
/// ends it. Nothing in the loop waits on the AP taking input in, nor on the
/// page for longer than [`SEND_TIMEOUT`], so it always sees a logout, the idle
/// limit and the page's end.
async fn bridge(socket: &mut WebSocket, s: &AppState, mac: Mac, t: Target, size: &Size, session: &SessionId, pace: &Pace) -> Result<End, String> {
    let ended = crate::api::session_ends(&s.auth, Some(&session.hash));
    tokio::pin!(ended);
    let (cols, rows) = size.clamped();
    let start = async {
        let ssh = match ssh::connect(ssh::shell_config(), &t.ip, t.port, &t.logins, Some(t.expected)).await {
            Err(Failure::HostKey) => return Err(ssh::host_key_mismatch(s, mac, &t.ip).await),
            r => r?,
        };
        let ch = ssh.shell(cols, rows).await?;
        Ok((ssh, ch))
    };
    tokio::pin!(start);
    // Logging in may take a minute and more: the page may go meanwhile, or its session end.
    let (ssh, ch) = loop {
        tokio::select! {
            started = &mut start => break started.map_err(|f| f.to_string())?,
            _ = &mut ended => return Ok(End::LoggedOut),
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_)) | Err(_)) | None => return Ok(End::Gone),
                // (The page sends nothing before it is told the shell runs.)
                _ => {}
            },
        }
    };
    s.note(Event::device(clock::now_ts(), EventKind::ApTerminalOpened, mac, json!({ "user": session.user }))).await;
    tracing::info!("{mac}: terminal opened by {}", session.user);
    if !send(socket, Message::Text(Utf8Bytes::from_static(r#"{"connected":true}"#))).await {
        return Ok(End::Gone);
    }
    let (mut output, input) = ch.split();
    let (queue, queued) = tokio::sync::mpsc::channel(QUEUED);
    let mut writer = tokio::spawn(to_ap(input, queued));
    let idle = tokio::time::sleep(pace.idle);
    tokio::pin!(idle);
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + pace.ping, pace.ping);
    // Pings sent since the page last sent anything (a pong, say).
    let mut unanswered = 0;
    let mut paused = false;
    let end = loop {
        // Room for one more of the page's frames (only this loop queues them).
        let reading = queue.capacity() > 0;
        tokio::select! {
            _ = &mut ended => break End::LoggedOut,
            _ = &mut idle => break End::Idle,
            // The session ended under the writer.
            _ = &mut writer => break End::Exited,
            _ = ping.tick() => {
                // Only while the page's frames are read: its pong waits behind what it typed.
                unanswered += u32::from(reading);
                if unanswered > UNANSWERED || !send(socket, Message::Ping(Default::default())).await {
                    break End::Gone;
                }
            }
            msg = output.wait(), if !paused => match msg {
                Some(russh::ChannelMsg::Data { data } | russh::ChannelMsg::ExtendedData { data, .. }) => {
                    if !send(socket, Message::Binary(data)).await {
                        break End::Gone;
                    }
                }
                Some(russh::ChannelMsg::Close) | None => break End::Exited,
                _ => {}
            },
            // Room again: the page's frames are read on.
            _ = queue.reserve(), if !reading => {}
            incoming = socket.recv(), if reading => {
                // Anything from the page shows it is there, as a pong does.
                unanswered = 0;
                match incoming {
                    Some(Ok(Message::Binary(typed))) => {
                        idle.as_mut().reset(tokio::time::Instant::now() + pace.idle);
                        let _ = queue.try_send(ToAp::Typed(typed));
                    }
                    Some(Ok(Message::Text(text))) => match serde_json::from_str::<Said>(&text) {
                        Ok(Said { pause: Some(pause), .. }) => paused = pause,
                        Ok(Said { size, .. }) => {
                            let (cols, rows) = size.clamped();
                            let _ = queue.try_send(ToAp::Size(cols, rows));
                        }
                        Err(_) => {}
                    },
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break End::Gone,
                    _ => {}
                }
            }
        }
    };
    writer.abort();
    // The session may be waiting to hand this a message: let it go on to the disconnect.
    drop(output);
    ssh.close().await;
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn sizes_are_kept_within_bounds() {
        let size = |text: &str| serde_json::from_str::<Size>(text).unwrap().clamped();
        assert_eq!(size(r#"{"cols":120,"rows":40}"#), (120, 40));
        assert_eq!(size("{}"), (80, 24), "left out: the usual size");
        assert_eq!(size(r#"{"cols":0,"rows":100000}"#), (1, 200));
        assert!(serde_json::from_str::<Size>(r#"{"cols":-1}"#).is_err());
    }

    /// An AP's SSH server, as far as a terminal needs one: the password `ubnt`
    /// logs in, the shell echoes what is typed in capitals and exits at `exit`,
    /// and the sizes it was given are kept. The user `nopty` gets no PTY, and
    /// `noshell` no shell, and `slow` takes 2 s to check a password. For
    /// `stuck` the shell prints a lot at the first input, and the AP takes in
    /// nothing more from then on.
    #[derive(Clone, Default)]
    struct Shell {
        sizes: Arc<std::sync::Mutex<Vec<(u32, u32)>>>,
        /// How much was typed, over all sessions.
        typed: Arc<AtomicUsize>,
        user: String,
        /// This session's AP takes in nothing more (see [`Stalling`]).
        stalled: Arc<AtomicBool>,
    }

    impl russh::server::Handler for Shell {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<russh::server::Auth, Self::Error> {
            if user == "slow" {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            self.user = user.to_string();
            Ok(if password == "ubnt" { russh::server::Auth::Accept } else { russh::server::Auth::reject() })
        }

        async fn channel_open_session(&mut self, _: russh::Channel<russh::server::Msg>, reply: russh::server::ChannelOpenHandle, _: &mut russh::server::Session) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn pty_request(&mut self, ch: russh::ChannelId, term: &str, cols: u32, rows: u32, _: u32, _: u32, _: &[(russh::Pty, u32)], session: &mut russh::server::Session) -> Result<(), Self::Error> {
            assert_eq!(term, "xterm-256color");
            if self.user == "nopty" {
                return session.channel_failure(ch);
            }
            self.sizes.lock().unwrap().push((cols, rows));
            session.channel_success(ch)
        }

        async fn shell_request(&mut self, ch: russh::ChannelId, session: &mut russh::server::Session) -> Result<(), Self::Error> {
            if self.user == "noshell" { session.channel_failure(ch) } else { session.channel_success(ch) }
        }

        async fn window_change_request(&mut self, _: russh::ChannelId, cols: u32, rows: u32, _: u32, _: u32, _: &mut russh::server::Session) -> Result<(), Self::Error> {
            self.sizes.lock().unwrap().push((cols, rows));
            Ok(())
        }

        async fn data(&mut self, ch: russh::ChannelId, data: &[u8], session: &mut russh::server::Session) -> Result<(), Self::Error> {
            self.typed.fetch_add(data.len(), Ordering::Relaxed);
            if self.user == "stuck" {
                // More than the client's channel holds (100 messages) while nothing drains it.
                if !self.stalled.swap(true, Ordering::Relaxed) {
                    let h = session.handle();
                    tokio::spawn(async move {
                        for _ in 0..300 {
                            if h.data(ch, vec![b'.'; 512]).await.is_err() {
                                return;
                            }
                        }
                    });
                }
                return Ok(());
            }
            if data == b"exit\r" {
                session.exit_status_request(ch, 0)?;
                return session.close(ch);
            }
            session.data(ch, data.to_ascii_uppercase())
        }
    }

    /// The AP's end of a connection, which reads nothing once `stalled`: no
    /// window adjustment then comes back, as from an AP whose program reads no
    /// input once its buffers are full.
    struct Stalling {
        tcp: tokio::net::TcpStream,
        stalled: Arc<AtomicBool>,
    }

    impl tokio::io::AsyncRead for Stalling {
        fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
            if self.stalled.load(Ordering::Relaxed) {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut self.tcp).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for Stalling {
        fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.tcp).poll_write(cx, buf)
        }

        fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.tcp).poll_flush(cx)
        }

        fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.tcp).poll_shutdown(cx)
        }
    }

    /// The query of the test's page route.
    #[derive(Deserialize)]
    struct Page {
        token: String,
        idle_ms: Option<u64>,
        ping_ms: Option<u64>,
    }

    /// An AP (see [`Shell`]) and a server whose page route `/t/{user}?token=`
    /// runs a terminal to it, logged in as `user` (`changed`: expecting another
    /// host key) for the session of `token`. Each terminal's end goes to `ends`.
    struct Rig {
        addr: std::net::SocketAddr,
        shell: Shell,
        state: AppState,
        engine: tokio::sync::mpsc::Receiver<crate::engine::Input>,
        ends: tokio::sync::mpsc::UnboundedReceiver<Result<End, String>>,
        _dir: crate::model::tests::TestDir,
    }

    impl Rig {
        async fn new() -> Rig {
            use axum::extract::Path;
            let key = russh::keys::PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]));
            let fingerprint = key.public_key().fingerprint(russh::keys::HashAlg::Sha256).to_string();
            // A small window, which an AP that takes in nothing soon uses up.
            let config = Arc::new(russh::server::Config { keys: vec![key], window_size: 4096, ..Default::default() });
            let shell = Shell::default();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = shell.clone();
            tokio::spawn(async move {
                loop {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let stalled = Arc::new(AtomicBool::new(false));
                    let (config, shell) = (config.clone(), Shell { stalled: stalled.clone(), ..server.clone() });
                    tokio::spawn(async move {
                        if let Ok(session) = russh::server::run_stream(config, Stalling { tcp, stalled }, shell).await {
                            let _ = session.await;
                        }
                    });
                }
            });
            let (state, engine, _dir) = crate::api::tests::state();
            let (done, ends) = tokio::sync::mpsc::unbounded_channel();
            let mac: Mac = "02:00:00:00:00:01".parse().unwrap();
            let page = move |State(s): State<AppState>, Path(user): Path<String>, Query(q): Query<Page>, upgrade: WebSocketUpgrade| async move {
                let expected = if user == "changed" { "SHA256:other".into() } else { fingerprint };
                // A wrong password first, as when the site's login is not the AP's.
                let logins = vec![(user.clone(), "wrong".to_string()), (user, "ubnt".to_string())];
                let t = Target { ip: "127.0.0.1".into(), port, expected, logins };
                let session = s.auth.session_of(&q.token).unwrap();
                let pace = Pace { idle: q.idle_ms.map_or(PACE.idle, Duration::from_millis), ping: q.ping_ms.map_or(PACE.ping, Duration::from_millis) };
                upgrade.on_upgrade(move |mut socket| async move {
                    let end = bridge(&mut socket, &s, mac, t, &Size { cols: Some(100), rows: Some(30) }, &session, &pace).await;
                    let _ = done.send(end.clone());
                    finish(socket, end).await;
                })
            };
            let app = axum::Router::new().route("/t/{user}", axum::routing::get(page)).with_state(state.clone());
            let addr = crate::api::tests::serve(app).await;
            Rig { addr, shell, state, engine, ends, _dir }
        }

        /// A page's terminal to the AP as `user`, for a new session: the
        /// connection, and the session's token.
        async fn open(&self, user: &str, query: &str) -> (tokio::net::TcpStream, String) {
            let token = self.state.auth.create("admin");
            let (status, tcp) = crate::api::tests::handshake(self.addr, &format!("/t/{user}?token={token}{query}"), "", None).await;
            assert_eq!(status, "101");
            (tcp, token)
        }

        /// The next event noted.
        async fn event(&mut self) -> EventKind {
            let Some(crate::engine::Input::Note(e)) = self.engine.recv().await else { panic!("no event") };
            e.kind
        }
    }

    /// A frame from the page: masked, as a browser sends it (with a zero mask, so as it is).
    async fn from_page(tcp: &mut tokio::net::TcpStream, op: u8, payload: &[u8]) {
        use tokio::io::AsyncWriteExt;
        let mut f = vec![0x80 | op];
        match payload.len() {
            n @ ..126 => f.push(0x80 | n as u8),
            n => {
                f.push(0x80 | 126);
                f.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
            }
        }
        f.extend_from_slice(&[0; 4]);
        f.extend_from_slice(payload);
        tcp.write_all(&f).await.unwrap();
    }

    /// The error the page is told, and that a close follows it.
    async fn error(tcp: &mut tokio::net::TcpStream) -> String {
        use crate::api::tests::frame;
        let (op, text) = frame(tcp).await;
        assert_eq!((op, frame(tcp).await.0), (1, 8), "text, then closed");
        serde_json::from_slice::<Value>(&text).unwrap()["error"].as_str().unwrap().to_string()
    }

    /// The close frame's code and reason, past what the shell prints.
    async fn closed(tcp: &mut tokio::net::TcpStream) -> (u16, String) {
        loop {
            match crate::api::tests::frame(tcp).await {
                (2, _) => continue,
                (8, close) => return (u16::from_be_bytes([close[0], close[1]]), String::from_utf8(close[2..].to_vec()).unwrap()),
                (op, _) => panic!("frame {op}"),
            }
        }
    }

    #[tokio::test]
    async fn a_terminal_carries_keystrokes_output_and_sizes_and_checks_the_host_key() {
        use crate::api::tests::frame;
        let mut rig = Rig::new().await;
        let (mut tcp, _) = rig.open("ubnt", "").await;
        assert_eq!(frame(&mut tcp).await, (1, br#"{"connected":true}"#.to_vec()));
        assert_eq!(rig.event().await, EventKind::ApTerminalOpened);
        from_page(&mut tcp, 2, b"uptime").await;
        assert_eq!(frame(&mut tcp).await, (2, b"UPTIME".to_vec()));
        // A resize, then a keystroke: the shell has the size by the time it echoes.
        from_page(&mut tcp, 1, br#"{"cols":120,"rows":40}"#).await;
        from_page(&mut tcp, 2, b"x").await;
        assert_eq!(frame(&mut tcp).await, (2, b"X".to_vec()));
        assert_eq!(*rig.shell.sizes.lock().unwrap(), [(100, 30), (120, 40)]);
        // Paused, the AP's output waits until the page asks for it again.
        from_page(&mut tcp, 1, br#"{"pause":true}"#).await;
        from_page(&mut tcp, 2, b"y").await;
        let held = tokio::time::timeout(Duration::from_millis(300), frame(&mut tcp)).await;
        assert!(held.is_err(), "nothing while paused");
        from_page(&mut tcp, 1, br#"{"pause":false}"#).await;
        assert_eq!(frame(&mut tcp).await, (2, b"Y".to_vec()));
        assert_eq!(rig.shell.sizes.lock().unwrap().len(), 2, "no resize");
        // The shell exits: a normal close, saying so.
        from_page(&mut tcp, 2, b"exit\r").await;
        assert_eq!(closed(&mut tcp).await, (1000, "the shell ended".into()));
        assert_eq!(rig.ends.recv().await, Some(Ok(End::Exited)));

        // A host key other than the one expected: no login, and an event.
        let (mut tcp, _) = rig.open("changed", "").await;
        assert_eq!(error(&mut tcp).await, "the AP's SSH host key isn't the one apctl knows for it");
        assert_eq!(rig.event().await, EventKind::ApHostKeyMismatch);

        // An AP that refuses the PTY or the shell: it says so, and no terminal was opened.
        assert_eq!(error(&mut rig.open("nopty", "").await.0).await, "could not start a shell on the AP: it refused a terminal (PTY)");
        assert_eq!(error(&mut rig.open("noshell", "").await.0).await, "could not start a shell on the AP: it refused a shell");
        assert!(rig.engine.try_recv().is_err(), "no event");
    }

    /// Opens a terminal to an AP that prints a lot and then takes in nothing,
    /// and pastes more than it and the queue for it hold.
    async fn stuck(rig: &mut Rig, query: &str) -> (tokio::net::TcpStream, String) {
        let (mut tcp, token) = rig.open("stuck", query).await;
        assert_eq!(crate::api::tests::frame(&mut tcp).await.0, 1, "connected");
        assert_eq!(rig.event().await, EventKind::ApTerminalOpened);
        let paste = vec![b'x'; 16 << 10];
        for _ in 0..QUEUED + 4 {
            from_page(&mut tcp, 2, &paste).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(rig.shell.typed.load(Ordering::Relaxed) < 2 * paste.len(), "the AP took in little");
        (tcp, token)
    }

    #[tokio::test]
    async fn an_ap_that_takes_in_nothing_holds_up_no_logout_and_no_idle_limit() {
        let mut rig = Rig::new().await;
        // Logged out meanwhile: closed at once, saying so.
        let (mut tcp, token) = stuck(&mut rig, "").await;
        rig.state.auth.revoke(&token);
        assert_eq!(closed(&mut tcp).await, (1008, "logged out".into()));
        assert_eq!(rig.ends.recv().await, Some(Ok(End::LoggedOut)));
        // Nothing typed for the idle limit: closed then.
        let (mut tcp, _) = stuck(&mut rig, "&idle_ms=1000").await;
        assert_eq!(closed(&mut tcp).await, (1000, "closed after 30 minutes without input".into()));
        assert_eq!(rig.ends.recv().await, Some(Ok(End::Idle)));
        // The page went: its terminal ends with it, though what it sent is still unread.
        let (tcp, _) = stuck(&mut rig, "&ping_ms=200").await;
        drop(tcp);
        assert_eq!(tokio::time::timeout(Duration::from_secs(5), rig.ends.recv()).await.unwrap(), Some(Ok(End::Gone)));
    }

    #[tokio::test]
    async fn a_page_that_went_or_logged_out_while_its_terminal_logged_in_gets_no_shell() {
        let mut rig = Rig::new().await;
        // Closed while the AP checks the password: no shell, no event.
        let (tcp, _) = rig.open("slow", "").await;
        drop(tcp);
        assert_eq!(tokio::time::timeout(Duration::from_secs(1), rig.ends.recv()).await.unwrap(), Some(Ok(End::Gone)));
        // Logged out meanwhile: told so at once.
        let (mut tcp, token) = rig.open("slow", "").await;
        rig.state.auth.revoke(&token);
        assert_eq!(tokio::time::timeout(Duration::from_secs(1), closed(&mut tcp)).await.unwrap(), (1008, "logged out".into()));
        assert!(rig.engine.try_recv().is_err(), "no terminal opened");
    }

    #[tokio::test]
    async fn a_page_that_answers_no_pings_has_gone() {
        use crate::api::tests::frame;
        let mut rig = Rig::new().await;
        let (mut tcp, _) = rig.open("ubnt", "&ping_ms=100").await;
        assert_eq!(frame(&mut tcp).await.0, 1, "connected");
        for _ in 0..UNANSWERED {
            assert_eq!(frame(&mut tcp).await.0, 9, "a ping");
        }
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), rig.ends.recv()).await.unwrap(), Some(Ok(End::Gone)));
    }
}
