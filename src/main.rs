use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use comfy_table::{Cell, Color, ContentArrangement, Table};
use cursive::event::Key;
use cursive::traits::{Nameable, Resizable};
use cursive::views::{EditView, LinearLayout, Panel, ScrollView, SelectView, TextView};
use cursive::{Cursive, CursiveExt};
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info};
use serde::Serialize;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};

#[derive(Parser, Debug)]
#[command(name = "ns", version, about = "A prettier netstat alternative")]
struct Args {
    #[arg(long, help = "Open interactive TUI")]
    tui: bool,

    #[arg(long, help = "Print once (non-interactive)")]
    once: bool,

    #[arg(long, help = "Show TCP sockets")]
    tcp: bool,

    #[arg(long, help = "Show UDP sockets")]
    udp: bool,

    #[arg(long, help = "Show IPv4 sockets")]
    ipv4: bool,

    #[arg(long, help = "Show IPv6 sockets")]
    ipv6: bool,

    #[arg(long, help = "Show only listening sockets")]
    listen: bool,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Filter by TCP state (comma-separated)"
    )]
    state: Vec<String>,

    #[arg(short = 'p', long, help = "Filter by local or remote port")]
    port: Option<u16>,

    #[arg(long, help = "Filter by PID")]
    pid: Option<u32>,

    #[arg(long, help = "Filter by process name (substring, case-insensitive)")]
    process: Option<String>,

    #[arg(long, value_enum, default_value_t = SortBy::LocalPort, help = "Sort rows")]
    sort: SortBy,

    #[arg(long, help = "Sort descending")]
    desc: bool,

    #[arg(long, help = "Output JSON instead of a table")]
    json: bool,

    #[arg(long, help = "Disable ANSI colors")]
    no_color: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SortBy {
    LocalPort,
    RemotePort,
    Pid,
    Process,
    State,
}

#[derive(Clone, Debug)]
struct Row {
    proto: Proto,
    local: SocketAddr,
    remote: SocketAddr,
    tcp_state: Option<TcpState>,
    pid: Option<u32>,
    process: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proto {
    Tcp,
    Udp,
}

#[derive(Serialize)]
struct JsonRow<'a> {
    proto: &'a str,
    local: String,
    remote: String,
    state: Option<&'a str>,
    pid: Option<u32>,
    process: Option<&'a str>,
}

const FILTER_VIEW: &str = "filter";
const LIST_VIEW: &str = "list";
const LIST_SCROLL_VIEW: &str = "list_scroll";
const DETAILS_VIEW: &str = "details";
const STATUS_VIEW: &str = "status";

#[derive(Clone, Debug)]
struct TuiConfig {
    filter: String,
    show_tcp: bool,
    show_udp: bool,
    show_ipv4: bool,
    show_ipv6: bool,
    listen: bool,
    sort: SortBy,
    desc: bool,
    refresh_ms: u64,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            filter: String::new(),
            show_tcp: true,
            show_udp: true,
            show_ipv4: true,
            show_ipv6: true,
            listen: false,
            sort: SortBy::LocalPort,
            desc: false,
            refresh_ms: 2000,
        }
    }
}

impl TuiConfig {
    fn from_args(args: &Args) -> anyhow::Result<Self> {
        let show_tcp = match (args.tcp, args.udp) {
            (true, false) => true,
            (false, true) => false,
            _ => true,
        };
        let show_udp = match (args.tcp, args.udp) {
            (true, false) => false,
            (false, true) => true,
            _ => true,
        };

        let show_ipv4 = match (args.ipv4, args.ipv6) {
            (true, false) => true,
            (false, true) => false,
            _ => true,
        };
        let show_ipv6 = match (args.ipv4, args.ipv6) {
            (true, false) => false,
            (false, true) => true,
            _ => true,
        };

        let mut filter_parts: Vec<String> = Vec::new();
        if let Some(pid) = args.pid {
            filter_parts.push(format!("pid:{pid}"));
        }
        if let Some(port) = args.port {
            filter_parts.push(format!("port:{port}"));
        }
        if let Some(process) = args.process.as_deref() {
            filter_parts.push(format!("proc:{process}"));
        }
        for state in &args.state {
            let s = state.trim();
            if !s.is_empty() {
                filter_parts.push(format!("state:{s}"));
            }
        }

        Ok(Self {
            filter: filter_parts.join(" "),
            show_tcp,
            show_udp,
            show_ipv4,
            show_ipv6,
            listen: args.listen,
            sort: args.sort,
            desc: args.desc,
            refresh_ms: 2000,
        })
    }
}

struct AppState {
    config: TuiConfig,
    all_rows: Vec<Row>,
    visible_rows: Vec<Row>,
    selected: usize,
    last_error: Option<String>,
}

impl AppState {
    fn new(config: TuiConfig) -> Self {
        Self {
            config,
            all_rows: Vec::new(),
            visible_rows: Vec::new(),
            selected: 0,
            last_error: None,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    if std::env::args_os().len() == 1 {
        return run_tui(TuiConfig::default());
    }

    let args = Args::parse();
    if args.tui {
        return run_tui(TuiConfig::from_args(&args)?);
    }

    run_cli(&args)
}

fn run_cli(args: &Args) -> anyhow::Result<()> {
    let af_flags = match (args.ipv4, args.ipv6) {
        (true, false) => AddressFamilyFlags::IPV4,
        (false, true) => AddressFamilyFlags::IPV6,
        _ => AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
    };

    let proto_flags = match (args.tcp, args.udp) {
        (true, false) => ProtocolFlags::TCP,
        (false, true) => ProtocolFlags::UDP,
        _ => ProtocolFlags::TCP | ProtocolFlags::UDP,
    };

    let mut rows = collect_rows(af_flags, proto_flags)?;

    let state_filters = build_state_filters(&args.state)?;
    rows.retain(|row| matches_filters(row, args, &state_filters));
    sort_rows(&mut rows, args.sort, args.desc);

    if args.json {
        let json_rows: Vec<JsonRow<'_>> = rows
            .iter()
            .map(|r| JsonRow {
                proto: match r.proto {
                    Proto::Tcp => "tcp",
                    Proto::Udp => "udp",
                },
                local: format_addr(r.local),
                remote: format_addr(r.remote),
                state: r.tcp_state.map(state_label),
                pid: r.pid,
                process: r.process.as_deref(),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_rows)?);
        return Ok(());
    }

    render_table(&rows, !args.no_color);
    Ok(())
}

fn collect_rows(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> anyhow::Result<Vec<Row>> {
    let sockets =
        get_sockets_info(af_flags, proto_flags).context("Failed to query socket table")?;

    let mut system = System::new_all();
    system.refresh_all();

    let mut pid_to_name: HashMap<u32, String> = HashMap::new();
    for (pid, process) in system.processes() {
        pid_to_name.insert(pid.as_u32(), process.name().to_string());
    }

    let mut rows: Vec<Row> = Vec::new();
    for socket in sockets {
        let (proto, local, remote, tcp_state) = match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => {
                let local = SocketAddr::new(tcp.local_addr, tcp.local_port);
                let remote = SocketAddr::new(tcp.remote_addr, tcp.remote_port);
                (Proto::Tcp, local, remote, Some(tcp.state))
            }
            ProtocolSocketInfo::Udp(udp) => {
                let local = SocketAddr::new(udp.local_addr, udp.local_port);
                let remote_ip = match udp.local_addr {
                    IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                };
                let remote = SocketAddr::new(remote_ip, 0);
                (Proto::Udp, local, remote, None)
            }
        };

        if socket.associated_pids.is_empty() {
            rows.push(Row {
                proto,
                local,
                remote,
                tcp_state,
                pid: None,
                process: None,
            });
            continue;
        }

        for pid in socket.associated_pids {
            rows.push(Row {
                proto,
                local,
                remote,
                tcp_state,
                pid: Some(pid),
                process: pid_to_name.get(&pid).cloned(),
            });
        }
    }

    Ok(rows)
}

fn run_tui(config: TuiConfig) -> anyhow::Result<()> {
    let state = Arc::new(Mutex::new(AppState::new(config.clone())));

    let mut siv = Cursive::default();

    let state_for_edit = Arc::clone(&state);
    let filter_view = EditView::new()
        .content(config.filter)
        .on_edit(move |s, text, _| {
            {
                let mut st = state_for_edit.lock().unwrap();
                st.config.filter = text.to_string();
                st.selected = 0;
            }
            rebuild_views(s, &state_for_edit);
        })
        .with_name(FILTER_VIEW)
        .full_width();

    let state_for_select = Arc::clone(&state);
    let list_view = SelectView::<usize>::new()
        .on_select(move |s, idx| {
            {
                let mut st = state_for_select.lock().unwrap();
                st.selected = *idx;
            }
            update_details(s, &state_for_select);
            s.call_on_name(LIST_SCROLL_VIEW, |v: &mut ScrollView<SelectView<usize>>| {
                v.scroll_to_important_area();
            });
        })
        .with_name(LIST_VIEW)
        .full_height();
    let list_view = ScrollView::new(list_view)
        .with_name(LIST_SCROLL_VIEW)
        .full_height();

    let details_view = TextView::new("").with_name(DETAILS_VIEW).full_height();
    let status_view = TextView::new("").with_name(STATUS_VIEW);

    let layout = LinearLayout::vertical()
        .child(Panel::new(filter_view).title("Filter"))
        .child(
            LinearLayout::horizontal()
                .child(Panel::new(list_view).title("Sockets").full_width())
                .child(Panel::new(details_view).title("Details").fixed_width(52)),
        )
        .child(Panel::new(status_view).title("Keys"));

    siv.add_fullscreen_layer(layout);

    {
        let state = Arc::clone(&state);
        siv.add_global_callback('q', |s| s.quit());
        siv.add_global_callback('/', move |s| {
            let _ = s.focus_name(FILTER_VIEW);
        });

        let state_for_clear = Arc::clone(&state);
        siv.add_global_callback('c', move |s| {
            {
                let mut st = state_for_clear.lock().unwrap();
                st.config.filter.clear();
                st.selected = 0;
            }
            s.call_on_name(FILTER_VIEW, |v: &mut EditView| v.set_content(""));
            rebuild_views(s, &state_for_clear);
        });

        let state_for_refresh = Arc::clone(&state);
        let sink = siv.cb_sink().clone();
        siv.add_global_callback('r', move |_| {
            request_refresh(sink.clone(), state_for_refresh.clone());
        });

        let state_for_tcp = Arc::clone(&state);
        siv.add_global_callback('t', move |s| {
            {
                let mut st = state_for_tcp.lock().unwrap();
                st.config.show_tcp = !st.config.show_tcp;
                if !st.config.show_tcp && !st.config.show_udp {
                    st.config.show_udp = true;
                }
                st.selected = 0;
            }
            rebuild_views(s, &state_for_tcp);
        });

        let state_for_udp = Arc::clone(&state);
        siv.add_global_callback('u', move |s| {
            {
                let mut st = state_for_udp.lock().unwrap();
                st.config.show_udp = !st.config.show_udp;
                if !st.config.show_tcp && !st.config.show_udp {
                    st.config.show_tcp = true;
                }
                st.selected = 0;
            }
            rebuild_views(s, &state_for_udp);
        });

        let state_for_v4 = Arc::clone(&state);
        siv.add_global_callback('4', move |s| {
            {
                let mut st = state_for_v4.lock().unwrap();
                st.config.show_ipv4 = !st.config.show_ipv4;
                if !st.config.show_ipv4 && !st.config.show_ipv6 {
                    st.config.show_ipv6 = true;
                }
                st.selected = 0;
            }
            rebuild_views(s, &state_for_v4);
        });

        let state_for_v6 = Arc::clone(&state);
        siv.add_global_callback('6', move |s| {
            {
                let mut st = state_for_v6.lock().unwrap();
                st.config.show_ipv6 = !st.config.show_ipv6;
                if !st.config.show_ipv4 && !st.config.show_ipv6 {
                    st.config.show_ipv4 = true;
                }
                st.selected = 0;
            }
            rebuild_views(s, &state_for_v6);
        });

        let state_for_listen = Arc::clone(&state);
        siv.add_global_callback('l', move |s| {
            {
                let mut st = state_for_listen.lock().unwrap();
                st.config.listen = !st.config.listen;
                st.selected = 0;
            }
            rebuild_views(s, &state_for_listen);
        });

        let state_for_sort = Arc::clone(&state);
        siv.add_global_callback('s', move |s| {
            {
                let mut st = state_for_sort.lock().unwrap();
                st.config.sort = cycle_sort(st.config.sort);
                st.selected = 0;
            }
            rebuild_views(s, &state_for_sort);
        });

        let state_for_desc = Arc::clone(&state);
        siv.add_global_callback('d', move |s| {
            {
                let mut st = state_for_desc.lock().unwrap();
                st.config.desc = !st.config.desc;
                st.selected = 0;
            }
            rebuild_views(s, &state_for_desc);
        });

        let state_for_escape = Arc::clone(&state);
        siv.add_global_callback(Key::Esc, move |s| {
            {
                let mut st = state_for_escape.lock().unwrap();
                st.config.filter.clear();
                st.selected = 0;
            }
            s.call_on_name(FILTER_VIEW, |v: &mut EditView| v.set_content(""));
            let _ = s.focus_name(LIST_VIEW);
            rebuild_views(s, &state_for_escape);
        });
    }

    start_refresh_loop(siv.cb_sink().clone(), Arc::clone(&state));
    rebuild_views(&mut siv, &state);
    siv.run();
    Ok(())
}

fn request_refresh(sink: cursive::CbSink, state: Arc<Mutex<AppState>>) {
    thread::spawn(move || {
        let result = collect_rows(
            AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
            ProtocolFlags::TCP | ProtocolFlags::UDP,
        )
        .map_err(|e| format!("{e:#}"));

        let _ = sink.send(Box::new(move |s| {
            {
                let mut st = state.lock().unwrap();
                match result {
                    Ok(rows) => {
                        st.all_rows = rows;
                        st.last_error = None;
                    }
                    Err(err) => {
                        st.last_error = Some(err);
                    }
                }
            }
            rebuild_views(s, &state);
        }));
    });
}

fn start_refresh_loop(sink: cursive::CbSink, state: Arc<Mutex<AppState>>) {
    thread::spawn(move || {
        loop {
            request_refresh(sink.clone(), state.clone());
            let refresh_ms = {
                let st = state.lock().unwrap();
                st.config.refresh_ms
            };
            thread::sleep(Duration::from_millis(refresh_ms));
        }
    });
}

fn rebuild_views(siv: &mut Cursive, state: &Arc<Mutex<AppState>>) {
    let (items, selected, status, details) = {
        let mut st = state.lock().unwrap();
        st.visible_rows = compute_visible_rows(&st.all_rows, &st.config);
        if st.selected >= st.visible_rows.len() {
            st.selected = 0;
        }
        let items: Vec<(String, usize)> = st
            .visible_rows
            .iter()
            .enumerate()
            .map(|(idx, row)| (row_line(row), idx))
            .collect();
        let details = st
            .visible_rows
            .get(st.selected)
            .map(details_text)
            .unwrap_or_else(|| "—".to_string());
        let status = status_text(&st);
        (items, st.selected, status, details)
    };

    siv.call_on_name(LIST_VIEW, |v: &mut SelectView<usize>| {
        v.clear();
        for (label, idx) in items {
            v.add_item(label, idx);
        }
        if !v.is_empty() {
            v.set_selection(selected);
        }
    });
    siv.call_on_name(LIST_SCROLL_VIEW, |v: &mut ScrollView<SelectView<usize>>| {
        v.scroll_to_important_area();
    });

    siv.call_on_name(DETAILS_VIEW, |v: &mut TextView| {
        v.set_content(details);
    });

    siv.call_on_name(STATUS_VIEW, |v: &mut TextView| {
        v.set_content(status);
    });
}

fn update_details(siv: &mut Cursive, state: &Arc<Mutex<AppState>>) {
    let details = {
        let st = state.lock().unwrap();
        st.visible_rows
            .get(st.selected)
            .map(details_text)
            .unwrap_or_else(|| "—".to_string())
    };
    siv.call_on_name(DETAILS_VIEW, |v: &mut TextView| {
        v.set_content(details);
    });
}

fn cycle_sort(sort: SortBy) -> SortBy {
    match sort {
        SortBy::LocalPort => SortBy::RemotePort,
        SortBy::RemotePort => SortBy::Pid,
        SortBy::Pid => SortBy::Process,
        SortBy::Process => SortBy::State,
        SortBy::State => SortBy::LocalPort,
    }
}

#[derive(Default)]
struct ParsedFilter {
    ports: Vec<u16>,
    pid: Option<u32>,
    process: Option<String>,
    states: Vec<TcpState>,
    proto: Option<Proto>,
    listen: bool,
    free: Vec<String>,
}

fn parse_filter(input: &str) -> ParsedFilter {
    let mut out = ParsedFilter::default();
    for raw in input.split_whitespace() {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        let lower = token.to_ascii_lowercase();

        if lower == "tcp" {
            out.proto = Some(Proto::Tcp);
            continue;
        }
        if lower == "udp" {
            out.proto = Some(Proto::Udp);
            continue;
        }
        if lower == "listen" || lower == "listening" {
            out.listen = true;
            continue;
        }

        if let Some(v) = lower
            .strip_prefix("port:")
            .or_else(|| lower.strip_prefix("p:"))
        {
            if let Ok(port) = v.parse::<u16>() {
                out.ports.push(port);
            }
            continue;
        }
        if let Some(v) = lower.strip_prefix("pid:") {
            if let Ok(pid) = v.parse::<u32>() {
                out.pid = Some(pid);
            }
            continue;
        }
        if let Some(v) = lower
            .strip_prefix("proc:")
            .or_else(|| lower.strip_prefix("process:"))
        {
            if !v.is_empty() {
                out.process = Some(v.to_string());
            }
            continue;
        }
        if let Some(v) = lower.strip_prefix("state:") {
            if let Some(state) = parse_tcp_state(v) {
                if !out.states.contains(&state) {
                    out.states.push(state);
                }
            }
            continue;
        }

        out.free.push(lower);
    }
    out
}

fn compute_visible_rows(all_rows: &[Row], config: &TuiConfig) -> Vec<Row> {
    let parsed = parse_filter(&config.filter);
    let mut out: Vec<Row> = all_rows
        .iter()
        .filter(|row| row_matches_tui(row, config, &parsed))
        .cloned()
        .collect();
    sort_rows(&mut out, config.sort, config.desc);
    out
}

fn row_matches_tui(row: &Row, config: &TuiConfig, parsed: &ParsedFilter) -> bool {
    match row.proto {
        Proto::Tcp if !config.show_tcp => return false,
        Proto::Udp if !config.show_udp => return false,
        _ => {}
    }

    match row.local.ip() {
        IpAddr::V4(_) if !config.show_ipv4 => return false,
        IpAddr::V6(_) if !config.show_ipv6 => return false,
        _ => {}
    }

    if config.listen && !is_listening(row) {
        return false;
    }

    if let Some(proto) = parsed.proto {
        if row.proto != proto {
            return false;
        }
    }
    if parsed.listen && !is_listening(row) {
        return false;
    }

    if let Some(pid) = parsed.pid {
        if row.pid != Some(pid) {
            return false;
        }
    }

    if !parsed.ports.is_empty() {
        let mut ok = false;
        for p in &parsed.ports {
            if row.local.port() == *p || row.remote.port() == *p {
                ok = true;
                break;
            }
        }
        if !ok {
            return false;
        }
    }

    if let Some(query) = parsed.process.as_deref() {
        let Some(name) = row.process.as_deref() else {
            return false;
        };
        if !name.to_ascii_lowercase().contains(query) {
            return false;
        }
    }

    if !parsed.states.is_empty() {
        if row.proto != Proto::Tcp {
            return false;
        }
        let Some(state) = row.tcp_state else {
            return false;
        };
        if !parsed.states.contains(&state) {
            return false;
        }
    }

    if !parsed.free.is_empty() {
        let haystack = row_haystack(row);
        for token in &parsed.free {
            if !haystack.contains(token) {
                return false;
            }
        }
    }

    true
}

fn row_haystack(row: &Row) -> String {
    let proto = match row.proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    };
    let state = row.tcp_state.map(state_label).unwrap_or("");
    let pid = row.pid.map(|p| p.to_string()).unwrap_or_default();
    let process = row.process.as_deref().unwrap_or("").to_string();
    let local = format_addr(row.local);
    let remote = format_remote_addr(row.remote);
    format!("{proto} {local} {remote} {state} {pid} {process}").to_ascii_lowercase()
}

fn row_line(row: &Row) -> String {
    let proto = match row.proto {
        Proto::Tcp => "TCP",
        Proto::Udp => "UDP",
    };
    let local = format_addr(row.local);
    let remote = format_remote_addr(row.remote);
    let state = row.tcp_state.map(state_label).unwrap_or("—");
    let pid = row
        .pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "—".to_string());
    let process = row.process.as_deref().unwrap_or("—");
    format!("{proto:<3} {local:<22} {remote:<22} {state:<9} {pid:>6} {process}")
}

fn details_text(row: &Row) -> String {
    let proto = match row.proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    };
    let state = row.tcp_state.map(state_label).unwrap_or("—");
    let pid = row
        .pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "—".to_string());
    let process = row.process.as_deref().unwrap_or("—");
    let local = format_addr(row.local);
    let remote = format_remote_addr(row.remote);
    format!(
        "proto: {proto}\nlocal: {local}\nremote: {remote}\nstate: {state}\npid: {pid}\nprocess: {process}"
    )
}

fn status_text(st: &AppState) -> String {
    let cfg = &st.config;
    let total = st.visible_rows.len();
    let all = st.all_rows.len();
    let sort = match cfg.sort {
        SortBy::LocalPort => "local-port",
        SortBy::RemotePort => "remote-port",
        SortBy::Pid => "pid",
        SortBy::Process => "process",
        SortBy::State => "state",
    };
    let tcp = if cfg.show_tcp { "TCP" } else { "tcp" };
    let udp = if cfg.show_udp { "UDP" } else { "udp" };
    let v4 = if cfg.show_ipv4 { "V4" } else { "v4" };
    let v6 = if cfg.show_ipv6 { "V6" } else { "v6" };
    let listen = if cfg.listen { "LISTEN" } else { "listen" };
    let desc = if cfg.desc { "desc" } else { "asc" };

    let err = st
        .last_error
        .as_deref()
        .map(|e| format!("\nerror: {e}"))
        .unwrap_or_default();

    format!(
        "{tcp} {udp} {v4} {v6} {listen}  sort:{sort} {desc}  refresh:{}ms  {total}/{all}\nq quit  / filter  r refresh  t tcp  u udp  4 v4  6 v6  l listen  s sort  d desc  c clear  esc reset{err}",
        cfg.refresh_ms
    )
}

fn build_state_filters(states: &[String]) -> anyhow::Result<StateFilters> {
    let mut tcp_states: Vec<TcpState> = Vec::new();
    let mut allow_udp = false;
    let mut allow_tcp = false;

    for raw in states {
        let s = raw.trim();
        if s.is_empty() {
            continue;
        }
        if s.eq_ignore_ascii_case("udp") {
            allow_udp = true;
            continue;
        }
        if s.eq_ignore_ascii_case("tcp") {
            allow_tcp = true;
            continue;
        }
        let parsed =
            parse_tcp_state(s).with_context(|| format!("Unknown TCP state filter: {s}"))?;
        if !tcp_states.contains(&parsed) {
            tcp_states.push(parsed);
        }
    }

    Ok(StateFilters {
        tcp_states,
        allow_udp,
        allow_tcp,
        any: states.iter().any(|s| !s.trim().is_empty()),
    })
}

struct StateFilters {
    tcp_states: Vec<TcpState>,
    allow_udp: bool,
    allow_tcp: bool,
    any: bool,
}

fn matches_filters(row: &Row, args: &Args, state_filters: &StateFilters) -> bool {
    if args.listen && !is_listening(row) {
        return false;
    }

    if let Some(port) = args.port {
        if row.local.port() != port && row.remote.port() != port {
            return false;
        }
    }

    if let Some(pid) = args.pid {
        if row.pid != Some(pid) {
            return false;
        }
    }

    if let Some(query) = args.process.as_deref() {
        let Some(name) = row.process.as_deref() else {
            return false;
        };
        if !name
            .to_ascii_lowercase()
            .contains(&query.to_ascii_lowercase())
        {
            return false;
        }
    }

    if state_filters.any {
        match row.proto {
            Proto::Udp => {
                if !state_filters.allow_udp {
                    return false;
                }
            }
            Proto::Tcp => {
                if state_filters.allow_tcp {
                    return true;
                }
                let Some(state) = row.tcp_state else {
                    return false;
                };
                if !state_filters.tcp_states.contains(&state) {
                    return false;
                }
            }
        }
    }

    true
}

fn is_listening(row: &Row) -> bool {
    match row.proto {
        Proto::Tcp => row.tcp_state == Some(TcpState::Listen),
        Proto::Udp => {
            row.remote.port() == 0
                && match row.remote.ip() {
                    std::net::IpAddr::V4(ip) => ip.is_unspecified(),
                    std::net::IpAddr::V6(ip) => ip.is_unspecified(),
                }
        }
    }
}

fn sort_rows(rows: &mut [Row], sort: SortBy, desc: bool) {
    rows.sort_by(|a, b| {
        let ord = match sort {
            SortBy::LocalPort => a.local.port().cmp(&b.local.port()),
            SortBy::RemotePort => a.remote.port().cmp(&b.remote.port()),
            SortBy::Pid => a.pid.unwrap_or(0).cmp(&b.pid.unwrap_or(0)),
            SortBy::Process => a
                .process
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase()
                .cmp(&b.process.as_deref().unwrap_or("").to_ascii_lowercase()),
            SortBy::State => state_label(a.tcp_state.unwrap_or(TcpState::Closed))
                .cmp(state_label(b.tcp_state.unwrap_or(TcpState::Closed))),
        };
        if desc { ord.reverse() } else { ord }
    });
}

fn render_table(rows: &[Row], color: bool) {
    let mut table = Table::new();
    table.load_preset(comfy_table::presets::UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Proto"),
        Cell::new("Local"),
        Cell::new("Remote"),
        Cell::new("State"),
        Cell::new("PID"),
        Cell::new("Process"),
    ]);

    for row in rows {
        let (proto_str, proto_color) = match row.proto {
            Proto::Tcp => ("TCP", Color::Cyan),
            Proto::Udp => ("UDP", Color::Magenta),
        };
        let mut proto_cell = Cell::new(proto_str);
        if color {
            proto_cell = proto_cell.fg(proto_color);
        }

        let local_cell = Cell::new(format_addr(row.local));
        let remote_cell = Cell::new(format_remote_addr(row.remote));

        let (state_str, state_color) = match row.tcp_state {
            Some(state) => (state_label(state), Some(state_to_color(state))),
            None => ("—", None),
        };
        let mut state_cell = Cell::new(state_str);
        if color {
            if let Some(c) = state_color {
                state_cell = state_cell.fg(c);
            }
        }

        let pid_cell = Cell::new(
            row.pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "—".to_string()),
        );
        let proc_cell = Cell::new(row.process.as_deref().unwrap_or("—").to_string());

        table.add_row(vec![
            proto_cell,
            local_cell,
            remote_cell,
            state_cell,
            pid_cell,
            proc_cell,
        ]);
    }

    let tcp = rows.iter().filter(|r| r.proto == Proto::Tcp).count();
    let udp = rows.iter().filter(|r| r.proto == Proto::Udp).count();
    println!("{table}");
    println!("{tcp} tcp, {udp} udp, {} total", rows.len());
}

fn format_addr(addr: SocketAddr) -> String {
    let port = addr.port();
    match addr.ip() {
        IpAddr::V4(ip) => {
            let host = if ip.is_unspecified() {
                "*".to_string()
            } else {
                ip.to_string()
            };
            format!("{host}:{port}")
        }
        IpAddr::V6(ip) => {
            let host = if ip.is_unspecified() {
                "*".to_string()
            } else {
                ip.to_string()
            };
            format!("[{host}]:{port}")
        }
    }
}

fn format_remote_addr(addr: SocketAddr) -> String {
    if addr.port() == 0 {
        let is_unspecified = match addr.ip() {
            IpAddr::V4(ip) => ip.is_unspecified(),
            IpAddr::V6(ip) => ip.is_unspecified(),
        };
        if is_unspecified {
            return "—".to_string();
        }
    }
    format_addr(addr)
}

fn parse_tcp_state(s: &str) -> Option<TcpState> {
    match s.trim().to_ascii_uppercase().as_str() {
        "LISTEN" | "LISTENING" => Some(TcpState::Listen),
        "SYN_SENT" | "SYNSENT" => Some(TcpState::SynSent),
        "SYN_RECEIVED" | "SYN_RECV" | "SYNRCVD" | "SYNRECEIVED" => Some(TcpState::SynReceived),
        "ESTABLISHED" | "ESTAB" => Some(TcpState::Established),
        "FIN_WAIT1" | "FIN_WAIT_1" | "FINWAIT1" => Some(TcpState::FinWait1),
        "FIN_WAIT2" | "FIN_WAIT_2" | "FINWAIT2" => Some(TcpState::FinWait2),
        "CLOSE_WAIT" | "CLOSEWAIT" => Some(TcpState::CloseWait),
        "CLOSING" => Some(TcpState::Closing),
        "LAST_ACK" | "LASTACK" => Some(TcpState::LastAck),
        "TIME_WAIT" | "TIMEWAIT" => Some(TcpState::TimeWait),
        "CLOSED" => Some(TcpState::Closed),
        "DELETE_TCB" | "DELETETCB" => Some(TcpState::DeleteTcb),
        "UNKNOWN" => Some(TcpState::Unknown),
        _ => None,
    }
}

fn state_label(state: TcpState) -> &'static str {
    match state {
        TcpState::Listen => "LISTEN",
        TcpState::SynSent => "SYN-SENT",
        TcpState::SynReceived => "SYN-RECV",
        TcpState::Established => "ESTAB",
        TcpState::FinWait1 => "FIN-WAIT-1",
        TcpState::FinWait2 => "FIN-WAIT-2",
        TcpState::CloseWait => "CLOSE-WAIT",
        TcpState::Closing => "CLOSING",
        TcpState::LastAck => "LAST-ACK",
        TcpState::TimeWait => "TIME-WAIT",
        TcpState::Closed => "CLOSED",
        TcpState::DeleteTcb => "DELETE-TCB",
        TcpState::Unknown => "UNKNOWN",
    }
}

fn state_to_color(state: TcpState) -> Color {
    match state {
        TcpState::Listen => Color::Green,
        TcpState::Established => Color::Cyan,
        TcpState::TimeWait => Color::Yellow,
        TcpState::CloseWait | TcpState::Closing | TcpState::LastAck => Color::Red,
        TcpState::SynSent | TcpState::SynReceived | TcpState::FinWait1 | TcpState::FinWait2 => {
            Color::Blue
        }
        TcpState::Closed | TcpState::DeleteTcb | TcpState::Unknown => Color::DarkGrey,
    }
}
