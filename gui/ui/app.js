// starea afisata vine doar de la daemon (evenimentele "vpn-event"); interfata nu tine logica de tunel
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

const LABELS = {
  disconnected: "Deconectat",
  connecting: "Conectare...",
  connected: "Conectat",
  need_code: "Cod TOTP necesar",
};

let online = false;
let status = null;

function bytes(n) {
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

function duration(s) {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return h ? `${h}h ${m}m` : m ? `${m}m ${sec}s` : `${sec}s`;
}

function render() {
  const state = online ? status?.state ?? "disconnected" : "offline";
  $("dot").className = `dot ${state}`;
  $("state").textContent = online ? LABELS[state] : "Daemon indisponibil";

  let detail = "";
  if (!online) detail = "porneste vpn-client daemon (ca administrator)";
  else if (state === "need_code") detail = status.reason ? `sesiune pierduta: ${status.reason}` : "";
  else if (state === "connected") detail = "cheile se reinnoiesc automat la 2 minute";
  $("detail").textContent = detail;

  const s = status ?? {};
  $("server").textContent = s.server || "-";
  $("mode").textContent = s.mode ? (s.mode === "full" ? "full tunnel" : "split tunnel") : "-";
  $("transport").textContent = s.transport ? s.transport.toUpperCase() : "-";
  $("tunnel").textContent = s.tunnel_address || "-";
  $("uptime").textContent = s.connected_secs != null ? duration(s.connected_secs) : "-";
  $("traffic").textContent = state === "connected" || state === "need_code" ? `↑ ${bytes(s.tx_bytes)}  ↓ ${bytes(s.rx_bytes)}` : "-";
  $("rekeys").textContent = state === "connected" ? String(s.rekeys) : "-";

  // formularul de cod: la conectare si cand sesiunea s-a pierdut
  const wantsCode = online && (state === "disconnected" || state === "need_code");
  $("code-form").hidden = !wantsCode;
  $("connect").textContent = state === "need_code" ? "Reconectare" : "Conectare";
  $("connect").disabled = !online;
  $("disconnect").hidden = !(online && (state === "connected" || state === "need_code"));
}

function showError(msg) {
  $("error").textContent = msg || "";
}

$("code-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  showError("");
  const code = $("code").value.trim();
  try {
    await invoke("connect", { code });
    $("code").value = "";
  } catch (err) {
    showError(String(err));
  }
});

$("code").addEventListener("input", (e) => {
  e.target.value = e.target.value.replace(/\D/g, "").slice(0, 6);
});

$("disconnect").addEventListener("click", async () => {
  showError("");
  try {
    await invoke("disconnect");
  } catch (err) {
    showError(String(err));
  }
});

async function start() {
  // intai ascultarea, apoi starea curenta: niciun eveniment nu se pierde intre ele (BUG-009)
  await listen("daemon", (e) => {
    online = e.payload.online;
    if (!online) status = null;
    render();
  });

  await listen("vpn-event", (e) => {
    const ev = e.payload;
    if (ev.type === "status") {
      if (status?.state !== ev.state && ev.state === "connected") showError("");
      status = ev;
      render();
    } else if (ev.type === "error") {
      showError(ev.message);
    }
  });

  const snap = await invoke("current");
  online = snap.online;
  status = snap.status ?? status;
  render();
  if (online && !status) invoke("refresh").catch(() => {});
}

render();
start();
