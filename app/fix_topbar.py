with open('/mnt/c/Users/anish/Downloads/honeypot-project/honeypot-project/templates/dashboard.html', 'r') as f:
    content = f.read()

# Find the broken row 1 div and replace everything up to end of row 2
start = content.find('    <div style="display:flex;align-items:center;gap:8px;">\n      <!-- Export CSV -->')
end   = content.find("'>👤 Profiles</a>") + len("'>👤 Profiles</a>")

if start == -1:
    print("ERROR — start not found")
    exit()

new_rows = """    <div style="display:flex;align-items:center;gap:8px;">
      <button onclick="exportCSV()" style="display:inline-flex;align-items:center;gap:6px;background:transparent;color:#00e599;padding:6px 14px;border-radius:5px;font-size:11px;font-weight:700;font-family:var(--mono);border:1px solid #00e599;cursor:pointer;transition:all 0.2s;" onmouseover="this.style.background='rgba(0,229,153,0.1)'" onmouseout="this.style.background='transparent'">📥 CSV</button>
      <button onclick="toggleSound()" id="sound-btn" style="display:inline-flex;align-items:center;gap:6px;background:transparent;color:#4a5568;padding:6px 14px;border-radius:5px;font-size:11px;font-weight:700;font-family:var(--mono);border:1px solid #4a5568;cursor:pointer;transition:all 0.2s;">🔇 Sound</button>
      <button onclick="toggleTheme()" id="theme-btn" style="display:inline-flex;align-items:center;gap:6px;background:transparent;color:#4a5568;padding:6px 14px;border-radius:5px;font-size:11px;font-weight:700;font-family:var(--mono);border:1px solid #4a5568;cursor:pointer;transition:all 0.2s;">☀️ Theme</button>
      <a href="/api/report" target="_blank" style="display:inline-flex;align-items:center;gap:6px;background:#ff6600;color:white;text-decoration:none;padding:6px 14px;border-radius:5px;font-size:11px;font-weight:700;font-family:var(--mono);transition:all 0.2s;" onmouseover="this.style.background='#e55a00'" onmouseout="this.style.background='#ff6600'">📄 PDF</a>
      <div class="live-badge" style="display:flex;align-items:center;gap:6px;margin-left:8px;">
        <div class="live-dot"></div>
        <span style="font-size:11px;color:#00e599;font-family:var(--mono);font-weight:700;">LIVE</span>
      </div>
      <span style="font-size:11px;color:#4a5568;font-family:var(--mono);">Updated <span id="last-update">—</span></span>
      <span style="font-size:11px;color:#2a3a55;font-family:var(--mono);" id="live-time">—</span>
    </div>
  </div>
  <!-- ROW 2: Navigation links -->
  <div style="display:flex;align-items:center;gap:6px;padding:8px 24px;background:#0d1017;flex-wrap:wrap;">
    <a href="/map"      style="display:inline-flex;align-items:center;gap:5px;color:#2a5cff;text-decoration:none;padding:5px 12px;border-radius:4px;font-size:11px;font-weight:700;font-family:var(--mono);border:1px solid rgba(42,92,255,0.4);transition:all 0.2s;" onmouseover="this.style.background='rgba(42,92,255,0.1)'" onmouseout="this.style.background='transparent'">🗺️ World Map</a>
    <a href="/sessions" style="display:inline-flex;align-items:center;gap:5px;color:#ff3b6e;text-decoration:none;padding:5px 12px;border-radius:4px;font-size:11px;font-weight:700;font-family:var(--mono);border:1px solid rgba(255,59,110,0.4);transition:all 0.2s;" onmouseover="this.style.background='rgba(255,59,110,0.1)'" onmouseout="this.style.background='transparent'">🎬 Sessions</a>
    <a href="/threat"   style="display:inline-flex;align-items:center;gap:5px;color:#00e599;text-decoration:none;padding:5px 12px;border-radius:4px;font-size:11px;font-weight:700;font-family:var(--mono);border:1px solid rgba(0,229,153,0.4);transition:all 0.2s;" onmouseover="this.style.background='rgba(0,229,153,0.1)'" onmouseout="this.style.background='transparent'">🔍 Threat Intel</a>
    <a href="/darkweb"  style="display:inline-flex;align-items:center;gap:5px;color:#a78bfa;text-decoration:none;padding:5px 12px;border-radius:4px;font-size:11px;font-weight:700;font-family:var(--mono);border:1px solid rgba(167,139,250,0.4);transition:all 0.2s;" onmouseover="this.style.background='rgba(167,139,250,0.1)'" onmouseout="this.style.background='transparent'">🕸️ Dark Web</a>
    <a href="/sessions" style="display:inline-flex;align-items:center;gap:5px;color:#ff8c42;text-decoration:none;padding:5px 12px;border-radius:4px;font-size:11px;font-weight:700;font-family:var(--mono);border:1px solid rgba(255,140,66,0.4);transition:all 0.2s;" onmouseover="this.style.background='rgba(255,140,66,0.1)'" onmouseout="this.style.background='transparent'">👤 Profiles</a>"""

content = content[:start] + new_rows + content[end:]

with open('/mnt/c/Users/anish/Downloads/honeypot-project/honeypot-project/templates/dashboard.html', 'w') as f:
    f.write(content)
print("SUCCESS!")
