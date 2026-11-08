async function runScan() {
  showError("scan-error", "");
  $("scan-btn").disabled = true;
  showLoading("scan-result", "Scanning ports, please wait...");

  try {
    var r = await postJSON("/api/scan", { host: $("scan-host").value, scan_type: $("scan-type").value });

    lastResult.scan = r;
    totalPorts += r.scanned;
    updateDashboard();
    addTimeline("Scanned " + r.host + " - " + r.open_ports.length + " open port(s)");

    for (var i = 0; i < r.open_ports.length; i++) {
      var p = r.open_ports[i];
      if (p.risk === "HIGH") {
        totalThreats += 1;
        addAlert("High risk port " + p.port + " (" + p.service + ") is open on " + r.host);
      }
    }
    updateDashboard();

    showScanResult(r);
  } catch (err) {
    $("scan-result").classList.add("hidden");
    showError("scan-error", err.message);
  }
  $("scan-btn").disabled = false;
}

function showScanResult(r) {
  var high = 0;
  var rows = [];
  for (var i = 0; i < r.open_ports.length; i++) {
    var p = r.open_ports[i];
    if (p.risk === "HIGH") {
      high += 1;
    }
    rows.push("<tr><td>" + p.port + "</td><td>" + esc(p.service) + "</td><td>open</td><td>" + badge(p.risk) + "</td></tr>");
  }

  var html = statBoxes([
    ["Target IP", r.ip],
    ["Ports Scanned", r.scanned],
    ["Open Ports", r.open_ports.length],
    ["High Risk", high],
  ]);

  html += '<div class="card"><div class="card-title"><i class="fas fa-table"></i> Open Ports</div><div class="card-body">';
  if (rows.length === 0) {
    html += '<p class="muted">No open ports found (scan took ' + r.seconds + " seconds).</p>";
  } else {
    html += table(["Port", "Service", "State", "Risk"], rows);
  }
  html += "</div></div>" + downloadButton("scan");

  $("scan-result").innerHTML = html;
  $("scan-result").classList.remove("hidden");
}
