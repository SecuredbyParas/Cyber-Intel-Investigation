async function analyzeLog() {
  showError("log-error", "");

  var file = $("log-file").files[0];
  if (!file) {
    showError("log-error", "Please choose a log file first.");
    return;
  }

  var formData = new FormData();
  formData.append("logfile", file);
  formData.append("log_type", $("log-type").value);

  showLoading("log-result", "Analysing log file...");
  try {
    var r = await postFile("/api/analyze-log", formData);

    lastResult.log = r;
    totalLines += r.total_lines;
    totalThreats += r.threat_total;
    addIPs(r.suspicious_ips);
    updateDashboard();
    addTimeline("Analyzed " + r.log_type + " (" + r.total_lines + " lines)");

    if (r.brute_force_ips.length > 0) {
      var ips = [];
      for (var i = 0; i < r.brute_force_ips.length; i++) {
        ips.push(r.brute_force_ips[i].ip);
      }
      addAlert("Brute force attack from " + ips.join(", "));
    }
    if (r.severity === "HIGH") {
      addAlert(r.log_type + ": HIGH severity activity found");
    }

    showLogResult(r);
  } catch (err) {
    $("log-result").classList.add("hidden");
    showError("log-error", err.message);
  }
}

function showLogResult(r) {
  var html = "";

  if (r.brute_force_ips.length > 0) {
    var text = [];
    for (var i = 0; i < r.brute_force_ips.length; i++) {
      var b = r.brute_force_ips[i];
      text.push(esc(b.ip) + " (" + b.attempts + " attempts)");
    }
    html += '<div class="alert-box"><b>Brute force attack detected!</b> From: ' + text.join(", ") + "</div>";
  }

  html += '<p style="margin-bottom:14px"><b>' + esc(r.log_type) + "</b> " + badge(r.severity);
  html += ' <span class="muted">&nbsp; ' + esc(r.file_name) + " - " + r.total_lines + " lines analysed</span></p>";

  var counts = [];
  for (var name in r.counts) {
    counts.push([name, r.counts[name]]);
  }
  html += statBoxes(counts);
  html += barChart(r.chart_title, r.chart);

  // one table for every kind of finding
  for (var title in r.findings) {
    var items = r.findings[title];
    if (items.length === 0) {
      continue;
    }
    var rows = [];
    for (var j = 0; j < items.length && j < 50; j++) {
      rows.push("<tr><td>" + esc(items[j].ip) + '</td><td class="raw">' + esc(items[j].line) + "</td></tr>");
    }
    html += '<div class="card"><div class="card-title">' + esc(title) + " (" + items.length + ")</div>";
    html += '<div class="card-body">' + table(["IP Address", "Log Entry"], rows) + "</div></div>";
  }

  html += downloadButton("log");
  $("log-result").innerHTML = html;
  $("log-result").classList.remove("hidden");
}
