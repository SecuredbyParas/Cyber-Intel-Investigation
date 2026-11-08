function packetTable(packets) {
  var rows = [];
  for (var i = 0; i < packets.length; i++) {
    var p = packets[i];
    var isAttack = p.threats.length > 0;
    var row = "";
    if (isAttack) {
      row = '<tr class="threat-row">';
    } else {
      row = "<tr>";
    }
    row += "<td>" + (i + 1) + "</td><td>" + esc(p.time) + "</td>";
    row += "<td>" + esc(p.src) + "</td><td>" + esc(p.dst) + "</td><td>" + esc(p.proto) + "</td>";
    row += "<td>" + p.sport + "</td><td>" + p.dport + "</td><td>" + esc(p.service) + "</td>";
    row += "<td>" + esc(p.flags) + "</td><td>" + p.length + "</td>";
    if (isAttack) {
      row += "<td>" + esc(p.threats.join(", ")) + "</td>";
    } else {
      row += "<td>-</td>";
    }
    row += '<td class="raw">' + esc(p.payload.slice(0, 120)) + "</td></tr>";
    rows.push(row);
  }
  return table(["#", "Time", "Source", "Destination", "Proto", "Sport", "Dport", "Service", "Flags", "Len", "Attack", "Payload"], rows);
}

function countAttacks(r) {
  var total = 0;
  for (var name in r.attack_counts) {
    total += r.attack_counts[name];
  }
  return total;
}

function packetResultHtml(r) {
  var html = "";

  if (r.port_scanners.length > 0) {
    var text = [];
    for (var i = 0; i < r.port_scanners.length; i++) {
      text.push(esc(r.port_scanners[i].ip) + " (" + r.port_scanners[i].ports + " ports)");
    }
    html += '<div class="alert-box"><b>Port scan detected!</b> From: ' + text.join(", ") + "</div>";
  }

  html += statBoxes([
    ["Total Packets", r.total],
    ["Attack Packets", countAttacks(r)],
    ["Port Scanners", r.port_scanners.length],
    ["Suspicious IPs", r.suspicious_ips.length],
  ]);

  html += '<div class="two-col">';
  html += barChart("Protocols", r.protocols);
  html += barChart("Attacks Found", r.attack_counts);
  html += barChart("Top Destination Ports", r.top_ports);
  html += barChart("Top Source IPs", r.top_talkers);
  html += "</div>";

  if (r.threat_packets.length > 0) {
    html += '<div class="card"><div class="card-title"><i class="fas fa-skull-crossbones"></i> Attack Packets (' + r.threat_packets.length + ")</div>";
    html += '<div class="card-body">' + packetTable(r.threat_packets) + "</div></div>";
  }

  html += '<div class="card"><div class="card-title"><i class="fas fa-table-list"></i> All Packets (first ' + r.packets.length + " of " + r.total + ")</div>";
  html += '<div class="card-body">' + packetTable(r.packets) + "</div></div>";
  return html;
}

// update the dashboard after a packet analysis
function recordPackets(r, source) {
  var attacks = countAttacks(r);
  totalThreats += attacks + r.port_scanners.length;
  addIPs(r.suspicious_ips);
  updateDashboard();
  addTimeline(source + ": " + r.total + " packets, " + attacks + " attack packet(s)");

  if (attacks > 0) {
    addAlert(source + ": " + attacks + " attack packet(s) found (" + Object.keys(r.attack_counts).join(", ") + ")");
  }
  for (var i = 0; i < r.port_scanners.length; i++) {
    addAlert("Port scan from " + r.port_scanners[i].ip + " (" + r.port_scanners[i].ports + " ports)");
  }
}


// ---------------- upload and analyse a pcap file ----------------
async function analyzePcap(useSample) {
  showError("pcap-error", "");
  var formData = new FormData();
  var url = "/api/analyze-pcap";

  if (useSample) {
    url += "?sample=1";
  } else {
    var file = $("pcap-file").files[0];
    if (!file) {
      showError("pcap-error", "Please choose a pcap file first.");
      return;
    }
    formData.append("pcap", file);
  }

  showLoading("pcap-result", "Reading packets...");
  try {
    var r = await postFile(url, formData);
    lastResult.pcap = r;
    recordPackets(r, "Pcap");
    $("pcap-result").innerHTML = packetResultHtml(r) + downloadButton("pcap");
  } catch (err) {
    $("pcap-result").classList.add("hidden");
    showError("pcap-error", err.message);
  }
}
