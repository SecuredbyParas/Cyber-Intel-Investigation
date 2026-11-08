
// fill the "network adapter" list with the IPs of this computer
async function loadAdapters() {
  var response = await fetch("/api/interfaces");
  var data = await response.json();
  var html = "";
  for (var i = 0; i < data.ips.length; i++) {
    html += '<option value="' + esc(data.ips[i]) + '">' + esc(data.ips[i]) + "</option>";
  }
  $("cap-adapter").innerHTML = html;
}

async function startCapture() {
  showError("cap-error", "");
  $("cap-btn").disabled = true;
  showLoading("cap-result", "Capturing real packets... open a website in another tab to create traffic.");

  try {
    var r = await postJSON("/api/capture", {
      adapter: $("cap-adapter").value,
      ip: $("cap-ip").value,
      count: $("cap-count").value,
      seconds: $("cap-seconds").value,
    });

    lastResult.live = r;
    if (r.total === 0) {
      $("cap-result").innerHTML = '<div class="alert-box">No packets were captured. Check that you selected the right network adapter, ' +
        "and open a website in another tab while the capture is running.</div>";
    } else {
      recordPackets(r, "Live capture");
      $("cap-result").innerHTML = packetResultHtml(r) + downloadButton("live");
    }
  } catch (err) {
    $("cap-result").classList.add("hidden");
    showError("cap-error", err.message);
  }
  $("cap-btn").disabled = false;
}

loadAdapters();
