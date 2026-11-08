var scrapeTabs = {};   // html of every tab of the scrape result

async function runScrape() {
  showError("scrape-error", "");
  $("scrape-btn").disabled = true;
  showLoading("scrape-result", "Analysing website...");

  try {
    var r = await postJSON("/api/scrape", { url: $("scrape-url").value });

    lastResult.scrape = r;
    totalThreats += r.risks.length;
    updateDashboard();
    addTimeline("Analysed website " + r.url);
    if (r.risks.length >= 3) {
      addAlert(r.url + " has " + r.risks.length + " security risks");
    }

    showScrapeResult(r);
  } catch (err) {
    $("scrape-result").classList.add("hidden");
    showError("scrape-error", err.message);
  }
  $("scrape-btn").disabled = false;
}

// small table with one column made from a list of texts
function listTable(header, items) {
  var rows = [];
  for (var i = 0; i < items.length; i++) {
    rows.push('<tr><td class="raw">' + esc(items[i]) + "</td></tr>");
  }
  return table([header], rows);
}

function showScrapeResult(r) {
  var counts = [];
  for (var name in r.counts) {
    counts.push([name, r.counts[name]]);
  }
  var html = statBoxes(counts);

  // page information and security headers
  var infoRows = "";
  for (var key in r.info) {
    infoRows += "<tr><td>" + esc(key) + "</td><td>" + esc(String(r.info[key])) + "</td></tr>";
  }
  var headerRows = "";
  for (var h in r.security_headers) {
    var state = "OK";
    if (r.security_headers[h] === "MISSING") {
      state = "MISSING";
    }
    headerRows += "<tr><td>" + esc(h) + "</td><td>" + badge(state) + "</td></tr>";
  }
  html += '<div class="two-col">';
  html += '<div class="card"><div class="card-title"><i class="fas fa-circle-info"></i> Page Information</div>';
  html += '<div class="card-body"><table class="kv">' + infoRows + "</table></div></div>";
  html += '<div class="card"><div class="card-title"><i class="fas fa-shield-halved"></i> Security Headers</div>';
  html += '<div class="card-body"><table class="kv">' + headerRows + "</table></div></div></div>";

  // risks
  html += '<div class="card"><div class="card-title"><i class="fas fa-triangle-exclamation"></i> Security Risks</div><div class="card-body">';
  if (r.risks.length === 0) {
    html += '<p class="muted">No obvious risks found.</p>';
  } else {
    html += '<ul class="risk-list">';
    for (var i = 0; i < r.risks.length; i++) {
      html += "<li>" + esc(r.risks[i]) + "</li>";
    }
    html += "</ul>";
  }
  html += "</div></div>";

  // build the html of every tab
  var linkRows = [];
  for (var a = 0; a < r.links.length; a++) {
    linkRows.push('<tr><td class="raw">' + esc(r.links[a].href) + "</td><td>" + r.links[a].type + "</td></tr>");
  }
  var formRows = [];
  for (var f = 0; f < r.forms.length; f++) {
    var form = r.forms[f];
    formRows.push("<tr><td>" + esc(form.action || "(same page)") + "</td><td>" + form.method + '</td><td class="raw">' + esc(form.fields.join(", ")) + "</td></tr>");
  }
  var cookieRows = [];
  for (var c = 0; c < r.cookies.length; c++) {
    var ck = r.cookies[c];
    var secure = "NO";
    var httponly = "NO";
    if (ck.secure) {
      secure = "YES";
    }
    if (ck.httponly) {
      httponly = "YES";
    }
    cookieRows.push("<tr><td>" + esc(ck.name) + "</td><td>" + badge(secure) + "</td><td>" + badge(httponly) + "</td></tr>");
  }

  scrapeTabs = {
    "Links": table(["Link", "Type"], linkRows),
    "Forms": table(["Action", "Method", "Fields"], formRows),
    "Cookies": table(["Name", "Secure", "HttpOnly"], cookieRows),
    "Scripts": listTable("Script URL", r.scripts),
    "Emails": listTable("Email", r.emails),
    "Technologies": listTable("Technology", r.technologies),
    "HTML Source": "<pre>" + esc(r.html) + "</pre>",
  };

  html += '<div class="card"><div class="tabs">';
  var first = true;
  for (var tab in scrapeTabs) {
    var cls = "tab-btn";
    if (first) {
      cls += " active";
      first = false;
    }
    html += '<button class="' + cls + '" onclick="showTab(this, \'' + tab + "')\">" + tab + "</button>";
  }
  html += '</div><div class="card-body" id="tab-content"></div></div>';
  html += downloadButton("scrape");

  $("scrape-result").innerHTML = html;
  $("scrape-result").classList.remove("hidden");
  $("tab-content").innerHTML = scrapeTabs["Links"];
}

function showTab(button, name) {
  var buttons = document.querySelectorAll(".tab-btn");
  for (var i = 0; i < buttons.length; i++) {
    buttons[i].classList.remove("active");
  }
  button.classList.add("active");
  $("tab-content").innerHTML = scrapeTabs[name];
}
