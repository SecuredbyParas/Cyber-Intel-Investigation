function $(id) {
  return document.getElementById(id);
}

function esc(text) {
  var div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// send JSON to the server and get the answer
async function postJSON(url, data) {
  var response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  var result = await response.json();
  if (!response.ok) {
    throw new Error(result.error || "Something went wrong");
  }
  return result;
}

// send a file to the server and get the answer
async function postFile(url, formData) {
  var response = await fetch(url, { method: "POST", body: formData });
  var result = await response.json();
  if (!response.ok) {
    throw new Error(result.error || "Something went wrong");
  }
  return result;
}

function badge(text) {
  return '<span class="badge ' + esc(text) + '">' + esc(text) + "</span>";
}

function showError(id, message) {
  $(id).textContent = message;
}

function showLoading(resultId, message) {
  $(resultId).innerHTML = '<div class="loading">' + message + "</div>";
  $(resultId).classList.remove("hidden");
}

// show the name of the chosen file inside the upload box
function showFileName(inputId, textId, defaultText) {
  var file = $(inputId).files[0];
  if (file) {
    $(textId).textContent = file.name;
  } else {
    $(textId).textContent = defaultText;
  }
}

// the 4 small boxes (like the dashboard) used on result pages
// items looks like: [["Label", value], ["Label", value]]
function statBoxes(items) {
  var icons = ["fa-bug", "fa-ban", "fa-server", "fa-shield-halved"];
  var colors = ["red", "orange", "blue", "green"];
  var html = '<div class="kpi-row">';
  for (var i = 0; i < items.length; i++) {
    var n = i % 4;
    html += '<div class="kpi ' + colors[n] + '"><i class="fas ' + icons[n] + '"></i>';
    html += "<div><b>" + esc(String(items[i][1])) + "</b><span>" + esc(items[i][0]) + "</span></div></div>";
  }
  return html + "</div>";
}

// bar chart made with plain divs. data looks like: {"label": 5, "other": 2}
function barChart(title, data) {
  var labels = Object.keys(data);
  if (labels.length === 0) {
    return "";
  }

  var max = 0;
  for (var i = 0; i < labels.length; i++) {
    if (data[labels[i]] > max) {
      max = data[labels[i]];
    }
  }

  var html = '<div class="card"><div class="card-title">' + esc(title) + '</div><div class="card-body">';
  for (var j = 0; j < labels.length; j++) {
    var value = data[labels[j]];
    var width = (value / max) * 100;
    html += '<div class="bar-row"><span class="bar-label">' + esc(labels[j]) + "</span>";
    html += '<div class="bar-track"><div class="bar-fill" style="width:' + width + '%"></div></div>';
    html += '<span class="bar-value">' + value + "</span></div>";
  }
  return html + "</div></div>";
}

// table: headers is a list of names, rows is a list of "<tr>...</tr>" strings
function table(headers, rows) {
  var html = '<div class="table-wrap"><table><tr>';
  for (var i = 0; i < headers.length; i++) {
    html += "<th>" + esc(headers[i]) + "</th>";
  }
  html += "</tr>" + rows.join("") + "</table></div>";
  return html;
}

function downloadButton(type) {
  return '<button class="btn" onclick="downloadJSON(\'' + type + '\')"><i class="fas fa-download"></i> Download JSON</button>';
}

function downloadJSON(type) {
  var text = JSON.stringify(lastResult[type], null, 2);
  var blob = new Blob([text], { type: "application/json" });
  var link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = type + "_result.json";
  link.click();
}
