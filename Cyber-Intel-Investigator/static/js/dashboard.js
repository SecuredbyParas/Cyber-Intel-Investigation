// numbers shown on the dashboard
var totalThreats = 0;
var totalPorts = 0;
var totalLines = 0;
var flaggedIPs = [];

// the last result of every module (used by the Download JSON button)
var lastResult = {};


// ---------------- dashboard ----------------
function updateDashboard() {
  $("kpi-threats").textContent = totalThreats;
  $("kpi-ips").textContent = flaggedIPs.length;
  $("kpi-ports").textContent = totalPorts;
  $("kpi-lines").textContent = totalLines;
}

function addTimeline(message) {
  var box = $("timeline");
  if (box.querySelector(".muted")) {
    box.innerHTML = "";
  }
  var time = new Date().toLocaleTimeString();
  box.insertAdjacentHTML("afterbegin",
    '<div class="timeline-item"><span class="dot"></span><div>' + esc(message) + "<small>" + time + "</small></div></div>");
}

function addAlert(message) {
  var box = $("alerts");
  if (box.querySelector(".muted")) {
    box.innerHTML = "";
  }
  box.insertAdjacentHTML("afterbegin",
    '<div class="alert-item"><i class="fas fa-triangle-exclamation"></i><span>' + esc(message) + "</span></div>");
}

function addIPs(list) {
  for (var i = 0; i < list.length; i++) {
    var ip = list[i];
    if (ip !== "unknown" && ip !== "-" && flaggedIPs.indexOf(ip) === -1) {
      flaggedIPs.push(ip);
    }
  }
}


// ---------------- changing pages ----------------
var pageTitles = {
  dashboard: ["fa-gauge-high", "Dashboard"],
  logs: ["fa-file-lines", "Log Analysis"],
  scan: ["fa-network-wired", "Network Scan"],
  packets: ["fa-magnifying-glass-chart", "Packet Analysis"],
  threat: ["fa-globe", "Threat Intelligence"],
  live: ["fa-satellite-dish", "Live Capture"],
};

function showPage(name) {
  var pages = document.querySelectorAll(".page");
  for (var i = 0; i < pages.length; i++) {
    pages[i].classList.add("hidden");
  }
  var links = document.querySelectorAll(".nav-link");
  for (var j = 0; j < links.length; j++) {
    links[j].classList.remove("active");
  }

  $("page-" + name).classList.remove("hidden");
  document.querySelector('[data-page="' + name + '"]').classList.add("active");
  $("page-title").innerHTML = '<i class="fas ' + pageTitles[name][0] + '"></i> ' + pageTitles[name][1];
}

var menuLinks = document.querySelectorAll(".nav-link");
for (var k = 0; k < menuLinks.length; k++) {
  menuLinks[k].addEventListener("click", function () {
    showPage(this.dataset.page);
  });
}
