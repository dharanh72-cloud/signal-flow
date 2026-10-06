(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const form = $("#upload-form");
  const input = $("#capture-file");
  const dropZone = $("#drop-zone");
  const analyzeButton = $("#analyze-button");
  const formError = $("#form-error");
  const formStatus = $("#form-status");
  const dashboard = $("#dashboard");
  const flowDialog = $("#flow-dialog");
  const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;
  const PAGE_SIZE = 25;
  const colors = {
    browsing: "#55967b", download: "#488bb0", gaming: "#c76873",
    streaming: "#d28b3e", video_call: "#7867ca", needs_review: "#8994a2",
    unknown: "#8994a2", too_short: "#b9c3ce",
  };
  let activeResult = null;
  let activeFile = null;
  let sortedFlows = [];
  let visibleLimit = PAGE_SIZE;
  let sortKey = "score";
  let sortDescending = true;
  let selectedFlow = null;
  let replayPaused = false;
  let replayRunning = false;
  let resumeWaiters = [];

  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
  const number = (value) => new Intl.NumberFormat().format(Number(value || 0));
  const formatBytes = (value) => {
    const bytes = Number(value || 0);
    if (bytes < 1024) return `${number(bytes)} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  };
  const safeStorage = {
    get(key) {
      try { return JSON.parse(localStorage.getItem(key) || "{}"); } catch { return {}; }
    },
    set(key, value) {
      try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* Private browsing can block storage. */ }
    },
  };
  const storageKey = () => `signal-flow:${activeResult?.analysis_id || "none"}`;
  const getReviewState = (flowId) => safeStorage.get(storageKey())[flowId] || {};

  input.addEventListener("change", () => {
    activeFile = input.files?.[0] || null;
    $("#file-name").textContent = activeFile ? activeFile.name : "Drop a capture here or browse";
    clearError();
  });
  for (const eventName of ["dragenter", "dragover"]) {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.add("drag-over");
    });
  }
  for (const eventName of ["dragleave", "drop"]) {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.remove("drag-over");
    });
  }
  dropZone.addEventListener("drop", (event) => {
    const file = event.dataTransfer?.files?.[0];
    if (!file) return;
    const transfer = new DataTransfer();
    transfer.items.add(file);
    input.files = transfer.files;
    input.dispatchEvent(new Event("change", { bubbles: true }));
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const file = input.files?.[0] || activeFile;
    if (file) analyzeFile(file);
  });
  document.querySelectorAll(".sample-button").forEach((button) => {
    button.addEventListener("click", () => loadSample(button.dataset.sample));
  });
  $("#severity-filter").addEventListener("change", () => { visibleLimit = PAGE_SIZE; renderTable(); });
  $("#flow-search").addEventListener("input", () => { visibleLimit = PAGE_SIZE; renderTable(); });
  document.querySelectorAll(".sort-button").forEach((button) => button.addEventListener("click", () => {
    if (sortKey === button.dataset.sort) sortDescending = !sortDescending;
    else { sortKey = button.dataset.sort; sortDescending = sortKey === "score" || sortKey === "bytes"; }
    visibleLimit = PAGE_SIZE;
    renderTable();
  }));
  $("#load-more").addEventListener("click", () => { visibleLimit += PAGE_SIZE; renderTable(); });
  ["csv", "json", "summary"].forEach((format) => {
    $(`#export-${format}`).addEventListener("click", () => {
      if (!activeResult) return;
      exportAnalysis(format);
    });
  });
  $("#flow-table-body").addEventListener("click", (event) => {
    const row = event.target.closest("tr[data-flow-id]");
    if (row) openFlow(row.dataset.flowId);
  });
  $("#flow-table-body").addEventListener("keydown", (event) => {
    if ((event.key === "Enter" || event.key === " ") && event.target.matches("tr[data-flow-id]")) {
      event.preventDefault();
      openFlow(event.target.dataset.flowId);
    }
  });
  $("#close-dialog").addEventListener("click", () => flowDialog.close());
  flowDialog.addEventListener("click", (event) => { if (event.target === flowDialog) flowDialog.close(); });
  $("#ack-button").addEventListener("click", () => updateReview({ acknowledged: true, dismissed: false }));
  $("#dismiss-button").addEventListener("click", () => updateReview({ dismissed: true, acknowledged: false }));
  $("#save-note").addEventListener("click", () => {
    const existing = getReviewState(selectedFlow?.flow_id);
    writeReviewState({ ...existing, note: $("#flow-note").value.trim() });
    updateReviewButtons();
    renderTable();
    formStatus.textContent = "Investigation note saved in this browser.";
  });
  $("#replay-button").addEventListener("click", toggleReplay);
  $("#replay-speed").addEventListener("change", () => {
    if (replayRunning) formStatus.textContent = "Replay speed applies when the next replay starts.";
  });
  const previewSample = new URLSearchParams(window.location.search).get("sample");
  if (["normal.pcap", "with_attacks.pcap"].includes(previewSample)) {
    window.setTimeout(() => loadSample(previewSample), 100);
  }

  async function loadSample(name) {
    clearError();
    setBusy(true, "Loading bundled synthetic capture…");
    try {
      const response = await fetch(`/sample/${encodeURIComponent(name)}`);
      if (!response.ok) throw new Error("The bundled sample capture is missing.");
      const blob = await response.blob();
      const file = new File([blob], name, { type: "application/vnd.tcpdump.pcap" });
      const transfer = new DataTransfer();
      transfer.items.add(file);
      input.files = transfer.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
      await analyzeFile(file);
    } catch (error) {
      showError(error.message || "Could not load this sample capture.");
      setBusy(false);
    }
  }

  async function exportAnalysis(format) {
    formStatus.textContent = "Preparing export…";
    const response = await fetch("/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        analysis_id: activeResult.analysis_id,
        format,
        reviews: safeStorage.get(storageKey()),
      }),
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      showError(error.error || "Could not prepare this export.");
      return;
    }
    const blob = await response.blob();
    const names = { csv: "traffic-alerts.csv", json: "traffic-analysis.json", summary: "incident-summary.html" };
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = names[format];
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    formStatus.textContent = "Export downloaded.";
  }

  async function analyzeFile(file) {
    clearError();
    if (!file.name.toLowerCase().match(/\.(pcap|pcapng|cap)$/)) {
      showError("Choose a .pcap, .pcapng, or .cap file.");
      return;
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      showError("This file exceeds the 25 MB upload limit.");
      return;
    }
    activeFile = file;
    setBusy(true, "Reading packet metadata and scoring flows…");
    const body = new FormData();
    body.append("capture", file, file.name);
    try {
      const response = await fetch("/analyze", { method: "POST", body });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || "Analysis failed. Check the capture and try again.");
      activeResult = payload;
      showResult(payload);
      formStatus.textContent = `Analysis complete · ${number(payload.summary.flow_count)} flows · ${number(payload.summary.anomaly_count)} medium or high alerts.`;
    } catch (error) {
      showError(error.message || "Could not analyze this capture.");
    } finally {
      setBusy(false);
    }
  }

  function showResult(result) {
    dashboard.hidden = false;
    $("#capture-title").textContent = result.filename || "Capture results";
    $("#metric-flows").textContent = number(result.summary.flow_count);
    $("#metric-anomalies").textContent = number(result.summary.anomaly_count);
    $("#metric-severity").textContent = `${number(result.summary.high_severity_count)} high · ${number(result.summary.medium_severity_count)} medium`;
    $("#metric-highest").textContent = (result.summary.highest_severity || "low").toUpperCase();
    $("#metric-reason").textContent = result.summary.top_reason || "No standout reason";
    $("#metric-packets").textContent = `${number(result.summary.packets_read)} packets read${result.summary.truncated ? " · packet cap reached" : ""}`;
    const dropped = result.summary.skipped_flows || 0;
    $("#truncation-note").textContent = result.summary.truncated || dropped ? `Processing caps applied: ${result.summary.truncated ? "packet cap reached" : ""}${result.summary.truncated && dropped ? "; " : ""}${dropped ? `${number(dropped)} flows skipped` : ""}.` : "";
    drawMix(result.mix || [], result.summary.low_confidence_share || 0);
    drawTimeline(result.time_series || []);
    drawScores(result.score_distribution || []);
    sortedFlows = result.flows || [];
    visibleLimit = PAGE_SIZE;
    renderTable();
    $("#replay-button").disabled = !activeFile;
    $("#replay-progress").value = 0;
    $("#replay-count").textContent = `${number(sortedFlows.length)} flows ready`;
    if (new URLSearchParams(window.location.search).get("preview") === "1") {
      window.scrollTo(0, 0);
    } else {
      dashboard.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function classCell(flow) {
    if (flow.classifiable === false) {
      return `<span class="muted-class" title="Fewer than 6 packets: too little data for the classifier">${escapeHtml(flow.label_name)}</span>`;
    }
    if (flow.needs_review) {
      return `Needs review <span class="muted-class" title="Low classifier confidence">· likely ${escapeHtml(flow.candidate_name)}</span>`;
    }
    return escapeHtml(flow.label_name);
  }

  function drawMix(items, lowConfidenceShare = 0) {
    const chart = $("#mix-chart");
    const legend = $("#mix-legend");
    const nonzero = items.filter((item) => item.bytes > 0);
    chart.innerHTML = nonzero.map((item) => `<span class="mix-segment" style="width:${Math.max(0, Number(item.percent) || 0)}%;background:${colorFor(item.key)}" title="${escapeHtml(item.name)}: ${Number(item.percent || 0).toFixed(1)}%"></span>`).join("");
    chart.setAttribute("aria-label", nonzero.map((item) => `${item.name}: ${Number(item.percent || 0).toFixed(1)}%`).join(", ") || "No traffic data");
    legend.innerHTML = nonzero.map((item) => `<div class="mix-item"><i style="background:${colorFor(item.key)}"></i><span>${escapeHtml(item.name)} · ${number(item.flows)}${item.needs_review ? ` · ${number(item.needs_review)} review` : ""}</span><b>${Number(item.percent || 0).toFixed(1)}%</b></div>`).join("") || "<span>No flows long enough to classify</span>";
    const warning = $("#mix-warning");
    if (warning) {
      const unreliable = lowConfidenceShare > 0.5;
      warning.hidden = !unreliable;
      warning.textContent = unreliable
        ? `${Math.round(lowConfidenceShare * 100)}% of flows are low-confidence. This capture looks unlike the traffic the classifier was trained on, so treat this mix as unreliable.`
        : "";
    }
  }

  function drawTimeline(items) {
    const chart = $("#timeline-chart");
    const maxValue = Math.max(1, ...items.map((item) => Number(item.flows || 0)));
    chart.innerHTML = items.map((item) => {
      const flowHeight = item.flows ? Math.max(4, Number(item.flows) / maxValue * 100) : 0;
      const alertHeight = item.anomalies ? Math.max(4, Number(item.anomalies) / maxValue * 100) : 0;
      return `<div class="time-col" title="Bucket ${Number(item.label) + 1}: ${number(item.flows)} flows, ${number(item.anomalies)} alerts"><i class="time-bar" style="height:${flowHeight}%"></i><i class="time-alert" style="height:${alertHeight}%"></i><span>${Number(item.label) + 1}</span></div>`;
    }).join("");
    chart.setAttribute("aria-label", items.map((item) => `bucket ${Number(item.label) + 1}, ${item.flows} flows, ${item.anomalies} alerts`).join("; "));
  }

  function drawScores(items) {
    const chart = $("#score-chart");
    const maximum = Math.max(1, ...items.map((item) => Number(item.count || 0)));
    chart.innerHTML = items.map((item, index) => {
      const value = Number(item.count || 0);
      return `<div class="score-col" title="Score ${escapeHtml(item.range)}: ${number(value)} flows"><i class="score-bar" style="height:${value ? Math.max(4, value / maximum * 100) : 0}%"></i><span>${index * 10}</span></div>`;
    }).join("");
    chart.setAttribute("aria-label", items.map((item) => `${item.range}: ${item.count} flows`).join("; "));
  }

  function colorFor(key) { return colors[key] || colors.unknown; }

  function renderTable() {
    const severity = $("#severity-filter").value;
    const query = $("#flow-search").value.trim().toLowerCase();
    const filtered = sortedFlows.filter((flow) => {
      if (severity !== "all" && flow.severity !== severity) return false;
      const searchable = `${flow.flow_id} ${flow.label_name} ${flow.candidate_name} ${flow.protocol} ${(flow.reasons || []).join(" ")}`.toLowerCase();
      return !query || searchable.includes(query);
    });
    filtered.sort((left, right) => {
      const leftValue = sortKey === "reasons" ? (left.reasons || []).join(" ") : left[sortKey];
      const rightValue = sortKey === "reasons" ? (right.reasons || []).join(" ") : right[sortKey];
      const compare = typeof leftValue === "number" && typeof rightValue === "number"
        ? leftValue - rightValue : String(leftValue ?? "").localeCompare(String(rightValue ?? ""));
      return sortDescending ? -compare : compare;
    });
    const page = filtered.slice(0, visibleLimit);
    $("#visible-flow-count").textContent = `${number(filtered.length)} ${filtered.length === 1 ? "flow" : "flows"}`;
    $("#table-range").textContent = filtered.length > PAGE_SIZE ? `Showing ${number(page.length)} of ${number(filtered.length)} matching flows` : "";
    $("#empty-state").hidden = filtered.length !== 0;
    $("#load-more").hidden = filtered.length <= visibleLimit;
    $("#flow-table-body").innerHTML = page.map((flow) => {
      const review = getReviewState(flow.flow_id);
      const state = review.dismissed ? "Dismissed" : review.acknowledged ? "Acknowledged" : "Unreviewed";
      const stateClass = review.dismissed ? "dismiss" : review.acknowledged ? "ack" : "";
      const reason = (flow.reasons || ["No standout anomaly reason."])[0];
      const score = Number(flow.score || 0);
      return `<tr data-flow-id="${escapeHtml(flow.flow_id)}" tabindex="0" aria-label="Score ${score}, ${escapeHtml(flow.severity)} severity, ${escapeHtml(flow.label_name)}. ${escapeHtml(reason)}">
        <td class="score-cell">${score}<span class="score-track"><i style="width:${score}%"></i></span></td>
        <td><span class="severity-pill ${escapeHtml(flow.severity)}">${escapeHtml(flow.severity.toUpperCase())}</span></td>
        <td class="reason-cell">${escapeHtml(reason)}</td>
        <td class="class-cell">${classCell(flow)}</td>
        <td class="size-cell">${escapeHtml(formatBytes(flow.bytes))} · ${number(flow.packet_count)} pkts</td>
        <td>${Number(flow.duration || 0).toFixed(2)} s</td>
        <td class="review-state ${stateClass}">${state}${review.note ? " · note" : ""}</td>
      </tr>`;
    }).join("");
  }

  async function openFlow(flowId) {
    selectedFlow = sortedFlows.find((flow) => flow.flow_id === flowId);
    if (!selectedFlow) return;
    const flow = selectedFlow;
    $("#dialog-title").textContent = `Flow ${flow.flow_id}`;
    $("#dialog-content").innerHTML = `<div class="dialog-score"><strong>${Number(flow.score)}/100</strong><span class="severity-pill ${escapeHtml(flow.severity)}">${escapeHtml(flow.severity.toUpperCase())}</span><span>${escapeHtml(flow.protocol)} · ${number(flow.packet_count)} packets · ${escapeHtml(formatBytes(flow.bytes))}</span></div><p>Loading flow details…</p>`;
    const review = getReviewState(flow.flow_id);
    $("#flow-note").value = review.note || "";
    updateReviewButtons();
    flowDialog.showModal();
    try {
      const response = await fetch(`/flow/${encodeURIComponent(activeResult.analysis_id)}/${encodeURIComponent(flow.flow_id)}`);
      const details = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(details.error || "Could not load this flow's details.");
      if (selectedFlow?.flow_id !== flowId || !flowDialog.open) return;
      renderFlowDetails(flow, details);
    } catch (error) {
      if (selectedFlow?.flow_id === flowId && flowDialog.open) {
        $("#dialog-content").insertAdjacentHTML("beforeend", `<p>${escapeHtml(error.message || "Could not load this flow's details.")}</p>`);
      }
    }
  }

  function renderFlowDetails(flow, details) {
    const featureNames = ["packet_count", "duration", "total_bytes", "packets_per_sec", "bytes_per_sec", "up_bytes", "down_bytes", "up_down_byte_ratio", "iat_cv", "pkt_size_mean", "max_concurrent_flows"];
    const featureMarkup = featureNames.map((name) => {
      const value = Number(details.features?.[name] || 0);
      const display = name === "duration" ? `${value.toFixed(3)} s` : name.includes("bytes") || name === "total_bytes" ? formatBytes(value) : value.toFixed(value >= 100 ? 0 : 2);
      return `<div><span>${escapeHtml(name.replaceAll("_", " "))}</span><b>${escapeHtml(display)}</b></div>`;
    }).join("");
    const reasons = (flow.reasons?.length ? flow.reasons : ["No standout anomaly reason."])
      .map((reason) => `<li>${escapeHtml(reason)}</li>`).join("");
    const rules = (flow.rule_hits || []).map((hit) => `<span class="severity severity-medium">${escapeHtml(hit.name)}</span>`).join(" ");
    $("#dialog-content").innerHTML = `<div class="dialog-score"><strong>${Number(flow.score)}/100</strong><span class="severity-pill ${escapeHtml(flow.severity)}">${escapeHtml(flow.severity.toUpperCase())}</span><span>${escapeHtml(flow.protocol)} · ${number(flow.packet_count)} packets · ${escapeHtml(formatBytes(flow.bytes))}</span></div>
      <ul class="dialog-reasons">${reasons}</ul>${rules ? `<div>${rules}</div>` : ""}
      <div class="detail-grid"><section class="detail-card"><h3>Packet timing and frame sizes</h3><canvas id="packet-chart" class="packet-canvas" aria-label="Packet frame sizes over time"></canvas></section><section class="detail-card"><h3>Packet metadata features</h3><div class="feature-list">${featureMarkup}</div></section></div>`;
    drawPacketChart(details.packet_trace || []);
  }

  function drawPacketChart(points) {
    const canvas = $("#packet-chart");
    if (!canvas) return;
    const width = canvas.clientWidth || 360;
    const height = 150;
    const ratio = window.devicePixelRatio || 1;
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    const context = canvas.getContext("2d");
    context.scale(ratio, ratio);
    context.clearRect(0, 0, width, height);
    context.strokeStyle = "#dfe6ee";
    context.beginPath(); context.moveTo(25, 12); context.lineTo(25, 126); context.lineTo(width - 8, 126); context.stroke();
    context.fillStyle = "#7b8999";
    context.font = "9px system-ui";
    context.fillText("frame bytes", 29, 13);
    if (!points.length) { context.fillText("No packet trace available", 38, 72); return; }
    const maximum = Math.max(100, ...points.map((point) => Number(point.size || 0)));
    points.forEach((point, index) => {
      const x = 30 + index * Math.max(2, (width - 45) / points.length);
      const barHeight = Math.max(2, Number(point.size) / maximum * 102);
      context.fillStyle = point.direction === "up" ? "#3974ca" : "#8cb49a";
      context.fillRect(x, 125 - barHeight, Math.max(1, Math.min(5, (width - 45) / points.length - 1)), barHeight);
    });
    context.fillStyle = "#7b8999";
    context.fillText(`${points.length} sampled packets`, 30, 143);
  }

  function writeReviewState(patch) {
    if (!selectedFlow) return;
    const all = safeStorage.get(storageKey());
    all[selectedFlow.flow_id] = { ...all[selectedFlow.flow_id], ...patch };
    safeStorage.set(storageKey(), all);
  }
  function updateReview(patch) {
    writeReviewState(patch);
    updateReviewButtons();
    renderTable();
  }
  function updateReviewButtons() {
    if (!selectedFlow) return;
    const state = getReviewState(selectedFlow.flow_id);
    $("#ack-button").textContent = state.acknowledged ? "Acknowledged ✓" : "Acknowledge";
    $("#dismiss-button").textContent = state.dismissed ? "Dismissed ✓" : "Dismiss alert";
  }

  async function toggleReplay() {
    if (replayRunning && replayPaused) {
      replayPaused = false;
      resumeWaiters.splice(0).forEach((resolve) => resolve());
      $("#replay-button").textContent = "Ⅱ Pause replay";
      return;
    }
    if (replayRunning) {
      replayPaused = true;
      $("#replay-button").textContent = "▶ Resume replay";
      return;
    }
    if (!activeFile) return;
    replayRunning = true;
    replayPaused = false;
    $("#replay-button").textContent = "Ⅱ Pause replay";
    $("#replay-progress").value = 0;
    const body = new FormData();
    body.append("capture", activeFile, activeFile.name);
    try {
      const speed = encodeURIComponent($("#replay-speed").value);
      const response = await fetch(`/replay?speed=${speed}`, { method: "POST", body });
      if (!response.ok || !response.body) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.error || "Replay could not start.");
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        await waitIfPaused();
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (line.trim()) await handleReplayEvent(JSON.parse(line));
        }
      }
      if (buffer.trim()) await handleReplayEvent(JSON.parse(buffer));
    } catch (error) {
      showError(error.message || "Replay failed.");
    } finally {
      replayRunning = false;
      replayPaused = false;
      resumeWaiters.splice(0).forEach((resolve) => resolve());
      $("#replay-button").textContent = "▶ Play replay";
    }
  }

  function waitIfPaused() {
    if (!replayPaused) return Promise.resolve();
    return new Promise((resolve) => resumeWaiters.push(resolve));
  }
  async function handleReplayEvent(event) {
    if (event.event === "start") {
      $("#replay-count").textContent = `0 / ${number(event.summary.flow_count)}`;
      return;
    }
    if (event.event === "flow") {
      await waitIfPaused();
      const flow = event.flow;
      const row = $(`#flow-table-body tr[data-flow-id="${CSS.escape(flow.flow_id)}"]`);
      if (row) {
        row.classList.add("replay-active");
        window.setTimeout(() => row.classList.remove("replay-active"), 900);
      }
      $("#replay-progress").value = event.total ? event.index / event.total * 100 : 0;
      $("#replay-count").textContent = `${number(event.index)} / ${number(event.total)}`;
      return;
    }
    if (event.event === "complete") {
      $("#replay-progress").value = 100;
      $("#replay-count").textContent = "Replay complete";
    }
  }

  function setBusy(isBusy, message = "") {
    analyzeButton.disabled = isBusy;
    analyzeButton.textContent = isBusy ? "Analyzing…" : "Analyze capture ↗";
    document.querySelectorAll(".sample-button").forEach((button) => { button.disabled = isBusy; });
    if (message) formStatus.textContent = message;
  }
  function clearError() { formError.hidden = true; formError.textContent = ""; }
  function showError(message) { formError.textContent = message; formError.hidden = false; }
})();
