const trackSelect = document.getElementById("trackSelect");
const scenarioSelect = document.getElementById("scenarioSelect");
const loadView = document.getElementById("loadView");

function valueClass(value) {
  if (["ADMISSIBLE", "REHASH_VERIFIED", "INACTIVE", true].includes(value)) {
    return "pass";
  }

  if (["HELD", "REHASH_MISMATCH", "ACTIVE", false].includes(value)) {
    return "hold";
  }

  return "neutral";
}

function setState(id, value) {
  const element = document.getElementById(id);
  element.textContent = String(value);
  element.className = `state ${valueClass(value)}`;
}

function renderDefinitionList(id, values) {
  const target = document.getElementById(id);
  target.innerHTML = "";

  for (const [key, value] of Object.entries(values)) {
    const term = document.createElement("dt");
    term.textContent = key;

    const description = document.createElement("dd");
    description.textContent =
      typeof value === "object" ? JSON.stringify(value) : String(value);

    target.append(term, description);
  }
}

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });

  if (!response.ok) {
    throw new Error(`${path} returned ${response.status}`);
  }

  return response.json();
}

async function loadTracks() {
  const payload = await getJson("/api/tracks");

  for (const track of payload.tracks) {
    const option = document.createElement("option");
    option.value = track.track_id;
    option.textContent = `${track.display_name} — ${track.priority_tier}`;
    trackSelect.appendChild(option);
  }
}

async function loadSelectedView() {
  const track = trackSelect.value;
  const scenario = scenarioSelect.value;

  const [evaluation, passport, display, reconstruction] = await Promise.all([
    getJson(`/api/scenario/${track}/${scenario}`),
    getJson(`/api/passport/${track}`),
    getJson(`/api/ramat/${track}`),
    getJson(`/api/reconstruction/${track}`)
  ]);

  setState("admissibility", evaluation.action_admissibility_state);
  setState("integrity", evaluation.integrity_state);
  setState("noBind", evaluation.no_bind_state);
  setState("dependencies", evaluation.dependencies_satisfied);

  renderDefinitionList("decisionDetails", {
    "Track": evaluation.track_name,
    "Scenario": evaluation.scenario_name,
    "Object ID": evaluation.object_id,
    "Action ID": evaluation.action_id,
    "Authority valid": evaluation.authority.authority_valid,
    "Timing valid": evaluation.timing_valid,
    "Evidence sufficient": evaluation.evidence_sufficient,
    "Source system": evaluation.official_source_system,
    "Execution performed": evaluation.execution_performed
  });

  const displayStates = document.getElementById("displayStates");
  displayStates.innerHTML = "";

  for (const state of evaluation.display_states) {
    const chip = document.createElement("span");
    chip.textContent = state;
    displayStates.appendChild(chip);
  }

  const dependencyList = document.getElementById("dependencyList");
  dependencyList.innerHTML = "";

  for (const dependency of evaluation.dependencies) {
    const row = document.createElement("div");
    row.className = "dependency";

    const name = document.createElement("strong");
    name.textContent = dependency.dependency_name;

    const status = document.createElement("div");
    status.textContent = dependency.dependency_status;
    status.className =
      dependency.dependency_status === "SATISFIED" ? "pass" : "hold";

    row.append(name, status);
    dependencyList.appendChild(row);
  }

  renderDefinitionList("passportDetails", {
    "Passport ID": passport.passport_id,
    "Passport type": passport.passport_type,
    "Priority tier": passport.priority_tier,
    "Object ID": passport.object_id,
    "Evidence hash": passport.evidence_hash,
    "Rehash state": passport.rehash_state,
    "Authority valid": passport.authority_valid,
    "No-Bind state": passport.no_bind_state,
    "Admissibility": passport.admissibility_state,
    "RAMAT boundary": passport.ramat_boundary,
    "Execution performed": passport.execution_performed
  });

  document.getElementById("reconstruction").textContent =
    JSON.stringify(reconstruction, null, 2);

  console.assert(
    display.display_authority === "DISPLAY / WITNESS ONLY",
    "Display boundary was not preserved."
  );
}

loadView.addEventListener("click", () => {
  loadSelectedView().catch(error => {
    document.getElementById("reconstruction").textContent =
      `Unable to load view: ${error.message}`;
  });
});

loadTracks()
  .then(loadSelectedView)
  .catch(error => {
    document.getElementById("reconstruction").textContent =
      `Unable to initialize console: ${error.message}`;
  });