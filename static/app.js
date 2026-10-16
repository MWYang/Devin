// Dashboard for the governed data layer. Every screen is generated from /api/tables + the
// caller's effective permissions; the server enforces policy, the UI only reflects it.
const state = { user: new URLSearchParams(location.search).get("as") || localStorage.getItem("user") || "alice", users: [], tables: [], me: null, meta: null };
const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(method, path, body) {
  const res = await fetch(path, {
    method, headers: { "X-User-Id": state.user, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.detail || res.statusText), { status: res.status });
  return data;
}

function toast(msg, error = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (error ? " error" : "");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.add("hidden"), 4000);
}
const openModal = (html) => { $("#modal-body").innerHTML = html; $("#modal").classList.remove("hidden"); };
const closeModal = () => $("#modal").classList.add("hidden");
$("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });

const chip = (text, cls = "") => `<span class="chip ${cls}">${esc(text)}</span>`;
const isMasked = (v) => typeof v === "string" && v.includes("•");

async function boot() {
  [state.users, state.meta] = await Promise.all([api("GET", "/api/users"), api("GET", "/api/meta")]);
  const sel = $("#user-select");
  sel.innerHTML = state.users.map((u) => `<option value="${u.id}">${esc(u.name)} (${esc(u.team)})</option>`).join("");
  sel.value = state.user;
  sel.onchange = async () => { state.user = sel.value; localStorage.setItem("user", state.user); await loadMe(); route(); };
  await loadMe();
  window.addEventListener("hashchange", route);
  route();
}

async function loadMe() {
  [state.me, state.tables] = await Promise.all([api("GET", "/api/me"), api("GET", "/api/tables")]);
  state.users = await api("GET", "/api/users");
  $("#user-roles").innerHTML = state.me.roles.map((r) => chip(r)).join("");
}

function renderNav() {
  const h = location.hash || "#/";
  const link = (href, label) => `<a href="${href}" class="${h === href ? "active" : ""}">${esc(label)}</a>`;
  $("#nav").innerHTML = `<h4>Home</h4>${link("#/", "Overview")}<h4>Apps</h4>` +
    state.tables.map((t) => link(`#/app/${t.name}`, t.label)).join("") +
    `<h4>Administration</h4>${link("#/roles", "Role editor")}${link("#/governance", "Data governance")}`;
}

async function route() {
  renderNav();
  const h = location.hash || "#/";
  try {
    if (h.startsWith("#/app/")) await renderApp(h.slice(6));
    else if (h === "#/roles") await renderRoles();
    else if (h === "#/governance") await renderGovernance();
    else await renderHome();
  } catch (e) {
    $("#main").innerHTML = `<div class="notice">${esc(e.message)}</div>`;
  }
}

// ---------------- overview ----------------
async function renderHome() {
  const eff = state.me.effective;
  const cards = await Promise.all(state.tables.map(async (t) => {
    const scopes = eff.tables[t.name];
    let count = "—";
    if (scopes.read !== "none") count = (await api("GET", `/api/data/${t.name}`)).length;
    return `<div class="card"><h3><a href="#/app/${t.name}">${esc(t.label)}</a></h3>
      <div class="small">${esc(t.description)}</div>
      <p><b>${count}</b> <span class="small">records visible to you</span></p>
      <div>${state.meta.privileges.map((p) => chip(`${p}: ${scopes[p]}`, "sc-" + scopes[p])).join("")}</div></div>`;
  }));
  $("#main").innerHTML = `<h1>Overview</h1>
    <p class="desc">Each app below is generated from a YAML file in <code>schema/</code>. The same governance engine
    (row scopes, field security, business rules, audit) applies to every one of them. Switch users in the top bar to see policy change.</p>
    <div class="cards">${cards.join("")}</div>
    <h2>Your capabilities</h2>
    <div>${state.me.effective.capabilities.map((c) => chip(c, "lvl-write")).join("") || '<span class="small">none (no role or audit administration)</span>'}</div>`;
}

// ---------------- generic app view ----------------
function cell(col, v) {
  if (v === undefined) return "";
  if (isMasked(v)) return `<span class="masked" title="masked by policy">${esc(v)}</span>`;
  if (v === null) return "";
  if (col.type === "choice") return chip(v, "st-" + v);
  if (col.type === "boolean") return v ? "✓" : "—";
  if (col.type === "decimal") return Number(v).toLocaleString(undefined, { minimumFractionDigits: 2 });
  return esc(v);
}

function describeRule(r) {
  if (r.type === "four_eyes") return `Four-eyes: setting ${Object.entries(r.when).map(([k, v]) => `${k}=${v}`).join(", ")} must be done by someone other than the creator; stamps <code>${r.stamp}</code>.`;
  if (r.type === "approval_threshold") return `Approval threshold: ${r.field} above ${r.threshold} requires role <code>${r.approver_role}</code>.`;
  return esc(JSON.stringify(r));
}

async function renderApp(name, filters = {}) {
  const t = state.tables.find((x) => x.name === name);
  if (!t) throw new Error("Unknown app");
  const eff = state.me.effective;
  const scopes = eff.tables[name];
  const head = `<h1>${esc(t.label)}</h1><p class="desc">${esc(t.description)}</p>
    <div>Your access: ${state.meta.privileges.map((p) => chip(`${p}: ${scopes[p]}`, "sc-" + scopes[p])).join("")}</div>
    ${t.rules.length ? `<div class="small" style="margin-top:6px">${t.rules.map(describeRule).join("<br>")}</div>` : ""}`;
  if (scopes.read === "none") {
    $("#main").innerHTML = head + `<div class="notice">Your roles grant no read access to this table.</div>`;
    return;
  }
  const qs = new URLSearchParams(Object.entries(filters).filter(([, v]) => v)).toString();
  const rows = await api("GET", `/api/data/${name}${qs ? "?" + qs : ""}`);
  const visible = t.columns.filter((c) => eff.fields[`${name}.${c.name}`] !== "hidden");
  const choiceCols = visible.filter((c) => c.type === "choice" && ["read", "write"].includes(eff.fields[`${name}.${c.name}`]));
  $("#main").innerHTML = head + `
    <div class="toolbar">
      ${choiceCols.map((c) => `<label>${esc(c.name)} <select data-filter="${c.name}"><option value="">all</option>
        ${c.choices.map((o) => `<option ${filters[c.name] === o ? "selected" : ""}>${esc(o)}</option>`).join("")}</select></label>`).join("")}
      <span style="flex:1"></span>
      <button class="primary" id="new-btn" ${scopes.create === "none" ? "disabled" : ""}>+ New record</button>
    </div>
    <table><thead><tr><th>#</th>${visible.map((c) => `<th>${esc(c.name)} ${c.sensitive ? chip(c.classification, c.classification) : ""}</th>`).join("")}<th>owner</th><th>team</th></tr></thead>
    <tbody>${rows.map((r) => `<tr class="clickable" data-id="${r.id}"><td>${r.id}</td>${visible.map((c) => `<td>${cell(c, r[c.name])}</td>`).join("")}
      <td class="small">${esc(r.owner_id)}</td><td class="small">${esc(r.team)}</td></tr>`).join("") || `<tr><td colspan="99" class="small">No records in your scope.</td></tr>`}</tbody></table>
    <p class="small">${rows.length} record(s). Hidden columns for your role: ${t.columns.filter((c) => !visible.includes(c)).map((c) => c.name).join(", ") || "none"}.</p>`;
  document.querySelectorAll("[data-filter]").forEach((s) => s.onchange = () => renderApp(name, { ...filters, [s.dataset.filter]: s.value }).catch((e) => toast(e.message, true)));
  $("#new-btn").onclick = () => recordForm(t, null, () => renderApp(name, filters));
  document.querySelectorAll("tr[data-id]").forEach((tr) => tr.onclick = async () => {
    try { recordForm(t, await api("GET", `/api/data/${name}/${tr.dataset.id}`), () => renderApp(name, filters)); }
    catch (e) { toast(e.message, true); }
  });
}

function input(col, value, editable) {
  const v = value ?? "";
  if (!editable) return `<div>${cell(col, value) || '<span class="small">—</span>'}</div>`;
  const a = `name="${col.name}" data-type="${col.type}"`;
  if (col.type === "choice") return `<select ${a}><option value=""></option>${col.choices.map((o) => `<option ${o === v ? "selected" : ""}>${esc(o)}</option>`).join("")}</select>`;
  if (col.type === "boolean") return `<input type="checkbox" ${a} ${value ? "checked" : ""}>`;
  if (col.type === "text") return `<textarea ${a}>${esc(v)}</textarea>`;
  const type = { integer: "number", decimal: "number", date: "date" }[col.type] || "text";
  return `<input type="${type}" ${col.type === "decimal" ? 'step="0.01"' : ""} ${a} value="${esc(v)}">`;
}

function recordForm(t, rec, done) {
  const eff = state.me.effective;
  const scopes = eff.tables[t.name];
  const canEdit = rec ? scopes.update !== "none" : true;
  const cols = t.columns.filter((c) => eff.fields[`${t.name}.${c.name}`] !== "hidden" && (rec || !c.system_stamped));
  const writable = (c) => canEdit && !c.system_stamped && eff.fields[`${t.name}.${c.name}`] === "write";
  openModal(`<h2 style="margin-top:0">${rec ? `${esc(t.label)} #${rec.id}` : `New ${esc(t.label)} record`}</h2>
    <div class="form-grid">${cols.map((c) => `<label>${esc(c.name)}${c.required ? " *" : ""} ${c.sensitive ? chip(c.classification, c.classification) : ""}</label>
      ${input(c, rec ? rec[c.name] : c.default, writable(c))}`).join("")}</div>
    ${rec ? `<p class="small">Owner ${esc(rec.owner_id)} · team ${esc(rec.team)} · created by ${esc(rec.created_by)} · updated ${esc(rec.updated_at)}</p>` : ""}
    <div class="toolbar"><button class="primary" id="save-btn" ${canEdit ? "" : "disabled"}>Save</button>
      <button id="cancel-btn">Cancel</button><span style="flex:1"></span>
      ${rec ? `<button class="danger" id="del-btn" ${scopes.delete === "none" ? "disabled" : ""}>Delete</button>` : ""}</div>`);
  $("#cancel-btn").onclick = closeModal;
  $("#save-btn").onclick = async () => {
    const body = {};
    document.querySelectorAll("#modal-body [name]").forEach((el) => {
      const val = el.type === "checkbox" ? el.checked : el.value;
      const orig = rec ? rec[el.name] : undefined;
      const changed = el.type === "checkbox" ? Boolean(orig) !== val : String(orig ?? "") !== val;
      if (!rec ? val !== "" && val !== false : changed) body[el.name] = val === "" ? null : val;
    });
    try {
      if (rec) await api("PATCH", `/api/data/${t.name}/${rec.id}`, body);
      else await api("POST", `/api/data/${t.name}`, body);
      closeModal(); toast("Saved"); done();
    } catch (e) { toast(`${e.status === 403 ? "Denied" : "Error"}: ${e.message}`, true); }
  };
  if (rec) $("#del-btn").onclick = async () => {
    try { await api("DELETE", `/api/data/${t.name}/${rec.id}`); closeModal(); toast("Deleted"); done(); }
    catch (e) { toast(`Denied: ${e.message}`, true); }
  };
}

// ---------------- role editor ----------------
let selectedRole = null;
async function renderRoles() {
  const caps = state.me.effective.capabilities;
  if (!caps.includes("manage_roles") && !caps.includes("view_audit")) {
    $("#main").innerHTML = `<h1>Role editor</h1><div class="notice">You need the <code>manage_roles</code> capability.
      Switch to <b>Grace Lee</b> (Governance Admin) in the top bar.</div>`;
    return;
  }
  const readOnly = !caps.includes("manage_roles");
  const roles = await api("GET", "/api/roles");
  if (!selectedRole || !roles.find((r) => r.id === selectedRole)) selectedRole = roles[0]?.id;
  const role = selectedRole === "__new" ? { id: "", name: "", description: "", permissions: { tables: {}, fields: {} }, capabilities: [] }
    : roles.find((r) => r.id === selectedRole);
  const m = state.meta;
  const sel = (name, opts, val, extra = "") => `<select name="${name}" ${readOnly ? "disabled" : ""} ${extra}>${opts.map((o) => `<option value="${o}" ${o === val ? "selected" : ""}>${o}</option>`).join("")}</select>`;
  const tableRows = state.tables.map((t) => `<tr><td>${esc(t.label)} <span class="small mono">${t.name}</span></td>${m.privileges.map((p) =>
    `<td>${sel(`t:${t.name}:${p}`, m.scopes, role.permissions.tables[t.name]?.[p] || "none")}</td>`).join("")}</tr>`).join("");
  const fieldRows = state.tables.flatMap((t) => t.columns.filter((c) => !c.system_stamped).map((c) => {
    const key = `${t.name}.${c.name}`, def = m.default_field_level[c.classification];
    return `<tr><td class="mono">${key}</td><td>${chip(c.classification, c.classification)}</td>
      <td>${sel(`f:${key}`, ["", ...m.field_levels], role.permissions.fields[key] || "").replace('<option value="" ', `<option value="" title="default"`).replace(">" + "</option>", `>default (${def})</option>`)}</td></tr>`;
  })).join("");
  $("#main").innerHTML = `<h1>Role editor</h1>
    <p class="desc">Roles grant per-table scopes (none / own / team / all) and per-column access (hidden / masked / read / write).
    Sensitive columns default to masked (pii, financial) or hidden (restricted). Users with several roles get the most permissive combination.
    Every change is audited and takes effect on the next request.</p>
    ${readOnly ? `<div class="notice">Read-only: you can view roles but not change them.</div>` : ""}
    <div class="split">
      <div class="list card">${roles.map((r) => `<a data-role="${r.id}" class="${r.id === selectedRole ? "active" : ""}">${esc(r.name)}</a>`).join("")}
        ${readOnly ? "" : `<a data-role="__new" class="${selectedRole === "__new" ? "active" : ""}">+ New role</a>`}</div>
      <div class="detail card" id="role-form">
        <div class="form-grid">
          <label>Role id</label><input name="id" value="${esc(role.id)}" ${selectedRole === "__new" ? "" : "disabled"} placeholder="e.g. risk_analyst">
          <label>Name</label><input name="name" value="${esc(role.name)}" ${readOnly ? "disabled" : ""}>
          <label>Description</label><input name="description" value="${esc(role.description)}" ${readOnly ? "disabled" : ""}>
          <label>Capabilities</label><div>${m.capabilities.map((c) => `<label style="margin-right:12px"><input type="checkbox" name="cap:${c}" ${role.capabilities.includes(c) ? "checked" : ""} ${readOnly ? "disabled" : ""}> ${c}</label>`).join("")}</div>
        </div>
        <h2>Table privileges</h2>
        <table><thead><tr><th>Table</th>${m.privileges.map((p) => `<th>${p}</th>`).join("")}</tr></thead><tbody>${tableRows}</tbody></table>
        <h2>Field security</h2>
        <table><thead><tr><th>Column</th><th>Classification</th><th>Access</th></tr></thead><tbody>${fieldRows}</tbody></table>
        <div class="toolbar">${readOnly ? "" : `<button class="primary" id="save-role">Save role</button>
          ${selectedRole !== "__new" ? `<button class="danger" id="del-role">Delete role</button>` : ""}`}</div>
      </div>
    </div>
    <h2>User role assignments</h2>
    <table><thead><tr><th>User</th><th>Team</th>${roles.map((r) => `<th>${esc(r.name)}</th>`).join("")}<th></th></tr></thead>
    <tbody>${state.users.map((u) => `<tr data-user="${u.id}"><td>${esc(u.name)}</td><td>${esc(u.team)}</td>
      ${roles.map((r) => `<td><input type="checkbox" value="${r.id}" ${u.roles.includes(r.id) ? "checked" : ""} ${readOnly ? "disabled" : ""}></td>`).join("")}
      <td>${readOnly ? "" : `<button data-save-user="${u.id}">Save</button>`}</td></tr>`).join("")}</tbody></table>`;

  document.querySelectorAll("[data-role]").forEach((a) => a.onclick = () => { selectedRole = a.dataset.role; renderRoles(); });
  if (readOnly) return;
  $("#save-role").onclick = async () => {
    const form = $("#role-form"), body = { permissions: { tables: {}, fields: {} }, capabilities: [] };
    form.querySelectorAll("[name]").forEach((el) => {
      const [kind, a, b] = el.name.split(":");
      if (kind === "t") { if (el.value !== "none") (body.permissions.tables[a] ||= {})[b] = el.value; }
      else if (kind === "f") { if (el.value) body.permissions.fields[a] = el.value; }
      else if (kind === "cap") { if (el.checked) body.capabilities.push(a); }
      else body[el.name] = el.value;
    });
    try {
      const saved = await api("PUT", `/api/roles/${encodeURIComponent(body.id)}`, body);
      selectedRole = saved.id; toast(`Role ${saved.id} saved`); await loadMe(); renderRoles();
    } catch (e) { toast(e.message, true); }
  };
  if ($("#del-role")) $("#del-role").onclick = async () => {
    try { await api("DELETE", `/api/roles/${selectedRole}`); selectedRole = null; toast("Role deleted"); renderRoles(); }
    catch (e) { toast(e.message, true); }
  };
  document.querySelectorAll("[data-save-user]").forEach((b) => b.onclick = async () => {
    const tr = document.querySelector(`tr[data-user="${b.dataset.saveUser}"]`);
    const roles = [...tr.querySelectorAll("input:checked")].map((i) => i.value);
    try { await api("PUT", `/api/users/${b.dataset.saveUser}/roles`, roles); toast("Assignments saved"); await loadMe(); renderRoles(); }
    catch (e) { toast(e.message, true); }
  });
}

// ---------------- governance ----------------
async function renderGovernance(filters = {}) {
  if (!state.me.effective.capabilities.includes("view_audit")) {
    $("#main").innerHTML = `<h1>Data governance</h1><div class="notice">You need the <code>view_audit</code> capability.
      Switch to <b>Grace Lee</b> (Governance Admin) or <b>Carol Diaz</b> (Compliance Manager).</div>`;
    return;
  }
  const qs = new URLSearchParams(Object.entries(filters).filter(([, v]) => v)).toString();
  const [matrix, log] = await Promise.all([api("GET", "/api/governance/matrix"), api("GET", `/api/audit${qs ? "?" + qs : ""}`)]);
  const users = matrix.users;
  const catalog = state.tables.map((t) => t.columns.map((c, i) => `<tr>${i === 0 ? `<td rowspan="${t.columns.length}"><b>${esc(t.label)}</b><br><span class="small mono">${t.name}</span></td>` : ""}
    <td class="mono">${c.name}</td><td>${c.type}</td><td>${chip(c.classification, c.classification)}</td>
    <td>${c.system_stamped ? '<span class="small">system-stamped</span>' : chip(state.meta.default_field_level[c.classification], "lvl-" + state.meta.default_field_level[c.classification])}</td></tr>`).join("")).join("");
  const opt = (name, values) => `<select data-af="${name}"><option value="">any ${name}</option>${values.map((v) => `<option ${filters[name] === v ? "selected" : ""}>${esc(v)}</option>`).join("")}</select>`;
  $("#main").innerHTML = `<h1>Data governance</h1>
    <p class="desc">Classification, effective access and a tamper-evident audit trail — computed by the same engine that serves the apps.</p>
    <h2>Who can see sensitive data</h2>
    <p class="small">Effective column access per user after combining all of their roles.</p>
    <table><thead><tr><th>Column</th><th>Class</th>${users.map((u) => `<th title="${esc(u.roles.join(", "))}">${esc(u.id)}</th>`).join("")}</tr></thead>
    <tbody>${Object.entries(matrix.fields).map(([k, f]) => `<tr><td class="mono">${k}</td><td>${chip(f.classification, f.classification)}</td>
      ${users.map((u) => `<td>${f.users[u.id] === "no_access" ? chip("no table access", "lvl-hidden") : chip(f.users[u.id], "lvl-" + f.users[u.id])}</td>`).join("")}</tr>`).join("")}</tbody></table>
    <h2>Row access (read scope)</h2>
    <table><thead><tr><th>Table</th>${users.map((u) => `<th>${esc(u.id)}</th>`).join("")}</tr></thead>
    <tbody>${Object.entries(matrix.tables).map(([t, byUser]) => `<tr><td class="mono">${t}</td>${users.map((u) => {
      const s = byUser[u.id]; return `<td title="${state.meta.privileges.map((p) => `${p}: ${s[p]}`).join(", ")}">${chip(s.read, "sc-" + s.read)}</td>`;
    }).join("")}</tr>`).join("")}</tbody></table>
    <h2>Audit log</h2>
    <div class="toolbar">${opt("entity", [...state.tables.map((t) => t.name), "roles", "users"])}
      ${opt("actor", ["system", ...users.map((u) => u.id)])}
      ${opt("action", ["create", "update", "delete", "denied", "read_sensitive", "import", "role_create", "role_update", "role_delete", "user_roles_update"])}
      <span style="flex:1"></span><button id="verify-btn">Verify integrity</button><span id="verify-result"></span></div>
    <table><thead><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Entity</th><th>Record</th><th>Details</th></tr></thead>
    <tbody>${log.map((e) => `<tr><td>${e.id}</td><td class="small">${esc(e.ts.replace("T", " ").slice(0, 19))}</td><td>${esc(e.actor)}</td>
      <td>${chip(e.action, e.action === "denied" ? "restricted" : e.action === "read_sensitive" ? "pii" : "")}</td><td class="mono">${esc(e.entity)}</td>
      <td>${esc(e.record_id)}</td><td class="details mono">${esc(JSON.stringify(e.details))}</td></tr>`).join("")}</tbody></table>
    <h2>Data catalog</h2>
    <table><thead><tr><th>Table</th><th>Column</th><th>Type</th><th>Classification</th><th>Default access</th></tr></thead><tbody>${catalog}</tbody></table>`;
  document.querySelectorAll("[data-af]").forEach((s) => s.onchange = () => renderGovernance({ ...filters, [s.dataset.af]: s.value }));
  $("#verify-btn").onclick = async () => {
    const r = await api("GET", "/api/audit/verify");
    $("#verify-result").innerHTML = r.ok ? `<span class="ok">✓ Chain intact · ${r.entries} entries · head ${r.head.slice(0, 12)}…</span>`
      : `<span class="bad">✗ Chain broken at entry #${r.broken_at}</span>`;
  };
}

boot().catch((e) => { $("#main").innerHTML = `<div class="notice">${esc(e.message)}</div>`; });
