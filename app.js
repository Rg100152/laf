const STORAGE_KEYS = {
  users: "laf.users.v1",
  session: "laf.session.v1"
};

const LOCK_LIMIT = 5;
const LOCK_MS = 30000;
const REQUEST_DELAY = 650;

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const attempts = new Map();
const idleLabels = new WeakMap();

const state = {
  mode: "login",
  user: null
};

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function readUsers() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.users);
    const parsed = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function writeUsers(users) {
  localStorage.setItem(STORAGE_KEYS.users, JSON.stringify(users));
}

function randomHex(bytes = 16) {
  const data = new Uint8Array(bytes);
  if (window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(data);
  } else {
    for (let i = 0; i < bytes; i += 1) data[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(data, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function digest(text) {
  if (window.crypto && window.crypto.subtle && window.TextEncoder) {
    const buffer = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");
  }
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (h2 >>> 0).toString(16).padStart(8, "0") + (h1 >>> 0).toString(16).padStart(8, "0");
}

async function hashPassword(password, salt) {
  return digest(`${salt}:${password}:laf`);
}

function normalizeEmail(value) {
  return value.trim().toLowerCase();
}

function passwordScore(password) {
  if (!password) return 0;
  let score = 0;
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  return Math.min(4, score);
}

function scoreLabel(score) {
  return ["", "Weak", "Fair", "Good", "Strong"][score] || "";
}

function scoreTone(score) {
  return ["", "weak", "fair", "good", "strong"][score] || "";
}

function passwordProblem(password) {
  if (!password) return "Please choose a password.";
  if (password.length < 8) return "Password must be at least 8 characters.";
  if (!/[A-Za-z]/.test(password)) return "Include at least one letter.";
  if (!/\d/.test(password)) return "Include at least one number.";
  return "";
}

function initialsOf(name, email) {
  const source = (name || email || "laf").trim();
  const parts = source.split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return source.slice(0, 2).toUpperCase();
}

function setFieldError(inputId, message) {
  const input = $(inputId);
  const error = document.querySelector(`[data-error-for="${inputId}"]`);
  const field = input ? input.closest(".field") : null;
  if (field) field.classList.toggle("invalid", Boolean(message));
  if (input) input.setAttribute("aria-invalid", message ? "true" : "false");
  if (error) {
    error.textContent = message || "";
    error.classList.toggle("is-visible", Boolean(message));
  }
}

function clearFormErrors(form) {
  form.querySelectorAll(".field").forEach((field) => field.classList.remove("invalid"));
  form.querySelectorAll(".field-error").forEach((error) => {
    error.textContent = "";
    error.classList.remove("is-visible");
  });
  form.querySelectorAll("input").forEach((input) => input.removeAttribute("aria-invalid"));
}

function toast(type, message) {
  const stack = $("toastStack");
  const glyphs = { success: "OK", error: "!", info: "i" };
  const node = document.createElement("div");
  node.className = `toast ${type}`;
  node.innerHTML = `<span class="toast-icon">${glyphs[type] || "i"}</span><p></p>`;
  node.querySelector("p").textContent = message;
  stack.appendChild(node);
  setTimeout(() => {
    node.classList.add("is-out");
    setTimeout(() => node.remove(), 320);
  }, 4200);
}

function setLoading(button, loading) {
  const label = button.querySelector(".btn-label");
  if (loading) {
    idleLabels.set(button, label.textContent);
    button.classList.add("is-loading");
    button.disabled = true;
  } else {
    button.classList.remove("is-loading");
    button.disabled = false;
    const idle = idleLabels.get(button);
    if (idle) label.textContent = idle;
  }
}

function setStatus(active) {
  const pill = $("statusPill");
  pill.classList.toggle("soft", active);
  pill.classList.toggle("busy", false);
  $("statusText").textContent = active ? "Session active" : "Demo mode";
}

/* Sessions */

function getSession() {
  const sources = [
    { storage: localStorage, remembered: true },
    { storage: sessionStorage, remembered: false }
  ];
  for (const source of sources) {
    try {
      const raw = source.storage.getItem(STORAGE_KEYS.session);
      if (!raw) continue;
      const parsed = JSON.parse(raw);
      if (parsed && parsed.email) return { ...parsed, remembered: source.remembered };
    } catch {
      source.storage.removeItem(STORAGE_KEYS.session);
    }
  }
  return null;
}

function createSession(email, remember) {
  const payload = JSON.stringify({ email, at: new Date().toISOString() });
  clearSession();
  (remember ? localStorage : sessionStorage).setItem(STORAGE_KEYS.session, payload);
}

function clearSession() {
  localStorage.removeItem(STORAGE_KEYS.session);
  sessionStorage.removeItem(STORAGE_KEYS.session);
}

/* Views */

function showView(name) {
  const auth = $("authView");
  const app = $("appView");
  const isApp = name === "app";
  auth.classList.toggle("hidden", isApp);
  app.classList.toggle("hidden", !isApp);
  auth.style.animation = "none";
  app.style.animation = "none";
  void (isApp ? app : auth).offsetWidth;
  auth.style.animation = "";
  app.style.animation = "";
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function setMode(mode) {
  state.mode = mode;
  const tabs = $("tabs");
  const heading = {
    login: ["Welcome back", "Sign in to laf", "Your space, your people, your pace."],
    signup: ["Join laf", "Create your account", "Set up your space in under a minute."],
    reset: ["Account recovery", "Reset your password", "Verify your email, then choose a new password."]
  }[mode];

  $("loginForm").classList.toggle("hidden", mode !== "login");
  $("signupForm").classList.toggle("hidden", mode !== "signup");
  $("resetForm").classList.toggle("hidden", mode !== "reset");
  tabs.classList.toggle("hidden", mode === "reset");
  tabs.dataset.active = mode === "signup" ? "signup" : "login";

  $("loginTab").classList.toggle("is-active", mode === "login");
  $("signupTab").classList.toggle("is-active", mode === "signup");
  $("loginTab").setAttribute("aria-selected", mode === "login" ? "true" : "false");
  $("signupTab").setAttribute("aria-selected", mode === "signup" ? "true" : "false");

  $("cardEyebrow").textContent = heading[0];
  $("cardTitle").textContent = heading[1];
  $("cardSubtitle").textContent = heading[2];

  document.title = mode === "signup" ? "laf — create account" : mode === "reset" ? "laf — reset password" : "laf — sign in";

  if (mode === "reset") {
    const email = $("loginEmail").value.trim();
    if (email) $("resetEmail").value = email;
  }

  const focusTarget = { login: "loginEmail", signup: "signupName", reset: "resetEmail" }[mode];
  setTimeout(() => {
    const input = $(focusTarget);
    if (input && !input.value) input.focus({ preventScroll: true });
  }, 220);
}

function enterApp(user) {
  state.user = user;
  const firstName = (user.name || user.email).split(/\s+/)[0];
  const hour = new Date().getHours();
  const greeting = hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
  const session = getSession();

  $("greeting").textContent = `${greeting}, ${firstName}`;
  $("dashName").textContent = user.name || "laf member";
  $("dashEmail").textContent = user.email;
  $("avatar").textContent = initialsOf(user.name, user.email);
  $("profName").textContent = user.name || "—";
  $("profEmail").textContent = user.email;
  $("profId").textContent = `LAF-${user.id.slice(0, 8).toUpperCase()}`;
  $("dashSince").textContent = new Date(user.createdAt).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric"
  });
  $("dashSession").textContent = session && session.remembered ? "Remembered" : "This browser";
  $("dashFootNote").textContent = session && session.remembered
    ? "You chose to stay signed in on this device."
    : "This session ends when you close the tab.";

  $("editForm").classList.add("hidden");
  $("profileList").classList.remove("hidden");
  $("editBtn").classList.remove("hidden");
  setStatus(true);
  showView("app");
  document.title = "laf — dashboard";
}

function leaveApp(message) {
  state.user = null;
  clearSession();
  $("loginForm").reset();
  $("signupForm").reset();
  $("resetForm").reset();
  clearFormErrors($("loginForm"));
  clearFormErrors($("signupForm"));
  clearFormErrors($("resetForm"));
  updateStrength("");
  setMode("login");
  setStatus(false);
  showView("auth");
  if (message) toast("info", message);
}

function refreshUserCount() {
  const count = Object.keys(readUsers()).length;
  $("userCount").textContent = String(count);
}

/* Password visibility */

document.querySelectorAll("[data-peek]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = $(button.dataset.peek);
    if (!input) return;
    const reveal = input.type === "password";
    input.type = reveal ? "text" : "password";
    button.classList.toggle("is-on", reveal);
    button.setAttribute("aria-pressed", reveal ? "true" : "false");
    button.setAttribute("aria-label", reveal ? "Hide password" : "Show password");
    input.focus({ preventScroll: true });
  });
});

/* Password strength */

function updateStrength(password) {
  const score = passwordScore(password);
  const meter = $("strength");
  const text = $("strengthText");
  meter.dataset.score = String(score);
  text.dataset.tone = scoreTone(score);
  if (!password) {
    text.textContent = "Use 8+ characters with letters and numbers.";
  } else if (password.length < 8) {
    text.textContent = `${scoreLabel(score) || "Too short"} — at least 8 characters needed.`;
  } else {
    text.textContent = `${scoreLabel(score)} password${score < 3 ? " — add length, numbers or symbols." : "."}`;
  }
}

$("signupPassword").addEventListener("input", (event) => {
  updateStrength(event.target.value);
  setFieldError("signupPassword", "");
});

/* Validation wiring */

const blurValidators = {
  loginEmail: (value) => (!value.trim() ? "Email is required." : !emailPattern.test(value.trim()) ? "Enter a valid email address." : ""),
  loginPassword: (value) => (!value ? "Password is required." : ""),
  signupName: (value) => (value.trim().length < 2 ? "Please enter your full name." : ""),
  signupEmail: (value) => (!value.trim() ? "Email is required." : !emailPattern.test(value.trim()) ? "Enter a valid email address." : ""),
  signupPassword: (value) => passwordProblem(value),
  signupConfirm: (value) => (!value ? "Please confirm your password." : value !== $("signupPassword").value ? "Passwords do not match." : ""),
  resetEmail: (value) => (!value.trim() ? "Email is required." : !emailPattern.test(value.trim()) ? "Enter a valid email address." : ""),
  resetPassword: (value) => passwordProblem(value),
  resetConfirm: (value) => (!value ? "Please confirm your new password." : value !== $("resetPassword").value ? "Passwords do not match." : ""),
  editName: (value) => (value.trim().length < 2 ? "Name must be at least 2 characters." : "")
};

Object.entries(blurValidators).forEach(([id, validate]) => {
  const input = $(id);
  if (!input) return;
  input.addEventListener("blur", () => {
    if (!input.value && id !== "signupName") return;
    setFieldError(id, validate(input.value));
  });
  input.addEventListener("input", () => {
    if (input.closest(".field") && input.closest(".field").classList.contains("invalid")) {
      setFieldError(id, validate(input.value));
    }
    if (id === "signupPassword" && $("signupConfirm").value) {
      setFieldError("signupConfirm", blurValidators.signupConfirm($("signupConfirm").value));
    }
  });
});

$("terms").addEventListener("change", () => {
  if ($("terms").checked) setFieldError("terms", "");
});

/* Mode switching */

document.querySelectorAll("[data-mode]").forEach((button) => {
  button.addEventListener("click", () => {
    const form = button.closest("form");
    if (form) clearFormErrors(form);
    setMode(button.dataset.mode);
  });
});

$("forgotBtn").addEventListener("click", () => {
  setMode("reset");
});

$("backToLogin").addEventListener("click", () => {
  clearFormErrors($("resetForm"));
  setMode("login");
});

$("brandLink").addEventListener("click", (event) => {
  event.preventDefault();
  if (state.user) showView("app");
  else setMode("login");
});

/* Lockout */

function lockState(email) {
  const entry = attempts.get(email);
  if (!entry) return 0;
  return Math.max(0, entry.until - Date.now());
}

function registerFailure(email) {
  const entry = attempts.get(email) || { count: 0, until: 0 };
  entry.count += 1;
  let locked = false;
  if (entry.count >= LOCK_LIMIT) {
    entry.count = 0;
    entry.until = Date.now() + LOCK_MS;
    locked = true;
  }
  attempts.set(email, entry);
  return { locked, remaining: locked ? 0 : LOCK_LIMIT - entry.count };
}

function startCooldown(button) {
  const label = button.querySelector(".btn-label");
  const idle = label.textContent;
  const end = Date.now() + LOCK_MS;
  button.disabled = true;
  const timer = setInterval(() => {
    const left = Math.ceil((end - Date.now()) / 1000);
    if (left <= 0) {
      clearInterval(timer);
      button.disabled = false;
      label.textContent = idle;
      return;
    }
    label.textContent = `Try again in ${left}s`;
  }, 250);
}

/* Login */

$("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const emailInput = $("loginEmail");
  const passwordInput = $("loginPassword");
  const email = normalizeEmail(emailInput.value);
  const password = passwordInput.value;
  const emailProblem = blurValidators.loginEmail(emailInput.value);
  const passwordProblemText = blurValidators.loginPassword(password);

  setFieldError("loginEmail", emailProblem);
  setFieldError("loginPassword", passwordProblemText);
  if (emailProblem || passwordProblemText) {
    (emailProblem ? emailInput : passwordInput).focus();
    return;
  }

  const remaining = lockState(email);
  if (remaining > 0) {
    startCooldown($("loginSubmit"));
    toast("error", "Too many attempts. Please wait before trying again.");
    return;
  }

  const button = $("loginSubmit");
  setLoading(button, true);
  await sleep(REQUEST_DELAY);

  const users = readUsers();
  const user = users[email];

  if (!user) {
    registerFailure(email);
    setLoading(button, false);
    setFieldError("loginEmail", "No laf account found with this email.");
    toast("error", "We couldn't find that account.");
    return;
  }

  const hash = await hashPassword(password, user.salt);
  if (hash !== user.hash) {
    const result = registerFailure(email);
    setLoading(button, false);
    if (result.locked) {
      setFieldError("loginPassword", "Too many failed attempts. Try again in 30 seconds.");
      startCooldown(button);
      toast("error", "Account temporarily paused for 30 seconds.");
    } else {
      setFieldError("loginPassword", `Incorrect password. ${result.remaining} ${result.remaining === 1 ? "attempt" : "attempts"} left.`);
      toast("error", "Incorrect password.");
    }
    return;
  }

  attempts.delete(email);
  const remember = $("rememberMe").checked;
  createSession(email, remember);
  $("loginForm").reset();
  clearFormErrors($("loginForm"));
  setLoading(button, false);
  enterApp(user);
  toast("success", `Welcome back, ${(user.name || email).split(/\s+/)[0]}.`);
});

/* Sign up */

$("signupForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const nameInput = $("signupName");
  const emailInput = $("signupEmail");
  const passwordInput = $("signupPassword");
  const confirmInput = $("signupConfirm");
  const name = nameInput.value.trim();
  const email = normalizeEmail(emailInput.value);
  const password = passwordInput.value;
  const confirm = confirmInput.value;
  const terms = $("terms").checked;

  const problems = {
    signupName: blurValidators.signupName(name),
    signupEmail: blurValidators.signupEmail(emailInput.value),
    signupPassword: passwordProblem(password),
    signupConfirm: blurValidators.signupConfirm(confirm)
  };

  Object.entries(problems).forEach(([id, message]) => setFieldError(id, message));
  setFieldError("terms", terms ? "" : "Please accept the terms to continue.");
  const firstProblem = Object.entries(problems).find(([, message]) => message);
  if (firstProblem || !terms) {
    if (firstProblem) $(firstProblem[0]).focus();
    return;
  }

  const button = $("signupSubmit");
  setLoading(button, true);
  await sleep(REQUEST_DELAY);

  const users = readUsers();
  if (users[email]) {
    setLoading(button, false);
    setFieldError("signupEmail", "An account already exists with this email.");
    toast("error", "That email is already registered.");
    return;
  }

  const salt = randomHex(16);
  const hash = await hashPassword(password, salt);
  const user = {
    id: randomHex(10),
    name,
    email,
    salt,
    hash,
    createdAt: new Date().toISOString()
  };

  users[email] = user;
  writeUsers(users);
  refreshUserCount();
  createSession(email, true);
  $("signupForm").reset();
  clearFormErrors($("signupForm"));
  updateStrength("");
  setLoading(button, false);
  enterApp(user);
  toast("success", "Account created. Welcome to laf.");
});

/* Reset password */

$("resetForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const emailInput = $("resetEmail");
  const passwordInput = $("resetPassword");
  const confirmInput = $("resetConfirm");
  const email = normalizeEmail(emailInput.value);
  const password = passwordInput.value;
  const confirm = confirmInput.value;

  const problems = {
    resetEmail: blurValidators.resetEmail(emailInput.value),
    resetPassword: passwordProblem(password),
    resetConfirm: blurValidators.resetConfirm(confirm)
  };
  Object.entries(problems).forEach(([id, message]) => setFieldError(id, message));
  const firstProblem = Object.entries(problems).find(([, message]) => message);
  if (firstProblem) {
    $(firstProblem[0]).focus();
    return;
  }

  const button = $("resetSubmit");
  setLoading(button, true);
  await sleep(REQUEST_DELAY);

  const users = readUsers();
  const user = users[email];
  if (!user) {
    setLoading(button, false);
    setFieldError("resetEmail", "No laf account found with this email.");
    toast("error", "We couldn't find that account.");
    return;
  }

  user.salt = randomHex(16);
  user.hash = await hashPassword(password, user.salt);
  users[email] = user;
  writeUsers(users);
  attempts.delete(email);

  $("loginEmail").value = email;
  $("loginPassword").value = "";
  $("loginPassword").focus();
  $("resetForm").reset();
  clearFormErrors($("resetForm"));
  setMode("login");
  setLoading(button, false);
  toast("success", "Password updated. Sign in with your new password.");
});

/* Dashboard */

$("editBtn").addEventListener("click", () => {
  $("editName").value = state.user ? state.user.name : "";
  $("profileList").classList.add("hidden");
  $("editBtn").classList.add("hidden");
  $("editForm").classList.remove("hidden");
  setTimeout(() => $("editName").focus({ preventScroll: true }), 60);
});

$("cancelEdit").addEventListener("click", () => {
  clearFormErrors($("editForm"));
  $("editForm").classList.add("hidden");
  $("profileList").classList.remove("hidden");
  $("editBtn").classList.remove("hidden");
});

$("editForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const nameInput = $("editName");
  const name = nameInput.value.trim();
  const problem = blurValidators.editName(name);
  setFieldError("editName", problem);
  if (problem) {
    nameInput.focus();
    return;
  }
  if (!state.user) return;

  const button = event.submitter;
  if (button) setLoading(button, true);
  await sleep(320);

  const users = readUsers();
  const user = users[state.user.email];
  if (!user) {
    if (button) setLoading(button, false);
    leaveApp("Your account could not be found. Please sign in again.");
    return;
  }

  user.name = name;
  users[user.email] = user;
  writeUsers(users);

  state.user = user;
  const firstName = name.split(/\s+/)[0];
  const hour = new Date().getHours();
  $("greeting").textContent = `${hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening"}, ${firstName}`;
  $("dashName").textContent = name;
  $("profName").textContent = name;
  $("avatar").textContent = initialsOf(name, user.email);

  if (button) setLoading(button, false);
  $("editForm").classList.add("hidden");
  $("profileList").classList.remove("hidden");
  $("editBtn").classList.remove("hidden");
  toast("success", "Profile updated.");
});

$("logoutBtn").addEventListener("click", () => {
  leaveApp("You have been signed out.");
});

$("termsLink").addEventListener("click", () => {
  toast("info", "Terms: laf is a client-side demo. Credentials stay on this device.");
});

/* Boot */

(function init() {
  refreshUserCount();
  const session = getSession();
  if (session) {
    const users = readUsers();
    const user = users[session.email];
    if (user) {
      enterApp(user);
      return;
    }
    clearSession();
  }
  setMode("login");
  $("loginEmail").focus({ preventScroll: true });
})();
