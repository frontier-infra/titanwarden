"use strict";

const decode = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const encode = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const csrf = document.querySelector('meta[name="csrf-token"]')?.content;

async function post(path, payload) {
  const response = await fetch(path, {method: "POST", credentials: "same-origin", cache: "no-store",
    headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf}, body: JSON.stringify(payload)});
  if (!response.ok) throw new Error("Authentication failed");
  return response.json();
}

document.querySelector("#passkey-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const enroll = form.dataset.enroll === "true";
  const button = form.querySelector("button");
  const message = document.querySelector("#auth-message");
  button.disabled = true;
  message.textContent = "Waiting for your passkey…";
  try {
    if (!window.isSecureContext || !navigator.credentials) throw new Error("Secure context required");
    const code = document.querySelector("#enrollment-code");
    const payload = enroll ? {capability: code.value} : {};
    if (code) code.value = "";
    const prefix = enroll ? "/auth/register" : "/auth";
    const options = await post(prefix + "/options", payload);
    if (enroll) payload.capability = "";
    options.challenge = decode(options.challenge);
    if (enroll) options.user.id = decode(options.user.id);
    for (const entry of (options.allowCredentials || options.excludeCredentials || [])) entry.id = decode(entry.id);
    const credential = enroll ? await navigator.credentials.create({publicKey: options}) : await navigator.credentials.get({publicKey: options});
    const response = {clientDataJSON: encode(credential.response.clientDataJSON)};
    if (enroll) response.attestationObject = encode(credential.response.attestationObject);
    else {
      response.authenticatorData = encode(credential.response.authenticatorData);
      response.signature = encode(credential.response.signature);
      response.userHandle = credential.response.userHandle ? encode(credential.response.userHandle) : null;
    }
    await post(prefix + "/verify", {credential: {id: credential.id, rawId: encode(credential.rawId), type: credential.type, response}});
    window.location.replace("/");
  } catch (_) {
    message.textContent = "We could not verify your passkey. Reload this page and try again.";
    button.disabled = false;
  }
});

document.querySelector("#put-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button");
  const message = document.querySelector("#put-message");
  const payload = Object.fromEntries(["project", "name", "class", "kind", "note", "value"].map((k) => [k, form.elements[k].value]));
  form.elements.value.value = "";
  button.disabled = true;
  message.textContent = "Storing…";
  try {
    const response = await fetch("/secrets/put", {method: "POST", credentials: "same-origin", cache: "no-store",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf}, body: JSON.stringify(payload)});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Request denied");
    window.location.reload();
  } catch (error) {
    message.textContent = error.message;
    button.disabled = false;
  }
});

for (const pick of document.querySelectorAll(".reveal-pick")) {
  pick.addEventListener("click", () => {
    const section = document.querySelector("#reveal");
    const form = document.querySelector("#reveal-form");
    section.hidden = false;
    form.elements.path.value = pick.dataset.path;
    document.querySelector("#revealed").hidden = true;
    document.querySelector("#reveal-message").textContent = "";
    form.elements.reason.focus();
    section.scrollIntoView({block: "nearest"});
  });
}

document.querySelector("#reveal-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button");
  const message = document.querySelector("#reveal-message");
  const shown = document.querySelector("#revealed");
  const payload = {path: form.elements.path.value, reason: form.elements.reason.value, passphrase: form.elements.passphrase.value};
  form.elements.passphrase.value = "";
  button.disabled = true;
  shown.hidden = true;
  message.textContent = "Checking your passphrase…";
  try {
    const response = await fetch("/secrets/reveal", {method: "POST", credentials: "same-origin", cache: "no-store",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf}, body: JSON.stringify(payload)});
    payload.passphrase = "";
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Request denied");
    shown.textContent = data.encoding === "base64" ? "(binary value, base64)\n" + data.value : data.value;
    shown.hidden = false;
    let left = 30;
    message.textContent = "Masked in 30 seconds.";
    const tick = setInterval(() => {
      left -= 1;
      if (left > 0) { message.textContent = "Masked in " + left + " seconds."; return; }
      clearInterval(tick);
      shown.textContent = "";
      shown.hidden = true;
      message.textContent = "Masked. Reveal again if you still need it.";
    }, 1000);
  } catch (error) {
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

async function submitJSON(path, payload) {
  const response = await fetch(path, {method: "POST", credentials: "same-origin", cache: "no-store",
    headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf}, body: JSON.stringify(payload)});
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Request denied");
  return data;
}

document.querySelector("#unseal-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button");
  const message = document.querySelector("#unseal-message");
  const payload = {passphrase: form.elements.passphrase.value};
  form.elements.passphrase.value = "";
  button.disabled = true;
  message.textContent = "Unsealing…";
  try {
    await submitJSON("/unseal", payload);
    payload.passphrase = "";
    window.location.replace("/");
  } catch (error) {
    message.textContent = error.message;
    button.disabled = false;
  }
});

document.querySelector("#seal-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button");
  const message = document.querySelector("#seal-message");
  button.disabled = true;
  try {
    await submitJSON("/seal", {});
    window.location.reload();
  } catch (error) {
    message.textContent = error.message;
    button.disabled = false;
  }
});
