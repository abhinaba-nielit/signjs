const publicKeyStatus = document.getElementById("public-key-status");
const refreshStatusButton = document.getElementById("refresh-status");
const generateKeysButton = document.getElementById("generate-keys");
const privateKeyDownload = document.getElementById("private-key-download");
const uploadPublicKeyButton = document.getElementById("upload-public-key");
const privateKeySavedCheckbox = document.getElementById("private-key-saved");
const publicKeyPreview = document.getElementById("public-key-preview");
const dataFileInput = document.getElementById("data-file");
const privateKeyFileInput = document.getElementById("private-key-file");
const createSignatureButton = document.getElementById("create-signature");
const signatureOutput = document.getElementById("signature-output");
const submitSignatureButton = document.getElementById("submit-signature");
const verificationResult = document.getElementById("verification-result");

let generatedPublicKey = "";
let signedDataBase64 = "";
let signatureBase64 = "";
let serverHasPublicKey = false;

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function pemToArrayBuffer(pem) {
  const headerPattern = /-----BEGIN [^-]+-----/;
  const footerPattern = /-----END [^-]+-----/;
  const body = pem.replace(headerPattern, "")
    .replace(footerPattern, "")
    .replace(/\s+/g, "");
  const binary = atob(body);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return buffer;
}

function updateUploadButtonState() {
  uploadPublicKeyButton.disabled = !(generatedPublicKey && privateKeySavedCheckbox.checked);
}

function setStatusBadge(text, type) {
  publicKeyStatus.textContent = text;
  publicKeyStatus.classList.remove("badge-success", "badge-warning", "badge-error");
  publicKeyStatus.classList.add(type);
}

async function fetchPublicKeyStatus() {
  setStatusBadge("Checking...", "badge-warning");
  try {
    const response = await fetch("/api/public-key/status");
    if (!response.ok) {
      throw new Error("Unable to check status");
    }
    const payload = await response.json();
    serverHasPublicKey = Boolean(payload.exists);
    if (serverHasPublicKey) {
      setStatusBadge("Public key stored", "badge-success");
    } else {
      setStatusBadge("No public key saved", "badge-error");
    }
  } catch (error) {
    serverHasPublicKey = false;
    setStatusBadge("Status unavailable", "badge-error");
  }
}

async function generateKeyPair() {
  generatedPublicKey = "";
  signatureBase64 = "";
  signedDataBase64 = "";
  signatureOutput.value = "";
  verificationResult.textContent = "";

  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  const privateKeyDer = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const publicKeyDer = await crypto.subtle.exportKey("spki", keyPair.publicKey);

  const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${arrayBufferToBase64(privateKeyDer)
    .match(/.{1,64}/g)
    .join("\n")}\n-----END PRIVATE KEY-----`;
  const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${arrayBufferToBase64(publicKeyDer)
    .match(/.{1,64}/g)
    .join("\n")}\n-----END PUBLIC KEY-----`;

  generatedPublicKey = publicKeyPem;
  privateKeySavedCheckbox.checked = false;
  const privateBlob = new Blob([privateKeyPem], { type: "application/x-pem-file" });
  privateKeyDownload.href = URL.createObjectURL(privateBlob);
  privateKeyDownload.classList.remove("hidden");
  privateKeyPreview.textContent = publicKeyPem;
  publicKeyPreview.classList.remove("hidden");
  updateUploadButtonState();
}

async function savePublicKey() {
  if (!generatedPublicKey) {
    alert("Generate and download a key pair first.");
    return;
  }
  if (!privateKeySavedCheckbox.checked) {
    alert("Please confirm you downloaded the private key before saving the public key.");
    return;
  }

  const response = await fetch("/api/public-key", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ public_key: generatedPublicKey })
  });

  if (!response.ok) {
    alert("Unable to save public key on the server.");
    return;
  }

  await fetchPublicKeyStatus();
  alert("Public key saved on the server. Only the last uploaded key is kept.");
}

async function createSignature() {
  verificationResult.textContent = "";
  signatureOutput.value = "";
  signatureBase64 = "";
  signedDataBase64 = "";

  if (!serverHasPublicKey) {
    alert("No public key on the server. Upload one before signing.");
    return;
  }

  const dataFile = dataFileInput.files[0];
  const privateKeyFile = privateKeyFileInput.files[0];

  if (!dataFile || !privateKeyFile) {
    alert("Select both a data file and a private key file.");
    return;
  }

  const dataBuffer = await dataFile.arrayBuffer();
  const privateKeyText = await privateKeyFile.text();
  const privateKeyBuffer = pemToArrayBuffer(privateKeyText);

  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    privateKeyBuffer,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );

  const signatureBuffer = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    privateKey,
    dataBuffer
  );

  signatureBase64 = arrayBufferToBase64(signatureBuffer);
  signedDataBase64 = arrayBufferToBase64(dataBuffer);
  signatureOutput.value = signatureBase64;
  privateKeyFileInput.value = ""; // remove uploaded private key reference
}

async function submitSignature() {
  verificationResult.textContent = "";

  if (!serverHasPublicKey) {
    alert("No public key stored on the server.");
    return;
  }
  if (!signedDataBase64 || !signatureBase64) {
    alert("Create a signature first.");
    return;
  }

  const response = await fetch("/api/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data: signedDataBase64, signature: signatureBase64 })
  });

  if (!response.ok) {
    verificationResult.textContent = "Verification failed to run.";
    verificationResult.classList.add("badge-error");
    return;
  }

  const payload = await response.json();
  if (payload.valid) {
    verificationResult.textContent = "Signature is valid.";
    verificationResult.classList.remove("badge-error");
    verificationResult.classList.add("badge-success");
  } else {
    verificationResult.textContent = "Signature is NOT valid.";
    verificationResult.classList.remove("badge-success");
    verificationResult.classList.add("badge-error");
  }
}

refreshStatusButton.addEventListener("click", fetchPublicKeyStatus);
generateKeysButton.addEventListener("click", generateKeyPair);
privateKeySavedCheckbox.addEventListener("change", updateUploadButtonState);
uploadPublicKeyButton.addEventListener("click", savePublicKey);
createSignatureButton.addEventListener("click", createSignature);
submitSignatureButton.addEventListener("click", submitSignature);

fetchPublicKeyStatus();

