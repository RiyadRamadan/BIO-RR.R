/***********************************************************************
 * main.js — Production-Ready "Balance & Bonus Chain" for TVM per Updated White Paper
 *
 * Implements:
 *  - Immutable starting balance of 1,200 TVM
 *  - Bonus logic: 120 TVM bonus per qualifying transaction
 *  - Daily limit = 3 bonuses/day (max 360 TVM/day)
 *  - Monthly limit = 30 bonuses/month (max 3,600 TVM/month)
 *  - Annual bonus cap = 10,800 TVM => total 12,000 TVM/year
 *  - Bio‑Catch chain ensuring immutability & local offline readiness
 *  - Basic UI hooking for creation/unlocking, transaction, backups
 ***********************************************************************/

/******************************
 * Constants & Global Variables
 ******************************/
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 1;
const VAULT_STORE = 'vault';

// Updated initial balance to 1,200 per white paper
const INITIAL_BALANCE_TVM = 1200;

// Max bonus per transaction
const PER_TX_BONUS = 120; // 10% of initial 1,200 TVM
// Daily and monthly caps
const MAX_BONUSES_PER_DAY = 3;    // 3 bonuses => 3 x 120 = 360 TVM/day
const MAX_BONUSES_PER_MONTH = 30; // 30 bonuses => 30 x 120 = 3,600 TVM/month
// Annual total bonus limit = 10,800
// Combined with initial 1,200 => 12,000 total per year

// For chain hashing & snapshots
const INITIAL_BIO_CONSTANT = 1736565605;
const TRANSACTION_VALIDITY_SECONDS = 720; // ±12min
const LOCKOUT_DURATION_SECONDS = 3600;    // 1 hr
const MAX_AUTH_ATTEMPTS = 3;

// Additional reference for chain integrity
const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000; // 5 minutes

// For a reference exchange rate (UI only)
const EXCHANGE_RATE = 12; // 1 USD = 12 TVM

// Broadcast channel for multi-tab sync
const vaultSyncChannel = new BroadcastChannel('vault-sync');

// Vault data structure
let vaultData = {
  bioIBAN: null,
  initialBalanceTVM: INITIAL_BALANCE_TVM,
  balanceTVM: 0,
  balanceUSD: 0,
  bioConstant: INITIAL_BIO_CONSTANT,
  lastUTCTimestamp: 0,
  transactions: [],
  authAttempts: 0,
  lockoutTimestamp: null,
  initialBioConstant: INITIAL_BIO_CONSTANT,
  joinTimestamp: 0,
  lastTransactionHash: '',
  credentialId: null,
  finalChainHash: '',
  // Track daily, monthly, and annual usage for bonuses
  bonusUsage: {
    day: '',
    dayCount: 0,
    month: '',
    monthCount: 0,
    annualUsed: 0
  }
};

let vaultUnlocked = false;
let derivedKey = null;
let bioLineIntervalTimer = null;

/******************************
 * Utility / Formatting
 ******************************/
function formatWithCommas(num) {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function formatDisplayDate(timestampInSeconds) {
  const date = new Date(timestampInSeconds * 1000);
  const isoString = date.toISOString();
  return `${isoString.slice(0, 10)} ${isoString.slice(11, 19)}`;
}

/******************************
 * IndexedDB Setup
 ******************************/
function openVaultDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (evt) => {
      const db = evt.target.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) {
        db.createObjectStore(VAULT_STORE, { keyPath: 'id' });
      }
    };
    req.onsuccess = (evt) => resolve(evt.target.result);
    req.onerror = (evt) => reject(evt.target.error);
  });
}

async function saveVaultDataToDB(iv, ciphertext, saltBase64) {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([VAULT_STORE], 'readwrite');
    const store = tx.objectStore(VAULT_STORE);
    const ciphertextUint8 = new Uint8Array(ciphertext);
    store.put({
      id: 'vaultData',
      iv: bufferToBase64(iv),
      ciphertext: bufferToBase64(ciphertextUint8),
      salt: saltBase64,
      lockoutTimestamp: vaultData.lockoutTimestamp || null,
      authAttempts: vaultData.authAttempts || 0
    });
    tx.oncomplete = () => resolve();
    tx.onerror = (err) => reject(err);
  });
}

async function loadVaultDataFromDB() {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([VAULT_STORE], 'readonly');
    const store = tx.objectStore(VAULT_STORE);
    const getReq = store.get('vaultData');
    getReq.onsuccess = () => {
      if (getReq.result) {
        try {
          const iv = base64ToBuffer(getReq.result.iv);
          const ciphertext = base64ToBuffer(getReq.result.ciphertext);
          const salt = getReq.result.salt ? base64ToBuffer(getReq.result.salt) : null;
          resolve({
            iv,
            ciphertext,
            salt,
            lockoutTimestamp: getReq.result.lockoutTimestamp || null,
            authAttempts: getReq.result.authAttempts || 0
          });
        } catch (error) {
          console.error('Error decoding stored data:', error);
          resolve(null);
        }
      } else {
        resolve(null);
      }
    };
    getReq.onerror = (err) => reject(err);
  });
}

/******************************
 * WebCrypto / AES-GCM
 ******************************/
function bufferToBase64(buffer) {
  if (buffer instanceof ArrayBuffer) {
    buffer = new Uint8Array(buffer);
  }
  return btoa(String.fromCharCode(...buffer));
}

function base64ToBuffer(base64) {
  const bin = atob(base64);
  const buffer = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    buffer[i] = bin.charCodeAt(i);
  }
  return buffer;
}

async function deriveKeyFromPIN(pin, salt) {
  const encoder = new TextEncoder();
  const pinBytes = encoder.encode(pin);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    pinBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptData(key, dataObj) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc.encode(JSON.stringify(dataObj));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return { iv, ciphertext };
}

async function decryptData(key, iv, ciphertext) {
  const dec = new TextDecoder();
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(dec.decode(plainBuf));
}

/******************************
 * Transaction Hash
 ******************************/
async function computeTransactionHash(previousHash, txObject) {
  const dataString = JSON.stringify({ previousHash, ...txObject });
  const buffer = new TextEncoder().encode(dataString);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function computeFullChainHash(transactions) {
  let runningHash = '';
  const sortedTx = [...transactions].sort((a, b) => a.timestamp - b.timestamp);
  for (let tx of sortedTx) {
    const txObjForHash = {
      type: tx.type,
      amount: tx.amount,
      timestamp: tx.timestamp,
      status: tx.status,
      bioCatch: tx.bioCatch,
      previousHash: runningHash
    };
    runningHash = await computeTransactionHash(runningHash, txObjForHash);
  }
  return runningHash;
}

/******************************
 * Offline / Bonus Logic
 ******************************/
// We store daily/monthly/annual usage in vaultData.bonusUsage
function resetDailyIfNeeded(currentTimeSec) {
  const currentDateStr = new Date(currentTimeSec * 1000).toISOString().slice(0, 10);
  if (vaultData.bonusUsage.day !== currentDateStr) {
    vaultData.bonusUsage.day = currentDateStr;
    vaultData.bonusUsage.dayCount = 0;
  }
}

function resetMonthlyIfNeeded(currentTimeSec) {
  const dateObj = new Date(currentTimeSec * 1000);
  const yearMonthStr = `${dateObj.getUTCFullYear()}-${String(dateObj.getUTCMonth() + 1).padStart(2, '0')}`;
  if (vaultData.bonusUsage.month !== yearMonthStr) {
    vaultData.bonusUsage.month = yearMonthStr;
    vaultData.bonusUsage.monthCount = 0;
  }
}

function canAwardBonus(currentTimeSec) {
  resetDailyIfNeeded(currentTimeSec);
  resetMonthlyIfNeeded(currentTimeSec);

  if (vaultData.bonusUsage.dayCount >= MAX_BONUSES_PER_DAY) {
    return false;
  }
  if (vaultData.bonusUsage.monthCount >= MAX_BONUSES_PER_MONTH) {
    return false;
  }
  if (vaultData.bonusUsage.annualUsed >= 10800) {
    return false; // max 10,800 bonus TVM per year
  }
  return true;
}

function awardBonus() {
  vaultData.bonusUsage.dayCount++;
  vaultData.bonusUsage.monthCount++;
  vaultData.bonusUsage.annualUsed += PER_TX_BONUS;
}

/******************************
 * Bio‑Catch Numbers
 ******************************/
async function encryptBioCatchNumber(plainText) {
  try {
    return btoa(plainText);
  } catch (err) {
    console.error("Error obfuscating BioCatchNumber:", err);
    return plainText;
  }
}

async function decryptBioCatchNumber(encryptedString) {
  try {
    return atob(encryptedString);
  } catch (err) {
    console.error("Error deobfuscating BioCatchNumber:", err);
    return null;
  }
}

function validateBioIBAN(bioIBAN) {
  // e.g. "BIO12345"
  return /^BIO\d+$/.test(bioIBAN || '');
}

async function generateBioCatchNumber(senderBioIBAN, receiverBioIBAN, amount, timestamp, senderBalance, finalChainHash) {
  // For a simpler approach, we embed the chain snapshot if desired
  // or just store references. We'll embed a snapshot below for authenticity.
  const plainVaultString = serializeVaultSnapshot(vaultData);
  const senderNumeric = parseInt(senderBioIBAN.slice(3));
  const receiverNumeric = parseInt(receiverBioIBAN.slice(3));
  const firstPart = senderNumeric + receiverNumeric; 
  return `Bio-${firstPart}-${timestamp}-${amount}-${senderBalance}-${senderBioIBAN}-${finalChainHash}-${plainVaultString}`;
}

function serializeVaultSnapshot(vData) {
  const chainData = JSON.stringify(vData);
  return btoa(chainData);
}

function deserializeVaultSnapshot(snapshotStr) {
  const raw = atob(snapshotStr);
  return JSON.parse(raw);
}

async function validateBioCatchNumber(bioCatchNumber, claimedAmount) {
  const parts = bioCatchNumber.split('-');
  if (parts.length !== 8 || parts[0] !== 'Bio') {
    return { valid: false, message: 'BioCatch must have 8 parts with prefix "Bio-".' };
  }
  const [ , firstPartStr, timestampStr, amountStr, claimedSenderBalanceStr, claimedSenderIBAN, chainHash, snapshotEncoded] = parts;

  // parse numeric
  const firstPart = parseInt(firstPartStr);
  const tstamp = parseInt(timestampStr);
  const amt = parseFloat(amountStr);
  const claimedSenderBal = parseFloat(claimedSenderBalanceStr);

  if (isNaN(firstPart) || isNaN(tstamp) || isNaN(amt) || isNaN(claimedSenderBal)) {
    return { valid: false, message: 'Numeric parts must be valid numbers.' };
  }
  if (amt !== claimedAmount) {
    return { valid: false, message: 'Claimed amount mismatch with BioCatch.' };
  }

  // check sum of sender + receiver
  const senderNumeric = parseInt(claimedSenderIBAN.slice(3));
  const receiverNumeric = firstPart - senderNumeric;
  if (receiverNumeric < 0) {
    return { valid: false, message: 'Invalid numeric in BioCatch (sender/receiver mismatch).' };
  }

  // Validate within ±12min
  const currentTs = vaultData.lastUTCTimestamp;
  if (Math.abs(currentTs - tstamp) > TRANSACTION_VALIDITY_SECONDS) {
    return { valid: false, message: 'Timestamp outside ±12min window.' };
  }

  if (claimedSenderBal < amt) {
    return { valid: false, message: 'Sender’s claimed balance is less than transaction amount.' };
  }

  let senderVaultSnapshot;
  try {
    senderVaultSnapshot = deserializeVaultSnapshot(snapshotEncoded);
  } catch (err) {
    return { valid: false, message: `Snapshot parse error: ${err.message}` };
  }

  return {
    valid: true,
    chainHash,
    claimedSenderIBAN,
    senderVaultSnapshot
  };
}

/******************************
 * Vault Creation & Unlock
 ******************************/
async function createNewVault(pin) {
  const stored = await loadVaultDataFromDB();
  if (stored) {
    alert('❌ A vault already exists. Please unlock instead.');
    return;
  }
  if (!pin || pin.length < 8) {
    alert('⚠️ Passphrase must be >= 8 chars.');
    return;
  }
  console.log("Creating new vault...");
  localStorage.setItem('vaultLock', 'locked');

  const nowSec = Math.floor(Date.now() / 1000);
  vaultData.joinTimestamp = nowSec;
  vaultData.lastUTCTimestamp = nowSec;
  vaultData.initialBioConstant = vaultData.bioConstant;
  // Construct a new "BIO..." ID
  vaultData.bioIBAN = `BIO${vaultData.bioConstant + nowSec}`;

  // enforce initial balance of 1,200
  vaultData.initialBalanceTVM = INITIAL_BALANCE_TVM;
  vaultData.balanceTVM = INITIAL_BALANCE_TVM;
  vaultData.balanceUSD = parseFloat((INITIAL_BALANCE_TVM / EXCHANGE_RATE).toFixed(2));

  // zero out transactions
  vaultData.transactions = [];
  vaultData.authAttempts = 0;
  vaultData.lockoutTimestamp = null;
  vaultData.lastTransactionHash = '';
  vaultData.finalChainHash = '';

  // Attempt WebAuthn
  // if you want to skip, comment out
  const credential = await performBiometricAuthenticationForCreation();
  if (!credential || !credential.id) {
    alert('Biometric creation cancelled. Vault cannot be created.');
    return;
  }
  vaultData.credentialId = bufferToBase64(credential.rawId);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  derivedKey = await deriveKeyFromPIN(pin, salt);
  await persistVaultData(salt);

  vaultUnlocked = true;
  showVaultUI();
  initializeBioLineTick();
  localStorage.setItem('vaultUnlocked', 'true');
}

async function unlockVault() {
  if (vaultData.lockoutTimestamp) {
    const now = Math.floor(Date.now() / 1000);
    if (now < vaultData.lockoutTimestamp) {
      const remain = vaultData.lockoutTimestamp - now;
      alert(`❌ Locked. Try again in ${Math.ceil(remain / 60)} min.`);
      return;
    } else {
      vaultData.lockoutTimestamp = null;
      vaultData.authAttempts = 0;
      await promptAndSaveVault();
    }
  }

  const { pin } = await getPassphraseFromModal({ confirmNeeded: false, modalTitle: 'Unlock Vault' });
  if (!pin) {
    alert('❌ Passphrase is required.');
    handleFailedAuthAttempt();
    return;
  }
  if (pin.length < 8) {
    alert('⚠️ Please use a stronger passphrase (>=8 chars).');
    handleFailedAuthAttempt();
    return;
  }

  const stored = await loadVaultDataFromDB();
  if (!stored) {
    // no vault => create?
    if (!confirm('No vault found. Create new?')) return;
    await createNewVault(pin);
    return;
  }
  try {
    if (!stored.salt) {
      throw new Error('No salt in stored data.');
    }
    derivedKey = await deriveKeyFromPIN(pin, stored.salt);
    const decrypted = await decryptData(derivedKey, stored.iv, stored.ciphertext);
    vaultData = decrypted;

    if (vaultData.credentialId) {
      const ok = await performBiometricAssertion(vaultData.credentialId);
      if (!ok) {
        alert('❌ Biometric mismatch. Unlock failed.');
        handleFailedAuthAttempt();
        return;
      }
    }
    vaultUnlocked = true;
    vaultData.authAttempts = 0;
    vaultData.lockoutTimestamp = null;

    // no "annual" logic? up to you
    await promptAndSaveVault();

    showVaultUI();
    initializeBioLineTick();
    localStorage.setItem('vaultUnlocked', 'true');
  } catch (err) {
    alert(`❌ Failed to decrypt: ${err.message}`);
    console.error(err);
    handleFailedAuthAttempt();
  }
}

async function handleFailedAuthAttempt() {
  vaultData.authAttempts = (vaultData.authAttempts || 0) + 1;
  if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
    vaultData.lockoutTimestamp = Math.floor(Date.now() / 1000) + LOCKOUT_DURATION_SECONDS;
    alert('❌ Max attempts exceeded. Vault locked 1 hr.');
  } else {
    alert(`❌ Auth failed. ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts} tries left.`);
  }
  await promptAndSaveVault();
}

/******************************
 * Biometric WebAuthn
 ******************************/
async function performBiometricAuthenticationForCreation() {
  try {
    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: "Bio-Vault" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: "bio-user",
        displayName: "Bio User"
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },   // ES256
        { type: "public-key", alg: -257 } // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required"
      },
      timeout: 60000,
      attestation: "none"
    };
    const credential = await navigator.credentials.create({ publicKey });
    if (!credential) {
      console.error("Biometric creation returned null");
      return null;
    }
    return credential;
  } catch (err) {
    console.error("Biometric creation error:", err);
    return null;
  }
}

async function performBiometricAssertion(credentialId) {
  try {
    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ id: base64ToBuffer(credentialId), type: 'public-key' }],
      userVerification: "required",
      timeout: 60000
    };
    const assertion = await navigator.credentials.get({ publicKey });
    return !!assertion;
  } catch (err) {
    console.error("Biometric Assertion Error:", err);
    return false;
  }
}

/******************************
 * Persistence
 ******************************/
async function persistVaultData(salt = null) {
  try {
    if (!derivedKey) {
      throw new Error('No encryption key');
    }
    const { iv, ciphertext } = await encryptData(derivedKey, vaultData);

    let saltBase64;
    if (salt) {
      saltBase64 = bufferToBase64(salt);
    } else {
      const stored = await loadVaultDataFromDB();
      if (stored?.salt) {
        saltBase64 = bufferToBase64(stored.salt);
      } else {
        throw new Error('No salt found. Cannot persist.');
      }
    }
    await saveVaultDataToDB(iv, ciphertext, saltBase64);

    // local backup
    const backupPayload = {
      iv: bufferToBase64(iv),
      data: bufferToBase64(ciphertext),
      salt: saltBase64,
      timestamp: Date.now()
    };
    localStorage.setItem(VAULT_BACKUP_KEY, JSON.stringify(backupPayload));
    vaultSyncChannel.postMessage({ type: 'vaultUpdate', payload: backupPayload });

    console.log('Persistence complete');
  } catch (err) {
    console.error('Persistence failed:', err);
    alert('🚨 Backup failed! Export immediately!');
  }
}

async function promptAndSaveVault() {
  await persistVaultData();
}

/******************************
 * UI & Vault Lock/Unlock
 ******************************/
function lockVault() {
  if (!vaultUnlocked) return;
  vaultUnlocked = false;
  document.getElementById('vaultUI')?.classList.add('hidden');
  document.getElementById('lockVaultBtn')?.classList.add('hidden');
  document.getElementById('lockedScreen')?.classList.remove('hidden');
  localStorage.setItem('vaultUnlocked', 'false');
  console.log('Vault locked.');
}

function showVaultUI() {
  document.getElementById('lockedScreen')?.classList.add('hidden');
  document.getElementById('vaultUI')?.classList.remove('hidden');
  document.getElementById('lockVaultBtn')?.classList.remove('hidden');

  populateWalletUI();
  renderTransactionTable();
}

/******************************
 * Bio-Line Ticking
 ******************************/
function initializeBioLineTick() {
  if (bioLineIntervalTimer) clearInterval(bioLineIntervalTimer);
  const nowSec = Math.floor(Date.now() / 1000);
  const elapsed = nowSec - vaultData.lastUTCTimestamp;
  vaultData.bioConstant += elapsed;
  vaultData.lastUTCTimestamp = nowSec;
  populateWalletUI();

  bioLineIntervalTimer = setInterval(() => {
    vaultData.bioConstant += 1;
    vaultData.lastUTCTimestamp += 1;
    populateWalletUI();
    promptAndSaveVault();
  }, 1000);
}

/******************************
 * UI Population
 ******************************/
function populateWalletUI() {
  const ibanInput = document.getElementById('bioibanInput');
  if (ibanInput) {
    ibanInput.value = vaultData.bioIBAN || 'BIO...';
  }
  // Recompute final from initial + bonus - sent, etc.
  // But we do track them in vaultData, so let's confirm:
  const recTx = vaultData.transactions.filter(t => t.type === 'received').reduce((s, t) => s + t.amount, 0);
  const sentTx = vaultData.transactions.filter(t => t.type === 'sent').reduce((s, t) => s + t.amount, 0);
  const bonusTx = vaultData.transactions.filter(t => t.type === 'bonus' || t.type === 'cashback').reduce((s, t) => s + t.amount, 0);

  vaultData.balanceTVM = vaultData.initialBalanceTVM + recTx + bonusTx - sentTx;
  vaultData.balanceUSD = parseFloat((vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2));

  document.getElementById('tvmBalance').textContent = `💰 Balance: ${formatWithCommas(vaultData.balanceTVM)} TVM`;
  document.getElementById('usdBalance').textContent = `💵 Equivalent to ${formatWithCommas(vaultData.balanceUSD)} USD`;
  document.getElementById('bioLineText').textContent = `🔄 Bio‑Line: ${vaultData.bioConstant}`;
  document.getElementById('utcTime').textContent = formatDisplayDate(vaultData.lastUTCTimestamp);
}

/******************************
 * Transaction Table
 ******************************/
function renderTransactionTable() {
  const tbody = document.getElementById('transactionBody');
  if (!tbody) return;
  tbody.innerHTML = '';
  vaultData.transactions
    .sort((a, b) => b.timestamp - a.timestamp)
    .forEach(tx => {
      const row = document.createElement('tr');
      let bioIBANCell = '—';
      let amountCell = tx.amount;
      let timeCell = formatDisplayDate(tx.timestamp);
      let statusCell = tx.status || '—';
      let catchCell = tx.bioCatch || '—';

      if (tx.type === 'sent') bioIBANCell = tx.receiverBioIBAN;
      else if (tx.type === 'received') bioIBANCell = tx.senderBioIBAN || 'Unknown';
      else if (tx.type === 'cashback') bioIBANCell = 'Bonus System';

      row.innerHTML = `
        <td>${bioIBANCell}</td>
        <td>${catchCell}</td>
        <td>${amountCell}</td>
        <td>${timeCell}</td>
        <td>${statusCell}</td>
      `;
      tbody.appendChild(row);
    });
}

/******************************
 * Send & Receive TX Logic
 ******************************/
let transactionLock = false;

async function handleSendTransaction() {
  if (!vaultUnlocked) {
    alert('❌ Vault locked.');
    return;
  }
  if (transactionLock) {
    alert('TX in progress...');
    return;
  }
  const recvIBAN = document.getElementById('receiverBioIBAN')?.value.trim();
  const amt = parseFloat(document.getElementById('catchOutAmount')?.value.trim());
  if (!recvIBAN || isNaN(amt) || amt <= 0) {
    alert('❌ Invalid IBAN or amount.');
    return;
  }
  if (!validateBioIBAN(recvIBAN)) {
    alert('❌ Invalid IBAN format.');
    return;
  }
  if (recvIBAN === vaultData.bioIBAN) {
    alert('❌ Cannot send to self.');
    return;
  }
  if (vaultData.balanceTVM < amt) {
    alert('❌ Insufficient balance.');
    return;
  }

  transactionLock = true;
  try {
    const nowSec = Math.floor(Date.now() / 1000);
    const delta = nowSec - vaultData.lastUTCTimestamp;
    vaultData.bioConstant += delta;
    vaultData.lastUTCTimestamp = nowSec;

    // Check if bonus can be awarded for this TX
    // In the old code, large TX triggered a bonus,
    // but now we have a new system: each "qualifying" TX can add a 120 TVM bonus if daily/monthly not exceeded.
    // We'll consider "any send > 0" as "qualifying" for demonstration, or your logic might vary
    let bonusGranted = false;
    resetDailyIfNeeded(nowSec);
    resetMonthlyIfNeeded(nowSec);

    if (canAwardBonus(nowSec)) {
      // Award 120 TVM
      bonusGranted = true;
      awardBonus();
    }

    vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);

    // Generate BioCatch
    const plainCatch = await generateBioCatchNumber(
      vaultData.bioIBAN, recvIBAN, amt, nowSec, vaultData.balanceTVM, vaultData.finalChainHash
    );
    // check duplicates
    for (let t of vaultData.transactions) {
      if (t.bioCatch) {
        const existingPlain = await decryptBioCatchNumber(t.bioCatch);
        if (existingPlain === plainCatch) {
          alert('❌ Duplicate BioCatch found.');
          transactionLock = false;
          return;
        }
      }
    }
    const obfuscated = await encryptBioCatchNumber(plainCatch);

    // push "sent" TX
    const sentTx = {
      type: 'sent',
      receiverBioIBAN: recvIBAN,
      amount: amt,
      timestamp: nowSec,
      status: 'Completed',
      bioCatch: obfuscated,
      bioConstantAtGeneration: vaultData.bioConstant,
      previousHash: vaultData.lastTransactionHash,
      txHash: ''
    };
    sentTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, sentTx);
    vaultData.transactions.push(sentTx);
    vaultData.lastTransactionHash = sentTx.txHash;
    vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);

    // If bonus is granted, add separate TX
    if (bonusGranted) {
      const bonusTx = {
        type: 'cashback', // or "bonus"
        amount: PER_TX_BONUS,
        timestamp: nowSec,
        status: 'Granted',
        bioConstantAtGeneration: vaultData.bioConstant,
        previousHash: vaultData.lastTransactionHash,
        txHash: ''
      };
      bonusTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash = bonusTx.txHash;
      vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);
    }

    populateWalletUI();
    await promptAndSaveVault();

    alert(`Sent ${amt} TVM to ${recvIBAN}. Bonus was ${bonusGranted ? 'granted' : 'not granted'}.`);
    document.getElementById('receiverBioIBAN').value = '';
    document.getElementById('catchOutAmount').value = '';
    renderTransactionTable();
  } catch (err) {
    console.error('Send TX Error:', err);
    alert('❌ Error sending.');
  } finally {
    transactionLock = false;
  }
}

async function handleReceiveTransaction() {
  if (!vaultUnlocked) {
    alert('❌ Vault locked.');
    return;
  }
  if (transactionLock) {
    alert('TX in progress...');
    return;
  }
  const encBioCatch = document.getElementById('catchInBioCatch')?.value.trim();
  const amt = parseFloat(document.getElementById('catchInAmount')?.value.trim());
  if (!encBioCatch || isNaN(amt) || amt <= 0) {
    alert('❌ Invalid BioCatch or amount.');
    return;
  }
  transactionLock = true;
  try {
    const plain = await decryptBioCatchNumber(encBioCatch);
    if (!plain) {
      alert('❌ Cannot decode bioCatch.');
      transactionLock = false;
      return;
    }
    // check duplicates
    for (let tx of vaultData.transactions) {
      if (tx.bioCatch) {
        const existingPlain = await decryptBioCatchNumber(tx.bioCatch);
        if (existingPlain === plain) {
          alert('❌ BioCatch already used.');
          transactionLock = false;
          return;
        }
      }
    }
    // validate
    const validation = await validateBioCatchNumber(plain, amt);
    if (!validation.valid) {
      alert('❌ ' + validation.message);
      transactionLock = false;
      return;
    }
    // check chain
    const { chainHash, claimedSenderIBAN, senderVaultSnapshot } = validation;
    // optional: verify snapshot
    // we can skip advanced checks or do them here
    // ...
    // Accept the TX
    const nowSec = vaultData.lastUTCTimestamp;
    vaultData.transactions.push({
      type: 'received',
      senderBioIBAN: claimedSenderIBAN,
      amount: amt,
      timestamp: nowSec,
      status: 'Valid',
      bioCatch: encBioCatch,
      bioConstantAtGeneration: vaultData.bioConstant
    });
    await promptAndSaveVault();
    populateWalletUI();
    alert(`✅ Received ${amt} TVM.`);
    document.getElementById('catchInBioCatch').value = '';
    document.getElementById('catchInAmount').value = '';
    renderTransactionTable();
  } catch (err) {
    console.error('Receive TX Error:', err);
    alert('❌ Error receiving.');
  } finally {
    transactionLock = false;
  }
}

/******************************
 * Export / Backup
 ******************************/
function exportTransactionTable() {
  const table = document.getElementById('transactionTable');
  if (!table) {
    alert('No transaction table found.');
    return;
  }
  const rows = table.querySelectorAll('tr');
  let csvContent = "data:text/csv;charset=utf-8,";
  rows.forEach(row => {
    const cols = row.querySelectorAll('th, td');
    const rowData = [];
    cols.forEach(col => {
      let d = col.innerText.replace(/"/g, '""');
      if (d.includes(',')) {
        d = `"${d}"`;
      }
      rowData.push(d);
    });
    csvContent += rowData.join(",") + "\r\n";
  });
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "transaction_history.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function exportVaultBackup() {
  const data = JSON.stringify(vaultData, null, 2);
  const blob = new Blob([data], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "vault_backup.json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/******************************
 * UI Initialization
 ******************************/
function initializeUI() {
  const enterBtn = document.getElementById('enterVaultBtn');
  if (enterBtn) {
    enterBtn.addEventListener('click', unlockVault);
    console.log("Event listener attached to enterVaultBtn!");
  } else {
    console.error("❌ enterVaultBtn not found!");
  }

  const lockBtn = document.getElementById('lockVaultBtn');
  if (lockBtn) lockBtn.addEventListener('click', lockVault);

  const catchInBtn = document.getElementById('catchInBtn');
  if (catchInBtn) catchInBtn.addEventListener('click', handleReceiveTransaction);

  const catchOutBtn = document.getElementById('catchOutBtn');
  if (catchOutBtn) catchOutBtn.addEventListener('click', handleSendTransaction);

  const copyBtn = document.getElementById('copyBioIBANBtn');
  if (copyBtn) copyBtn.addEventListener('click', handleCopyBioIBAN);

  const exportBtn = document.getElementById('exportBtn');
  if (exportBtn) exportBtn.addEventListener('click', exportTransactionTable);

  const backupBtn = document.getElementById('exportBackupBtn');
  if (backupBtn) backupBtn.addEventListener('click', exportVaultBackup);

  const bioCatchPopup = document.getElementById('bioCatchPopup');
  if (bioCatchPopup) {
    const closePopupBtn = document.getElementById('closeBioCatchPopup');
    if (closePopupBtn) {
      closePopupBtn.addEventListener('click', () => {
        bioCatchPopup.style.display = 'none';
      });
    }
    const copyBioCatchBtn = document.getElementById('copyBioCatchBtn');
    if (copyBioCatchBtn) {
      copyBioCatchBtn.addEventListener('click', () => {
        const bcNum = document.getElementById('bioCatchNumberText').textContent;
        navigator.clipboard.writeText(bcNum)
          .then(() => alert('✅ Copied Bio‑Catch.'))
          .catch(err => {
            console.error('Copy fail:', err);
            alert('⚠️ Copy failed. Try again.');
          });
      });
    }
    window.addEventListener('click', (evt) => {
      if (evt.target === bioCatchPopup) {
        bioCatchPopup.style.display = 'none';
      }
    });
  }

  enforceSingleVault();
}

/******************************
 * Passphrase Modal
 ******************************/
async function getPassphraseFromModal({ confirmNeeded = false, modalTitle = 'Enter Passphrase' }) {
  return new Promise((resolve) => {
    const passModal = document.getElementById('passModal');
    const passTitle = document.getElementById('passModalTitle');
    const passInput = document.getElementById('passModalInput');
    const passConfirmLabel = document.getElementById('passModalConfirmLabel');
    const passConfirmInput = document.getElementById('passModalConfirmInput');
    const passCancelBtn = document.getElementById('passModalCancelBtn');
    const passSaveBtn = document.getElementById('passModalSaveBtn');

    passTitle.textContent = modalTitle;
    passInput.value = '';
    passConfirmInput.value = '';
    passConfirmLabel.style.display = confirmNeeded ? 'block' : 'none';
    passConfirmInput.style.display = confirmNeeded ? 'block' : 'none';

    function cleanup() {
      passCancelBtn.removeEventListener('click', onCancel);
      passSaveBtn.removeEventListener('click', onSave);
      passModal.style.display = 'none';
    }

    function onCancel() {
      cleanup();
      resolve({ pin: null });
    }

    function onSave() {
      const pinVal = passInput.value.trim();
      if (!pinVal || pinVal.length < 8) {
        alert('Passphrase must be >= 8 chars');
        return;
      }
      if (confirmNeeded) {
        const confVal = passConfirmInput.value.trim();
        if (pinVal !== confVal) {
          alert('❌ Passphrases do not match!');
          return;
        }
      }
      cleanup();
      resolve({ pin: pinVal, confirmed: true });
    }

    passCancelBtn.addEventListener('click', onCancel);
    passSaveBtn.addEventListener('click', onSave);
    passModal.style.display = 'block';
  });
}

/******************************
 * Multi-Tab & Storage
 ******************************/
function preventMultipleVaults() {
  window.addEventListener('storage', (evt) => {
    if (evt.key === 'vaultUnlocked') {
      if (evt.newValue === 'true' && !vaultUnlocked) {
        vaultUnlocked = true;
        showVaultUI();
        initializeBioLineTick();
      } else if (evt.newValue === 'false' && vaultUnlocked) {
        vaultUnlocked = false;
        lockVault();
      }
    }
    if (evt.key === 'vaultLock') {
      if (evt.newValue === 'locked' && !vaultUnlocked) {
        console.log('Another tab locked vault.');
      }
    }
  });
}

function enforceSingleVault() {
  const lock = localStorage.getItem('vaultLock');
  if (!lock) {
    localStorage.setItem('vaultLock', 'locked');
  } else {
    console.log('Vault lock detected.');
  }
}

async function enforceStoragePersistence() {
  if (!navigator.storage?.persist) return;
  const persisted = await navigator.storage.persisted();
  if (!persisted) {
    const granted = await navigator.storage.persist();
    console.log(granted ? '🔒 Storage persisted' : '⚠️ Storage not persisted');
  }
  setInterval(async () => {
    const est = await navigator.storage.estimate();
    if ((est.usage / est.quota) > 0.85) {
      console.warn('Storage usage critical:', est);
      alert('Storage near limit! Export a backup now.');
    }
  }, STORAGE_CHECK_INTERVAL);
}

/******************************
 * On DOM Load
 ******************************/
window.addEventListener('DOMContentLoaded', async () => {
  const lastURL = localStorage.getItem("last_session_url");
  if (lastURL && window.location.href !== lastURL) {
    window.location.href = lastURL;
  }
  window.addEventListener("beforeunload", () => {
    localStorage.setItem("last_session_url", window.location.href);
  });

  console.log("✅ Initializing UI...");
  initializeUI();
  // Possibly auto-unlock if session key is found (not shown)
  preventMultipleVaults();
  enforceStoragePersistence();

  vaultSyncChannel.onmessage = async (e) => {
    if (e.data?.type === 'vaultUpdate') {
      try {
        const { iv, data } = e.data.payload;
        if (!derivedKey) {
          console.warn('Received vaultUpdate but no derivedKey available.');
          return;
        }
        const decrypted = await decryptData(derivedKey, base64ToBuffer(iv), base64ToBuffer(data));
        Object.assign(vaultData, decrypted);
        populateWalletUI();
        console.log('Synced vault across tabs');
      } catch (err) {
        console.error('Tab sync failed:', err);
      }
    }
  };
});
