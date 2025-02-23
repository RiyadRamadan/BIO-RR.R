/***********************************************************************
 * main.js — Production-Ready "Balance & Bonus Chain" Code
 *           with Updated Bonus Logic and Full Snapshot Fields
 *
 * Preserves old code & functions, while:
 *  - Using an initial 1,200 TVM per user
 *  - Awarding 120 TVM bonuses (up to 10,800/year),
 *    with daily/monthly usage limits
 *  - Storing balanceTVM, bioConstant, and lastUTCTimestamp in the snapshot
 *    so bridging/smart-contract logic can validate the entire bonus chain
 *  - Keeping periodic increments (15K every ~3 months) if desired
 *
 * No old function is removed (e.g. copyBioIBAN, exportTransactionTable).
 ***********************************************************************/

/******************************
 * Constants & Global Variables
 ******************************/
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 1;
const VAULT_STORE = 'vault';

// From updated paper: 1,200 initial
const INITIAL_BALANCE_TVM = 1200;

// Bonus logic from new specs
const PER_TX_BONUS = 120;           // 10% of 1,200 => 120
const MAX_BONUSES_PER_DAY = 3;      // 360 TVM/day
const MAX_BONUSES_PER_MONTH = 30;   // 3,600 TVM/month
const MAX_ANNUAL_BONUS_TVM = 10800; // total 10,800 => 12,000/year

// Periodic increments (if you keep them)
const THREE_MONTHS_SECONDS = 7776000;  // ~90 days
const MAX_ANNUAL_INTERVALS = 4;
const BIO_LINE_INCREMENT_AMOUNT = 15000;

const EXCHANGE_RATE = 12; // 1 USD = 12 TVM
const INITIAL_BIO_CONSTANT = 1736565605;
const TRANSACTION_VALIDITY_SECONDS = 720; // ±12 min
const LOCKOUT_DURATION_SECONDS = 3600;    // 1 hour
const MAX_AUTH_ATTEMPTS = 3;

// For local backups
const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000; // 5 minutes

// Cross-tab sync
const vaultSyncChannel = new BroadcastChannel('vault-sync');

let vaultUnlocked = false;
let derivedKey = null;
let bioLineIntervalTimer = null;

/**
 * Updated vaultData to track monthly usage,
 * daily usage, & annual bonus usage
 * while preserving old fields (dailyCashback, etc.)
 */
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

  // For the periodic increments (if desired)
  incrementsUsed: 0,

  // For chain hashing
  lastTransactionHash: '',
  credentialId: null,
  finalChainHash: '',

  // Old daily usage structure
  dailyCashback: {
    date: '',
    usedCount: 0
  },

  // Additional monthly usage & annual usage
  monthlyUsage: {
    yearMonth: '',
    usedCount: 0
  },
  annualBonusUsed: 0
};

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
 * "Add to Home Screen" Prompt
 ******************************/
let deferredPrompt = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  console.log("⭐ 'beforeinstallprompt' captured — call promptInstallA2HS() to show UI prompt.");
});

function promptInstallA2HS() {
  if (!deferredPrompt) {
    console.log("No deferredPrompt available or user already installed.");
    return;
  }
  deferredPrompt.prompt();
  deferredPrompt.userChoice.then(choiceResult => {
    console.log(`A2HS result: ${choiceResult.outcome}`);
    deferredPrompt = null;
  });
}

/******************************
 * Transaction Hashing
 ******************************/
function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function computeTransactionHash(previousHash, txObject) {
  const dataString = JSON.stringify({ previousHash, ...txObject });
  const buffer = new TextEncoder().encode(dataString);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return bufferToHex(hashBuffer);
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
 * Cross‑Device Chain & Bio-Constant Validation
 ******************************/
async function verifyFullChainAndBioConstant(senderSnapshot) {
  try {
    const { joinTimestamp, initialBioConstant, transactions, finalChainHash } = senderSnapshot;
    const recomputedHash = await computeFullChainHash(transactions);
    if (recomputedHash !== finalChainHash) {
      return { success: false, reason: 'Chain Hash mismatch' };
    }
    let simulatedBio = initialBioConstant;
    let prevTs = joinTimestamp;
    const sortedTx = [...transactions].sort((a, b) => a.timestamp - b.timestamp);
    for (let tx of sortedTx) {
      const delta = tx.timestamp - prevTs;
      if (delta < 0) {
        return { success: false, reason: 'Transaction timestamps out of order' };
      }
      simulatedBio += delta;
      if (tx.bioConstantAtGeneration !== undefined && tx.bioConstantAtGeneration !== simulatedBio) {
        return { success: false, reason: `BioConstant mismatch on TX at timestamp ${tx.timestamp}` };
      }
      prevTs = tx.timestamp;
    }
    return { success: true };
  } catch (err) {
    console.error('verifyFullChainAndBioConstant error:', err);
    return { success: false, reason: err.message };
  }
}

/******************************
 * WebCrypto / PBKDF2 / AES-GCM
 ******************************/
function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
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

/******************************
 * WebAuthn / Biometric
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
        { type: "public-key", alg: -7 },  
        { type: "public-key", alg: -257 }
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
      console.error("❌ Biometric creation returned null.");
      return null;
    }
    console.log("✅ Biometric Credential Created:", credential);
    return credential;
  } catch (err) {
    console.error("❌ Biometric Credential Creation Error:", err);
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
    console.error("❌ Biometric Assertion Error:", err);
    return false;
  }
}

/******************************
 * Encryption / Decryption
 ******************************/
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

/******************************
 * IndexedDB CRUD
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
 * Periodic Increments
 ******************************/
async function applyPeriodicIncrements() {
  // Keep old periodic increments logic if you want it
  if (!vaultUnlocked) return;
  if (vaultData.incrementsUsed >= MAX_ANNUAL_INTERVALS) return;

  const nowSec = vaultData.lastUTCTimestamp;
  const intervalsPassed = Math.floor((nowSec - vaultData.joinTimestamp) / THREE_MONTHS_SECONDS);

  while (vaultData.incrementsUsed < intervalsPassed && vaultData.incrementsUsed < MAX_ANNUAL_INTERVALS) {
    vaultData.incrementsUsed++;
    const incrementTx = {
      type: 'increment',
      amount: BIO_LINE_INCREMENT_AMOUNT,
      timestamp: nowSec,
      status: 'Granted',
      bioConstantAtGeneration: vaultData.bioConstant,
      previousHash: vaultData.lastTransactionHash,
      txHash: ''
    };
    incrementTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, incrementTx);
    vaultData.transactions.push(incrementTx);
    vaultData.lastTransactionHash = incrementTx.txHash;
    vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);
    console.log(`✅ Periodic increment awarded: +${BIO_LINE_INCREMENT_AMOUNT} TVM (Used: ${vaultData.incrementsUsed})`);
  }
}

/******************************
 * Updated Bonus Usage Logic
 ******************************/
function resetDailyUsageIfNeeded(nowSec) {
  const currentDateStr = new Date(nowSec * 1000).toISOString().slice(0, 10);
  if (vaultData.dailyCashback.date !== currentDateStr) {
    vaultData.dailyCashback.date = currentDateStr;
    vaultData.dailyCashback.usedCount = 0;
  }
}

function resetMonthlyUsageIfNeeded(nowSec) {
  const d = new Date(nowSec * 1000);
  const ym = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
  if (!vaultData.monthlyUsage) {
    vaultData.monthlyUsage = { yearMonth: '', usedCount: 0 };
  }
  if (vaultData.monthlyUsage.yearMonth !== ym) {
    vaultData.monthlyUsage.yearMonth = ym;
    vaultData.monthlyUsage.usedCount = 0;
  }
}

function canGive120Bonus(nowSec) {
  resetDailyUsageIfNeeded(nowSec);
  resetMonthlyUsageIfNeeded(nowSec);

  if (vaultData.dailyCashback.usedCount >= MAX_BONUSES_PER_DAY) return false;
  if (vaultData.monthlyUsage.usedCount >= MAX_BONUSES_PER_MONTH) return false;
  if ((vaultData.annualBonusUsed || 0) >= MAX_ANNUAL_BONUS_TVM) return false;

  return true;
}

function record120BonusUsage() {
  vaultData.dailyCashback.usedCount++;
  vaultData.monthlyUsage.usedCount++;
  vaultData.annualBonusUsed = (vaultData.annualBonusUsed || 0) + PER_TX_BONUS;
}

/******************************
 * Vault Creation / Unlock Logic
 ******************************/
async function handleFailedAuthAttempt() {
  vaultData.authAttempts = (vaultData.authAttempts || 0) + 1;
  if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
    vaultData.lockoutTimestamp = Math.floor(Date.now() / 1000) + LOCKOUT_DURATION_SECONDS;
    alert('❌ Max authentication attempts exceeded. Vault locked for 1 hour.');
  } else {
    alert(`❌ Auth failed. You have ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts} tries left.`);
  }
  await promptAndSaveVault();
}

function lockVault() {
  if (!vaultUnlocked) return;
  vaultUnlocked = false;
  document.getElementById('vaultUI')?.classList.add('hidden');
  document.getElementById('lockVaultBtn')?.classList.add('hidden');
  document.getElementById('lockedScreen')?.classList.remove('hidden');
  localStorage.setItem('vaultUnlocked', 'false');
  console.log('🔒 Vault locked.');
}

/******************************
 * Persistence
 ******************************/
async function persistVaultData(salt = null) {
  try {
    if (!derivedKey) {
      throw new Error('🔴 No encryption key');
    }
    const { iv, ciphertext } = await encryptData(derivedKey, vaultData);

    let saltBase64;
    if (salt) {
      saltBase64 = bufferToBase64(salt);
    } else {
      const stored = await loadVaultDataFromDB();
      if (stored && stored.salt) {
        saltBase64 = bufferToBase64(stored.salt);
      } else {
        throw new Error('🔴 Salt not found. Cannot persist vault data.');
      }
    }

    await saveVaultDataToDB(iv, ciphertext, saltBase64);
    const backupPayload = {
      iv: bufferToBase64(iv),
      data: bufferToBase64(ciphertext),
      salt: saltBase64,
      timestamp: Date.now()
    };
    localStorage.setItem(VAULT_BACKUP_KEY, JSON.stringify(backupPayload));
    vaultSyncChannel.postMessage({ type: 'vaultUpdate', payload: backupPayload });
    console.log('💾 Triply-redundant persistence complete');
  } catch (err) {
    console.error('💥 Persistence failed:', err);
    alert('🚨 CRITICAL: VAULT BACKUP FAILED! EXPORT IMMEDIATELY!');
  }
}

async function promptAndSaveVault() {
  await persistVaultData();
}

/******************************
 * Validate Sender Snapshot
 ******************************/
async function validateSenderVaultSnapshot(senderSnapshot, claimedSenderIBAN) {
  const errors = [];

  if (senderSnapshot.initialBalanceTVM !== INITIAL_BALANCE_TVM) {
    errors.push(`Invalid initial balance: expected ${INITIAL_BALANCE_TVM}, found ${senderSnapshot.initialBalanceTVM}`);
  }
  if (senderSnapshot.initialBioConstant !== INITIAL_BIO_CONSTANT) {
    errors.push(`Invalid initial bio constant: expected ${INITIAL_BIO_CONSTANT}, found ${senderSnapshot.initialBioConstant}`);
  }
  try {
    const computedChainHash = await computeFullChainHash(senderSnapshot.transactions);
    if (computedChainHash !== senderSnapshot.finalChainHash) {
      errors.push(`Chain hash mismatch: computed ${computedChainHash} vs stored ${senderSnapshot.finalChainHash}`);
    }
  } catch (err) {
    errors.push(`Error computing chain hash: ${err.message}`);
  }

  const receivedTVM = senderSnapshot.transactions
    .filter(tx => tx.type === 'received')
    .reduce((sum, tx) => sum + tx.amount, 0);
  const sentTVM = senderSnapshot.transactions
    .filter(tx => tx.type === 'sent')
    .reduce((sum, tx) => sum + tx.amount, 0);
  const bonusTVM = senderSnapshot.transactions
    .filter(tx => tx.type === 'cashback' || tx.type === 'increment')
    .reduce((sum, tx) => sum + tx.amount, 0);

  const computedBalance = senderSnapshot.initialBalanceTVM + receivedTVM + bonusTVM - sentTVM;
  if (computedBalance !== senderSnapshot.balanceTVM) {
    errors.push(`Balance mismatch: computed ${computedBalance} vs stored ${senderSnapshot.balanceTVM}`);
  }

  const expectedBioConstant = senderSnapshot.initialBioConstant
    + (senderSnapshot.lastUTCTimestamp - senderSnapshot.joinTimestamp);
  if (expectedBioConstant !== senderSnapshot.bioConstant) {
    errors.push(`BioConstant mismatch: expected ${expectedBioConstant} vs stored ${senderSnapshot.bioConstant}`);
  }

  const computedSenderIBAN = `BIO${senderSnapshot.bioConstant + senderSnapshot.joinTimestamp}`;
  if (claimedSenderIBAN !== computedSenderIBAN) {
    errors.push(`Sender Bio‑IBAN mismatch: computed ${computedSenderIBAN} vs claimed ${claimedSenderIBAN}`);
  }

  return { valid: errors.length === 0, errors };
}

/******************************
 * Snapshot Serialization
 * Add top-level fields: balanceTVM, bioConstant, lastUTCTimestamp
 ******************************/
function serializeVaultSnapshotForBioCatch(vData) {
  const fieldSep = '|';
  const txSep = '^';
  const txFieldSep = '~';

  // Convert transactions to a string
  const txParts = (vData.transactions || []).map(tx => {
    return [
      tx.type || '',
      tx.receiverBioIBAN || '',
      tx.senderBioIBAN || '',
      tx.amount || 0,
      tx.timestamp || 0,
      tx.status || '',
      tx.bioCatch || '',
      tx.bioConstantAtGeneration || 0,
      tx.previousHash || '',
      tx.txHash || ''
    ].join(txFieldSep);
  });
  const txString = txParts.join(txSep);

  // Add new fields for vData.balanceTVM, vData.bioConstant, vData.lastUTCTimestamp
  const rawString = [
    vData.joinTimestamp || 0,
    vData.initialBioConstant || 0,
    vData.incrementsUsed || 0,
    vData.finalChainHash || '',
    vData.initialBalanceTVM || 0,
    vData.balanceTVM || 0,        // new
    vData.bioConstant || 0,       // new
    vData.lastUTCTimestamp || 0,  // new
    txString
  ].join(fieldSep);

  return btoa(rawString);
}

function deserializeVaultSnapshotFromBioCatch(base64String) {
  const raw = atob(base64String);
  const parts = raw.split('|');
  if (parts.length < 9) {
    throw new Error('Vault snapshot missing fields: expecting at least 9 top-level fields');
  }
  const joinTimestamp = parseInt(parts[0], 10);
  const initialBioConstant = parseInt(parts[1], 10);
  const incrementsUsed = parseInt(parts[2], 10);
  const finalChainHash = parts[3];
  const initialBalanceTVM = parseInt(parts[4], 10);
  const balanceTVM = parseInt(parts[5], 10);
  const bioConstant = parseInt(parts[6], 10);
  const lastUTCTimestamp = parseInt(parts[7], 10);

  const txString = parts[8] || '';
  const txSep = '^';
  const txFieldSep = '~';
  const txChunks = txString.split(txSep).filter(Boolean);
  const transactions = txChunks.map(chunk => {
    const txFields = chunk.split(txFieldSep);
    return {
      type: txFields[0] || '',
      receiverBioIBAN: txFields[1] || '',
      senderBioIBAN: txFields[2] || '',
      amount: parseFloat(txFields[3]) || 0,
      timestamp: parseInt(txFields[4], 10) || 0,
      status: txFields[5] || '',
      bioCatch: txFields[6] || '',
      bioConstantAtGeneration: parseInt(txFields[7], 10) || 0,
      previousHash: txFields[8] || '',
      txHash: txFields[9] || ''
    };
  });

  return {
    joinTimestamp,
    initialBioConstant,
    incrementsUsed,
    finalChainHash,
    initialBalanceTVM,
    balanceTVM,         // new
    bioConstant,        // new
    lastUTCTimestamp,   // new
    transactions
  };
}

/******************************
 * UI & Table
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
      let bioCatchCell = tx.bioCatch || '—';
      let amountCell = tx.amount;
      let timestampCell = formatDisplayDate(tx.timestamp);
      let statusCell = tx.status;

      if (tx.type === 'sent') {
        bioIBANCell = tx.receiverBioIBAN;
      } else if (tx.type === 'received') {
        bioIBANCell = tx.senderBioIBAN || 'Unknown';
      } else if (tx.type === 'cashback') {
        bioIBANCell = 'System/Bonus';
      } else if (tx.type === 'increment') {
        bioIBANCell = 'Periodic Increment';
      }

      let styleCell = '';
      if (tx.type === 'sent') {
        styleCell = 'style="background-color: #FFCCCC;"';
      } else if (tx.type === 'received') {
        styleCell = 'style="background-color: #CCFFCC;"';
      } else if (tx.type === 'cashback') {
        styleCell = 'style="background-color: #CCFFFF;"';
      } else if (tx.type === 'increment') {
        styleCell = 'style="background-color: #FFFFCC;"';
      }

      row.innerHTML = `
        <td ${styleCell}>${bioIBANCell}</td>
        <td>${bioCatchCell}</td>
        <td>${amountCell}</td>
        <td>${timestampCell}</td>
        <td>${statusCell}</td>
      `;
      tbody.appendChild(row);
    });
}

function handleCopyBioIBAN() {
  const bioIBANInput = document.getElementById('bioibanInput');
  if (!bioIBANInput || !bioIBANInput.value.trim()) {
    alert('❌ No Bio‑IBAN to copy.');
    return;
  }
  navigator.clipboard.writeText(bioIBANInput.value.trim())
    .then(() => alert('✅ Bio‑IBAN copied to clipboard!'))
    .catch(err => {
      console.error('❌ Clipboard copy failed:', err);
      alert('⚠️ Failed to copy. Try again!');
    });
}

function exportTransactionTable() {
  const table = document.getElementById('transactionTable');
  if (!table) {
    alert('No transaction table found.');
    return;
  }
  const rows = table.querySelectorAll('tr');
  let csvContent = "data:text/csv;charset=utf-8,";
  rows.forEach(r => {
    const cols = r.querySelectorAll('th, td');
    const rowData = [];
    cols.forEach(c => {
      let d = c.innerText.replace(/"/g, '""');
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

/******************************
 * Export Vault Backup
 ******************************/
function exportVaultBackup() {
  const backupData = JSON.stringify(vaultData, null, 2);
  const blob = new Blob([backupData], { type: "application/json" });
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
 * UI & Synchronization Helpers
 ******************************/
function initializeBioConstantAndUTCTime() {
  if (bioLineIntervalTimer) clearInterval(bioLineIntervalTimer);
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const elapsed = currentTimestamp - vaultData.lastUTCTimestamp;
  vaultData.bioConstant += elapsed;
  vaultData.lastUTCTimestamp = currentTimestamp;
  populateWalletUI();

  bioLineIntervalTimer = setInterval(() => {
    vaultData.bioConstant += 1;
    vaultData.lastUTCTimestamp += 1;
    populateWalletUI();
    promptAndSaveVault();
  }, 1000);
}

function populateWalletUI() {
  const ibanInput = document.getElementById('bioibanInput');
  if (ibanInput) {
    ibanInput.value = vaultData.bioIBAN || 'BIO...';
  }

  // Recompute final from initial + bonus - sent
  const receivedTVM = vaultData.transactions.filter(tx => tx.type === 'received').reduce((s, tx) => s + tx.amount, 0);
  const sentTVM = vaultData.transactions.filter(tx => tx.type === 'sent').reduce((s, tx) => s + tx.amount, 0);
  const bonusTVM = vaultData.transactions.filter(tx => tx.type === 'cashback' || tx.type === 'increment')
    .reduce((s, tx) => s + tx.amount, 0);

  vaultData.balanceTVM = vaultData.initialBalanceTVM + receivedTVM + bonusTVM - sentTVM;
  vaultData.balanceUSD = parseFloat((vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2));

  const tvmBalanceElem = document.getElementById('tvmBalance');
  if (tvmBalanceElem) {
    tvmBalanceElem.textContent = `💰 Balance: ${formatWithCommas(vaultData.balanceTVM)} TVM`;
  }
  const usdBalanceElem = document.getElementById('usdBalance');
  if (usdBalanceElem) {
    usdBalanceElem.textContent = `💵 Equivalent to ${formatWithCommas(vaultData.balanceUSD)} USD`;
  }
  const bioLineTextElem = document.getElementById('bioLineText');
  if (bioLineTextElem) {
    bioLineTextElem.textContent = `🔄 Bio‑Line: ${vaultData.bioConstant}`;
  }
  const utcTimeElem = document.getElementById('utcTime');
  if (utcTimeElem) {
    utcTimeElem.textContent = formatDisplayDate(vaultData.lastUTCTimestamp);
  }
}

function initializeUI() {
  const enterVaultBtn = document.getElementById('enterVaultBtn');
  if (enterVaultBtn) {
    enterVaultBtn.addEventListener('click', unlockVault);
    console.log("✅ Event listener attached to enterVaultBtn!");
  } else {
    console.error("❌ enterVaultBtn NOT FOUND in DOM!");
  }

  const lockVaultBtn = document.getElementById('lockVaultBtn');
  lockVaultBtn?.addEventListener('click', lockVault);

  const catchInBtn = document.getElementById('catchInBtn');
  catchInBtn?.addEventListener('click', handleReceiveTransaction);

  const catchOutBtn = document.getElementById('catchOutBtn');
  catchOutBtn?.addEventListener('click', handleSendTransaction);

  const copyBioIBANBtn = document.getElementById('copyBioIBANBtn');
  copyBioIBANBtn?.addEventListener('click', handleCopyBioIBAN);

  const exportBtn = document.getElementById('exportBtn');
  exportBtn?.addEventListener('click', exportTransactionTable);

  const exportBackupBtn = document.getElementById('exportBackupBtn');
  exportBackupBtn?.addEventListener('click', exportVaultBackup);

  const bioCatchPopup = document.getElementById('bioCatchPopup');
  if (bioCatchPopup) {
    const closeBioCatchPopupBtn = document.getElementById('closeBioCatchPopup');
    closeBioCatchPopupBtn?.addEventListener('click', () => {
      bioCatchPopup.style.display = 'none';
    });
    const copyBioCatchPopupBtn = document.getElementById('copyBioCatchBtn');
    copyBioCatchPopupBtn?.addEventListener('click', () => {
      const bcNum = document.getElementById('bioCatchNumberText').textContent;
      navigator.clipboard.writeText(bcNum)
        .then(() => alert('✅ Bio‑Catch Number copied to clipboard!'))
        .catch(err => {
          console.error('❌ Clipboard copy failed:', err);
          alert('⚠️ Failed to copy. Try again!');
        });
    });
    window.addEventListener('click', (event) => {
      if (event.target === bioCatchPopup) {
        bioCatchPopup.style.display = 'none';
      }
    });
  }

  enforceSingleVault();
}

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
        alert("⚠️ Passphrase must be >= 8 chars.");
        return;
      }
      if (confirmNeeded) {
        const confVal = passConfirmInput.value.trim();
        if (pinVal !== confVal) {
          alert("❌ Passphrases do not match!");
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
 * Multi-Tab / Single Vault
 ******************************/
function preventMultipleVaults() {
  window.addEventListener('storage', (evt) => {
    if (evt.key === 'vaultUnlocked') {
      if (evt.newValue === 'true' && !vaultUnlocked) {
        vaultUnlocked = true;
        showVaultUI();
        initializeBioConstantAndUTCTime();
      } else if (evt.newValue === 'false' && vaultUnlocked) {
        vaultUnlocked = false;
        lockVault();
      }
    }
    if (evt.key === 'vaultLock') {
      if (evt.newValue === 'locked' && !vaultUnlocked) {
        console.log('🔒 Another tab indicated vault lock is in place.');
      }
    }
  });
}

function enforceSingleVault() {
  const vaultLock = localStorage.getItem('vaultLock');
  if (!vaultLock) {
    localStorage.setItem('vaultLock', 'locked');
  } else {
    console.log('🔒 Vault lock detected. Ensuring single vault instance.');
  }
}

async function enforceStoragePersistence() {
  if (!navigator.storage?.persist) return;
  const persisted = await navigator.storage.persisted();
  if (!persisted) {
    const granted = await navigator.storage.persist();
    console.log(granted ? '🔒 Storage hardened' : '⚠️ Storage vulnerable');
  }
  setInterval(async () => {
    const estimate = await navigator.storage.estimate();
    if ((estimate.usage / estimate.quota) > 0.85) {
      console.warn('🚨 Storage critical:', estimate);
      alert('❗ Vault storage nearing limit! Export backup!');
    }
  }, STORAGE_CHECK_INTERVAL);
}

/******************************
 * Show/Hide Vault UI
 ******************************/
function showVaultUI() {
  document.getElementById('lockedScreen')?.classList.add('hidden');
  document.getElementById('vaultUI')?.classList.remove('hidden');
  document.getElementById('lockVaultBtn')?.classList.remove('hidden');

  populateWalletUI();
  renderTransactionTable();
}

/******************************
 * Show BioCatch Popup
 ******************************/
function showBioCatchPopup(obfuscatedCatch) {
  const popup = document.getElementById('bioCatchPopup');
  if (!popup) return;
  popup.style.display = 'block';
  const bcTextElem = document.getElementById('bioCatchNumberText');
  if (bcTextElem) {
    bcTextElem.textContent = obfuscatedCatch;
  }
}

/******************************
 * Create & Unlock With Modals
 ******************************/
async function createNewVault(pinFromUser = null) {
  const stored = await loadVaultDataFromDB();
  if (stored) {
    alert('❌ A vault already exists on this device. Please unlock it instead.');
    return;
  }
  if (!pinFromUser) {
    const { pin } = await getPassphraseFromModal({ confirmNeeded: true, modalTitle: 'Create New Vault (Set Passphrase)' });
    pinFromUser = pin;
  }
  if (!pinFromUser || pinFromUser.length < 8) {
    alert('⚠️ Passphrase must be >= 8 characters.');
    return;
  }
  console.log("No existing vault found. Proceeding with NEW vault creation...");
  localStorage.setItem('vaultLock', 'locked');

  const nowSec = Math.floor(Date.now() / 1000);
  vaultData.joinTimestamp = nowSec;
  vaultData.lastUTCTimestamp = nowSec;
  vaultData.initialBioConstant = vaultData.bioConstant;
  vaultData.bioIBAN = `BIO${vaultData.bioConstant + nowSec}`;

  // 1,200 initial
  vaultData.initialBalanceTVM = INITIAL_BALANCE_TVM;
  vaultData.balanceTVM = INITIAL_BALANCE_TVM;
  vaultData.balanceUSD = parseFloat((INITIAL_BALANCE_TVM / EXCHANGE_RATE).toFixed(2));

  vaultData.transactions = [];
  vaultData.authAttempts = 0;
  vaultData.lockoutTimestamp = null;
  vaultData.incrementsUsed = 0;
  vaultData.lastTransactionHash = '';
  vaultData.finalChainHash = '';

  const credential = await performBiometricAuthenticationForCreation();
  if (!credential || !credential.id) {
    alert('Biometric credential creation failed/cancelled. Vault cannot be created.');
    return;
  }
  vaultData.credentialId = bufferToBase64(credential.rawId);

  console.log('🆕 Creating new vault:', vaultData);

  const salt = generateSalt();
  derivedKey = await deriveKeyFromPIN(pinFromUser, salt);
  await persistVaultData(salt);

  vaultUnlocked = true;
  showVaultUI();
  initializeBioConstantAndUTCTime();
  localStorage.setItem('vaultUnlocked', 'true');
}

async function unlockVault() {
  if (vaultData.lockoutTimestamp) {
    const now = Math.floor(Date.now() / 1000);
    if (now < vaultData.lockoutTimestamp) {
      const remain = vaultData.lockoutTimestamp - now;
      alert(`❌ Vault locked. Try again in ${Math.ceil(remain / 60)} min.`);
      return;
    } else {
      vaultData.lockoutTimestamp = null;
      vaultData.authAttempts = 0;
      await promptAndSaveVault();
    }
  }

  const { pin } = await getPassphraseFromModal({ confirmNeeded: false, modalTitle: 'Unlock Vault' });
  if (!pin) {
    alert('❌ Passphrase is required or user canceled the modal.');
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
    if (!confirm('⚠️ No vault found. Create a new vault?')) return;
    await createNewVault(pin);
    return;
  }

  try {
    if (!stored.salt) {
      throw new Error('🔴 Salt not found in stored data.');
    }
    derivedKey = await deriveKeyFromPIN(pin, stored.salt);
    const decrypted = await decryptData(derivedKey, stored.iv, stored.ciphertext);
    vaultData = decrypted;

    vaultData.lockoutTimestamp = stored.lockoutTimestamp;
    vaultData.authAttempts = stored.authAttempts;

    if (vaultData.credentialId) {
      const ok = await performBiometricAssertion(vaultData.credentialId);
      if (!ok) {
        alert('❌ Device credential mismatch. Unlock failed.');
        handleFailedAuthAttempt();
        return;
      }
    } else {
      console.log("🔶 No credentialId found, skipping WebAuthn check.");
    }

    vaultUnlocked = true;
    vaultData.authAttempts = 0;
    vaultData.lockoutTimestamp = null;

    await applyPeriodicIncrements();
    await promptAndSaveVault();

    showVaultUI();
    initializeBioConstantAndUTCTime();
    localStorage.setItem('vaultUnlocked', 'true');
  } catch (err) {
    alert(`❌ Failed to decrypt: ${err.message}`);
    console.error(err);
    handleFailedAuthAttempt();
  }
}

/******************************
 * On DOM Load
 ******************************/
function loadVaultOnStartup() {
  // If you want to auto-unlock using sessionStorage, do so here
}

window.addEventListener('DOMContentLoaded', () => {
  let lastURL = localStorage.getItem("last_session_url");
  if (lastURL && window.location.href !== lastURL) {
    window.location.href = lastURL;
  }
  window.addEventListener("beforeunload", () => {
    localStorage.setItem("last_session_url", window.location.href);
  });

  console.log("✅ Bio‑Vault: Initializing UI...");
  initializeUI();
  loadVaultOnStartup();
  preventMultipleVaults();
  enforceStoragePersistence();

  vaultSyncChannel.onmessage = async (e) => {
    if (e.data?.type === 'vaultUpdate') {
      try {
        const { iv, data } = e.data.payload;
        if (!derivedKey) {
          console.warn('🔒 Received vaultUpdate but derivedKey is not available yet.');
          return;
        }
        const decrypted = await decryptData(derivedKey, base64ToBuffer(iv), base64ToBuffer(data));
        Object.assign(vaultData, decrypted);
        populateWalletUI();
        console.log('🔄 Synced vault across tabs');
      } catch (err) {
        console.error('Tab sync failed:', err);
      }
    }
  };

  enforceStoragePersistence();
});
