/***********************************************************************
 * main.js — Updated Final Version with Extra Logging
 * 
 * Changes (only added console.logs):
 *   - Inserted console.log statements at the start and end of each function
 *   - Logging parameter values, return values, catches, and key steps
 ***********************************************************************/

/******************************
 * Constants & Global Variables
 ******************************/
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 1;
const VAULT_STORE = 'vault';

// Balance & Bonus Settings
const INITIAL_BALANCE_TVM = 1200;
const PER_TX_BONUS = 120; 
const MAX_BONUSES_PER_DAY = 3; 
const MAX_BONUSES_PER_MONTH = 30; 
const MAX_ANNUAL_BONUS_TVM = 10800; // total annual bonus TVM

const EXCHANGE_RATE = 12;  // 1 USD = 12 TVM
const INITIAL_BIO_CONSTANT = 1736565605; // The genesis "BioConstant"
const TRANSACTION_VALIDITY_SECONDS = 720; // ±12 minutes
const LOCKOUT_DURATION_SECONDS = 3600;    // 1 hour
const MAX_AUTH_ATTEMPTS = 3;

const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000;   // 5 minutes

const vaultSyncChannel = new BroadcastChannel('vault-sync');

let vaultUnlocked = false;
let derivedKey = null;
let bioLineIntervalTimer = null;

/**
 * Master vaultData structure.
 *
 *  - 'initialBioConstant' is the immutable genesis number (1736565605).
 *  - 'bonusConstant' is a static difference (joinTimestamp - initialBioConstant).
 *    We no longer increment it over time.
 */
let vaultData = {
  bioIBAN: null,
  initialBioConstant: 0,
  bonusConstant: 0,
  initialBalanceTVM: INITIAL_BALANCE_TVM,
  balanceTVM: 0,
  balanceUSD: 0,
  lastUTCTimestamp: 0,
  transactions: [],
  authAttempts: 0,
  lockoutTimestamp: null,
  joinTimestamp: 0,
  lastTransactionHash: '',
  credentialId: null,
  finalChainHash: '',
  dailyCashback: { date: '', usedCount: 0 },
  monthlyUsage: { yearMonth: '', usedCount: 0 },
  annualBonusUsed: 0
};

/******************************
 * Utility / Formatting
 ******************************/
function formatWithCommas(num) {
  console.log("[formatWithCommas] Called with:", num);
  const result = num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  console.log("[formatWithCommas] Returning:", result);
  return result;
}

function formatDisplayDate(timestampInSeconds) {
  console.log("[formatDisplayDate] Called with:", timestampInSeconds);
  const date = new Date(timestampInSeconds * 1000);
  const isoString = date.toISOString();
  const result = `${isoString.slice(0, 10)} ${isoString.slice(11, 19)}`;
  console.log("[formatDisplayDate] Returning:", result);
  return result;
}

/******************************
 * PWA "Add to Home Screen"
 ******************************/
let deferredPrompt = null;
window.addEventListener('beforeinstallprompt', (e) => {
  console.log("[Event - beforeinstallprompt] Firing. Prevent default & store event.");
  e.preventDefault();
  deferredPrompt = e;
  console.log("⭐ 'beforeinstallprompt' captured — call promptInstallA2HS() to show UI prompt.");
});

function promptInstallA2HS() {
  console.log("[promptInstallA2HS] Called.");
  if (!deferredPrompt) {
    console.log("[promptInstallA2HS] No deferredPrompt available or user already installed.");
    return;
  }
  deferredPrompt.prompt();
  deferredPrompt.userChoice.then(choiceResult => {
    console.log(`[promptInstallA2HS] A2HS result: ${choiceResult.outcome}`);
    deferredPrompt = null;
  });
}

/******************************
 * Transaction Hashing
 ******************************/
async function computeTransactionHash(previousHash, txObject) {
  console.log("[computeTransactionHash] Called with previousHash:", previousHash, "txObject:", txObject);
  const dataString = JSON.stringify({ previousHash, ...txObject });
  const buffer = new TextEncoder().encode(dataString);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const result = Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  console.log("[computeTransactionHash] Returning:", result);
  return result;
}

async function computeFullChainHash(transactions) {
  console.log("[computeFullChainHash] Called with transactions:", transactions);
  let runningHash = '';
  const sortedTx = [...transactions].sort((a, b) => a.timestamp - b.timestamp);
  for (let tx of sortedTx) {
    const txObjForHash = {
      type: tx.type,
      amount: tx.amount,
      timestamp: tx.timestamp,
      status: tx.status,
      bioCatch: tx.bioCatch,
      bonusConstantAtGeneration: tx.bonusConstantAtGeneration,
      previousHash: runningHash
    };
    runningHash = await computeTransactionHash(runningHash, txObjForHash);
  }
  console.log("[computeFullChainHash] Final runningHash:", runningHash);
  return runningHash;
}

/******************************
 * Buffer & Salt Utilities
 ******************************/
function bufferToBase64(buffer) {
  console.log("[bufferToBase64] Called with buffer:", buffer);
  const result = btoa(String.fromCharCode(...new Uint8Array(buffer)));
  console.log("[bufferToBase64] Returning:", result);
  return result;
}

function base64ToBuffer(base64) {
  console.log("[base64ToBuffer] Called with base64:", base64);
  const bin = atob(base64);
  const buffer = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    buffer[i] = bin.charCodeAt(i);
  }
  console.log("[base64ToBuffer] Returning Uint8Array of length:", buffer.length);
  return buffer;
}

function generateSalt() {
  console.log("[generateSalt] Called.");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  console.log("[generateSalt] Returning new random salt:", salt);
  return salt;
}

/******************************
 * WebAuthn / Biometric
 ******************************/
async function performBiometricAuthenticationForCreation() {
  console.log("[performBiometricAuthenticationForCreation] Called.");
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
    console.log("[performBiometricAuthenticationForCreation] About to create credential with publicKey:", publicKey);
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
  console.log("[performBiometricAssertion] Called with credentialId:", credentialId);
  try {
    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ id: base64ToBuffer(credentialId), type: 'public-key' }],
      userVerification: "required",
      timeout: 60000
    };
    console.log("[performBiometricAssertion] About to get credential with publicKey:", publicKey);
    const assertion = await navigator.credentials.get({ publicKey });
    const result = !!assertion;
    console.log("[performBiometricAssertion] Assertion result:", result);
    return result;
  } catch (err) {
    console.error("❌ Biometric Assertion Error:", err);
    return false;
  }
}

/******************************
 * Encryption / Decryption
 ******************************/
async function encryptData(key, dataObj) {
  console.log("[encryptData] Called with dataObj:", dataObj);
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc.encode(JSON.stringify(dataObj));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  console.log("[encryptData] Encryption success. IV length:", iv.length, "Ciphertext byteLength:", ciphertext.byteLength);
  return { iv, ciphertext };
}

async function decryptData(key, iv, ciphertext) {
  console.log("[decryptData] Called with IV:", iv, "Ciphertext length:", ciphertext.byteLength);
  const dec = new TextDecoder();
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  const result = JSON.parse(dec.decode(plainBuf));
  console.log("[decryptData] Decryption success, returning object with keys:", Object.keys(result));
  return result;
}

async function encryptBioCatchNumber(plainText) {
  console.log("[encryptBioCatchNumber] Called with plainText:", plainText);
  try {
    const result = btoa(plainText);
    console.log("[encryptBioCatchNumber] Returning obfuscated string.");
    return result;
  } catch (err) {
    console.error("Error obfuscating BioCatchNumber:", err);
    return plainText;
  }
}

async function decryptBioCatchNumber(encryptedString) {
  console.log("[decryptBioCatchNumber] Called with encryptedString:", encryptedString);
  try {
    const result = atob(encryptedString);
    console.log("[decryptBioCatchNumber] Returning deobfuscated string.");
    return result;
  } catch (err) {
    console.error("Error deobfuscating BioCatchNumber:", err);
    return null;
  }
}

/******************************
 * IndexedDB CRUD
 ******************************/
async function openVaultDB() {
  console.log("[openVaultDB] Called.");
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (evt) => {
      console.log("[openVaultDB] onupgradeneeded event fired.");
      const db = evt.target.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) {
        db.createObjectStore(VAULT_STORE, { keyPath: 'id' });
        console.log("[openVaultDB] Created object store:", VAULT_STORE);
      }
    };
    req.onsuccess = (evt) => {
      console.log("[openVaultDB] Database opened successfully.");
      resolve(evt.target.result);
    };
    req.onerror = (evt) => {
      console.error("[openVaultDB] Error opening DB:", evt.target.error);
      reject(evt.target.error);
    };
  });
}

async function saveVaultDataToDB(iv, ciphertext, saltBase64) {
  console.log("[saveVaultDataToDB] Called with IV:", iv, "Ciphertext length:", ciphertext.byteLength, "saltBase64:", saltBase64);
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([VAULT_STORE], 'readwrite');
    const store = tx.objectStore(VAULT_STORE);
    store.put({
      id: 'vaultData',
      iv: bufferToBase64(iv),
      ciphertext: bufferToBase64(ciphertext),
      salt: saltBase64,
      lockoutTimestamp: vaultData.lockoutTimestamp || null,
      authAttempts: vaultData.authAttempts || 0
    });
    tx.oncomplete = () => {
      console.log("[saveVaultDataToDB] Transaction oncomplete. Data saved.");
      resolve();
    };
    tx.onerror = (err) => {
      console.error("[saveVaultDataToDB] Transaction onerror:", err);
      reject(err);
    };
  });
}

async function loadVaultDataFromDB() {
  console.log("[loadVaultDataFromDB] Called.");
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([VAULT_STORE], 'readonly');
    const store = tx.objectStore(VAULT_STORE);
    const getReq = store.get('vaultData');
    getReq.onsuccess = () => {
      if (getReq.result) {
        console.log("[loadVaultDataFromDB] Found vaultData record in DB.");
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
          console.error('[loadVaultDataFromDB] Error decoding stored data:', error);
          resolve(null);
        }
      } else {
        console.log("[loadVaultDataFromDB] No vaultData record found.");
        resolve(null);
      }
    };
    getReq.onerror = (err) => {
      console.error("[loadVaultDataFromDB] getReq.onerror:", err);
      reject(err);
    };
  });
}

/******************************
 * Vault Creation / Unlock Helpers
 ******************************/
async function deriveKeyFromPIN(pin, salt) {
  console.log("[deriveKeyFromPIN] Called with pin length:", pin.length, "and salt:", salt);
  const encoder = new TextEncoder();
  const pinBytes = encoder.encode(pin);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    pinBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  const result = await crypto.subtle.deriveKey(
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
  console.log("[deriveKeyFromPIN] Derived key successfully.");
  return result;
}

async function handleFailedAuthAttempt() {
  console.log("[handleFailedAuthAttempt] Called.");
  vaultData.authAttempts = (vaultData.authAttempts || 0) + 1;
  console.log("[handleFailedAuthAttempt] Updated authAttempts to:", vaultData.authAttempts);
  if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
    vaultData.lockoutTimestamp = Math.floor(Date.now() / 1000) + LOCKOUT_DURATION_SECONDS;
    console.log("[handleFailedAuthAttempt] Max attempts exceeded. Setting lockoutTimestamp to:", vaultData.lockoutTimestamp);
    alert('❌ Max authentication attempts exceeded. Vault locked for 1 hour.');
  } else {
    alert(`❌ Auth failed. You have ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts} tries left.`);
  }
  await promptAndSaveVault();
}

function lockVault() {
  console.log("[lockVault] Called.");
  if (!vaultUnlocked) {
    console.log("[lockVault] Vault is already locked. Doing nothing.");
    return;
  }
  vaultUnlocked = false;
  document.getElementById('vaultUI')?.classList.add('hidden');
  document.getElementById('lockVaultBtn')?.classList.add('hidden');
  document.getElementById('lockedScreen')?.classList.remove('hidden');
  localStorage.setItem('vaultUnlocked', 'false');
  console.log('🔒 Vault locked by lockVault().');
}

/******************************
 * Persistence
 ******************************/
async function persistVaultData(salt = null) {
  console.log("[persistVaultData] Called with salt:", salt);
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
  console.log("[promptAndSaveVault] Called.");
  await persistVaultData();
}

/******************************
 * Bonus Logic (Daily, Monthly, Annual)
 ******************************/
function resetDailyUsageIfNeeded(nowSec) {
  console.log("[resetDailyUsageIfNeeded] Called with nowSec:", nowSec);
  const currentDateStr = new Date(nowSec * 1000).toISOString().slice(0, 10);
  if (vaultData.dailyCashback.date !== currentDateStr) {
    vaultData.dailyCashback.date = currentDateStr;
    vaultData.dailyCashback.usedCount = 0;
    console.log("[resetDailyUsageIfNeeded] Daily usage reset. New date:", currentDateStr);
  }
}

function resetMonthlyUsageIfNeeded(nowSec) {
  console.log("[resetMonthlyUsageIfNeeded] Called with nowSec:", nowSec);
  const d = new Date(nowSec * 1000);
  const ym = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
  if (!vaultData.monthlyUsage) {
    vaultData.monthlyUsage = { yearMonth: '', usedCount: 0 };
  }
  if (vaultData.monthlyUsage.yearMonth !== ym) {
    vaultData.monthlyUsage.yearMonth = ym;
    vaultData.monthlyUsage.usedCount = 0;
    console.log("[resetMonthlyUsageIfNeeded] Monthly usage reset. New yearMonth:", ym);
  }
}

function bonusDiversityCheck(newTxType) {
  console.log("[bonusDiversityCheck] Called with newTxType:", newTxType);
  const currentDateStr = vaultData.dailyCashback.date;
  let sentTriggeredCount = 0;
  let receivedTriggeredCount = 0;

  for (const tx of vaultData.transactions) {
    if (tx.type === 'cashback') {
      const dateStr = new Date(tx.timestamp * 1000).toISOString().slice(0, 10);
      if (dateStr === currentDateStr && tx.triggerOrigin) {
        if (tx.triggerOrigin === 'sent') sentTriggeredCount++;
        else if (tx.triggerOrigin === 'received') receivedTriggeredCount++;
      }
    }
  }

  console.log("[bonusDiversityCheck] sentTriggeredCount:", sentTriggeredCount, "receivedTriggeredCount:", receivedTriggeredCount);

  if (newTxType === 'sent' && sentTriggeredCount >= 2) {
    console.log("[bonusDiversityCheck] Failing due to 2+1 rule for 'sent'.");
    return false;
  }
  if (newTxType === 'received' && receivedTriggeredCount >= 2) {
    console.log("[bonusDiversityCheck] Failing due to 2+1 rule for 'received'.");
    return false;
  }
  return true;
}

function canGive120Bonus(nowSec, newTxType, newTxAmount) {
  console.log("[canGive120Bonus] Called with nowSec:", nowSec, "newTxType:", newTxType, "newTxAmount:", newTxAmount);
  resetDailyUsageIfNeeded(nowSec);
  resetMonthlyUsageIfNeeded(nowSec);
  if (vaultData.dailyCashback.usedCount >= MAX_BONUSES_PER_DAY) {
    console.log("[canGive120Bonus] Daily bonus limit reached.");
    return false;
  }
  if (vaultData.monthlyUsage.usedCount >= MAX_BONUSES_PER_MONTH) {
    console.log("[canGive120Bonus] Monthly bonus limit reached.");
    return false;
  }
  if ((vaultData.annualBonusUsed || 0) >= MAX_ANNUAL_BONUS_TVM) {
    console.log("[canGive120Bonus] Annual bonus limit reached.");
    return false;
  }

  if (newTxType === 'sent' && newTxAmount <= 240) {
    console.log("[canGive120Bonus] 'sent' transaction amount does not exceed threshold 240 TVM.");
    return false;
  }

  if (!bonusDiversityCheck(newTxType)) {
    console.log("[canGive120Bonus] Failing 2+1 type rule in bonusDiversityCheck.");
    return false;
  }

  console.log("[canGive120Bonus] All bonus checks passed. Returning true.");
  return true;
}

function record120BonusUsage(triggerOrigin) {
  console.log("[record120BonusUsage] Called with triggerOrigin:", triggerOrigin);
  vaultData.dailyCashback.usedCount++;
  vaultData.monthlyUsage.usedCount++;
  vaultData.annualBonusUsed = (vaultData.annualBonusUsed || 0) + PER_TX_BONUS;
  console.log("[record120BonusUsage] Updated usage:", vaultData.dailyCashback, vaultData.monthlyUsage, "annualBonusUsed:", vaultData.annualBonusUsed);
}

/******************************
 * Snapshot Serialization & Validation
 ******************************/
function serializeVaultSnapshotForBioCatch(vData) {
  console.log("[serializeVaultSnapshotForBioCatch] Called.");
  const fieldSep = '|';
  const txSep = '^';
  const txFieldSep = '~';
  const txParts = (vData.transactions || []).map(tx => {
    return [
      tx.type || '',
      tx.receiverBioIBAN || '',
      tx.senderBioIBAN || '',
      tx.amount || 0,
      tx.timestamp || 0,
      tx.status || '',
      tx.bioCatch || '',
      tx.bonusConstantAtGeneration || 0,
      tx.previousHash || '',
      tx.txHash || ''
    ].join(txFieldSep);
  });
  const txString = txParts.join(txSep);
  const rawString = [
    vData.joinTimestamp || 0,
    vData.initialBioConstant || 0,
    vData.bonusConstant || 0,
    vData.finalChainHash || '',
    vData.initialBalanceTVM || 0,
    vData.balanceTVM || 0,
    vData.lastUTCTimestamp || 0,
    txString
  ].join(fieldSep);
  const result = btoa(rawString);
  console.log("[serializeVaultSnapshotForBioCatch] Returning base64 snapshot. Length:", result.length);
  return result;
}

function deserializeVaultSnapshotFromBioCatch(base64String) {
  console.log("[deserializeVaultSnapshotFromBioCatch] Called. base64String length:", base64String.length);
  const raw = atob(base64String);
  const parts = raw.split('|');
  if (parts.length < 8) {
    throw new Error('Vault snapshot missing fields: need >= 8 top-level fields');
  }
  const joinTimestamp = parseInt(parts[0], 10);
  const initialBioConstant = parseInt(parts[1], 10);
  const bonusConstant = parseInt(parts[2], 10);
  const finalChainHash = parts[3];
  const initialBalanceTVM = parseInt(parts[4], 10);
  const balanceTVM = parseInt(parts[5], 10);
  const lastUTCTimestamp = parseInt(parts[6], 10);
  const txString = parts[7] || '';

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
      bonusConstantAtGeneration: parseInt(txFields[7], 10) || 0,
      previousHash: txFields[8] || '',
      txHash: txFields[9] || ''
    };
  });
  const result = {
    joinTimestamp,
    initialBioConstant,
    bonusConstant,
    finalChainHash,
    initialBalanceTVM,
    balanceTVM,
    lastUTCTimestamp,
    transactions
  };
  console.log("[deserializeVaultSnapshotFromBioCatch] Returning snapshot object with fields:", Object.keys(result));
  return result;
}

async function generateBioCatchNumber(senderBioIBAN, receiverBioIBAN, amount, timestamp, senderBalance, finalChainHash) {
  console.log("[generateBioCatchNumber] Called with:", { senderBioIBAN, receiverBioIBAN, amount, timestamp, senderBalance, finalChainHash });
  const encodedVault = serializeVaultSnapshotForBioCatch(vaultData);
  const senderNumeric = parseInt(senderBioIBAN.slice(3));
  const receiverNumeric = parseInt(receiverBioIBAN.slice(3));
  const firstPart = senderNumeric + receiverNumeric;
  const result = `Bio-${firstPart}-${timestamp}-${amount}-${senderBalance}-${senderBioIBAN}-${finalChainHash}-${encodedVault}`;
  console.log("[generateBioCatchNumber] Returning:", result);
  return result;
}

async function validateBioCatchNumber(bioCatchNumber, claimedAmount) {
  console.log("[validateBioCatchNumber] Called with bioCatchNumber:", bioCatchNumber, "claimedAmount:", claimedAmount);
  const parts = bioCatchNumber.split('-');
  if (parts.length !== 8 || parts[0] !== 'Bio') {
    return { valid: false, message: 'BioCatch must have 8 parts with prefix "Bio-".' };
  }
  const [ , firstPartStr, timestampStr, amountStr, claimedSenderBalanceStr, claimedSenderIBAN, chainHash, snapshotEncoded] = parts;
  const firstPart = parseInt(firstPartStr);
  const encodedTimestamp = parseInt(timestampStr);
  const encodedAmount = parseFloat(amountStr);
  const claimedSenderBalance = parseFloat(claimedSenderBalanceStr);

  if (isNaN(firstPart) || isNaN(encodedTimestamp) || isNaN(encodedAmount) || isNaN(claimedSenderBalance)) {
    return { valid: false, message: 'Numeric parts must be valid numbers.' };
  }
  const senderNumeric = parseInt(claimedSenderIBAN.slice(3));
  const receiverNumeric = firstPart - senderNumeric;
  if (receiverNumeric < 0) {
    return { valid: false, message: 'Invalid sender numeric in BioCatch.' };
  }
  const expectedFirstPart = senderNumeric + receiverNumeric;
  if (firstPart !== expectedFirstPart) {
    return { valid: false, message: 'Mismatch in sum of IBAN numerics.' };
  }
  if (!vaultData.bioIBAN) {
    return { valid: false, message: 'Receiver IBAN not found in vault.' };
  }
  const receiverNumericFromVault = parseInt(vaultData.bioIBAN.slice(3));
  if (receiverNumeric !== receiverNumericFromVault) {
    return { valid: false, message: 'This BioCatch is not intended for this receiver IBAN.' };
  }
  if (encodedAmount !== claimedAmount) {
    return { valid: false, message: 'Claimed amount does not match BioCatch amount.' };
  }

  const currentTimestamp = vaultData.lastUTCTimestamp;
  const timeDiff = Math.abs(currentTimestamp - encodedTimestamp);
  if (timeDiff > TRANSACTION_VALIDITY_SECONDS) {
    return { valid: false, message: 'Timestamp outside ±12min window.' };
  }

  let senderVaultSnapshot;
  try {
    senderVaultSnapshot = deserializeVaultSnapshotFromBioCatch(snapshotEncoded);
  } catch (err) {
    return { valid: false, message: `Snapshot parse error: ${err.message}` };
  }

  if (claimedSenderIBAN.startsWith("BONUS")) {
    const offset = encodedTimestamp - senderVaultSnapshot.joinTimestamp;
    const expected = "BONUS" + (senderVaultSnapshot.bonusConstant + offset);
    if (claimedSenderIBAN !== expected) {
      return { valid: false, message: 'Mismatched Bonus Sender IBAN in BioCatch.' };
    }
  } else {
    const expectedSenderIBAN = `BIO${senderVaultSnapshot.initialBioConstant + senderVaultSnapshot.joinTimestamp}`;
    if (claimedSenderIBAN !== expectedSenderIBAN) {
      return { valid: false, message: 'Mismatched Sender IBAN in BioCatch.' };
    }
  }

  return {
    valid: true,
    message: 'OK',
    chainHash,
    claimedSenderIBAN,
    senderVaultSnapshot
  };
}

/******************************
 * Transaction Handlers
 ******************************/
let transactionLock = false;

async function handleSendTransaction() {
  console.log("[handleSendTransaction] Called.");
  if (!vaultUnlocked) {
    alert('❌ Please unlock the vault first.');
    console.log("[handleSendTransaction] Vault is locked. Aborting.");
    return;
  }
  if (transactionLock) {
    alert('🔒 A transaction is already in progress. Please wait.');
    console.log("[handleSendTransaction] Transaction lock is active. Aborting.");
    return;
  }

  const receiverBioIBAN = document.getElementById('receiverBioIBAN')?.value.trim();
  const amount = parseFloat(document.getElementById('catchOutAmount')?.value.trim());
  console.log("[handleSendTransaction] receiverBioIBAN:", receiverBioIBAN, "amount:", amount);
  
  if (!receiverBioIBAN || isNaN(amount) || amount <= 0) {
    alert('❌ Invalid receiver Bio‑IBAN or amount.');
    console.log("[handleSendTransaction] Invalid input. Aborting.");
    return;
  }
  if (!validateBioIBAN(receiverBioIBAN)) {
    alert('❌ Invalid Bio‑IBAN format.');
    console.log("[handleSendTransaction] Invalid BioIBAN. Aborting.");
    return;
  }
  if (receiverBioIBAN === vaultData.bioIBAN) {
    alert('❌ Cannot send to self.');
    console.log("[handleSendTransaction] Attempted to send to self. Aborting.");
    return;
  }
  if (vaultData.balanceTVM < amount) {
    alert('❌ Insufficient TVM balance.');
    console.log("[handleSendTransaction] Insufficient balance. Aborting.");
    return;
  }

  transactionLock = true;
  console.log("[handleSendTransaction] Setting transactionLock to true.");
  try {
    const nowSec = Math.floor(Date.now() / 1000);
    vaultData.lastUTCTimestamp = nowSec;

    let bonusGranted = false;
    if (canGive120Bonus(nowSec, 'sent', amount)) {
      record120BonusUsage('sent');
      bonusGranted = true;
    }
    vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);

    const plainBioCatchNumber = await generateBioCatchNumber(
      vaultData.bioIBAN,
      receiverBioIBAN,
      amount,
      nowSec,
      vaultData.balanceTVM,
      vaultData.finalChainHash
    );

    for (let tx of vaultData.transactions) {
      if (tx.bioCatch) {
        const existingPlain = await decryptBioCatchNumber(tx.bioCatch);
        if (existingPlain === plainBioCatchNumber) {
          alert('❌ This BioCatch number already exists. Try again.');
          console.log("[handleSendTransaction] BioCatch number collision. Aborting.");
          transactionLock = false;
          return;
        }
      }
    }

    const obfuscatedCatch = await encryptBioCatchNumber(plainBioCatchNumber);
    const newTx = {
      type: 'sent',
      receiverBioIBAN,
      amount,
      timestamp: nowSec,
      status: 'Completed',
      bioCatch: obfuscatedCatch,
      bonusConstantAtGeneration: vaultData.bonusConstant,
      previousHash: vaultData.lastTransactionHash,
      txHash: ''
    };
    newTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, newTx);
    vaultData.transactions.push(newTx);
    vaultData.lastTransactionHash = newTx.txHash;
    vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);

    if (bonusGranted) {
      const offset = nowSec - vaultData.joinTimestamp;
      const bonusIBAN = "BONUS" + (vaultData.bonusConstant + offset);

      const bonusTx = {
        type: 'cashback',
        amount: PER_TX_BONUS,
        timestamp: nowSec,
        status: 'Granted',
        bonusConstantAtGeneration: vaultData.bonusConstant,
        previousHash: vaultData.lastTransactionHash,
        txHash: '',
        senderBioIBAN: bonusIBAN,
        triggerOrigin: 'sent'
      };
      bonusTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash = bonusTx.txHash;
      vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);
      console.log("[handleSendTransaction] Bonus transaction added:", bonusTx);
    }

    populateWalletUI();
    await promptAndSaveVault();
    alert(`✅ Sent ${amount} TVM. Bonus: ${bonusGranted ? '120 TVM' : 'None'}`);
    showBioCatchPopup(obfuscatedCatch);

    document.getElementById('receiverBioIBAN').value = '';
    document.getElementById('catchOutAmount').value = '';
    renderTransactionTable();
  } catch (err) {
    console.error('[handleSendTransaction] Error:', err);
    alert('❌ An error occurred processing the transaction.');
  } finally {
    console.log("[handleSendTransaction] Setting transactionLock to false.");
    transactionLock = false;
  }
}

async function handleReceiveTransaction() {
  console.log("[handleReceiveTransaction] Called.");
  if (!vaultUnlocked) {
    alert('❌ Please unlock the vault first.');
    console.log("[handleReceiveTransaction] Vault locked. Aborting.");
    return;
  }
  if (transactionLock) {
    alert('🔒 A transaction is in progress. Please wait.');
    console.log("[handleReceiveTransaction] Transaction lock is active. Aborting.");
    return;
  }

  const encryptedBioCatchInput = document.getElementById('catchInBioCatch')?.value.trim();
  const amount = parseFloat(document.getElementById('catchInAmount')?.value.trim());
  console.log("[handleReceiveTransaction] encryptedBioCatchInput:", encryptedBioCatchInput, "amount:", amount);

  if (!encryptedBioCatchInput || isNaN(amount) || amount <= 0) {
    alert('❌ Invalid BioCatch number or amount.');
    console.log("[handleReceiveTransaction] Invalid input. Aborting.");
    return;
  }

  transactionLock = true;
  console.log("[handleReceiveTransaction] Setting transactionLock to true.");
  try {
    const nowSec = Math.floor(Date.now() / 1000);
    vaultData.lastUTCTimestamp = nowSec;

    let bonusGranted = false;
    if (canGive120Bonus(nowSec, 'received', amount)) {
      record120BonusUsage('received');
      bonusGranted = true;
    }

    const bioCatchNumber = await decryptBioCatchNumber(encryptedBioCatchInput);
    if (!bioCatchNumber) {
      alert('❌ Unable to decode BioCatch number.');
      console.log("[handleReceiveTransaction] Could not decode BioCatch. Aborting.");
      transactionLock = false;
      return;
    }

    for (let tx of vaultData.transactions) {
      if (tx.bioCatch) {
        const existingPlain = await decryptBioCatchNumber(tx.bioCatch);
        if (existingPlain === bioCatchNumber) {
          alert('❌ This BioCatch number has already been used.');
          console.log("[handleReceiveTransaction] BioCatch number already used. Aborting.");
          transactionLock = false;
          return;
        }
      }
    }

    const validation = await validateBioCatchNumber(bioCatchNumber, amount);
    if (!validation.valid) {
      alert(`❌ BioCatch Validation Failed: ${validation.message}`);
      console.log("[handleReceiveTransaction] BioCatch validation failed. Aborting.");
      transactionLock = false;
      return;
    }

    const { chainHash, claimedSenderIBAN, senderVaultSnapshot } = validation;
    const crossCheck = await verifyFullChainAndBioConstant(senderVaultSnapshot);
    if (!crossCheck.success) {
      alert(`❌ Sender chain mismatch: ${crossCheck.reason}`);
      console.log("[handleReceiveTransaction] Cross-check failed. Aborting.");
      transactionLock = false;
      return;
    }
    if (senderVaultSnapshot.finalChainHash !== chainHash) {
      alert('❌ The chain hash in the BioCatch does not match the snapshot’s final chain hash!');
      console.log("[handleReceiveTransaction] Chain hash mismatch. Aborting.");
      transactionLock = false;
      return;
    }
    const snapshotValidation = await validateSenderVaultSnapshot(senderVaultSnapshot, claimedSenderIBAN);
    if (!snapshotValidation.valid) {
      alert("❌ Sender snapshot integrity check failed: " + snapshotValidation.errors.join("; "));
      console.log("[handleReceiveTransaction] Snapshot integrity check failed. Aborting.");
      transactionLock = false;
      return;
    }

    const rxTx = {
      type: 'received',
      senderBioIBAN: claimedSenderIBAN,
      bioCatch: encryptedBioCatchInput,
      amount,
      timestamp: nowSec,
      status: 'Valid',
      bonusConstantAtGeneration: vaultData.bonusConstant
    };
    vaultData.transactions.push(rxTx);

    if (bonusGranted) {
      const offset = nowSec - vaultData.joinTimestamp;
      const bonusIBAN = "BONUS" + (vaultData.bonusConstant + offset);

      const bonusTx = {
        type: 'cashback',
        amount: PER_TX_BONUS,
        timestamp: nowSec,
        status: 'Granted',
        bonusConstantAtGeneration: vaultData.bonusConstant,
        previousHash: vaultData.lastTransactionHash,
        txHash: '',
        senderBioIBAN: bonusIBAN,
        triggerOrigin: 'received'
      };
      bonusTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash = bonusTx.txHash;
      vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);
      console.log("[handleReceiveTransaction] Bonus transaction added:", bonusTx);
    }

    await promptAndSaveVault();
    populateWalletUI();
    alert(`✅ Transaction received successfully! +${amount} TVM. Bonus: ${bonusGranted ? '120 TVM' : 'None'}`);
    document.getElementById('catchInBioCatch').value = '';
    document.getElementById('catchInAmount').value = '';
    renderTransactionTable();
  } catch (error) {
    console.error('[handleReceiveTransaction] Error:', error);
    alert('❌ An error occurred processing the transaction.');
  } finally {
    console.log("[handleReceiveTransaction] Setting transactionLock to false.");
    transactionLock = false;
  }
}

/******************************
 * UI & Table Rendering
 ******************************/
function renderTransactionTable() {
  console.log("[renderTransactionTable] Called.");
  const tbody = document.getElementById('transactionBody');
  if (!tbody) {
    console.log("[renderTransactionTable] No transactionBody element found. Exiting.");
    return;
  }
  tbody.innerHTML = '';

  vaultData.transactions.sort((a, b) => b.timestamp - a.timestamp).forEach(tx => {
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
  console.log("[renderTransactionTable] Completed rendering table.");
}

function handleCopyBioIBAN() {
  console.log("[handleCopyBioIBAN] Called.");
  const bioIBANInput = document.getElementById('bioibanInput');
  if (!bioIBANInput || !bioIBANInput.value.trim()) {
    alert('❌ No Bio‑IBAN to copy.');
    console.log("[handleCopyBioIBAN] No BioIBAN to copy. Aborting.");
    return;
  }
  navigator.clipboard.writeText(bioIBANInput.value.trim())
    .then(() => {
      alert('✅ Bio‑IBAN copied to clipboard!');
      console.log("[handleCopyBioIBAN] Successfully copied to clipboard.");
    })
    .catch(err => {
      console.error('❌ Clipboard copy failed:', err);
      alert('⚠️ Failed to copy. Try again!');
    });
}

function exportTransactionTable() {
  console.log("[exportTransactionTable] Called.");
  const table = document.getElementById('transactionTable');
  if (!table) {
    alert('No transaction table found.');
    console.log("[exportTransactionTable] No transactionTable element found. Aborting.");
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
  console.log("[exportTransactionTable] CSV export completed.");
}

function exportVaultBackup() {
  console.log("[exportVaultBackup] Called.");
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
  console.log("[exportVaultBackup] Vault backup exported.");
}

/******************************
 * UI & Synchronization Helpers
 ******************************/
function initializeBioConstantAndUTCTime() {
  console.log("[initializeBioConstantAndUTCTime] Called.");
  const currentTimestamp = Math.floor(Date.now() / 1000);
  vaultData.lastUTCTimestamp = currentTimestamp;
  populateWalletUI();

  if (bioLineIntervalTimer) clearInterval(bioLineIntervalTimer);
  bioLineIntervalTimer = setInterval(() => {
    vaultData.lastUTCTimestamp = Math.floor(Date.now() / 1000);
    populateWalletUI();
  }, 1000);
  console.log("[initializeBioConstantAndUTCTime] Interval timer set for updating lastUTCTimestamp.");
}

function populateWalletUI() {
  console.log("[populateWalletUI] Called.");
  const ibanInput = document.getElementById('bioibanInput');
  if (ibanInput) {
    ibanInput.value = vaultData.bioIBAN || 'BIO...';
  }
  const receivedTVM = vaultData.transactions.filter(tx => tx.type === 'received').reduce((s, t) => s + t.amount, 0);
  const sentTVM = vaultData.transactions.filter(tx => tx.type === 'sent').reduce((s, t) => s + t.amount, 0);
  const bonusTVM = vaultData.transactions.filter(tx => tx.type === 'cashback' || tx.type === 'increment')
    .reduce((s, t) => s + t.amount, 0);

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
    bioLineTextElem.textContent = `🔄 BonusConstant: ${vaultData.bonusConstant}`;
  }

  const utcTimeElem = document.getElementById('utcTime');
  if (utcTimeElem) {
    utcTimeElem.textContent = formatDisplayDate(vaultData.lastUTCTimestamp);
  }
  console.log("[populateWalletUI] Updated wallet UI elements with current vaultData.");
}

function showVaultUI() {
  console.log("[showVaultUI] Called.");
  document.getElementById('lockedScreen')?.classList.add('hidden');
  document.getElementById('vaultUI')?.classList.remove('hidden');
  document.getElementById('lockVaultBtn')?.classList.remove('hidden');
  populateWalletUI();
  renderTransactionTable();
}

function showBioCatchPopup(obfuscatedCatch) {
  console.log("[showBioCatchPopup] Called with obfuscatedCatch:", obfuscatedCatch);
  const popup = document.getElementById('bioCatchPopup');
  if (!popup) {
    console.log("[showBioCatchPopup] No bioCatchPopup element found. Exiting.");
    return;
  }
  popup.style.display = 'block';
  const bcTextElem = document.getElementById('bioCatchNumberText');
  if (bcTextElem) {
    bcTextElem.textContent = obfuscatedCatch;
  }
}

/******************************
 * Additional Helpers
 ******************************/
function validateBioIBAN(str) {
  console.log("[validateBioIBAN] Called with str:", str);
  const result = /^BIO\d+$/.test(str) || /^BONUS\d+$/.test(str);
  console.log("[validateBioIBAN] Returning:", result);
  return result;
}

async function verifyFullChainAndBioConstant(senderVaultSnapshot) {
  console.log("[verifyFullChainAndBioConstant] Called with senderVaultSnapshot:", senderVaultSnapshot);
  // Stub: always return success
  const result = { success: true };
  console.log("[verifyFullChainAndBioConstant] Returning stub result:", result);
  return result;
}

async function validateSenderVaultSnapshot(senderVaultSnapshot, claimedSenderIBAN) {
  console.log("[validateSenderVaultSnapshot] Called with claimedSenderIBAN:", claimedSenderIBAN);
  // Stub: always valid
  const result = { valid: true, errors: [] };
  console.log("[validateSenderVaultSnapshot] Returning stub result:", result);
  return result;
}

/******************************
 * Passphrase Modal & Vault Creation / Unlock
 ******************************/
async function getPassphraseFromModal({ confirmNeeded = false, modalTitle = 'Enter Passphrase' }) {
  console.log("[getPassphraseFromModal] Called with confirmNeeded:", confirmNeeded, "modalTitle:", modalTitle);
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
      console.log("[getPassphraseFromModal.cleanup] Called.");
      passCancelBtn.removeEventListener('click', onCancel);
      passSaveBtn.removeEventListener('click', onSave);
      passModal.style.display = 'none';
    }

    function onCancel() {
      console.log("[getPassphraseFromModal.onCancel] User canceled passphrase input.");
      cleanup();
      resolve({ pin: null });
    }

    function onSave() {
      console.log("[getPassphraseFromModal.onSave] Attempting to save passphrase input.");
      const pinVal = passInput.value.trim();
      if (!pinVal || pinVal.length < 8) {
        alert("⚠️ Passphrase must be >= 8 chars.");
        console.log("[getPassphraseFromModal.onSave] Passphrase too short. Aborting save.");
        return;
      }
      if (confirmNeeded) {
        const confVal = passConfirmInput.value.trim();
        if (pinVal !== confVal) {
          alert("❌ Passphrases do not match!");
          console.log("[getPassphraseFromModal.onSave] Confirmation mismatch. Aborting save.");
          return;
        }
      }
      cleanup();
      console.log("[getPassphraseFromModal.onSave] Passphrase input confirmed. Resolving.");
      resolve({ pin: pinVal, confirmed: true });
    }

    passCancelBtn.addEventListener('click', onCancel);
    passSaveBtn.addEventListener('click', onSave);
    passModal.style.display = 'block';
  });
}

async function checkAndUnlockVault() {
  console.log("[checkAndUnlockVault] Called.");
  const stored = await loadVaultDataFromDB();
  if (!stored) {
    console.log("[checkAndUnlockVault] No vault found in DB.");
    if (!confirm('⚠️ No vault found. Create a new vault?')) return;
    const { pin } = await getPassphraseFromModal({ confirmNeeded: true, modalTitle: 'Create New Vault (Set Passphrase)' });
    await createNewVault(pin);
  } else {
    console.log("[checkAndUnlockVault] Vault data found. Proceeding to unlock.");
    await unlockVault();
  }
}

async function createNewVault(pinFromUser = null) {
  console.log("[createNewVault] Called with pinFromUser length:", pinFromUser ? pinFromUser.length : null);
  if (!pinFromUser) {
    const result = await getPassphraseFromModal({ confirmNeeded: true, modalTitle: 'Create New Vault (Set Passphrase)' });
    pinFromUser = result.pin;
  }
  if (!pinFromUser || pinFromUser.length < 8) {
    alert('⚠️ Passphrase must be >= 8 characters.');
    console.log("[createNewVault] Invalid or short passphrase. Aborting creation.");
    return;
  }
  console.log("[createNewVault] Proceeding with NEW vault creation...");

  localStorage.setItem('vaultLock', 'locked');

  const nowSec = Math.floor(Date.now() / 1000);
  vaultData.joinTimestamp = nowSec;
  vaultData.lastUTCTimestamp = nowSec;
  vaultData.initialBioConstant = INITIAL_BIO_CONSTANT;
  vaultData.bonusConstant = vaultData.joinTimestamp - vaultData.initialBioConstant;
  vaultData.bioIBAN = `BIO${vaultData.initialBioConstant + vaultData.joinTimestamp}`;
  vaultData.initialBalanceTVM = INITIAL_BALANCE_TVM;
  vaultData.balanceTVM = INITIAL_BALANCE_TVM;
  vaultData.balanceUSD = parseFloat((INITIAL_BALANCE_TVM / EXCHANGE_RATE).toFixed(2));
  vaultData.transactions = [];
  vaultData.authAttempts = 0;
  vaultData.lockoutTimestamp = null;
  vaultData.lastTransactionHash = '';
  vaultData.finalChainHash = '';

  const credential = await performBiometricAuthenticationForCreation();
  if (!credential || !credential.id) {
    alert('Biometric credential creation failed/cancelled. Vault cannot be created.');
    console.log("[createNewVault] Biometric credential creation failed. Aborting.");
    return;
  }
  vaultData.credentialId = bufferToBase64(credential.rawId);

  console.log("[createNewVault] Vault data pre-persistence:", vaultData);

  const salt = generateSalt();
  derivedKey = await deriveKeyFromPIN(pinFromUser, salt);
  await persistVaultData(salt);

  vaultUnlocked = true;
  showVaultUI();
  initializeBioConstantAndUTCTime();
  localStorage.setItem('vaultUnlocked', 'true');
}

async function unlockVault() {
  console.log("[unlockVault] Called.");
  if (vaultData.lockoutTimestamp) {
    const now = Math.floor(Date.now() / 1000);
    console.log("[unlockVault] Checking lockoutTimestamp. Now:", now, "lockoutTimestamp:", vaultData.lockoutTimestamp);
    if (now < vaultData.lockoutTimestamp) {
      const remain = vaultData.lockoutTimestamp - now;
      alert(`❌ Vault locked. Try again in ${Math.ceil(remain / 60)} min.`);
      console.log("[unlockVault] Vault still locked. Aborting unlock.");
      return;
    } else {
      console.log("[unlockVault] Lockout period has passed. Clearing lockoutTimestamp.");
      vaultData.lockoutTimestamp = null;
      vaultData.authAttempts = 0;
      await promptAndSaveVault();
    }
  }

  const { pin } = await getPassphraseFromModal({ confirmNeeded: false, modalTitle: 'Unlock Vault' });
  if (!pin) {
    alert('❌ Passphrase is required or user canceled the modal.');
    console.log("[unlockVault] No pin provided. Handling failed auth attempt.");
    handleFailedAuthAttempt();
    return;
  }
  if (pin.length < 8) {
    alert('⚠️ Please use a stronger passphrase (>=8 chars).');
    console.log("[unlockVault] Pin too short. Handling failed auth attempt.");
    handleFailedAuthAttempt();
    return;
  }

  const stored = await loadVaultDataFromDB();
  if (!stored) {
    console.log("[unlockVault] No vault found in DB. Asking to create new vault.");
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
        console.log("[unlockVault] Biometric assertion failed. Handling failed auth attempt.");
        handleFailedAuthAttempt();
        return;
      }
    } else {
      console.log("[unlockVault] No credentialId found. Skipping WebAuthn check.");
    }

    vaultUnlocked = true;
    vaultData.authAttempts = 0;
    vaultData.lockoutTimestamp = null;

    await promptAndSaveVault();
    showVaultUI();
    initializeBioConstantAndUTCTime();
    localStorage.setItem('vaultUnlocked', 'true');
  } catch (err) {
    alert(`❌ Failed to decrypt: ${err.message}`);
    console.error("[unlockVault] Decrypt error:", err);
    handleFailedAuthAttempt();
  }
}

/******************************
 * Multi‑Tab / Single Vault
 ******************************/
function preventMultipleVaults() {
  console.log("[preventMultipleVaults] Called.");
  window.addEventListener('storage', (evt) => {
    if (evt.key === 'vaultUnlocked') {
      console.log("[preventMultipleVaults] storage event: vaultUnlocked changed to:", evt.newValue);
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
  console.log("[enforceSingleVault] Called.");
  const vaultLock = localStorage.getItem('vaultLock');
  if (!vaultLock) {
    console.log("[enforceSingleVault] Setting 'vaultLock' to 'locked' in localStorage.");
    localStorage.setItem('vaultLock', 'locked');
  } else {
    console.log('🔒 Vault lock detected. Ensuring single vault instance.');
  }
}

async function enforceStoragePersistence() {
  console.log("[enforceStoragePersistence] Called.");
  if (!navigator.storage?.persist) {
    console.log("[enforceStoragePersistence] navigator.storage.persist not supported. Exiting.");
    return;
  }
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
 * On DOM Load & UI Initialization
 ******************************/
function loadVaultOnStartup() {
  console.log("[loadVaultOnStartup] Called. (Currently does nothing by default.)");
  // Optional auto‑unlock or detection
}

window.addEventListener('DOMContentLoaded', () => {
  console.log("[DOMContentLoaded] Fired. Initializing application...");
  let lastURL = localStorage.getItem("last_session_url");
  if (lastURL && window.location.href !== lastURL) {
    console.log("[DOMContentLoaded] last_session_url found. Redirecting to:", lastURL);
    window.location.href = lastURL;
  }
  window.addEventListener("beforeunload", () => {
    localStorage.setItem("last_session_url", window.location.href);
    console.log("[beforeunload] Saving last_session_url:", window.location.href);
  });

  console.log("✅ Bio‑Vault: Initializing UI...");
  initializeUI();
  loadVaultOnStartup();
  preventMultipleVaults();
  enforceStoragePersistence();

  vaultSyncChannel.onmessage = async (e) => {
    console.log("[BroadcastChannel.onmessage] Received message:", e.data);
    if (e.data?.type === 'vaultUpdate') {
      try {
        const { iv, data } = e.data.payload;
        if (!derivedKey) {
          console.warn('[BroadcastChannel.onmessage] Received vaultUpdate but derivedKey is not available yet.');
          return;
        }
        const decrypted = await decryptData(derivedKey, base64ToBuffer(iv), base64ToBuffer(data));
        Object.assign(vaultData, decrypted);
        populateWalletUI();
        console.log('[BroadcastChannel.onmessage] Synced vault across tabs');
      } catch (err) {
        console.error('[BroadcastChannel.onmessage] Tab sync failed:', err);
      }
    }
  };
  enforceStoragePersistence();
});

function initializeUI() {
  console.log("[initializeUI] Called.");
  const enterVaultBtn = document.getElementById('enterVaultBtn');
  if (enterVaultBtn) {
    enterVaultBtn.addEventListener('click', checkAndUnlockVault);
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
      console.log("[initializeUI] Closed bioCatchPopup.");
    });
    const copyBioCatchPopupBtn = document.getElementById('copyBioCatchBtn');
    copyBioCatchPopupBtn?.addEventListener('click', () => {
      const bcNum = document.getElementById('bioCatchNumberText').textContent;
      navigator.clipboard.writeText(bcNum)
        .then(() => {
          alert('✅ Bio‑Catch Number copied to clipboard!');
          console.log("[initializeUI] Bio‑Catch number copied to clipboard from popup.");
        })
        .catch(err => {
          console.error('❌ Clipboard copy failed:', err);
          alert('⚠️ Failed to copy. Try again!');
        });
    });
    window.addEventListener('click', (event) => {
      if (event.target === bioCatchPopup) {
        bioCatchPopup.style.display = 'none';
        console.log("[initializeUI] bioCatchPopup closed by outside click.");
      }
    });
  }

  enforceSingleVault();
}

/******************************
 * Display Logic for Info & Vault Screens
 ******************************/
document.addEventListener("DOMContentLoaded", function() {
  console.log("[Inline DOMContentLoaded] Managing display logic for infoSection/backBtn...");
  const infoSection = document.getElementById('infoSection');
  const backBtn = document.getElementById('backBtn');
  const enterVaultBtn = document.getElementById('enterVaultBtn');
  const lockedScreen = document.getElementById('lockedScreen');
  const vaultUI = document.getElementById('vaultUI');
  const lockVaultBtn = document.getElementById('lockVaultBtn');

  // Display the info section when the page loads
  infoSection.style.display = 'block';
  backBtn.style.display = 'none';

  // Handle the back button to hide the info section and show the vault UI
  backBtn.addEventListener('click', function() {
    console.log("[Inline DOMContentLoaded] Back button clicked.");
    infoSection.style.display = 'none';
    vaultUI.classList.remove('hidden');
    lockVaultBtn.classList.remove('hidden');
  });

  // Handle the enter vault button to hide the info section and show vault UI
  enterVaultBtn.addEventListener('click', function() {
    console.log("[Inline DOMContentLoaded] Enter Vault button clicked.");
    infoSection.style.display = 'none';
    vaultUI.classList.remove('hidden');
    lockVaultBtn.classList.remove('hidden');
  });

  // Lock Vault Button to hide vault UI and show locked screen
  lockVaultBtn.addEventListener('click', function() {
    console.log("[Inline DOMContentLoaded] Lock Vault button clicked.");
    vaultUI.classList.add('hidden');
    lockVaultBtn.classList.add('hidden');
    lockedScreen.classList.remove('hidden');
    infoSection.style.display = 'none'; // Ensure infoSection is hidden when vault is locked
  });

  // Make sure the info section appears only when not in vault UI
  if (lockedScreen.classList.contains('hidden')) {
    infoSection.style.display = 'block';
    backBtn.style.display = 'inline-block';
  } else {
    infoSection.style.display = 'none';
  }
});
