
/***********************************************************************
 * main.js — Same Code, Now with Extensive Console Logging
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
 *  - 'bonusConstant' is a static difference = (joinTimestamp - initialBioConstant)
 *    => never increments after creation
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
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function formatDisplayDate(timestampInSeconds) {
  const date = new Date(timestampInSeconds * 1000);
  const isoString = date.toISOString();
  return `${isoString.slice(0, 10)} ${isoString.slice(11, 19)}`;
}

/******************************
 * PWA "Add to Home Screen"
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
async function computeTransactionHash(previousHash, txObject) {
  console.log("[computeTransactionHash] previousHash =", previousHash, ", txObject =", txObject);
  const dataString = JSON.stringify({ previousHash, ...txObject });
  const buffer = new TextEncoder().encode(dataString);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashHex = Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  console.log("[computeTransactionHash] => result =", hashHex);
  return hashHex;
}

async function computeFullChainHash(transactions) {
  console.log("[computeFullChainHash] Building full chain hash for all transactions...");
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
  console.log("[computeFullChainHash] Final chain hash =", runningHash);
  return runningHash;
}

/******************************
 * Buffer & Salt Utilities
 ******************************/
function bufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBuffer(base64) {
  const bin = atob(base64);
  const buffer = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    buffer[i] = bin.charCodeAt(i);
  }
  return buffer;
}

function generateSalt() {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  console.log("[generateSalt] =>", salt);
  return salt;
}

/******************************
 * WebAuthn / Biometric
 ******************************/
async function performBiometricAuthenticationForCreation() {
  console.log("[performBiometricAuthenticationForCreation] Attempting to create credential...");
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
      console.error("[performBiometricAuthenticationForCreation] ❌ Creation returned null.");
      return null;
    }
    console.log("[performBiometricAuthenticationForCreation] ✅ Created Credential:", credential);
    return credential;
  } catch (err) {
    console.error("[performBiometricAuthenticationForCreation] ❌ Error:", err);
    return null;
  }
}

async function performBiometricAssertion(credentialId) {
  console.log("[performBiometricAssertion] Checking credential with ID =", credentialId);
  try {
    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ id: base64ToBuffer(credentialId), type: 'public-key' }],
      userVerification: "required",
      timeout: 60000
    };
    const assertion = await navigator.credentials.get({ publicKey });
    console.log("[performBiometricAssertion] Assertion success? =>", !!assertion);
    return !!assertion;
  } catch (err) {
    console.error("[performBiometricAssertion] ❌ Error:", err);
    return false;
  }
}

/******************************
 * Encryption / Decryption
 ******************************/
async function encryptData(key, dataObj) {
  console.log("[encryptData] dataObj =", dataObj);
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc.encode(JSON.stringify(dataObj));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  console.log("[encryptData] Encryption complete, IV =", iv);
  return { iv, ciphertext };
}

async function decryptData(key, iv, ciphertext) {
  console.log("[decryptData] Attempting decryption...");
  const dec = new TextDecoder();
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  const result = JSON.parse(dec.decode(plainBuf));
  console.log("[decryptData] Decryption success =>", result);
  return result;
}

async function encryptBioCatchNumber(plainText) {
  console.log("[encryptBioCatchNumber] plainText =", plainText);
  try {
    const encoded = btoa(plainText);
    console.log("[encryptBioCatchNumber] =>", encoded);
    return encoded;
  } catch (err) {
    console.error("[encryptBioCatchNumber] ❌ Error:", err);
    return plainText;
  }
}

async function decryptBioCatchNumber(encryptedString) {
  console.log("[decryptBioCatchNumber] encryptedString =", encryptedString);
  try {
    const decoded = atob(encryptedString);
    console.log("[decryptBioCatchNumber] =>", decoded);
    return decoded;
  } catch (err) {
    console.error("[decryptBioCatchNumber] ❌ Error:", err);
    return null;
  }
}

/******************************
 * IndexedDB CRUD
 ******************************/
async function openVaultDB() {
  console.log("[openVaultDB] Opening...");
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (evt) => {
      console.log("[openVaultDB] onupgradeneeded triggered");
      const db = evt.target.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) {
        db.createObjectStore(VAULT_STORE, { keyPath: 'id' });
      }
    };
    req.onsuccess = (evt) => {
      console.log("[openVaultDB] success");
      resolve(evt.target.result);
    };
    req.onerror = (evt) => {
      console.error("[openVaultDB] ❌ onerror =>", evt.target.error);
      reject(evt.target.error);
    };
  });
}

async function saveVaultDataToDB(iv, ciphertext, saltBase64) {
  console.log("[saveVaultDataToDB] Storing encrypted vault...");
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
      console.log("[saveVaultDataToDB] completed");
      resolve();
    };
    tx.onerror = (err) => {
      console.error("[saveVaultDataToDB] ❌ tx.onerror =>", err);
      reject(err);
    };
  });
}

async function loadVaultDataFromDB() {
  console.log("[loadVaultDataFromDB] Loading...");
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([VAULT_STORE], 'readonly');
    const store = tx.objectStore(VAULT_STORE);
    const getReq = store.get('vaultData');
    getReq.onsuccess = () => {
      if (getReq.result) {
        try {
          console.log("[loadVaultDataFromDB] Found data =>", getReq.result);
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
          console.error("[loadVaultDataFromDB] ❌ Error decoding =>", error);
          resolve(null);
        }
      } else {
        console.log("[loadVaultDataFromDB] No existing vault data found.");
        resolve(null);
      }
    };
    getReq.onerror = (err) => {
      console.error("[loadVaultDataFromDB] ❌ onerror =>", err);
      reject(err);
    };
  });
}

/******************************
 * Vault Creation / Unlock Helpers
 ******************************/
async function deriveKeyFromPIN(pin, salt) {
  console.log("[deriveKeyFromPIN] Deriving key from pin with salt:", salt);
  const encoder = new TextEncoder();
  const pinBytes = encoder.encode(pin);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    pinBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  const derived = await crypto.subtle.deriveKey(
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
  console.log("[deriveKeyFromPIN] Key derived successfully.");
  return derived;
}

async function handleFailedAuthAttempt() {
  vaultData.authAttempts = (vaultData.authAttempts || 0) + 1;
  console.warn("[handleFailedAuthAttempt] Attempts =", vaultData.authAttempts);
  if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
    vaultData.lockoutTimestamp = Math.floor(Date.now() / 1000) + LOCKOUT_DURATION_SECONDS;
    alert('❌ Max authentication attempts exceeded. Vault locked for 1 hour.');
    console.warn("[handleFailedAuthAttempt] Vault locked until", vaultData.lockoutTimestamp);
  } else {
    alert(`❌ Auth failed. You have ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts} tries left.`);
  }
  await promptAndSaveVault();
}

function lockVault() {
  if (!vaultUnlocked) return;
  console.log("[lockVault] Locking vault...");
  vaultUnlocked = false;
  document.getElementById('vaultUI')?.classList.add('hidden');
  document.getElementById('lockVaultBtn')?.classList.add('hidden');
  document.getElementById('lockedScreen')?.classList.remove('hidden');
  localStorage.setItem('vaultUnlocked', 'false');
  console.log("[lockVault] Vault locked");
}

/******************************
 * Persistence
 ******************************/
async function persistVaultData(salt = null) {
  console.log("[persistVaultData] Attempting to encrypt & store vaultData...");
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
    console.log("[persistVaultData] 💾 Triply-redundant persistence complete");
  } catch (err) {
    console.error('[persistVaultData] ❌ Persistence failed:', err);
    alert('🚨 CRITICAL: VAULT BACKUP FAILED! EXPORT IMMEDIATELY!');
  }
}

async function promptAndSaveVault() {
  console.log("[promptAndSaveVault] => saving vault now...");
  await persistVaultData();
}

/******************************
 * Bonus Logic (Daily, Monthly, Annual)
 ******************************/

/** 
 * The daily "2+1" rule among 3 daily bonuses, plus monthly & annual checks. 
 * For "sent" => must exceed 240. For "received" => no threshold. 
 */
function resetDailyUsageIfNeeded(nowSec) {
  const currentDateStr = new Date(nowSec * 1000).toISOString().slice(0, 10);
  if (vaultData.dailyCashback.date !== currentDateStr) {
    console.log("[resetDailyUsageIfNeeded] New day => resetting daily usage");
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
    console.log("[resetMonthlyUsageIfNeeded] New month => resetting monthly usage");
    vaultData.monthlyUsage.yearMonth = ym;
    vaultData.monthlyUsage.usedCount = 0;
  }
}

/** 
 * Checks how many 'sent' vs. 'received' bonuses we've triggered today 
 */
function bonusDiversityCheck(newTxType) {
  console.log("[bonusDiversityCheck] Checking daily usage for type =", newTxType);
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

  console.log("[bonusDiversityCheck] So far => sentTriggeredCount =", sentTriggeredCount, ", receivedTriggeredCount =", receivedTriggeredCount);

  // If we have 2 from the same type, next must be different:
  if (newTxType === 'sent' && sentTriggeredCount >= 2) {
    console.warn("[bonusDiversityCheck] Already 2 'sent' bonuses => must be 'received'");
    return false;
  }
  if (newTxType === 'received' && receivedTriggeredCount >= 2) {
    console.warn("[bonusDiversityCheck] Already 2 'received' bonuses => must be 'sent'");
    return false;
  }
  return true;
}

/**
 * Final "canGive120Bonus()" check => daily, monthly, annual, "sent" threshold, and 2+1 rule
 */
function canGive120Bonus(nowSec, newTxType, newTxAmount) {
  console.log("[canGive120Bonus] Checking bonus eligibility =>", { nowSec, newTxType, newTxAmount });
  resetDailyUsageIfNeeded(nowSec);
  resetMonthlyUsageIfNeeded(nowSec);

  if (vaultData.dailyCashback.usedCount >= MAX_BONUSES_PER_DAY) {
    console.warn("[canGive120Bonus] dailyCashback.usedCount >= 3 => false");
    return false;
  }
  if (vaultData.monthlyUsage.usedCount >= MAX_BONUSES_PER_MONTH) {
    console.warn("[canGive120Bonus] monthlyUsage.usedCount >= 30 => false");
    return false;
  }
  if ((vaultData.annualBonusUsed || 0) >= MAX_ANNUAL_BONUS_TVM) {
    console.warn("[canGive120Bonus] annualBonusUsed >= 10800 => false");
    return false;
  }

  // "sent" must exceed 240
  if (newTxType === 'sent' && newTxAmount <= 240) {
    console.warn("[canGive120Bonus] 'sent' but amount <= 240 => false");
    return false;
  }

  // 2+1 rule
  if (!bonusDiversityCheck(newTxType)) {
    console.warn("[canGive120Bonus] Fails 2+1 type rule => false");
    return false;
  }

  console.log("[canGive120Bonus] => true");
  return true;
}

function record120BonusUsage(triggerOrigin) {
  vaultData.dailyCashback.usedCount++;
  vaultData.monthlyUsage.usedCount++;
  vaultData.annualBonusUsed = (vaultData.annualBonusUsed || 0) + PER_TX_BONUS;
  console.log("[record120BonusUsage] recorded usage => daily:", vaultData.dailyCashback.usedCount,
              ", monthly:", vaultData.monthlyUsage.usedCount,
              ", annual:", vaultData.annualBonusUsed,
              ", triggerOrigin:", triggerOrigin);
}

/******************************
 * Snapshot Serialization & Validation
 ******************************/
function serializeVaultSnapshotForBioCatch(vData) {
  console.log("[serializeVaultSnapshotForBioCatch] Serializing vaultData =>", vData);
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
  const encoded = btoa(rawString);
  console.log("[serializeVaultSnapshotForBioCatch] =>", encoded);
  return encoded;
}

function deserializeVaultSnapshotFromBioCatch(base64String) {
  console.log("[deserializeVaultSnapshotFromBioCatch] base64String =", base64String);
  const raw = atob(base64String);
  console.log("[deserializeVaultSnapshotFromBioCatch] Decoded raw =>", raw);
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
  const snapshot = {
    joinTimestamp,
    initialBioConstant,
    bonusConstant,
    finalChainHash,
    initialBalanceTVM,
    balanceTVM,
    lastUTCTimestamp,
    transactions
  };
  console.log("[deserializeVaultSnapshotFromBioCatch] => snapshot =", snapshot);
  return snapshot;
}

async function generateBioCatchNumber(senderBioIBAN, receiverBioIBAN, amount, timestamp, senderBalance, finalChainHash) {
  console.log("[generateBioCatchNumber] senderIBAN =", senderBioIBAN, ", receiverIBAN =", receiverBioIBAN, ", amount =", amount);
  const encodedVault = serializeVaultSnapshotForBioCatch(vaultData);
  const senderNumeric = parseInt(senderBioIBAN.slice(3));
  const receiverNumeric = parseInt(receiverBioIBAN.slice(3));
  const firstPart = senderNumeric + receiverNumeric;

  const result = `Bio-${firstPart}-${timestamp}-${amount}-${senderBalance}-${senderBioIBAN}-${finalChainHash}-${encodedVault}`;
  console.log("[generateBioCatchNumber] =>", result);
  return result;
}

async function validateBioCatchNumber(bioCatchNumber, claimedAmount) {
  console.log("[validateBioCatchNumber] Checking =>", bioCatchNumber, ", claimedAmount =", claimedAmount);
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

  // If it's a BONUS IBAN, check the offset
  if (claimedSenderIBAN.startsWith("BONUS")) {
    const offset = encodedTimestamp - senderVaultSnapshot.joinTimestamp;
    const expected = "BONUS" + (senderVaultSnapshot.bonusConstant + offset);
    if (claimedSenderIBAN !== expected) {
      return { valid: false, message: 'Mismatched Bonus Sender IBAN in BioCatch.' };
    }
  } else {
    // Normal "BIO"
    const expectedSenderIBAN = `BIO${senderVaultSnapshot.initialBioConstant + senderVaultSnapshot.joinTimestamp}`;
    if (claimedSenderIBAN !== expectedSenderIBAN) {
      return { valid: false, message: 'Mismatched Sender IBAN in BioCatch.' };
    }
  }

  console.log("[validateBioCatchNumber] => success!");
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
  console.log("[handleSendTransaction] Initiated...");
  if (!vaultUnlocked) {
    alert('❌ Please unlock the vault first.');
    return;
  }
  if (transactionLock) {
    alert('🔒 A transaction is already in progress. Please wait.');
    return;
  }

  const receiverBioIBAN = document.getElementById('receiverBioIBAN')?.value.trim();
  const amount = parseFloat(document.getElementById('catchOutAmount')?.value.trim());
  console.log("[handleSendTransaction] receiverBioIBAN =", receiverBioIBAN, ", amount =", amount);
  if (!receiverBioIBAN || isNaN(amount) || amount <= 0) {
    alert('❌ Invalid receiver Bio‑IBAN or amount.');
    return;
  }
  if (!validateBioIBAN(receiverBioIBAN)) {
    alert('❌ Invalid Bio‑IBAN format.');
    return;
  }
  if (receiverBioIBAN === vaultData.bioIBAN) {
    alert('❌ Cannot send to self.');
    return;
  }
  if (vaultData.balanceTVM < amount) {
    alert('❌ Insufficient TVM balance.');
    return;
  }

  transactionLock = true;
  try {
    const nowSec = Math.floor(Date.now() / 1000);
    vaultData.lastUTCTimestamp = nowSec;

    // Check if "sent" qualifies for a bonus
    let bonusGranted = false;
    if (canGive120Bonus(nowSec, 'sent', amount)) {
      record120BonusUsage('sent');
      bonusGranted = true;
    }

    console.log("[handleSendTransaction] bonusGranted =", bonusGranted);
    vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);

    // Generate new BioCatch
    const plainBioCatchNumber = await generateBioCatchNumber(
      vaultData.bioIBAN,
      receiverBioIBAN,
      amount,
      nowSec,
      vaultData.balanceTVM,
      vaultData.finalChainHash
    );

    // Uniqueness check
    for (let tx of vaultData.transactions) {
      if (tx.bioCatch) {
        const existingPlain = await decryptBioCatchNumber(tx.bioCatch);
        if (existingPlain === plainBioCatchNumber) {
          console.warn("[handleSendTransaction] Found existing identical bioCatch => aborting");
          alert('❌ This BioCatch number already exists. Try again.');
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
    console.log("[handleSendTransaction] Creating 'sent' transaction =>", newTx);
    newTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, newTx);
    vaultData.transactions.push(newTx);
    vaultData.lastTransactionHash = newTx.txHash;
    vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);

    // Bonus TX if triggered
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
      console.log("[handleSendTransaction] Creating bonus TX =>", bonusTx);
      bonusTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash = bonusTx.txHash;
      vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);
    }

    populateWalletUI();
    await promptAndSaveVault();
    alert(`✅ Sent ${amount} TVM. Bonus: ${bonusGranted ? '120 TVM' : 'None'}`);
    showBioCatchPopup(obfuscatedCatch);

    document.getElementById('receiverBioIBAN').value = '';
    document.getElementById('catchOutAmount').value = '';
    renderTransactionTable();
  } catch (err) {
    console.error('[handleSendTransaction] ❌ Error:', err);
    alert('❌ An error occurred processing the transaction.');
  } finally {
    transactionLock = false;
    console.log("[handleSendTransaction] Completed.");
  }
}

async function handleReceiveTransaction() {
  console.log("[handleReceiveTransaction] Initiated...");
  if (!vaultUnlocked) {
    alert('❌ Please unlock the vault first.');
    return;
  }
  if (transactionLock) {
    alert('🔒 A transaction is in progress. Please wait.');
    return;
  }

  const encryptedBioCatchInput = document.getElementById('catchInBioCatch')?.value.trim();
  const amount = parseFloat(document.getElementById('catchInAmount')?.value.trim());
  console.log("[handleReceiveTransaction] encryptedBioCatchInput =", encryptedBioCatchInput, ", amount =", amount);
  if (!encryptedBioCatchInput || isNaN(amount) || amount <= 0) {
    alert('❌ Invalid BioCatch number or amount.');
    return;
  }

  transactionLock = true;
  try {
    const nowSec = Math.floor(Date.now() / 1000);
    vaultData.lastUTCTimestamp = nowSec;

    // Check if "received" triggers a bonus
    let bonusGranted = false;
    if (canGive120Bonus(nowSec, 'received', amount)) {
      record120BonusUsage('received');
      bonusGranted = true;
    }

    const bioCatchNumber = await decryptBioCatchNumber(encryptedBioCatchInput);
    if (!bioCatchNumber) {
      alert('❌ Unable to decode BioCatch number.');
      transactionLock = false;
      return;
    }

    // Ensure not used before
    for (let tx of vaultData.transactions) {
      if (tx.bioCatch) {
        const existingPlain = await decryptBioCatchNumber(tx.bioCatch);
        if (existingPlain === bioCatchNumber) {
          console.warn("[handleReceiveTransaction] Duplicate BioCatch => aborting");
          alert('❌ This BioCatch number has already been used.');
          transactionLock = false;
          return;
        }
      }
    }

    const validation = await validateBioCatchNumber(bioCatchNumber, amount);
    console.log("[handleReceiveTransaction] validateBioCatchNumber =>", validation);
    if (!validation.valid) {
      alert(`❌ BioCatch Validation Failed: ${validation.message}`);
      transactionLock = false;
      return;
    }

    const { chainHash, claimedSenderIBAN, senderVaultSnapshot } = validation;
    // Suppose you have a function:
    const crossCheck = await verifyFullChainAndBioConstant(senderVaultSnapshot);
    console.log("[handleReceiveTransaction] verifyFullChainAndBioConstant =>", crossCheck);
    if (!crossCheck.success) {
      alert(`❌ Sender chain mismatch: ${crossCheck.reason}`);
      transactionLock = false;
      return;
    }
    if (senderVaultSnapshot.finalChainHash !== chainHash) {
      alert('❌ The chain hash in the BioCatch does not match the snapshot’s final chain hash!');
      transactionLock = false;
      return;
    }
    const snapshotValidation = await validateSenderVaultSnapshot(senderVaultSnapshot, claimedSenderIBAN);
    console.log("[handleReceiveTransaction] validateSenderVaultSnapshot =>", snapshotValidation);
    if (!snapshotValidation.valid) {
      alert("❌ Sender snapshot integrity check failed: " + snapshotValidation.errors.join("; "));
      transactionLock = false;
      return;
    }

    // Record the "received" transaction
    const rxTx = {
      type: 'received',
      senderBioIBAN: claimedSenderIBAN,
      bioCatch: encryptedBioCatchInput,
      amount,
      timestamp: nowSec,
      status: 'Valid',
      bonusConstantAtGeneration: vaultData.bonusConstant
    };
    console.log("[handleReceiveTransaction] Creating 'received' transaction =>", rxTx);
    vaultData.transactions.push(rxTx);

    // If bonus is triggered
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
      console.log("[handleReceiveTransaction] Creating bonus TX =>", bonusTx);
      bonusTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash = bonusTx.txHash;
      vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);
    }

    await promptAndSaveVault();
    populateWalletUI();
    alert(`✅ Transaction received successfully! +${amount} TVM. Bonus: ${bonusGranted ? '120 TVM' : 'None'}`);
    document.getElementById('catchInBioCatch').value = '';
    document.getElementById('catchInAmount').value = '';
    renderTransactionTable();
  } catch (error) {
    console.error('[handleReceiveTransaction] ❌ Error:', error);
    alert('❌ An error occurred processing the transaction.');
  } finally {
    transactionLock = false;
    console.log("[handleReceiveTransaction] Completed.");
  }
}

/******************************
 * UI & Table Rendering
 ******************************/
function renderTransactionTable() {
  console.log("[renderTransactionTable] Rendering transaction table...");
  const tbody = document.getElementById('transactionBody');
  if (!tbody) return;
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
}

function handleCopyBioIBAN() {
  console.log("[handleCopyBioIBAN] Attempting to copy IBAN...");
  const bioIBANInput = document.getElementById('bioibanInput');
  if (!bioIBANInput || !bioIBANInput.value.trim()) {
    alert('❌ No Bio‑IBAN to copy.');
    return;
  }
  navigator.clipboard.writeText(bioIBANInput.value.trim())
    .then(() => alert('✅ Bio‑IBAN copied to clipboard!'))
    .catch(err => {
      console.error('[handleCopyBioIBAN] ❌ Clipboard copy failed:', err);
      alert('⚠️ Failed to copy. Try again!');
    });
}

function exportTransactionTable() {
  console.log("[exportTransactionTable] Exporting as CSV...");
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

function exportVaultBackup() {
  console.log("[exportVaultBackup] Exporting vaultData as JSON...");
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
  console.log("[initializeBioConstantAndUTCTime] Setting up clock only, no increment to bonusConstant.");
  const currentTimestamp = Math.floor(Date.now() / 1000);
  vaultData.lastUTCTimestamp = currentTimestamp;
  populateWalletUI();

  if (bioLineIntervalTimer) clearInterval(bioLineIntervalTimer);
  bioLineIntervalTimer = setInterval(() => {
    vaultData.lastUTCTimestamp = Math.floor(Date.now() / 1000);
    populateWalletUI();
  }, 1000);
}

function populateWalletUI() {
  console.log("[populateWalletUI] Updating UI with current vaultData...");
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
}

function showVaultUI() {
  console.log("[showVaultUI] Showing vault UI...");
  document.getElementById('lockedScreen')?.classList.add('hidden');
  document.getElementById('vaultUI')?.classList.remove('hidden');
  document.getElementById('lockVaultBtn')?.classList.remove('hidden');
  populateWalletUI();
  renderTransactionTable();
}

function showBioCatchPopup(obfuscatedCatch) {
  console.log("[showBioCatchPopup] =>", obfuscatedCatch);
  const popup = document.getElementById('bioCatchPopup');
  if (!popup) return;
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
  return /^BIO\d+$/.test(str) || /^BONUS\d+$/.test(str);
}

async function verifyFullChainAndBioConstant(senderVaultSnapshot) {
  console.log("[verifyFullChainAndBioConstant] => Checking chain for snapshot:", senderVaultSnapshot);
  // Stub: always returns success
  return { success: true };
}

async function validateSenderVaultSnapshot(senderVaultSnapshot, claimedSenderIBAN) {
  console.log("[validateSenderVaultSnapshot] => Checking snapshot vs. IBAN:", claimedSenderIBAN);
  // Stub: always returns valid
  return { valid: true, errors: [] };
}

/******************************
 * Passphrase Modal & Vault Creation / Unlock
 ******************************/
async function getPassphraseFromModal({ confirmNeeded = false, modalTitle = 'Enter Passphrase' }) {
  console.log("[getPassphraseFromModal] confirmNeeded =", confirmNeeded, ", modalTitle =", modalTitle);
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
      console.log("[getPassphraseFromModal] => onCancel");
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
      console.log("[getPassphraseFromModal] => onSave, pinVal length =", pinVal.length);
      cleanup();
      resolve({ pin: pinVal, confirmed: true });
    }

    passCancelBtn.addEventListener('click', onCancel);
    passSaveBtn.addEventListener('click', onSave);
    passModal.style.display = 'block';
  });
}

async function checkAndUnlockVault() {
  console.log("[checkAndUnlockVault] Checking if vault exists...");
  const stored = await loadVaultDataFromDB();
  if (!stored) {
    console.log("[checkAndUnlockVault] No existing vault => creating new?");
    if (!confirm('⚠️ No vault found. Create a new vault?')) return;
    const { pin } = await getPassphraseFromModal({ confirmNeeded: true, modalTitle: 'Create New Vault (Set Passphrase)' });
    await createNewVault(pin);
  } else {
    console.log("[checkAndUnlockVault] Found existing vault => unlocking...");
    await unlockVault();
  }
}

async function createNewVault(pinFromUser = null) {
  console.log("[createNewVault] => Start, pinFromUser =", pinFromUser);
  if (!pinFromUser) {
    const result = await getPassphraseFromModal({ confirmNeeded: true, modalTitle: 'Create New Vault (Set Passphrase)' });
    pinFromUser = result.pin;
  }
  if (!pinFromUser || pinFromUser.length < 8) {
    alert('⚠️ Passphrase must be >= 8 characters.');
    return;
  }
  console.log("[createNewVault] => Proceeding with new vault creation");
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

  console.log("[createNewVault] => new vault data:", vaultData);

  const credential = await performBiometricAuthenticationForCreation();
  if (!credential || !credential.id) {
    alert('Biometric credential creation failed/cancelled. Vault cannot be created.');
    return;
  }
  vaultData.credentialId = bufferToBase64(credential.rawId);

  const salt = generateSalt();
  derivedKey = await deriveKeyFromPIN(pinFromUser, salt);
  await persistVaultData(salt);

  vaultUnlocked = true;
  showVaultUI();
  initializeBioConstantAndUTCTime();
  localStorage.setItem('vaultUnlocked', 'true');
  console.log("[createNewVault] => Done.");
}

async function unlockVault() {
  console.log("[unlockVault] => Start");
  if (vaultData.lockoutTimestamp) {
    const now = Math.floor(Date.now() / 1000);
    if (now < vaultData.lockoutTimestamp) {
      const remain = vaultData.lockoutTimestamp - now;
      alert(`❌ Vault locked. Try again in ${Math.ceil(remain / 60)} min.`);
      console.warn("[unlockVault] => still locked for", remain, "seconds");
      return;
    } else {
      vaultData.lockoutTimestamp = null;
      vaultData.authAttempts = 0;
      await promptAndSaveVault();
    }
  }

  const { pin } = await getPassphraseFromModal({ confirmNeeded: false, modalTitle: 'Unlock Vault' });
  if (!pin) {
    console.warn("[unlockVault] => user canceled or empty pin");
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
    console.log("[unlockVault] => no stored => create new vault?");
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
    console.log("[unlockVault] => Decrypted vaultData:", vaultData);

    if (vaultData.credentialId) {
      const ok = await performBiometricAssertion(vaultData.credentialId);
      if (!ok) {
        alert('❌ Device credential mismatch. Unlock failed.');
        handleFailedAuthAttempt();
        return;
      }
    } else {
      console.log("[unlockVault] => No credentialId found => skipping WebAuthn check.");
    }

    vaultUnlocked = true;
    vaultData.authAttempts = 0;
    vaultData.lockoutTimestamp = null;

    await promptAndSaveVault();

    showVaultUI();
    initializeBioConstantAndUTCTime();
    localStorage.setItem('vaultUnlocked', 'true');
    console.log("[unlockVault] => Vault unlocked successfully!");
  } catch (err) {
    console.error("[unlockVault] => ❌ Decrypt error:", err);
    alert(`❌ Failed to decrypt: ${err.message}`);
    handleFailedAuthAttempt();
  }
}

/******************************
 * Multi‑Tab / Single Vault
 ******************************/
function preventMultipleVaults() {
  console.log("[preventMultipleVaults] Installing 'storage' event listener for multi-tab sync...");
  window.addEventListener('storage', (evt) => {
    if (evt.key === 'vaultUnlocked') {
      if (evt.newValue === 'true' && !vaultUnlocked) {
        console.log("[preventMultipleVaults] => Another tab unlocked the vault => do same here");
        vaultUnlocked = true;
        showVaultUI();
        initializeBioConstantAndUTCTime();
      } else if (evt.newValue === 'false' && vaultUnlocked) {
        console.log("[preventMultipleVaults] => Another tab locked the vault => do same here");
        vaultUnlocked = false;
        lockVault();
      }
    }
    if (evt.key === 'vaultLock') {
      if (evt.newValue === 'locked' && !vaultUnlocked) {
        console.log("[preventMultipleVaults] => Another tab locked => recognized here");
      }
    }
  });
}

function enforceSingleVault() {
  const vaultLock = localStorage.getItem('vaultLock');
  if (!vaultLock) {
    localStorage.setItem('vaultLock', 'locked');
    console.log("[enforceSingleVault] => Setting vaultLock = locked");
  } else {
    console.log("[enforceSingleVault] => Vault lock detected => single instance enforced");
  }
}

async function enforceStoragePersistence() {
  if (!navigator.storage?.persist) return;
  const persisted = await navigator.storage.persisted();
  if (!persisted) {
    const granted = await navigator.storage.persist();
    console.log(granted ? "[enforceStoragePersistence] => 🔒 Storage hardened" : "[enforceStoragePersistence] => ⚠️ Storage vulnerable");
  }
  setInterval(async () => {
    const estimate = await navigator.storage.estimate();
    if ((estimate.usage / estimate.quota) > 0.85) {
      console.warn('[enforceStoragePersistence] => 🚨 Storage critical:', estimate);
      alert('❗ Vault storage nearing limit! Export backup!');
    }
  }, STORAGE_CHECK_INTERVAL);
}

/******************************
 * On DOM Load & UI Initialization
 ******************************/
function loadVaultOnStartup() {
  console.log("[loadVaultOnStartup] (Optional) No auto-unlock logic used here");
}

window.addEventListener('DOMContentLoaded', () => {
  let lastURL = localStorage.getItem("last_session_url");
  if (lastURL && window.location.href !== lastURL) {
    console.log("[DOMContentLoaded] => redirecting to lastURL:", lastURL);
    window.location.href = lastURL;
  }
  window.addEventListener("beforeunload", () => {
    localStorage.setItem("last_session_url", window.location.href);
  });

  console.log("✅ Bio‑Vault: Initializing UI & Checking Vault...");
  initializeUI();
  loadVaultOnStartup();
  preventMultipleVaults();
  enforceStoragePersistence();

  vaultSyncChannel.onmessage = async (e) => {
    if (e.data?.type === 'vaultUpdate') {
      console.log("[vaultSyncChannel] => Received 'vaultUpdate' from another tab", e.data.payload);
      try {
        const { iv, data } = e.data.payload;
        if (!derivedKey) {
          console.warn('[vaultSyncChannel] => derivedKey not available yet => ignoring sync');
          return;
        }
        const decrypted = await decryptData(derivedKey, base64ToBuffer(iv), base64ToBuffer(data));
        Object.assign(vaultData, decrypted);
        populateWalletUI();
        console.log('[vaultSyncChannel] => Synced vault across tabs => new vaultData:', vaultData);
      } catch (err) {
        console.error('[vaultSyncChannel] => Sync failed:', err);
      }
    }
  };
});

function initializeUI() {
  console.log("[initializeUI] Setting up all UI event listeners...");
  const enterVaultBtn = document.getElementById('enterVaultBtn');
  if (enterVaultBtn) {
    enterVaultBtn.addEventListener('click', checkAndUnlockVault);
    console.log("[initializeUI] => Attached to enterVaultBtn");
  } else {
    console.error("[initializeUI] => ❌ enterVaultBtn NOT FOUND in DOM!");
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
          console.error('[copyBioCatchPopupBtn] ❌ Clipboard copy failed:', err);
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



// JavaScript to manage the display logic
document.addEventListener("DOMContentLoaded", function() {
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
    infoSection.style.display = 'none';
    vaultUI.classList.remove('hidden');
    lockVaultBtn.classList.remove('hidden');
  });

  // Handle the enter vault button to hide the info section and show vault UI
  enterVaultBtn.addEventListener('click', function() {
    infoSection.style.display = 'none';
    vaultUI.classList.remove('hidden');
    lockVaultBtn.classList.remove('hidden');
  });

  // Lock Vault Button to hide vault UI and show locked screen
  lockVaultBtn.addEventListener('click', function() {
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
