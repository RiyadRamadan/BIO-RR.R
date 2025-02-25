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
const MAX_ANNUAL_BONUS_TVM = 10800;
const EXCHANGE_RATE = 12;
const INITIAL_BIO_CONSTANT = 1736565605;
const TRANSACTION_VALIDITY_SECONDS = 720; // ±12 minutes
const LOCKOUT_DURATION_SECONDS = 3600;    // 1 hour
const MAX_AUTH_ATTEMPTS = 3;

const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000; // 5 minutes

// Vault data – note: the vault owner’s IBAN is computed once at creation.
let vaultData = {
  bioIBAN: null, // "BIO" + (initialBioConstant + joinTimestamp)
  initialBalanceTVM: INITIAL_BALANCE_TVM,
  balanceTVM: 0,
  balanceUSD: 0,
  initialBioConstant: INITIAL_BIO_CONSTANT,
  bioConstant: INITIAL_BIO_CONSTANT, // evolves with time (balance chain)
  // BONUS CHAIN: bonusConstant is set at vault creation and never changes.
  bonusConstant: null,     // = bioConstant at vault creation
  lastBonusIncrement: null, // updated each time a bonus is granted
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
  annualBonusUsed: 0,
  annualUsageYear: null,
};

let vaultUnlocked = false;
let derivedKey = null;
let bioLineIntervalTimer = null;

const vaultSyncChannel = new BroadcastChannel('vault-sync');

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
 * Transaction Hashing
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
  return crypto.getRandomValues(new Uint8Array(16));
}

/******************************
 * Vault Persistence (IndexedDB)
 ******************************/
async function openVaultDB() {
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
    store.put({
      id: 'vaultData',
      iv: bufferToBase64(iv),
      ciphertext: bufferToBase64(ciphertext),
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

/******************************
 * Vault Creation / Unlock Helpers
 ******************************/
async function deriveKeyFromPIN(pin, salt) {
  const encoder = new TextEncoder();
  const pinBytes = encoder.encode(pin);
  const keyMaterial = await crypto.subtle.importKey('raw', pinBytes, { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/******************************
 * UI & Synchronization Helpers
 ******************************/
function populateWalletUI() {
  const tvmBalanceElem = document.getElementById('tvmBalance');
  const usdBalanceElem = document.getElementById('usdBalance');
  const bioLineTextElem = document.getElementById('bioLineText');
  const utcTimeElem = document.getElementById('utcTime');
  if (tvmBalanceElem) {
    tvmBalanceElem.textContent = `💰 Balance: ${formatWithCommas(vaultData.balanceTVM)} TVM`;
  }
  if (usdBalanceElem) {
    usdBalanceElem.textContent = `💵 Equivalent to ${formatWithCommas(vaultData.balanceUSD)} USD`;
  }
  if (bioLineTextElem) {
    bioLineTextElem.textContent = `🔄 Bio‑Line: ${vaultData.bioConstant}`;
  }
  if (utcTimeElem) {
    utcTimeElem.textContent = formatDisplayDate(vaultData.lastUTCTimestamp);
  }
}

/******************************
 * Main Workflow: Persistence & Backup
 ******************************/
async function promptAndSaveVault() {
  try {
    if (!derivedKey) throw new Error('🔴 No encryption key');
    const { iv, ciphertext } = await encryptData(derivedKey, vaultData);
    const stored = await loadVaultDataFromDB();
    let saltBase64;
    if (stored && stored.salt) {
      saltBase64 = bufferToBase64(stored.salt);
    } else {
      throw new Error('🔴 Salt not found. Cannot persist vault data.');
    }
    await saveVaultDataToDB(iv, ciphertext, saltBase64);
    localStorage.setItem(VAULT_BACKUP_KEY, JSON.stringify({ iv: bufferToBase64(iv), data: bufferToBase64(ciphertext) }));
    vaultSyncChannel.postMessage({ type: 'vaultUpdate', payload: { iv: bufferToBase64(iv), data: bufferToBase64(ciphertext) } });
    console.log('💾 Vault data persisted and backed up');
  } catch (err) {
    console.error('💥 Persistence failed:', err);
    alert('🚨 CRITICAL: VAULT BACKUP FAILED!');
  }
}

/******************************
 * Transaction Validation & Snapshot Serialization
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
  const receivedTVM = senderSnapshot.transactions.filter(tx => tx.type === 'received').reduce((s, tx) => s + tx.amount, 0);
  const sentTVM = senderSnapshot.transactions.filter(tx => tx.type === 'sent').reduce((s, tx) => s + tx.amount, 0);
  const bonusTVM = senderSnapshot.transactions.filter(tx => tx.type === 'cashback').reduce((s, tx) => s + tx.amount, 0);
  const computedBalance = senderSnapshot.initialBalanceTVM + receivedTVM + bonusTVM - sentTVM;
  if (computedBalance !== senderSnapshot.balanceTVM) {
    errors.push(`Balance mismatch: computed ${computedBalance} vs stored ${senderSnapshot.balanceTVM}`);
  }
  const computedSenderIBAN = `BIO${senderSnapshot.initialBioConstant + senderSnapshot.joinTimestamp}`;
  if (claimedSenderIBAN !== computedSenderIBAN) {
    errors.push(`Sender Bio‑IBAN mismatch: computed ${computedSenderIBAN} vs claimed ${claimedSenderIBAN}`);
  }
  return { valid: errors.length === 0, errors };
}

function serializeVaultSnapshotForBioCatch(vData) {
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
      tx.bioConstantAtGeneration || 0,
      tx.previousHash || '',
      tx.txHash || ''
    ].join(txFieldSep);
  });
  const txString = txParts.join(txSep);
  const rawString = [
    vData.joinTimestamp || 0,
    vData.initialBioConstant || 0,
    vData.finalChainHash || '',
    vData.initialBalanceTVM || 0,
    vData.balanceTVM || 0,
    vData.bioConstant || 0,
    vData.lastUTCTimestamp || 0,
    txString
  ].join(fieldSep);
  return btoa(rawString);
}

async function generateBioCatchNumber(senderBioIBAN, receiverBioIBAN, amount, timestamp, senderBalance, finalChainHash) {
  const encodedVault = serializeVaultSnapshotForBioCatch(vaultData);
  const senderNumeric = parseInt(senderBioIBAN.slice(3));
  const receiverNumeric = parseInt(receiverBioIBAN.slice(3));
  const firstPart = senderNumeric + receiverNumeric;
  return `Bio-${firstPart}-${timestamp}-${amount}-${senderBalance}-${senderBioIBAN}-${finalChainHash}-${encodedVault}`;
}

/******************************
 * Transaction Handlers
 ******************************/
let transactionLock = false;

async function handleSendTransaction() {
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
  if (!receiverBioIBAN || isNaN(amount) || amount <= 0) {
    alert('❌ Invalid receiver Bio‑IBAN or amount.');
    return;
  }
  if (!/^BIO\d+$/.test(receiverBioIBAN)) {
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
    const delta = nowSec - vaultData.lastUTCTimestamp;
    vaultData.bioConstant += delta;
    vaultData.lastUTCTimestamp = nowSec;

    let bonusGranted = false;
    if (amount > 240 && canGive120Bonus(nowSec)) {
      record120BonusUsage();
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
      bioConstantAtGeneration: vaultData.bioConstant,
      previousHash: vaultData.lastTransactionHash,
      txHash: ''
    };
    newTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, newTx);
    vaultData.transactions.push(newTx);
    vaultData.lastTransactionHash = newTx.txHash;
    vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);

    if (bonusGranted) {
      // Calculate bonus IBAN as specified.
      const bonusIBAN = `BONUS${vaultData.joinTimestamp - vaultData.initialBioConstant}`;
      // Compute bonus difference:
      // For the first bonus, bonusDiff = current bioConstant - bonusConstant.
      // For subsequent bonuses, bonusDiff = current bioConstant - lastBonusIncrement.
      const bonusDiff = vaultData.bioConstant - vaultData.lastBonusIncrement;
      // Update lastBonusIncrement
      vaultData.lastBonusIncrement = vaultData.bioConstant;
      
      const bonusTx = {
        type: 'cashback',
        amount: PER_TX_BONUS,
        timestamp: nowSec,
        status: 'Granted',
        bioConstantAtGeneration: vaultData.bioConstant,
        previousHash: vaultData.lastTransactionHash,
        txHash: '',
        senderBioIBAN: bonusIBAN,
        bonusDiff: bonusDiff // new field representing the difference for this bonus
      };
      bonusTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash = bonusTx.txHash;
      vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);
    }

    // Update balance calculations
    const receivedTVM = vaultData.transactions.filter(tx => tx.type === 'received').reduce((s, t) => s + t.amount, 0);
    const sentTVM = vaultData.transactions.filter(tx => tx.type === 'sent').reduce((s, t) => s + t.amount, 0);
    const bonusTVM = vaultData.transactions.filter(tx => tx.type === 'cashback').reduce((s, t) => s + t.amount, 0);
    vaultData.balanceTVM = vaultData.initialBalanceTVM + receivedTVM + bonusTVM - sentTVM;
    vaultData.balanceUSD = parseFloat((vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2));

    populateWalletUI();
    await promptAndSaveVault();

    alert(`✅ Sent ${amount} TVM. Bonus: ${bonusGranted ? '120 TVM' : 'None'}`);
    showBioCatchPopup(obfuscatedCatch);

    document.getElementById('receiverBioIBAN').value = '';
    document.getElementById('catchOutAmount').value = '';
    renderTransactionTable();
  } catch (err) {
    console.error('Send Transaction Error:', err);
    alert('❌ An error occurred processing the transaction.');
  } finally {
    transactionLock = false;
  }
}

async function handleReceiveTransaction() {
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
  if (!encryptedBioCatchInput || isNaN(amount) || amount <= 0) {
    alert('❌ Invalid BioCatch number or amount.');
    return;
  }
  transactionLock = true;
  try {
    const bioCatchNumber = await decryptBioCatchNumber(encryptedBioCatchInput);
    if (!bioCatchNumber) {
      alert('❌ Unable to decode BioCatch number.');
      transactionLock = false;
      return;
    }
    for (let tx of vaultData.transactions) {
      if (tx.bioCatch) {
        const existingPlain = await decryptBioCatchNumber(tx.bioCatch);
        if (existingPlain === bioCatchNumber) {
          alert('❌ This BioCatch number has already been used.');
          transactionLock = false;
          return;
        }
      }
    }
    const validation = await validateBioCatchNumber(bioCatchNumber, amount);
    if (!validation.valid) {
      alert(`❌ BioCatch Validation Failed: ${validation.message}`);
      transactionLock = false;
      return;
    }
    const { chainHash, claimedSenderIBAN, senderVaultSnapshot } = validation;
    const snapshotValidation = await validateSenderVaultSnapshot(senderVaultSnapshot, claimedSenderIBAN);
    if (!snapshotValidation.valid) {
      alert("❌ Sender snapshot integrity check failed: " + snapshotValidation.errors.join("; "));
      transactionLock = false;
      return;
    }
    const nowSec = vaultData.lastUTCTimestamp;
    vaultData.transactions.push({
      type: 'received',
      senderBioIBAN: claimedSenderIBAN,
      bioCatch: encryptedBioCatchInput,
      amount,
      timestamp: nowSec,
      status: 'Valid',
      bioConstantAtGeneration: vaultData.bioConstant
    });
    await promptAndSaveVault();

    const receivedTVM = vaultData.transactions.filter(tx => tx.type === 'received').reduce((s, t) => s + t.amount, 0);
    const sentTVM = vaultData.transactions.filter(tx => tx.type === 'sent').reduce((s, t) => s + t.amount, 0);
    const bonusTVM = vaultData.transactions.filter(tx => tx.type === 'cashback').reduce((s, t) => s + t.amount, 0);
    vaultData.balanceTVM = vaultData.initialBalanceTVM + receivedTVM + bonusTVM - sentTVM;
    vaultData.balanceUSD = parseFloat((vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2));

    populateWalletUI();
    alert(`✅ Transaction received successfully! +${amount} TVM.`);

    document.getElementById('catchInBioCatch').value = '';
    document.getElementById('catchInAmount').value = '';
    renderTransactionTable();
  } catch (error) {
    console.error('Receive Transaction Error:', error);
    alert('❌ An error occurred processing the transaction.');
  } finally {
    transactionLock = false;
  }
}

/******************************
 * Validation & Snapshot Functions
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
  const receivedTVM = senderSnapshot.transactions.filter(tx => tx.type === 'received').reduce((s, tx) => s + tx.amount, 0);
  const sentTVM = senderSnapshot.transactions.filter(tx => tx.type === 'sent').reduce((s, tx) => s + tx.amount, 0);
  const bonusTVM = senderSnapshot.transactions.filter(tx => tx.type === 'cashback').reduce((s, tx) => s + tx.amount, 0);
  const computedBalance = senderSnapshot.initialBalanceTVM + receivedTVM + bonusTVM - sentTVM;
  if (computedBalance !== senderSnapshot.balanceTVM) {
    errors.push(`Balance mismatch: computed ${computedBalance} vs stored ${senderSnapshot.balanceTVM}`);
  }
  const computedSenderIBAN = `BIO${senderSnapshot.initialBioConstant + senderSnapshot.joinTimestamp}`;
  if (claimedSenderIBAN !== computedSenderIBAN) {
    errors.push(`Sender Bio‑IBAN mismatch: computed ${computedSenderIBAN} vs claimed ${claimedSenderIBAN}`);
  }
  return { valid: errors.length === 0, errors };
}

function serializeVaultSnapshotForBioCatch(vData) {
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
      tx.bioConstantAtGeneration || 0,
      tx.previousHash || '',
      tx.txHash || ''
    ].join(txFieldSep);
  });
  const txString = txParts.join(txSep);
  const rawString = [
    vData.joinTimestamp || 0,
    vData.initialBioConstant || 0,
    vData.finalChainHash || '',
    vData.initialBalanceTVM || 0,
    vData.balanceTVM || 0,
    vData.bioConstant || 0,
    vData.lastUTCTimestamp || 0,
    txString
  ].join(fieldSep);
  return btoa(rawString);
}

async function generateBioCatchNumber(senderBioIBAN, receiverBioIBAN, amount, timestamp, senderBalance, finalChainHash) {
  const encodedVault = serializeVaultSnapshotForBioCatch(vaultData);
  const senderNumeric = parseInt(senderBioIBAN.slice(3));
  const receiverNumeric = parseInt(receiverBioIBAN.slice(3));
  const firstPart = senderNumeric + receiverNumeric;
  return `Bio-${firstPart}-${timestamp}-${amount}-${senderBalance}-${senderBioIBAN}-${finalChainHash}-${encodedVault}`;
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
 * UI Rendering & Event Handlers
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
      }
      let styleCell = '';
      if (tx.type === 'sent') {
        styleCell = 'style="background-color: #FFCCCC;"';
      } else if (tx.type === 'received') {
        styleCell = 'style="background-color: #CCFFCC;"';
      } else if (tx.type === 'cashback') {
        styleCell = 'style="background-color: #CCFFFF;"';
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
 * Time & UI Sync Helpers
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

/******************************
 * Passphrase Modal & Vault Creation/Unlock
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

async function checkAndUnlockVault() {
  const stored = await loadVaultDataFromDB();
  if (!stored) {
    if (!confirm('⚠️ No vault found. Create a new vault?')) return;
    const { pin } = await getPassphraseFromModal({ confirmNeeded: true, modalTitle: 'Create New Vault (Set Passphrase)' });
    await createNewVault(pin);
  } else {
    await unlockVault();
  }
}

async function createNewVault(pinFromUser = null) {
  if (!pinFromUser) {
    const result = await getPassphraseFromModal({ confirmNeeded: true, modalTitle: 'Create New Vault (Set Passphrase)' });
    pinFromUser = result.pin;
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
  vaultData.bioIBAN = `BIO${vaultData.initialBioConstant + nowSec}`;
  // Also set bonusConstant and lastBonusIncrement:
  vaultData.bonusConstant = vaultData.bioConstant;
  vaultData.lastBonusIncrement = vaultData.bonusConstant;
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
    return;
  }
  vaultData.credentialId = bufferToBase64(credential.rawId);
  console.log('🆕 Creating new vault:', vaultData);
  const salt = generateSalt();
  derivedKey = await deriveKeyFromPIN(pinFromUser, salt);
  await promptAndSaveVault();
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
    await handleFailedAuthAttempt();
    return;
  }
  if (pin.length < 8) {
    alert('⚠️ Please use a stronger passphrase (>=8 chars).');
    await handleFailedAuthAttempt();
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
        await handleFailedAuthAttempt();
        return;
      }
    } else {
      console.log("🔶 No credentialId found, skipping WebAuthn check.");
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
    console.error(err);
    await handleFailedAuthAttempt();
  }
}

/******************************
 * Failed Auth & Lockout
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
 * Multi‑Tab & Storage Persistence
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
 * On DOM Load & UI Initialization
 ******************************/
function loadVaultOnStartup() {
  // Optional auto‑unlock logic can be placed here if desired.
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

function initializeUI() {
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
