// Helper: Convert ArrayBuffer to Hex String
function bufToHex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

// Helper: Convert Hex String to ArrayBuffer
function hexToBuf(hexString) {
    if (hexString.length % 2 !== 0) {
        throw new Error("Invalid hex string");
    }
    const bytes = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
        bytes[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
    }
    return bytes.buffer;
}

// Helper: Format Bytes to Human Readable Size
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// ----------------------------------------------------
// Cryptography Functions
// ----------------------------------------------------

// Generate a random 256-bit AES-GCM key
async function generateRandomKey() {
    return await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Derive a 256-bit AES key from a password and salt using PBKDF2
async function deriveKeyFromPassword(password, saltBytes) {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    
    const baseKey = await window.crypto.subtle.importKey(
        "raw",
        passwordBytes,
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    
    return await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: 100000,
            hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Encrypt metadata object
async function encryptMetadata(metadataObj, key, salt = null) {
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(JSON.stringify(metadataObj));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        dataBytes
    );
    
    // Structure: [Salt (if exists)] + [IV (12 bytes)] + [Ciphertext]
    let resultBytes;
    if (salt) {
        resultBytes = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
        resultBytes.set(salt, 0);
        resultBytes.set(iv, salt.length);
        resultBytes.set(new Uint8Array(ciphertext), salt.length + iv.length);
    } else {
        resultBytes = new Uint8Array(iv.length + ciphertext.byteLength);
        resultBytes.set(iv, 0);
        resultBytes.set(new Uint8Array(ciphertext), iv.length);
    }
    
    return bufToHex(resultBytes.buffer);
}

// Decrypt metadata string
async function decryptMetadata(encryptedHex, key, hasSalt = false) {
    const encryptedBytes = new Uint8Array(hexToBuf(encryptedHex));
    let iv, ciphertext;
    
    if (hasSalt) {
        // Skip first 16 bytes (salt)
        iv = encryptedBytes.slice(16, 16 + 12);
        ciphertext = encryptedBytes.slice(16 + 12);
    } else {
        iv = encryptedBytes.slice(0, 12);
        ciphertext = encryptedBytes.slice(12);
    }
    
    const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        ciphertext
    );
    
    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decrypted));
}

// Encrypt file ArrayBuffer
async function encryptFile(arrayBuffer, key) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        arrayBuffer
    );
    
    // Concat IV + Ciphertext
    const resultBytes = new Uint8Array(iv.length + ciphertext.byteLength);
    resultBytes.set(iv, 0);
    resultBytes.set(new Uint8Array(ciphertext), iv.length);
    
    return resultBytes;
}

// Decrypt file ArrayBuffer
async function decryptFile(encryptedBytes, key) {
    const iv = encryptedBytes.slice(0, 12);
    const ciphertext = encryptedBytes.slice(12);
    
    return await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        ciphertext
    );
}

// ----------------------------------------------------
// UI Logic & Routing
// ----------------------------------------------------

let selectedFile = null;

// DOM Elements
const uploadView = document.getElementById('upload-view');
const downloadView = document.getElementById('download-view');

// Upload Elements
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const dropZonePrompt = document.getElementById('drop-zone-prompt');
const dropZoneFileInfo = document.getElementById('drop-zone-file-info');
const selectedFileName = document.getElementById('selected-file-name');
const selectedFileSize = document.getElementById('selected-file-size');
const removeFileBtn = document.getElementById('remove-file-btn');
const expirySelect = document.getElementById('expiry-select');
const selfDestructChk = document.getElementById('self-destruct-chk');
const passwordToggleChk = document.getElementById('password-toggle-chk');
const passwordInputWrapper = document.getElementById('password-input-wrapper');
const uploadPassword = document.getElementById('upload-password');
const toggleUploadPw = document.getElementById('toggle-upload-pw');
const uploadActionBtn = document.getElementById('upload-action-btn');
const optionsContainer = document.getElementById('options-container');

// Progress & Results (Upload)
const uploadProgressContainer = document.getElementById('upload-progress-container');
const uploadProgressBar = document.getElementById('upload-progress-bar');
const progressStatusLbl = document.getElementById('progress-status-lbl');
const progressPctLbl = document.getElementById('progress-pct-lbl');
const stepKeygen = document.getElementById('step-keygen');
const stepEncrypt = document.getElementById('step-encrypt');
const stepUpload = document.getElementById('step-upload');
const uploadResultContainer = document.getElementById('upload-result-container');
const shareUrlInput = document.getElementById('share-url');
const copyShareUrlBtn = document.getElementById('copy-share-url-btn');
const uploadAnotherBtn = document.getElementById('upload-another-btn');

// Download Elements
const downloadLoadingStatus = document.getElementById('download-loading-status');
const downloadErrorStatus = document.getElementById('download-error-status');
const errorTitle = document.getElementById('error-title');
const errorDesc = document.getElementById('error-desc');
const downloadReadyContainer = document.getElementById('download-ready-container');
const downloadFileName = document.getElementById('download-file-name');
const downloadFileSize = document.getElementById('download-file-size');
const downloadFileExpiry = document.getElementById('download-file-expiry');
const downloadSelfDestructWarning = document.getElementById('download-self-destruct-warning');
const downloadPasswordPrompt = document.getElementById('download-password-prompt');
const downloadPassword = document.getElementById('download-password');
const toggleDownloadPw = document.getElementById('toggle-download-pw');
const decryptDownloadBtn = document.getElementById('decrypt-download-btn');
const downloadProgressContainer = document.getElementById('download-progress-container');
const downloadProgressBar = document.getElementById('download-progress-bar');
const downloadProgressStatus = document.getElementById('download-progress-status');
const downloadProgressPct = document.getElementById('download-progress-pct');
const downloadStepFetch = document.getElementById('download-step-fetch');
const downloadStepDecrypt = document.getElementById('download-step-decrypt');
const downloadStepSave = document.getElementById('download-step-save');
const downloadSuccessContainer = document.getElementById('download-success-container');
const downloadFileIcon = document.getElementById('download-file-icon');

// Router Setup
function route() {
    const hash = window.location.hash;
    if (hash.startsWith('#/download')) {
        uploadView.classList.remove('active');
        downloadView.classList.add('active');
        initiateDownloadView();
    } else {
        downloadView.classList.remove('active');
        uploadView.classList.add('active');
        resetUploadForm();
    }
}

window.addEventListener('hashchange', route);
window.addEventListener('DOMContentLoaded', route);

// ----------------------------------------------------
// Upload View Handlers
// ----------------------------------------------------

// Password Toggle visibility slider
passwordToggleChk.addEventListener('change', () => {
    if (passwordToggleChk.checked) {
        passwordInputWrapper.classList.remove('hidden');
        uploadPassword.focus();
    } else {
        passwordInputWrapper.classList.add('hidden');
        uploadPassword.value = '';
    }
});

// Toggle password visibility
toggleUploadPw.addEventListener('click', () => {
    const type = uploadPassword.getAttribute('type') === 'password' ? 'text' : 'password';
    uploadPassword.setAttribute('type', type);
    toggleUploadPw.classList.toggle('fa-eye');
    toggleUploadPw.classList.toggle('fa-eye-slash');
});

toggleDownloadPw.addEventListener('click', () => {
    const type = downloadPassword.getAttribute('type') === 'password' ? 'text' : 'password';
    downloadPassword.setAttribute('type', type);
    toggleDownloadPw.classList.toggle('fa-eye');
    toggleDownloadPw.classList.toggle('fa-eye-slash');
});

// Drag & Drop event bindings
dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
        handleFileSelect(e.dataTransfer.files[0]);
    }
});

fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
        handleFileSelect(fileInput.files[0]);
    }
});

function handleFileSelect(file) {
    if (file.size > 100 * 1024 * 1024) {
        alert("Maximum file size allowed is 100MB!");
        return;
    }
    selectedFile = file;
    selectedFileName.textContent = file.name;
    selectedFileSize.textContent = formatBytes(file.size);
    
    dropZonePrompt.classList.add('hidden');
    dropZoneFileInfo.classList.remove('hidden');
    
    uploadActionBtn.removeAttribute('disabled');
    uploadActionBtn.innerHTML = '<i class="fa-solid fa-lock"></i> Encrypt & Share File';
}

removeFileBtn.addEventListener('click', (e) => {
    e.stopPropagation(); // prevent triggering click event on dropZone parent
    resetUploadForm();
});

function resetUploadForm() {
    selectedFile = null;
    fileInput.value = '';
    dropZonePrompt.classList.remove('hidden');
    dropZoneFileInfo.classList.add('hidden');
    uploadActionBtn.setAttribute('disabled', 'true');
    uploadActionBtn.innerHTML = '<i class="fa-solid fa-lock-open"></i> Select a file to encrypt';
    
    passwordToggleChk.checked = false;
    passwordInputWrapper.classList.add('hidden');
    uploadPassword.value = '';
    
    optionsContainer.classList.remove('hidden');
    dropZone.classList.remove('hidden');
    uploadProgressContainer.classList.add('hidden');
    uploadResultContainer.classList.add('hidden');
}

// Reset view on "Share Another File"
uploadAnotherBtn.addEventListener('click', () => {
    window.location.hash = '';
    resetUploadForm();
});

// Copy Share URL to clipboard
copyShareUrlBtn.addEventListener('click', () => {
    shareUrlInput.select();
    shareUrlInput.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(shareUrlInput.value)
        .then(() => {
            copyShareUrlBtn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
            setTimeout(() => {
                copyShareUrlBtn.innerHTML = '<i class="fa-regular fa-copy"></i> Copy';
            }, 2000);
        })
        .catch(err => {
            console.error("Clipboard copy failed:", err);
        });
});

// Upload trigger action
uploadActionBtn.addEventListener('click', async () => {
    if (!selectedFile) return;
    
    const isPasswordProtected = passwordToggleChk.checked;
    const password = uploadPassword.value.trim();
    
    if (isPasswordProtected && !password) {
        alert("Please enter a decryption password!");
        uploadPassword.focus();
        return;
    }
    
    // UI adjustment to show progress
    optionsContainer.classList.add('hidden');
    dropZone.classList.add('hidden');
    uploadProgressContainer.classList.remove('hidden');
    
    // Set step indicators to default
    stepKeygen.className = 'step-indicator active';
    stepEncrypt.className = 'step-indicator';
    stepUpload.className = 'step-indicator';
    uploadProgressBar.style.width = '0%';
    progressPctLbl.textContent = '0%';
    
    try {
        progressStatusLbl.textContent = 'Generating cryptographic credentials...';
        
        let encryptionKey;
        let salt = null;
        let saltHex = '';
        
        if (isPasswordProtected) {
            // Step 1: Derive key from password using a random salt
            salt = window.crypto.getRandomValues(new Uint8Array(16));
            saltHex = bufToHex(salt.buffer);
            encryptionKey = await deriveKeyFromPassword(password, salt);
        } else {
            // Step 1: Generate completely random AES key
            encryptionKey = await generateRandomKey();
        }
        
        stepKeygen.className = 'step-indicator completed';
        stepEncrypt.className = 'step-indicator active';
        progressStatusLbl.textContent = 'Encrypting file payload locally...';
        uploadProgressBar.style.width = '20%';
        progressPctLbl.textContent = '20%';
        
        // Read file contents as ArrayBuffer
        const fileReader = new FileReader();
        
        fileReader.onload = async (e) => {
            try {
                const arrayBuffer = e.target.result;
                
                // Encrypt payload
                const encryptedPayloadBytes = await encryptFile(arrayBuffer, encryptionKey);
                
                uploadProgressBar.style.width = '50%';
                progressPctLbl.textContent = '50%';
                progressStatusLbl.textContent = 'Encrypting file metadata...';
                
                // Create unencrypted metadata object
                const metadata = {
                    name: selectedFile.name,
                    size: selectedFile.size,
                    type: selectedFile.type
                };
                
                // Encrypt metadata. If password protected, prepend the salt to metadata hex string
                const encryptedMetadataStr = await encryptMetadata(metadata, encryptionKey, salt);
                
                stepEncrypt.className = 'step-indicator completed';
                stepUpload.className = 'step-indicator active';
                progressStatusLbl.textContent = 'Uploading encrypted package to server...';
                
                // Package data as FormData
                const formData = new FormData();
                const encryptedBlob = new Blob([encryptedPayloadBytes], { type: 'application/octet-stream' });
                formData.append('file', encryptedBlob, 'payload.enc');
                formData.append('metadata', encryptedMetadataStr);
                formData.append('expiry', expirySelect.value);
                formData.append('self_destruct', selfDestructChk.checked);
                
                // Perform upload with progress tracking using XMLHttpRequest
                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/api/upload', true);
                
                xhr.upload.onprogress = (event) => {
                    if (event.lengthComputable) {
                        const percentComplete = 50 + Math.floor((event.loaded / event.total) * 45); // Map to remaining 50% - 95%
                        uploadProgressBar.style.width = percentComplete + '%';
                        progressPctLbl.textContent = percentComplete + '%';
                    }
                };
                
                xhr.onload = async () => {
                    if (xhr.status === 200) {
                        const response = JSON.parse(xhr.responseText);
                        const fileId = response.fileId;
                        
                        uploadProgressBar.style.width = '100%';
                        progressPctLbl.textContent = '100%';
                        stepUpload.className = 'step-indicator completed';
                        progressStatusLbl.textContent = 'Finished!';
                        
                        // Generate sharing link
                        let shareLink = `${window.location.origin}/#/download?id=${fileId}`;
                        if (!isPasswordProtected) {
                            // Export raw key to append in hash
                            const rawKey = await window.crypto.subtle.exportKey('raw', encryptionKey);
                            const hexKey = bufToHex(rawKey);
                            shareLink += `&key=${hexKey}`;
                        }
                        
                        shareUrlInput.value = shareLink;
                        
                        setTimeout(() => {
                            uploadProgressContainer.classList.add('hidden');
                            uploadResultContainer.classList.remove('hidden');
                        }, 600);
                    } else {
                        throw new Error(xhr.responseText || "Upload failed");
                    }
                };
                
                xhr.onerror = () => {
                    throw new Error("Network error during upload.");
                };
                
                xhr.send(formData);
                
            } catch (err) {
                alert("Encryption / Upload failed: " + err.message);
                resetUploadForm();
            }
        };
        
        fileReader.readAsArrayBuffer(selectedFile);
        
    } catch (err) {
        alert("Key derivation failed: " + err.message);
        resetUploadForm();
    }
});

// ----------------------------------------------------
// Download View Handlers
// ----------------------------------------------------

let currentMetaData = null;
let currentFileId = null;
let currentHexKey = null;

async function initiateDownloadView() {
    // Hide containers
    downloadLoadingStatus.classList.remove('hidden');
    downloadErrorStatus.classList.add('hidden');
    downloadReadyContainer.classList.add('hidden');
    downloadProgressContainer.classList.add('hidden');
    downloadSuccessContainer.classList.add('hidden');
    
    // Parse URL parameters
    const hash = window.location.hash;
    const urlParams = new URLSearchParams(hash.substring(hash.indexOf('?')));
    currentFileId = urlParams.get('id');
    currentHexKey = urlParams.get('key');
    
    if (!currentFileId) {
        showDownloadError("Invalid Link", "The link is missing the file ID parameter.");
        return;
    }
    
    try {
        // Fetch metadata from server
        const res = await fetch(`/api/metadata/${currentFileId}`);
        if (!res.ok) {
            throw new Error("File not found, expired, or deleted.");
        }
        
        currentMetaData = await res.json();
        
        // Show self-destruct warning if configured
        if (currentMetaData.self_destruct) {
            downloadSelfDestructWarning.classList.remove('hidden');
        } else {
            downloadSelfDestructWarning.classList.add('hidden');
        }
        
        // Set expiry label
        const remainingSecs = Math.max(0, Math.floor((currentMetaData.upload_time + currentMetaData.expiry) - (Date.now() / 1000)));
        if (currentMetaData.expiry === 0) {
            downloadFileExpiry.textContent = "Never";
        } else if (remainingSecs > 3600) {
            downloadFileExpiry.textContent = `In ${Math.ceil(remainingSecs / 3600)} Hours`;
        } else if (remainingSecs > 60) {
            downloadFileExpiry.textContent = `In ${Math.ceil(remainingSecs / 60)} Minutes`;
        } else {
            downloadFileExpiry.textContent = `In ${remainingSecs} Seconds`;
        }
        
        if (currentHexKey) {
            // Standard E2EE sharing link. We can decrypt metadata instantly.
            downloadPasswordPrompt.classList.add('hidden');
            
            try {
                const keyBuffer = hexToBuf(currentHexKey);
                const key = await window.crypto.subtle.importKey(
                    "raw",
                    keyBuffer,
                    "AES-GCM",
                    true,
                    ["encrypt", "decrypt"]
                );
                
                const decMeta = await decryptMetadata(currentMetaData.metadata_enc, key, false);
                
                // Load details to UI
                downloadFileName.textContent = decMeta.name;
                downloadFileSize.textContent = formatBytes(decMeta.size);
                updateFileIcon(decMeta.type);
                
                // Show ready screen
                downloadLoadingStatus.classList.add('hidden');
                downloadReadyContainer.classList.remove('hidden');
                
            } catch (err) {
                console.error(err);
                showDownloadError("Decryption Failed", "The decryption key in the link is invalid or corrupt.");
            }
        } else {
            // Password Protected Share
            downloadPasswordPrompt.classList.remove('hidden');
            downloadPassword.value = '';
            
            // Set generic placeholder info until password unlocks it
            downloadFileName.textContent = "Locked File";
            downloadFileSize.textContent = formatBytes(currentMetaData.size);
            downloadFileIcon.className = "fa-solid fa-file-shield fa-3x";
            
            downloadLoadingStatus.classList.add('hidden');
            downloadReadyContainer.classList.remove('hidden');
        }
        
    } catch (err) {
        showDownloadError("File Unavailable", err.message);
    }
}

// Adjust icons according to MIME type
function updateFileIcon(mimeType) {
    let iconClass = "fa-solid fa-file-lines fa-3x";
    if (mimeType.startsWith('image/')) {
        iconClass = "fa-solid fa-file-image fa-3x";
    } else if (mimeType.startsWith('video/')) {
        iconClass = "fa-solid fa-file-video fa-3x";
    } else if (mimeType.startsWith('audio/')) {
        iconClass = "fa-solid fa-file-audio fa-3x";
    } else if (mimeType.includes('pdf')) {
        iconClass = "fa-solid fa-file-pdf fa-3x";
    } else if (mimeType.includes('zip') || mimeType.includes('rar') || mimeType.includes('tar') || mimeType.includes('gz')) {
        iconClass = "fa-solid fa-file-zipper fa-3x";
    } else if (mimeType.includes('word') || mimeType.includes('document')) {
        iconClass = "fa-solid fa-file-word fa-3x";
    } else if (mimeType.includes('excel') || mimeType.includes('sheet')) {
        iconClass = "fa-solid fa-file-excel fa-3x";
    }
    downloadFileIcon.className = iconClass;
}

function showDownloadError(title, description) {
    downloadLoadingStatus.classList.add('hidden');
    downloadReadyContainer.classList.add('hidden');
    downloadProgressContainer.classList.add('hidden');
    downloadSuccessContainer.classList.add('hidden');
    
    errorTitle.textContent = title;
    errorDesc.textContent = description;
    downloadErrorStatus.classList.remove('hidden');
}

// Decrypt and Download trigger
decryptDownloadBtn.addEventListener('click', async () => {
    let key;
    let isPasswordProtected = !currentHexKey;
    
    if (isPasswordProtected) {
        const password = downloadPassword.value.trim();
        if (!password) {
            alert("Please enter the decryption password!");
            downloadPassword.focus();
            return;
        }
        
        try {
            // Extract the 16-byte salt from the first 32 characters of metadata_enc
            const metaEnc = currentMetaData.metadata_enc;
            if (metaEnc.length < 32) throw new Error("Metadata payload is corrupt.");
            
            const saltHex = metaEnc.substring(0, 32);
            const saltBytes = new Uint8Array(hexToBuf(saltHex));
            
            // Derive key
            key = await deriveKeyFromPassword(password, saltBytes);
            
            // Validate password by attempting metadata decryption
            const decMeta = await decryptMetadata(metaEnc, key, true);
            
            // If we successfully decrypted metadata, update card details and keep going
            downloadFileName.textContent = decMeta.name;
            downloadFileSize.textContent = formatBytes(decMeta.size);
            updateFileIcon(decMeta.type);
            
        } catch (err) {
            alert("Incorrect password! Decryption failed.");
            downloadPassword.focus();
            return;
        }
    } else {
        // Standard link: derive key from URL key parameter
        const keyBuffer = hexToBuf(currentHexKey);
        key = await window.crypto.subtle.importKey(
            "raw",
            keyBuffer,
            "AES-GCM",
            true,
            ["encrypt", "decrypt"]
        );
    }
    
    // Hide card view, show progress view
    downloadReadyContainer.classList.add('hidden');
    downloadProgressContainer.classList.remove('hidden');
    
    downloadProgressBar.style.width = '0%';
    downloadProgressPct.textContent = '0%';
    downloadStepFetch.className = 'step-indicator active';
    downloadStepDecrypt.className = 'step-indicator';
    downloadStepSave.className = 'step-indicator';
    downloadProgressStatus.textContent = 'Downloading encrypted payload...';
    
    try {
        // Fetch encrypted payload using XMLHttpRequest to track download progress
        const xhr = new XMLHttpRequest();
        xhr.open('GET', `/api/download/${currentFileId}`, true);
        xhr.responseType = 'arraybuffer';
        
        xhr.onprogress = (event) => {
            if (event.lengthComputable) {
                const percent = Math.floor((event.loaded / event.total) * 75); // Map to 0% - 75%
                downloadProgressBar.style.width = percent + '%';
                downloadProgressPct.textContent = percent + '%';
            }
        };
        
        xhr.onload = async () => {
            if (xhr.status === 200) {
                try {
                    downloadProgressBar.style.width = '80%';
                    downloadProgressPct.textContent = '80%';
                    downloadStepFetch.className = 'step-indicator completed';
                    downloadStepDecrypt.className = 'step-indicator active';
                    downloadProgressStatus.textContent = 'Decrypting file payload locally...';
                    
                    const encryptedPayloadBytes = new Uint8Array(xhr.response);
                    
                    // Decrypt the file arraybuffer
                    const decryptedBuffer = await decryptFile(encryptedPayloadBytes, key);
                    
                    downloadProgressBar.style.width = '95%';
                    downloadProgressPct.textContent = '95%';
                    downloadStepDecrypt.className = 'step-indicator completed';
                    downloadStepSave.className = 'step-indicator active';
                    downloadProgressStatus.textContent = 'Rebuilding original file...';
                    
                    // Decrypt the metadata again to ensure we have the correct original name and type
                    // (For password protected, key is already valid)
                    const decMeta = await decryptMetadata(currentMetaData.metadata_enc, key, isPasswordProtected);
                    
                    // Create blob and trigger download
                    const decryptedBlob = new Blob([decryptedBuffer], { type: decMeta.type || 'application/octet-stream' });
                    const downloadUrl = URL.createObjectURL(decryptedBlob);
                    
                    const downloadLink = document.createElement('a');
                    downloadLink.href = downloadUrl;
                    downloadLink.download = decMeta.name;
                    document.body.appendChild(downloadLink);
                    downloadLink.click();
                    document.body.removeChild(downloadLink);
                    URL.revokeObjectURL(downloadUrl);
                    
                    downloadProgressBar.style.width = '100%';
                    downloadProgressPct.textContent = '100%';
                    downloadStepSave.className = 'step-indicator completed';
                    downloadProgressStatus.textContent = 'Finished!';
                    
                    setTimeout(() => {
                        downloadProgressContainer.classList.add('hidden');
                        downloadSuccessContainer.classList.remove('hidden');
                    }, 600);
                    
                } catch (err) {
                    console.error("Payload decryption error:", err);
                    showDownloadError("Decryption Failed", "An error occurred while decrypting the payload. The file may be corrupt.");
                }
            } else {
                showDownloadError("Download Failed", "Server returned an error status while downloading.");
            }
        };
        
        xhr.onerror = () => {
            showDownloadError("Network Error", "A network error occurred while downloading the file.");
        };
        
        xhr.send();
        
    } catch (err) {
        showDownloadError("Download Error", err.message);
    }
});
