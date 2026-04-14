/**
 * JWT Decoder - Professional Frontend JavaScript
 * Handles JWT token decoding with client-side processing
 */

document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const tokenInput = document.getElementById('tokenInput');
    const decodeBtn = document.getElementById('decodeBtn');
    const pasteBtn = document.getElementById('pasteBtn');
    const clearBtn = document.getElementById('clearBtn');
    const copyClaimsBtn = document.getElementById('copyClaimsBtn');
    const resultsContainer = document.getElementById('resultsContainer');
    const errorMessage = document.getElementById('errorMessage');
    
    // Result display elements
    const statusCard = document.getElementById('statusCard');
    const statusIndicator = document.getElementById('statusIndicator');
    const statusTitle = document.getElementById('statusTitle');
    const statusDescription = document.getElementById('statusDescription');
    const headerContent = document.getElementById('headerContent').querySelector('code');
    const payloadContent = document.getElementById('payloadContent').querySelector('code');
    const signatureContent = document.getElementById('signatureContent').querySelector('code');
    const jsonDisplay = document.getElementById('jsonDisplay').querySelector('code');
    const algorithmValue = document.getElementById('algorithmValue');
    const expiresValue = document.getElementById('expiresValue');
    const expiryCountdown = document.getElementById('expiryCountdown');
    const tokenStatus = document.getElementById('tokenStatus');
    const errorDescription = document.getElementById('errorDescription');
    
    let countdownInterval = null;
    
    /**
     * Base64URL decode function
     */
    function base64UrlDecode(str) {
        // Replace non-url compatible chars
        let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        
        // Pad with '=' if needed
        while (base64.length % 4) {
            base64 += '=';
        }
        
        try {
            // Decode and handle unicode characters
            return decodeURIComponent(atob(base64).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
        } catch (e) {
            throw new Error('Invalid Base64URL encoding');
        }
    }
    
    /**
     * Parse JWT token into its components
     */
    function parseJWT(token) {
        const parts = token.trim().split('.');
        
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format: must have 3 parts separated by dots');
        }
        
        const [headerB64, payloadB64, signature] = parts;
        
        if (!headerB64 || !payloadB64) {
            throw new Error('Invalid JWT: header or payload is empty');
        }
        
        try {
            const header = JSON.parse(base64UrlDecode(headerB64));
            const payload = JSON.parse(base64UrlDecode(payloadB64));
            
            return {
                header,
                payload,
                signature,
                headerB64,
                payloadB64
            };
        } catch (e) {
            throw new Error('Invalid JWT: ' + e.message);
        }
    }
    
    /**
     * Format date for display
     */
    function formatDate(timestamp) {
        const date = new Date(timestamp * 1000);
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            timeZoneName: 'short'
        });
    }
    
    /**
     * Calculate time until expiry
     */
    function getTimeUntilExpiry(expTimestamp) {
        const now = Math.floor(Date.now() / 1000);
        const diff = expTimestamp - now;
        
        if (diff <= 0) {
            return 'Expired';
        }
        
        const days = Math.floor(diff / (24 * 60 * 60));
        const hours = Math.floor((diff % (24 * 60 * 60)) / (60 * 60));
        const minutes = Math.floor((diff % (60 * 60)) / 60);
        const seconds = diff % 60;
        
        if (days > 0) {
            return `${days}d ${hours}h ${minutes}m`;
        } else if (hours > 0) {
            return `${hours}h ${minutes}m ${seconds}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${seconds}s`;
        } else {
            return `${seconds}s`;
        }
    }
    
    /**
     * Update expiry countdown timer
     */
    function updateCountdown(expTimestamp) {
        if (countdownInterval) {
            clearInterval(countdownInterval);
        }
        
        function update() {
            const countdown = getTimeUntilExpiry(expTimestamp);
            expiryCountdown.textContent = countdown;
            
            if (countdown === 'Expired') {
                clearInterval(countdownInterval);
                updateTokenStatus(false);
            }
        }
        
        update();
        countdownInterval = setInterval(update, 1000);
    }
    
    /**
     * Syntax highlight JSON
     */
    function syntaxHighlightJSON(json) {
        if (typeof json !== 'string') {
            json = JSON.stringify(json, undefined, 2);
        }
        
        // Escape HTML characters
        json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        
        return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            let cls = 'json-number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'json-key';
                } else {
                    cls = 'json-string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'json-boolean';
            } else if (/null/.test(match)) {
                cls = 'json-null';
            }
            return '<span class="' + cls + '">' + match + '</span>';
        });
    }
    
    /**
     * Update token status display
     */
    function updateTokenStatus(isValid) {
        statusCard.className = 'status-card ' + (isValid ? 'valid' : 'expired');
        tokenStatus.className = 'info-value status-badge ' + (isValid ? 'valid' : 'expired');
        
        if (isValid) {
            statusTitle.textContent = 'Token Valid';
            statusDescription.textContent = 'This token is valid and has not expired';
            tokenStatus.textContent = 'Active';
        } else {
            statusTitle.textContent = 'Token Expired';
            statusDescription.textContent = 'This token has expired and is no longer valid';
            tokenStatus.textContent = 'Expired';
        }
    }
    
    /**
     * Display decoded JWT results
     */
    function displayResults(jwtData) {
        const { header, payload, signature, headerB64, payloadB64 } = jwtData;
        
        // Show results container
        resultsContainer.style.display = 'flex';
        errorMessage.style.display = 'none';
        
        // Display token parts
        headerContent.textContent = JSON.stringify(header, null, 2);
        payloadContent.textContent = JSON.stringify(payload, null, 2);
        signatureContent.textContent = signature.substring(0, 50) + (signature.length > 50 ? '...' : '');
        
        // Display full JSON with syntax highlighting
        jsonDisplay.innerHTML = syntaxHighlightJSON(JSON.stringify(payload, null, 2));
        
        // Display algorithm
        algorithmValue.textContent = header.alg || 'N/A';
        
        // Check expiration
        const expTimestamp = payload.exp;
        const now = Math.floor(Date.now() / 1000);
        const isValid = !expTimestamp || expTimestamp > now;
        
        // Update status
        updateTokenStatus(isValid);
        
        // Display expiration info
        if (expTimestamp) {
            expiresValue.textContent = formatDate(expTimestamp);
            updateCountdown(expTimestamp);
        } else {
            expiresValue.textContent = 'No expiration';
            expiryCountdown.textContent = 'N/A';
        }
        
        // Scroll to results
        resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    
    /**
     * Display error message
     */
    function displayError(message) {
        resultsContainer.style.display = 'none';
        errorMessage.style.display = 'block';
        errorDescription.textContent = message;
        
        if (countdownInterval) {
            clearInterval(countdownInterval);
            countdownInterval = null;
        }
    }
    
    /**
     * Hide all messages
     */
    function hideMessages() {
        resultsContainer.style.display = 'none';
        errorMessage.style.display = 'none';
        
        if (countdownInterval) {
            clearInterval(countdownInterval);
            countdownInterval = null;
        }
    }
    
    /**
     * Decode JWT token
     */
    function decodeToken() {
        const token = tokenInput.value.trim();
        
        if (!token) {
            displayError('Please enter a JWT token');
            return;
        }
        
        try {
            const jwtData = parseJWT(token);
            displayResults(jwtData);
        } catch (e) {
            displayError(e.message);
        }
    }
    
    /**
     * Copy claims to clipboard
     */
    async function copyClaims() {
        const token = tokenInput.value.trim();
        
        if (!token) {
            return;
        }
        
        try {
            const jwtData = parseJWT(token);
            const text = JSON.stringify(jwtData.payload, null, 2);
            
            await navigator.clipboard.writeText(text);
            
            // Show temporary success feedback
            const originalText = copyClaimsBtn.innerHTML;
            copyClaimsBtn.innerHTML = `
                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M22 11.08V12C21.9988 14.1564 21.3005 16.2547 20.0093 17.9818C18.7182 19.709 16.9033 20.9725 14.8354 21.5839C12.7674 22.1953 10.5573 22.1219 8.53447 21.3746C6.51168 20.6273 4.78465 19.2461 3.61096 17.4371C2.43727 15.628 1.87979 13.4881 2.02168 11.3363C2.16356 9.18455 2.99721 7.13631 4.40097 5.48976C5.80473 3.84322 7.70526 2.68453 9.82004 2.18522C11.9348 1.68592 14.1512 1.87273 16.16 2.72" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M22 4L12 14.01L9 11.01" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Copied!
            `;
            
            setTimeout(() => {
                copyClaimsBtn.innerHTML = originalText;
            }, 2000);
        } catch (e) {
            console.error('Failed to copy:', e);
        }
    }
    
    /**
     * Paste from clipboard
     */
    async function pasteFromClipboard() {
        try {
            const text = await navigator.clipboard.readText();
            tokenInput.value = text.trim();
            hideMessages();
            tokenInput.focus();
        } catch (e) {
            console.error('Failed to paste:', e);
            // Fallback: select the input for manual paste
            tokenInput.select();
            document.execCommand('paste');
        }
    }
    
    /**
     * Clear input and results
     */
    function clearAll() {
        tokenInput.value = '';
        hideMessages();
        tokenInput.focus();
    }
    
    // Event Listeners
    decodeBtn.addEventListener('click', decodeToken);
    pasteBtn.addEventListener('click', pasteFromClipboard);
    clearBtn.addEventListener('click', clearAll);
    copyClaimsBtn.addEventListener('click', copyClaims);
    
    // Allow Enter key to trigger decode (with Ctrl/Cmd)
    tokenInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
            e.preventDefault();
            decodeToken();
        }
    });
    
    // Auto-hide error when user starts typing
    tokenInput.addEventListener('input', function() {
        if (errorMessage.style.display !== 'none') {
            hideMessages();
        }
    });
    
    // Sample token for testing (optional - can be removed)
    // Uncomment to add a sample token button
    /*
    const sampleToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE5MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    */
});
