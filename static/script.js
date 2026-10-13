/**
 * JWT Decoder - Professional Frontend JavaScript
 *
 * Decodes JWT tokens in the browser and renders every piece of the token in
 * its own field: header, payload, signature, claims and token info.
 */

document.addEventListener('DOMContentLoaded', function () {
    'use strict';

    var byId = function (id) {
        return document.getElementById(id);
    };

    // Field that contains a <code> child (falls back to the element itself).
    var codeOf = function (id) {
        var el = byId(id);
        if (!el) {
            return null;
        }
        return el.querySelector('code') || el;
    };

    // DOM Elements
    var tokenInput = byId('tokenInput');
    var decodeBtn = byId('decodeBtn');
    var pasteBtn = byId('pasteBtn');
    var clearBtn = byId('clearBtn');
    var copyClaimsBtn = byId('copyClaimsBtn');
    var copyApiBtn = byId('copyApiBtn');
    var openApiLink = byId('openApiLink');
    var resultsContainer = byId('resultsContainer');
    var errorMessage = byId('errorMessage');

    // Result display elements
    var statusCard = byId('statusCard');
    var statusTitle = byId('statusTitle');
    var statusDescription = byId('statusDescription');
    var headerField = codeOf('headerContent');
    var payloadField = codeOf('payloadContent');
    var signatureField = codeOf('signatureContent');
    var claimsField = codeOf('jsonDisplay');
    var algorithmValue = byId('algorithmValue');
    var tokenTypeValue = byId('tokenTypeValue');
    var issuedAtValue = byId('issuedAtValue');
    var expiresValue = byId('expiresValue');
    var expiryCountdown = byId('expiryCountdown');
    var tokenStatus = byId('tokenStatus');
    var apiUrlField = byId('apiUrl');
    var errorDescription = byId('errorDescription');

    var countdownInterval = null;
    var lastApiUrl = '';

    var DASH = '\u2014';

    /**
     * Base64URL decode (works with unicode payloads).
     */
    function base64UrlDecode(str) {
        var base64 = str.replace(/-/g, '+').replace(/_/g, '/');

        while (base64.length % 4) {
            base64 += '=';
        }

        var binary;
        try {
            binary = atob(base64);
        } catch (e) {
            throw new Error('the token contains an invalid Base64URL segment');
        }

        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }

        if (typeof TextDecoder === 'function') {
            return new TextDecoder('utf-8').decode(bytes);
        }

        // Fallback for very old browsers.
        var encoded = '';
        for (var j = 0; j < bytes.length; j++) {
            encoded += '%' + ('00' + bytes[j].toString(16)).slice(-2);
        }
        return decodeURIComponent(encoded);
    }

    /**
     * Parse a JWT token into its components.
     */
    function parseJWT(token) {
        // Tokens are often pasted with line breaks or surrounding spaces.
        var cleaned = token.replace(/\s+/g, '');

        if (cleaned.toLowerCase().indexOf('bearer') === 0) {
            cleaned = cleaned.slice(6);
        }

        if (!cleaned) {
            throw new Error('Please enter a JWT token');
        }

        var parts = cleaned.split('.');

        if (parts.length === 5) {
            throw new Error('This looks like an encrypted JWT (JWE, 5 parts) - only signed tokens can be decoded');
        }

        if (parts.length !== 3) {
            throw new Error('Invalid JWT format: expected 3 parts separated by dots, found ' + parts.length);
        }

        if (!parts[0] || !parts[1]) {
            throw new Error('Invalid JWT: the header or the payload segment is empty');
        }

        var header;
        var payload;

        try {
            header = JSON.parse(base64UrlDecode(parts[0]));
        } catch (e) {
            throw new Error('Invalid header: ' + e.message);
        }

        try {
            payload = JSON.parse(base64UrlDecode(parts[1]));
        } catch (e) {
            throw new Error('Invalid payload: ' + e.message);
        }

        if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
            throw new Error('Invalid JWT: the payload must be a JSON object');
        }

        return {
            header: header,
            payload: payload,
            signature: parts[2],
            headerB64: parts[0],
            payloadB64: parts[1]
        };
    }

    /**
     * Convert a claim into a usable unix timestamp (numbers or numeric strings).
     * Returns null when the value is not a sane timestamp.
     */
    function toTimestamp(value) {
        var numeric;

        if (typeof value === 'number') {
            numeric = value;
        } else if (typeof value === 'string' && value.trim() !== '' && !isNaN(Number(value))) {
            numeric = Number(value);
        } else {
            return null;
        }

        if (!isFinite(numeric)) {
            return null;
        }

        var date = new Date(numeric * 1000);
        var year = date.getUTCFullYear();

        if (isNaN(date.getTime()) || year < 1970 || year > 3000) {
            return null;
        }

        return numeric;
    }

    /**
     * Format a unix timestamp for display.
     */
    function formatDate(timestamp) {
        var date = new Date(timestamp * 1000);
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
     * UTC representation, used as tooltip so local/UTC cannot be confused.
     */
    function formatUtc(timestamp) {
        return new Date(timestamp * 1000).toISOString().replace('.000Z', 'Z');
    }

    /**
     * Human readable "time until expiry" string.
     */
    function getTimeUntilExpiry(expTimestamp) {
        var diff = expTimestamp - Math.floor(Date.now() / 1000);

        if (diff <= 0) {
            return 'Expired';
        }

        var days = Math.floor(diff / 86400);
        var hours = Math.floor((diff % 86400) / 3600);
        var minutes = Math.floor((diff % 3600) / 60);
        var seconds = diff % 60;

        if (days > 0) {
            return days + 'd ' + hours + 'h ' + minutes + 'm';
        }
        if (hours > 0) {
            return hours + 'h ' + minutes + 'm ' + seconds + 's';
        }
        if (minutes > 0) {
            return minutes + 'm ' + seconds + 's';
        }
        return seconds + 's';
    }

    /**
     * Update the expiry countdown every second.
     */
    function updateCountdown(expTimestamp) {
        if (countdownInterval) {
            clearInterval(countdownInterval);
            countdownInterval = null;
        }

        function update() {
            var countdown = getTimeUntilExpiry(expTimestamp);
            expiryCountdown.textContent = countdown;

            if (countdown === 'Expired') {
                clearInterval(countdownInterval);
                countdownInterval = null;
                updateTokenStatus('expired');
            }
        }

        update();
        countdownInterval = setInterval(update, 1000);
    }

    /**
     * Syntax highlight a JSON string (HTML escaped first).
     */
    function syntaxHighlightJSON(json) {
        if (typeof json !== 'string') {
            json = JSON.stringify(json, undefined, 2);
        }

        json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

        return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            var cls = 'json-number';
            if (/^"/.test(match)) {
                cls = /:$/.test(match) ? 'json-key' : 'json-string';
            } else if (/true|false/.test(match)) {
                cls = 'json-boolean';
            } else if (/null/.test(match)) {
                cls = 'json-null';
            }
            return '<span class="' + cls + '">' + match + '</span>';
        });
    }

    /**
     * Update the status card and the "Token Status" field.
     * state: 'valid' | 'expired' | 'unknown'
     */
    function updateTokenStatus(state) {
        statusCard.className = 'status-card ' + state;
        tokenStatus.className = 'info-value status-badge ' + state;

        if (state === 'valid') {
            statusTitle.textContent = 'Token Valid';
            statusDescription.textContent = 'This token is valid and has not expired';
            tokenStatus.textContent = 'Active';
        } else if (state === 'expired') {
            statusTitle.textContent = 'Token Expired';
            statusDescription.textContent = 'This token has expired and is no longer valid';
            tokenStatus.textContent = 'Expired';
        } else {
            statusTitle.textContent = 'Token Decoded';
            statusDescription.textContent = 'No valid "exp" claim found, the expiration cannot be checked';
            tokenStatus.textContent = 'Unknown';
        }
    }

    /**
     * Build the API URL for the current token and show it in its own field.
     */
    function updateApiField(token) {
        lastApiUrl = window.location.origin + '/decode_jwt?token=' + encodeURIComponent(token);

        if (apiUrlField) {
            apiUrlField.textContent = lastApiUrl;
        }
        if (openApiLink) {
            openApiLink.href = lastApiUrl;
        }
    }

    /**
     * Display the decoded token. Every value goes into its own field.
     */
    function displayResults(jwtData, rawToken) {
        var header = jwtData.header;
        var payload = jwtData.payload;
        var signature = jwtData.signature;

        resultsContainer.classList.remove('is-hidden');
        errorMessage.classList.add('is-hidden');

        // --- token parts, one field each --------------------------------- #
        headerField.textContent = JSON.stringify(header, null, 2);
        payloadField.textContent = JSON.stringify(payload, null, 2);
        signatureField.textContent = signature ? signature : '(empty signature)';
        signatureField.title = signature ? signature : '';

        // --- decoded claims --------------------------------------------- #
        claimsField.innerHTML = syntaxHighlightJSON(JSON.stringify(payload, null, 2));

        // --- token info -------------------------------------------------- #
        algorithmValue.textContent = header.alg || 'N/A';
        tokenTypeValue.textContent = header.typ || 'N/A';

        var issuedTimestamp = toTimestamp(payload.iat);
        if (issuedTimestamp !== null) {
            issuedAtValue.textContent = formatDate(issuedTimestamp);
            issuedAtValue.title = 'UTC: ' + formatUtc(issuedTimestamp);
        } else {
            issuedAtValue.textContent = 'No issued time';
            issuedAtValue.title = '';
        }

        var expTimestamp = toTimestamp(payload.exp);
        var hasExpClaim = Object.prototype.hasOwnProperty.call(payload, 'exp');

        if (expTimestamp !== null) {
            expiresValue.textContent = formatDate(expTimestamp);
            expiresValue.title = 'UTC: ' + formatUtc(expTimestamp);
            updateCountdown(expTimestamp);
            updateTokenStatus(expTimestamp > Math.floor(Date.now() / 1000) ? 'valid' : 'expired');
        } else {
            expiresValue.textContent = hasExpClaim ? 'Invalid "exp" claim' : 'No expiration';
            expiresValue.title = '';
            expiryCountdown.textContent = hasExpClaim ? DASH : 'N/A';
            if (countdownInterval) {
                clearInterval(countdownInterval);
                countdownInterval = null;
            }
            updateTokenStatus('unknown');
        }

        // --- REST API field --------------------------------------------- #
        updateApiField(rawToken);

        resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    /**
     * Display an error message and hide the results.
     */
    function displayError(message) {
        resultsContainer.classList.add('is-hidden');
        errorMessage.classList.remove('is-hidden');
        errorDescription.textContent = message;

        if (countdownInterval) {
            clearInterval(countdownInterval);
            countdownInterval = null;
        }
    }

    /**
     * Hide results and errors.
     */
    function hideMessages() {
        resultsContainer.classList.add('is-hidden');
        errorMessage.classList.add('is-hidden');

        if (countdownInterval) {
            clearInterval(countdownInterval);
            countdownInterval = null;
        }
    }

    /**
     * Decode the token currently in the input.
     */
    function decodeToken() {
        var token = tokenInput.value.trim();

        if (!token) {
            displayError('Please enter a JWT token');
            return;
        }

        try {
            var jwtData = parseJWT(token);
            displayResults(jwtData, token);
        } catch (e) {
            displayError(e.message);
        }
    }

    /**
     * Copy arbitrary text and flash a short confirmation on the button.
     */
    function copyText(text, button, originalText) {
        function done() {
            button.innerHTML = '<svg class="btn-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M20 6L9 17L4 12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>Copied!';
            setTimeout(function () {
                button.innerHTML = originalText;
            }, 2000);
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done).catch(function () {
                console.error('Failed to copy to clipboard');
            });
            return;
        }

        // Fallback for browsers without the async clipboard API.
        var helper = document.createElement('textarea');
        helper.value = text;
        helper.setAttribute('readonly', 'readonly');
        helper.style.position = 'absolute';
        helper.style.left = '-9999px';
        document.body.appendChild(helper);
        helper.select();
        try {
            document.execCommand('copy');
            done();
        } catch (e) {
            console.error('Failed to copy to clipboard', e);
        }
        document.body.removeChild(helper);
    }

    /**
     * Copy the decoded claims.
     */
    function copyClaims() {
        var token = tokenInput.value.trim();

        if (!token) {
            return;
        }

        try {
            var jwtData = parseJWT(token);
            copyText(JSON.stringify(jwtData.payload, null, 2), copyClaimsBtn, copyClaimsBtn.innerHTML);
        } catch (e) {
            console.error('Failed to copy claims:', e.message);
        }
    }

    /**
     * Copy the REST API URL of the current token.
     */
    function copyApiUrl() {
        if (!lastApiUrl) {
            return;
        }
        copyText(lastApiUrl, copyApiBtn, copyApiBtn.innerHTML);
    }

    /**
     * Paste from the clipboard.
     */
    function pasteFromClipboard() {
        if (!navigator.clipboard || !navigator.clipboard.readText) {
            tokenInput.focus();
            return;
        }

        navigator.clipboard.readText().then(function (text) {
            tokenInput.value = text.trim();
            hideMessages();
            tokenInput.focus();
            if (tokenInput.value) {
                decodeToken();
            }
        }).catch(function (e) {
            console.error('Failed to paste:', e);
            tokenInput.focus();
        });
    }

    /**
     * Clear the input and the results.
     */
    function clearAll() {
        tokenInput.value = '';
        hideMessages();
        tokenInput.focus();
    }

    // Event listeners
    decodeBtn.addEventListener('click', decodeToken);
    pasteBtn.addEventListener('click', pasteFromClipboard);
    clearBtn.addEventListener('click', clearAll);
    copyClaimsBtn.addEventListener('click', copyClaims);
    copyApiBtn.addEventListener('click', copyApiUrl);

    // Ctrl/Cmd + Enter decodes, a plain Enter keeps its default behaviour.
    tokenInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
            e.preventDefault();
            decodeToken();
        }
    });

    // Hide the error as soon as the user edits the token again.
    tokenInput.addEventListener('input', function () {
        if (!errorMessage.classList.contains('is-hidden')) {
            hideMessages();
        }
    });
});
