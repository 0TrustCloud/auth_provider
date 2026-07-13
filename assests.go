package auth_provider

import "net/http"

func (p *Provider) ServeJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(webauthnClientJS))
}

const webauthnClientJS = `
// Capture the exact origin safely for the network payload
const authScope = window.location.origin;

function currentUsername(username) {
    const v = (username || '').trim();
    if (v) return v;
    const el = document.getElementById('username');
    return el ? el.value.trim() : '';
}

function authReturnTo() {
    const params = new URLSearchParams(window.location.search);
    return params.get('return_to') || params.get('redirect') || '';
}

function finishURL(path, username) {
    let url = path + '?username=' + encodeURIComponent(username);
    const ret = authReturnTo();
    if (ret) url += '&return_to=' + encodeURIComponent(ret);
    return url;
}

let enrollmentVerified = false;

async function verifyEnrollmentCode() {
    try {
        const username = currentUsername();
        const totpEl = document.getElementById('totp');
        const passcode = totpEl ? totpEl.value.trim() : '';
        if (!username) throw new Error('Enter your provisioned username');
        if (!passcode) throw new Error('Enter the 6-digit enrollment code from your administrator');

        const resp = await fetch('/auth/provision/verify', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, passcode }),
        });
        if (!resp.ok) throw new Error(await resp.text());
        enrollmentVerified = true;
        alert('Enrollment code verified. You can now register your device passkey.');
    } catch (err) {
        console.error('Enrollment verification error:', err);
        alert('Verification failed: ' + err.message);
    }
}

async function enrollPasskey() {
    const username = currentUsername();
    if (!username) {
        alert('Enter your provisioned username');
        return;
    }
    if (!enrollmentVerified) {
        const statusResp = await fetch('/auth/provision/status?username=' + encodeURIComponent(username));
        if (statusResp.ok) {
            const status = await statusResp.json();
            if (status.open_enrollment || status.bootstrap || status.verified) {
                enrollmentVerified = true;
            }
        }
    }
    if (!enrollmentVerified) {
        alert('Verify your enrollment code before registering a passkey.');
        return;
    }
    await passkeyRegister(username);
}

async function registerPasskey() {
    const username = currentUsername();
    if (!username) {
        alert('Enter your username first');
        return;
    }
    const statusResp = await fetch('/auth/provision/status?username=' + encodeURIComponent(username));
    if (statusResp.ok) {
        const status = await statusResp.json();
        if (status.registered) {
            alert('Passkey already registered — use Sign In with Passkey.');
            return;
        }
        if (status.open_enrollment || status.bootstrap || status.verified) {
            await passkeyRegister(username);
            return;
        }
        if (status.provisioned && !status.verified) {
            window.location.href = '/auth/enroll?username=' + encodeURIComponent(username);
            return;
        }
    }
    window.location.href = '/auth/enroll?username=' + encodeURIComponent(username);
}

async function passkeyRegister(username) {
    try {
        username = currentUsername(username);
        if (!username) throw new Error("Please enter a username");
        
        // Pass scope safely as a query parameter to the backend
        const resp = await fetch('/auth/register/begin?username=' + encodeURIComponent(username) + '&scope=' + encodeURIComponent(authScope));
        if (!resp.ok) {
            const msg = await resp.text();
            if (resp.status === 403) throw new Error(msg || 'Registration is invite-only. Use the enrollment link from your administrator.');
            if (resp.status === 409) throw new Error(msg || 'Passkey already registered — use Sign In with Passkey.');
            throw new Error("Server error: " + msg);
        }
        
        const opts = await resp.json();
        opts.publicKey.challenge = base64urlToBuffer(opts.publicKey.challenge);
        opts.publicKey.user.id = base64urlToBuffer(opts.publicKey.user.id);
        if(opts.publicKey.excludeCredentials) { opts.publicKey.excludeCredentials.forEach(c => c.id = base64urlToBuffer(c.id)); }
        
        // Let the native API execute with pristine, valid options
        const cred = await navigator.credentials.create({ publicKey: opts.publicKey });
        
        const finishResp = await fetch(finishURL('/auth/register/finish', username), {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                id: cred.id, 
                rawId: bufferToBase64url(cred.rawId), 
                type: cred.type, 
                scope: authScope, // Inject scope into the backend validation payload
                response: { 
                    attestationObject: bufferToBase64url(cred.response.attestationObject), 
                    clientDataJSON: bufferToBase64url(cred.response.clientDataJSON), 
                }, 
            }),
        });
        if (!finishResp.ok) throw new Error("Server rejected registration: " + await finishResp.text());
        await completeAuthCeremony(finishResp);
    } catch (err) { 
        console.error("Registration Error:", err); 
        alert("Registration Failed: " + err.message); 
    }
}

async function passkeyLogin(username) {
    try {
        username = currentUsername(username);
        if (!username) throw new Error("Please enter a username");
        
        // Pass scope safely as a query parameter to the backend
        const resp = await fetch('/auth/login/begin?username=' + encodeURIComponent(username) + '&scope=' + encodeURIComponent(authScope));
        if (!resp.ok) {
            const msg = await resp.text();
            if (resp.status === 404) {
                const statusResp = await fetch('/auth/provision/status?username=' + encodeURIComponent(username));
                if (statusResp.ok) {
                    const status = await statusResp.json();
                    if (status.open_enrollment || status.bootstrap || status.verified) {
                        if (confirm('No account/passkey for "' + username + '". Register a passkey on this device now?')) {
                            await passkeyRegister(username);
                            return;
                        }
                        throw new Error('Cancelled — use Register Passkey to create "' + username + '" on this identity face');
                    } else if (status.provisioned) {
                        window.location.href = '/auth/enroll?username=' + encodeURIComponent(username);
                        return;
                    }
                }
                throw new Error(msg || ('No account for "' + username + '" — click Register Passkey first'));
            }
            throw new Error("Server error: " + msg);
        }
        
        const opts = await resp.json();
        const pk = opts.publicKey || opts;
        if (!pk || !pk.challenge) throw new Error('Login options missing publicKey.challenge');
        pk.challenge = base64urlToBuffer(pk.challenge);
        // Decode allowCredentials the same way register decodes excludeCredentials.
        // Strip empty transports — [] can block Windows Hello / platform authenticators.
        if (Array.isArray(pk.allowCredentials)) {
            pk.allowCredentials = pk.allowCredentials.map(function (c) {
                const out = {
                    type: c.type || 'public-key',
                    id: base64urlToBuffer(c.id),
                };
                if (c.transports && c.transports.length) out.transports = c.transports;
                return out;
            });
        }
        if (!pk.userVerification) pk.userVerification = 'preferred';
        
        // Let the native API execute with pristine, valid options
        const assertion = await navigator.credentials.get({ publicKey: pk });
        
        const finishResp = await fetch(finishURL('/auth/login/finish', username), {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                id: assertion.id, 
                rawId: bufferToBase64url(assertion.rawId), 
                type: assertion.type, 
                scope: authScope, // Inject scope into the backend validation payload
                response: { 
                    authenticatorData: bufferToBase64url(assertion.response.authenticatorData), 
                    clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON), 
                    signature: bufferToBase64url(assertion.response.signature), 
                    userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null, 
                }, 
            }),
        });
        if (!finishResp.ok) throw new Error("Server rejected login: " + await finishResp.text());
        await completeAuthCeremony(finishResp);
    } catch (err) { 
        console.error("Login Error:", err); 
        alert("Login Failed: " + err.message); 
    }
}

async function registerDBSCFromResponse(finishResp) {
    // Secure-Session-Registration means "please bind a device key" — it must NOT skip polyfill.
    // Server also sets Sec-Session-Registration with challenge="…".
    const regHeader = finishResp.headers.get('Sec-Session-Registration') || '';
    const secureHdr = finishResp.headers.get('Secure-Session-Registration') || '';
    if (!regHeader && !secureHdr) {
        // Session is already passkey-bound server-side; optional client key upgrade only.
        return;
    }

    let challenge = '';
    const challengeMatch = regHeader.match(/challenge="([^"]+)"/);
    if (challengeMatch) challenge = challengeMatch[1];

    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign']
    );
    const pubJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    delete pubJwk.key_ops;
    delete pubJwk.ext;

    const header = { alg: 'ES256', typ: 'JWT', jwk: pubJwk };
    const payload = { challenge: challenge, iat: Math.floor(Date.now() / 1000) };
    const encodedHeader = bufferToBase64url(new TextEncoder().encode(JSON.stringify(header)));
    const encodedPayload = bufferToBase64url(new TextEncoder().encode(JSON.stringify(payload)));
    const jwt = encodedHeader + '.' + encodedPayload + '.';

    const regResp = await fetch('/auth/dbsc/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ jwt: jwt })
    });
    if (!regResp.ok) {
        // Passkey already bound server-side; client upgrade failure is non-fatal but logged.
        const body = await regResp.text();
        console.warn('DBSC client key upgrade failed (session still passkey-bound):', body);
        return;
    }
}

async function completeAuthCeremony(finishResp) {
    // Always attempt device binding before leaving the identity host.
    await registerDBSCFromResponse(finishResp);
    const resData = await finishResp.json();
    if (resData.redirect_to) { window.location.href = resData.redirect_to; }
    else { window.location.href = '/index'; }
}

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const charCode of bytes) { str += String.fromCharCode(charCode); }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function base64urlToBuffer(base64url) {
    const padding = '=='.slice(0, (4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const str = atob(base64);
    const buffer = new ArrayBuffer(str.length);
    const byteView = new Uint8Array(buffer);
    for (let i = 0; i < str.length; i++) { byteView[i] = str.charCodeAt(i); }
    return buffer;
}
`
