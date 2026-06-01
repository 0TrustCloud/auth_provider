package auth_provider

import "net/http"

func (p *Provider) ServeJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	_, _ = w.Write([]byte(`
async function passkeyRegister(username) {
    try {
        if (!username) throw new Error("Please enter a username");
        const resp = await fetch('/auth/register/begin?username=' + encodeURIComponent(username));
        if (!resp.ok) throw new Error("Server error: " + await resp.text());
        const opts = await resp.json();
        
        opts.publicKey.challenge = base64urlToBuffer(opts.publicKey.challenge);
        opts.publicKey.user.id = base64urlToBuffer(opts.publicKey.user.id);
        if(opts.publicKey.excludeCredentials) { opts.publicKey.excludeCredentials.forEach(c => c.id = base64urlToBuffer(c.id)); }
        
        // DBSC FIX: Explicitly request hardware-bound session extensions and define the scope
        opts.publicKey.extensions = opts.publicKey.extensions || {};
        opts.publicKey.extensions.devicePubKey = { attestation: "none" };
        opts.publicKey.extensions.sessionScope = window.location.origin;

        const cred = await navigator.credentials.create({ publicKey: opts.publicKey });
        
        // Extract the hardware extension results to send back to the SDF SessionManager
        const extResults = cred.getClientExtensionResults();

        const finishResp = await fetch('/auth/register/finish?username=' + encodeURIComponent(username), {
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                id: cred.id, 
                rawId: bufferToBase64url(cred.rawId), 
                type: cred.type, 
                extensions: extResults, // Pass DBSC payload to backend
                response: { 
                    attestationObject: bufferToBase64url(cred.response.attestationObject), 
                    clientDataJSON: bufferToBase64url(cred.response.clientDataJSON), 
                }, 
            }),
        });
        
        if (!finishResp.ok) throw new Error("Server rejected registration: " + await finishResp.text());
        
        const resData = await finishResp.json();
        if (resData.redirect_to) { window.location.href = resData.redirect_to; } 
        else { window.location.href = "/"; }
    } catch (err) { console.error(err); alert("Registration Failed: " + err.message); }
}

async function passkeyLogin(username) {
    try {
        if (!username) throw new Error("Please enter a username");
        const resp = await fetch('/auth/login/begin?username=' + encodeURIComponent(username));
        if (!resp.ok) throw new Error("Server error: " + await resp.text());
        const opts = await resp.json();
        
        opts.publicKey.challenge = base64urlToBuffer(opts.publicKey.challenge);
        if (opts.publicKey.allowCredentials) { opts.publicKey.allowCredentials.forEach(c => c.id = base64urlToBuffer(c.id)); }
        
        // DBSC FIX: Explicitly request hardware-bound session extensions and define the scope
        opts.publicKey.extensions = opts.publicKey.extensions || {};
        opts.publicKey.extensions.devicePubKey = { attestation: "none" };
        opts.publicKey.extensions.sessionScope = window.location.origin;

        const assertion = await navigator.credentials.get({ publicKey: opts.publicKey });
        
        // Extract the hardware extension results to send back to the SDF SessionManager
        const extResults = assertion.getClientExtensionResults();

        const finishResp = await fetch('/auth/login/finish?username=' + encodeURIComponent(username), {
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                id: assertion.id, 
                rawId: bufferToBase64url(assertion.rawId), 
                type: assertion.type, 
                extensions: extResults, // Pass DBSC signature to backend
                response: { 
                    authenticatorData: bufferToBase64url(assertion.response.authenticatorData), 
                    clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON), 
                    signature: bufferToBase64url(assertion.response.signature), 
                    userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null, 
                }, 
            }),
        });
        
        if (!finishResp.ok) throw new Error("Server rejected login: " + await finishResp.text());
        
        const resData = await finishResp.json();
        if (resData.redirect_to) { window.location.href = resData.redirect_to; } 
        else { window.location.href = "/"; }
    } catch (err) { console.error(err); alert("Login Failed: " + err.message); }
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
`))
}
