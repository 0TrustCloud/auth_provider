package auth_provider

import "net/http"

func (p *Provider) ServeJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	_, _ = w.Write([]byte(`
// Capture the exact origin safely for the network payload
const authScope = window.location.origin;

async function passkeyRegister(username) {
    try {
        if (!username) throw new Error("Please enter a username");
        
        // Pass scope safely as a query parameter to the backend
        const resp = await fetch('/auth/register/begin?username=' + encodeURIComponent(username) + '&scope=' + encodeURIComponent(authScope));
        if (!resp.ok) throw new Error("Server error: " + await resp.text());
        
        const opts = await resp.json();
        opts.publicKey.challenge = base64urlToBuffer(opts.publicKey.challenge);
        opts.publicKey.user.id = base64urlToBuffer(opts.publicKey.user.id);
        if(opts.publicKey.excludeCredentials) { opts.publicKey.excludeCredentials.forEach(c => c.id = base64urlToBuffer(c.id)); }
        
        // Let the native API execute with pristine, valid options
        const cred = await navigator.credentials.create({ publicKey: opts.publicKey });
        
        const finishResp = await fetch('/auth/register/finish?username=' + encodeURIComponent(username), {
            method: 'POST', 
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
        
        const resData = await finishResp.json();
        if (resData.redirect_to) { window.location.href = resData.redirect_to; } 
        else { window.location.href = "/"; }
    } catch (err) { 
        console.error("Registration Error:", err); 
        alert("Registration Failed: " + err.message); 
    }
}

async function passkeyLogin(username) {
    try {
        if (!username) throw new Error("Please enter a username");
        
        // Pass scope safely as a query parameter to the backend
        const resp = await fetch('/auth/login/begin?username=' + encodeURIComponent(username) + '&scope=' + encodeURIComponent(authScope));
        if (!resp.ok) throw new Error("Server error: " + await resp.text());
        
        const opts = await resp.json();
        opts.publicKey.challenge = base64urlToBuffer(opts.publicKey.challenge);
        if (opts.publicKey.allowCredentials) { opts.publicKey.allowCredentials.forEach(c => c.id = base64urlToBuffer(c.id)); }
        
        // Let the native API execute with pristine, valid options
        const assertion = await navigator.credentials.get({ publicKey: opts.publicKey });
        
        const finishResp = await fetch('/auth/login/finish?username=' + encodeURIComponent(username), {
            method: 'POST', 
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
        
        const resData = await finishResp.json();
        if (resData.redirect_to) { window.location.href = resData.redirect_to; } 
        else { window.location.href = "/"; }
    } catch (err) { 
        console.error("Login Error:", err); 
        alert("Login Failed: " + err.message); 
    }
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
