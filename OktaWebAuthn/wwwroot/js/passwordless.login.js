document.getElementById('signin-form').addEventListener('submit', handleSignInSubmit);

async function handleSignInSubmit(event) {
    event.preventDefault();
    
    let username = this.email.value;

    var formData = new FormData();
    formData.append('username', username);

    let publicKeyOptions;
    try {
        var res = await fetch('/Account/SignInOptions', {
            method: 'POST',
            body: formData,
            headers: {
                'Accept': 'application/json'
            }
        });

        publicKeyOptions = await res.json();
    } catch (e) {
        alert("Request to server failed");
        return;
    }

    if (publicKeyOptions.status !== "ok") {
        alert(publicKeyOptions.errorMessage);
        return;
    }

    const challenge = publicKeyOptions.challenge.replace(/-/g, "+").replace(/_/g, "/");
    publicKeyOptions.challenge = Uint8Array.from(atob(challenge), c => c.charCodeAt(0));

    publicKeyOptions.allowCredentials.forEach(function (listItem) {
        var fixedId = listItem.id.replace(/\_/g, "/").replace(/\-/g, "+");
        listItem.id = Uint8Array.from(atob(fixedId), c => c.charCodeAt(0));
    });
    
    // ask browser for credentials (browser will ask connected authenticators)
    let credential;
    try {
        credential = await navigator.credentials.get({ publicKey: publicKeyOptions });

        try {
            await verifyAssertionWithServer(credential);
        } catch (e) {
            alert("Could not verify assertion");
        }
    } catch (err) {
        alert(err.message ? err.message : err);
    }
}

async function verifyAssertionWithServer(assertedCredential) {
    let authData = new Uint8Array(assertedCredential.response.authenticatorData);
    let clientDataJSON = new Uint8Array(assertedCredential.response.clientDataJSON);
    let rawId = new Uint8Array(assertedCredential.rawId);
    let sig = new Uint8Array(assertedCredential.response.signature);
    const data = {
        id: assertedCredential.id,
        rawId: coerceToBase64Url(rawId),
        type: assertedCredential.type,
        extensions: assertedCredential.getClientExtensionResults(),
        response: {
            authenticatorData: coerceToBase64Url(authData),
            clientDataJson: coerceToBase64Url(clientDataJSON),
            signature: coerceToBase64Url(sig)
        }
    };

    let response;
    try {
        let res = await fetch("/Account/SignIn", {
            method: 'POST',
            body: JSON.stringify(data),
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });

        response = await res.json();
    } catch (e) {
        alert("Request to server failed", e);
        throw e;
    }

    console.log("Assertion Object", response);

    if (response.status !== "ok") {
        alert(response.errorMessage);
        return;
    }

    window.location.href = "/Account/Profile";
}
