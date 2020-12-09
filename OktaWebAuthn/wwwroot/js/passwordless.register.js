document.getElementById('register-form').addEventListener('submit', handleRegisterSubmit);

async function handleRegisterSubmit(event) {
    event.preventDefault();

    let email = this.email.value;
    let firstName = this.firstName.value;
    let lastName = this.lastName.value;

    // possible values: none, direct, indirect
    let attestationType = "none";
    // possible values: <empty>, platform, cross-platform
    let authenticatorAttachment = "";

    // possible values: preferred, required, discouraged
    let userVerification = "preferred";

    // possible values: true,false
    let requireResidentKey = "false";

    // prepare form post data
    var data = new FormData();
    
    data.append('username', email);
    data.append('firstName', firstName);
    data.append('lastName', lastName);
    //data.append('authType', authenticatorAttachment);
    //data.append('userVerification', userVerification);
    //data.append('requireResidentKey', requireResidentKey);

    // send to server for registering
    let credentialOptions;
    try {
        credentialOptions = await fetchMakeCredentialOptions({ email: email, firstName: firstName, lastName: lastName });

    } catch (e) {
        console.error(e);
        alert("Something went really wrong");
        return;
    }

    if (credentialOptions.status !== "ok") {
        alert(credentialOptions.errorMessage);
        return;
    }

    // Turn the challenge back into the accepted format of padded base64
    credentialOptions.challenge = coerceToArrayBuffer(credentialOptions.challenge);
    credentialOptions.user.id = coerceToArrayBuffer(credentialOptions.user.id);

    credentialOptions.excludeCredentials = credentialOptions.excludeCredentials.map((c) => {
        c.id = coerceToArrayBuffer(c.id);
        return c;
    });

    if (credentialOptions.authenticatorSelection.authenticatorAttachment === null) {
        credentialOptions.authenticatorSelection.authenticatorAttachment = undefined;
    }

    let newCredential;
    try {
        newCredential = await navigator.credentials.create({
            publicKey: credentialOptions
        });
    } catch (e) {
        alert("Could not create credentials in browser.");
        return;
    }

    try {
        await registerNewCredential(newCredential);
        window.location.replace("/Account/Signin");
    } catch (e) {
        alert("Could not register new credentials on server");
    }
}

async function fetchMakeCredentialOptions(formData) {
    let response = await fetch('/Account/CredentialOptions', {
        method: 'POST',
        body: JSON.stringify(formData),
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    });

    let data = await response.json();

    return data;
}


// This should be used to verify the auth data with the server
async function registerNewCredential(newCredential) {

    let attestationObject = new Uint8Array(newCredential.response.attestationObject);
    let clientDataJSON = new Uint8Array(newCredential.response.clientDataJSON);
    let rawId = new Uint8Array(newCredential.rawId);

    const data = {
        id: newCredential.id,
        rawId: coerceToBase64Url(rawId),
        type: newCredential.type,
        extensions: newCredential.getClientExtensionResults(),
        response: {
            AttestationObject: coerceToBase64Url(attestationObject),
            clientDataJson: coerceToBase64Url(clientDataJSON)
        }
    };

    let response;
    try {
        response = await registerCredentialWithServer(data);
    } catch (e) {
        alert(e);
        return;
    }

    console.log("Credential Object", response);

    // show error
    if (response.status !== "ok") {
        alert(response.errorMessage);
        return;
    }

    alert("You've registered successfully. You will now be redirected to sign in page");
}

async function registerCredentialWithServer(formData) {
    let response = await fetch('/Account/SaveCredentials', {
        method: 'POST',
        body: JSON.stringify(formData),
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    });

    let data = await response.json();

    return data;
}
