export const bufferToBase64Url = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

export const base64UrlToBuffer = (value: string): Uint8Array<ArrayBuffer> => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  const binary = atob(normalized + pad);
  const buffer = new ArrayBuffer(binary.length);
  const bytes: Uint8Array<ArrayBuffer> = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

export interface CreationOptionsJSON {
  challenge: string;
  rp: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntity & { id: string };
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  excludeCredentials?: (PublicKeyCredentialDescriptor & { id: string })[];
}

export interface RequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: (PublicKeyCredentialDescriptor & { id: string })[];
  userVerification?: UserVerificationRequirement;
}

export const inflateCreationOptions = (json: CreationOptionsJSON): PublicKeyCredentialCreationOptions => ({
  ...json,
  challenge: base64UrlToBuffer(json.challenge),
  user: {
    ...json.user,
    id: base64UrlToBuffer(json.user.id),
  },
  excludeCredentials: json.excludeCredentials?.map((cred) => ({
    ...cred,
    id: base64UrlToBuffer(cred.id),
  })),
});

export const inflateRequestOptions = (json: RequestOptionsJSON): PublicKeyCredentialRequestOptions => ({
  ...json,
  challenge: base64UrlToBuffer(json.challenge),
  allowCredentials: json.allowCredentials?.map((cred) => ({
    ...cred,
    id: base64UrlToBuffer(cred.id),
  })),
});

export function serializeCredential(credential: PublicKeyCredential) {
  const base = {
    id: credential.id,
    type: credential.type,
    rawId: bufferToBase64Url(credential.rawId as ArrayBuffer),
  };
  const response = credential.response;
  if ('attestationObject' in response) {
    const attestation = response as AuthenticatorAttestationResponse & {
      getTransports?: () => AuthenticatorTransport[];
    };
    const transports = attestation.getTransports?.();
    return {
      ...base,
      response: {
        clientDataJSON: bufferToBase64Url(attestation.clientDataJSON),
        attestationObject: bufferToBase64Url(attestation.attestationObject),
        transports,
      },
    };
  }
  if ('authenticatorData' in response) {
    const assertion = response as AuthenticatorAssertionResponse;
    return {
      ...base,
      response: {
        authenticatorData: bufferToBase64Url(assertion.authenticatorData),
        clientDataJSON: bufferToBase64Url(assertion.clientDataJSON),
        signature: bufferToBase64Url(assertion.signature),
        userHandle: assertion.userHandle ? bufferToBase64Url(assertion.userHandle) : null,
      },
    };
  }
  throw new Error('Unsupported credential response');
}
