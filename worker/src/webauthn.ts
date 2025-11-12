import { Decoder } from 'cbor-x';
import { fromBase64Url, toBase64Url } from './base64';

const encoder = new TextEncoder();
const textDecoder = new TextDecoder();

export interface RegistrationCredentialPayload {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: string[];
  };
}

export interface AssertionCredentialPayload {
  id: string;
  rawId: string;
  type: string;
  response: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
    userHandle?: string | null;
  };
}

export interface RegistrationVerificationInput {
  expectedChallenge: string;
  expectedOrigin: string;
  rpId: string;
  credential: RegistrationCredentialPayload;
}

export interface RegistrationVerificationResult {
  credentialId: string;
  publicKeyJwk: JsonWebKey;
  counter: number;
  transports?: string[];
}

export interface AssertionVerificationInput {
  expectedChallenge: string;
  expectedOrigin: string;
  rpId: string;
  credential: AssertionCredentialPayload;
  publicKeyJwk: JsonWebKey;
  prevCounter: number;
}

export interface AssertionVerificationResult {
  newCounter: number;
}

function cloneToArrayBuffer(data: ArrayBuffer | SharedArrayBuffer | Uint8Array<ArrayBufferLike>): ArrayBuffer {
  if (data instanceof ArrayBuffer) {
    return data.slice(0);
  }
  const source = data instanceof Uint8Array ? data : new Uint8Array(data);
  const copy = new Uint8Array(source.length);
  copy.set(source);
  return copy.buffer;
}

async function sha256(data: ArrayBuffer | Uint8Array | string): Promise<ArrayBuffer> {
  if (typeof data === 'string') {
    return crypto.subtle.digest('SHA-256', encoder.encode(data));
  }
  const buffer = cloneToArrayBuffer(data instanceof Uint8Array ? data : new Uint8Array(data));
  return crypto.subtle.digest('SHA-256', buffer);
}

function bufferEqual(a: Uint8Array, b: Uint8Array): boolean {
  const viewA = a;
  const viewB = b;
  if (viewA.length !== viewB.length) return false;
  for (let i = 0; i < viewA.length; i += 1) {
    if (viewA[i] !== viewB[i]) return false;
  }
  return true;
}

function parseClientData(clientDataJSON: string) {
  const bytes = fromBase64Url(clientDataJSON);
  const json = textDecoder.decode(bytes);
  return { payload: JSON.parse(json), bytes };
}

function parseAttestationObject(attestationObject: string) {
  const bytes = fromBase64Url(attestationObject);
  const decoded = new Decoder({ mapsAsObjects: false }).decode(bytes) as Map<string, unknown>;
  const authData = decoded.get('authData');
  if (!(authData instanceof Uint8Array)) {
    throw new Error('Invalid authData');
  }
  return {
    authData,
  };
}

function parseAuthenticatorData(authData: Uint8Array) {
  const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
  let offset = 0;
  const rpIdHash = authData.slice(offset, offset + 32);
  offset += 32;
  const flags = authData[offset];
  offset += 1;
  const counter = view.getUint32(offset, false);
  offset += 4;
  const attested = (flags & 0x40) === 0x40;
  let credentialId: Uint8Array | null = null;
  let credentialPublicKeyBytes: Uint8Array | null = null;
  if (attested) {
    offset += 16; // AAGUID
    const credIdLength = view.getUint16(offset, false);
    offset += 2;
    credentialId = authData.slice(offset, offset + credIdLength);
    offset += credIdLength;
    credentialPublicKeyBytes = authData.slice(offset);
  }
  return {
    rpIdHash,
    flags,
    counter,
    credentialId,
    credentialPublicKeyBytes,
  };
}

function coseEc2KeyToJwk(cose: Map<number, unknown>): JsonWebKey {
  const kty = cose.get(1);
  const alg = cose.get(3);
  const crv = cose.get(-1);
  const x = cose.get(-2);
  const y = cose.get(-3);
  if (kty !== 2 || alg !== -7 || crv !== 1) {
    throw new Error('Unsupported public key type');
  }
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
    throw new Error('Invalid EC key material');
  }
  return {
    kty: 'EC',
    crv: 'P-256',
    x: toBase64Url(x),
    y: toBase64Url(y),
    ext: true,
  };
}

export async function verifyRegistration(input: RegistrationVerificationInput): Promise<RegistrationVerificationResult> {
  const { credential } = input;
  if (credential.type !== 'public-key') {
    throw new Error('Unexpected credential type');
  }
  const { payload: clientData, bytes: clientDataBytes } = parseClientData(credential.response.clientDataJSON);
  if (clientData.type !== 'webauthn.create') {
    throw new Error('Invalid client data type');
  }
  if (clientData.challenge !== input.expectedChallenge) {
    throw new Error('Challenge mismatch');
  }
  if (clientData.origin !== input.expectedOrigin) {
    throw new Error('Origin mismatch');
  }
  const { authData } = parseAttestationObject(credential.response.attestationObject);
  const parsedAuthData = parseAuthenticatorData(authData);
  const rpIdHash = new Uint8Array(await sha256(input.rpId));
  if (!bufferEqual(parsedAuthData.rpIdHash, rpIdHash)) {
    throw new Error('RP ID hash mismatch');
  }
  if (!parsedAuthData.credentialId || !parsedAuthData.credentialPublicKeyBytes) {
    throw new Error('Missing attested credential data');
  }
  const coseStruct = new Decoder({ mapsAsObjects: false }).decode(parsedAuthData.credentialPublicKeyBytes) as Map<number, unknown>;
  const publicKeyJwk = coseEc2KeyToJwk(coseStruct);
  const credentialId = toBase64Url(parsedAuthData.credentialId);
  return {
    credentialId,
    publicKeyJwk,
    counter: parsedAuthData.counter,
    transports: credential.response.transports,
  };
}

async function importPublicKey(jwk: JsonWebKey) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}

function concatBuffers(a: ArrayBuffer, b: ArrayBuffer): ArrayBuffer {
  const aBytes = new Uint8Array(a);
  const bBytes = new Uint8Array(b);
  const buffer = new Uint8Array(aBytes.length + bBytes.length);
  buffer.set(aBytes, 0);
  buffer.set(bBytes, aBytes.length);
  return buffer.buffer;
}

export async function verifyAssertion(input: AssertionVerificationInput): Promise<AssertionVerificationResult> {
  const { credential } = input;
  if (credential.type !== 'public-key') {
    throw new Error('Unexpected credential type');
  }
  const { payload: clientData, bytes: clientDataBytes } = parseClientData(credential.response.clientDataJSON);
  if (clientData.type !== 'webauthn.get') {
    throw new Error('Invalid assertion type');
  }
  if (clientData.challenge !== input.expectedChallenge) {
    throw new Error('Challenge mismatch');
  }
  if (clientData.origin !== input.expectedOrigin) {
    throw new Error('Origin mismatch');
  }
  const authenticatorData = fromBase64Url(credential.response.authenticatorData);
  const parsedAuthData = parseAuthenticatorData(authenticatorData);
  const rpIdHash = new Uint8Array(await sha256(input.rpId));
  if (!bufferEqual(parsedAuthData.rpIdHash, rpIdHash)) {
    throw new Error('RP ID mismatch');
  }
  const signature = fromBase64Url(credential.response.signature);
  const publicKey = await importPublicKey(input.publicKeyJwk);
  const clientHash = await sha256(clientDataBytes);
  const authDataBuffer = cloneToArrayBuffer(authenticatorData);
  const signedData = concatBuffers(authDataBuffer, clientHash);
  const signatureBuffer = cloneToArrayBuffer(signature);
  const verified = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    signatureBuffer,
    signedData,
  );
  if (!verified) {
    throw new Error('Invalid assertion signature');
  }
  if (parsedAuthData.counter <= input.prevCounter) {
    throw new Error('Authenticator counter did not advance');
  }
  return { newCounter: parsedAuthData.counter };
}
