import {type Uuid,type Client, uuidToStr, type EP, type Password, decodePassword, encodePassword } from './decoder.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { blake3 } from '@noble/hashes/blake3';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/ciphers/webcrypto';


const API_URL = 'http://localhost:5173/api/';

export async function auth(uuid: Uuid, client: Client) {
  const response = await fetch(API_URL + 'challenge_json/' + uuidToStr(uuid));
  if (!response.ok) {
    return { result: null, client: null, error: response.statusText }; 
  }
  const challenge = await response.json();

  const challengeBytes = Uint8Array.from(challenge);
  const signature = ml_dsa87.sign(client.di_q, challengeBytes);
  const signArray = Array.from(signature);
  const response2 = await fetch(API_URL + 'verify_json/' + uuidToStr(uuid), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(signArray),
  });
  if (!response2.ok) {
    return { result: null, client: null, error: response2.statusText };  
  }
  const response3 = await fetch(API_URL + 'sync_json/' + uuidToStr(uuid));
  if (!response3.ok) {
    return { result: null, shared: null, error: response3.statusText };  
    }
  const result2 = Uint8Array.from(await response3.json());
  const shared = ml_kem1024.decapsulate(result2,client.ky_q);
  client.secret = shared;
  
  return {result: response2, client: client, error: null};
}

export async function get_all(uuid: Uuid, client: Client) {
  const response = await fetch(API_URL + 'send_all_json/' + uuidToStr(uuid));
  if (!response.ok) {
    return { result: null, error: response.statusText };  
  }
  const result = await response.json();
  const result2 = result;
  const passwordsPromises = result.map(async (item: [EP, Uuid]) => {
    const {result: result3, error} = receive(item[0], client);
    if (error) {
      console.error(error);
    }
    return [result3, item[1]];
  });
  const passwords = await Promise.all(passwordsPromises);
  return {result: passwords, error: null};
}

function receive(ep: EP, client: Client) {
  if (!client.secret) {
    return {result: null, client: client, error: null};
  }
  const secret = client.secret!;
  const hash = blake3(secret!);
  const key = hash.slice(0, 32);
  if (!ep.nonce2) {
    return {result: null,error: null};
  }
  const nonce = ep.nonce2.slice(0,24);
  const noo = Uint8Array.from(nonce);
  const chacha = xchacha20poly1305(key, noo);
  const ciphertext = Uint8Array.from(ep.ciphertext);
  const data = chacha.decrypt(ciphertext);
  const epr: EP = {
    ciphertext: data,
    nonce: ep.nonce,
    nonce2: null,
  }
  return decrypt(epr, client);
}

function decrypt(ep: EP, client: Client) {
  const hash = blake3(client.ky_q);
  const key = hash.slice(0, 32);
  const nonce = ep.nonce;
  const noo = Uint8Array.from(nonce);
  const cipher = xchacha20poly1305(key, noo);
  const ciphertext = Uint8Array.from(ep.ciphertext);
  const data = cipher.decrypt(ciphertext);
  const decoded = decodePassword(data);
  if (!decoded) {
    return {result: null, error: null};
  }
  return {result: decoded!, error: null};
}

function send(ep: EP, client: Client) {
  const secret = client.secret;
  if (!secret) {
    return {result: null, error: null};
  }
  const hash = blake3(secret);
  const key = hash.slice(0, 32);
  if (!ep.nonce) {
    return {result: null, error: null};
  }
  const nonce = randomBytes(24);
  const cipher = xchacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(Uint8Array.from(ep.ciphertext));
  const epr: EP = {
    ciphertext: ciphertext,
    nonce: ep.nonce,
    nonce2: nonce,
  }
  return {result: epr, error: null};
}

function encrypt(pass: Password, client: Client) {
  const passb = encodePassword(pass);
  if (!passb) {
    return {result: null, error: "Invalid password"};
  }
  const hash = blake3(client.ky_q);
  const key = hash.slice(0, 32);
  const nonce = randomBytes(24);
  const cipher = xchacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(passb!);
  const ep: EP = {
    ciphertext: ciphertext,
    nonce: nonce,
    nonce2: null,
  }
  return {result: ep, error: null};
}

export async function update_pass(uuid: Uuid, uuid2: Uuid, pass: Password, client: Client) {
  const encrypted = encrypt(pass, client);
  if (!encrypted.result) {
    return {result: null, error: encrypted.error};
  }
  const eq = send(encrypted.result, client);
  if (!eq.result) {
    return {result: null, error: eq.error};    
  }     
  const truer = {ciphertext: Array.from(eq.result.ciphertext), nonce: Array.from(eq.result.nonce), nonce2: Array.from(eq.result.nonce2!)};
  const res = await fetch(API_URL + 'update_pass_json/' + uuidToStr(uuid) + '/' + uuidToStr(uuid2), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(truer),
  });
  if (!res.ok) {
    return {result: null, error: res.statusText};
  }
  const result = await res.json();
  return {result: result, error: null};
}

export async function create_pass(uuid: Uuid, pass: Password, client: Client) {
  const encrypted = encrypt(pass, client);
  if (!encrypted.result) {
    return {result: null, error: encrypted.error};
  }
  const eq = send(encrypted.result, client);
  if (!eq.result) {
    return {result: null, error: eq.error};    
  }     
  const truer = {ciphertext: Array.from(eq.result.ciphertext), nonce: Array.from(eq.result.nonce), nonce2: Array.from(eq.result.nonce2!)};
  const res = await fetch(API_URL + 'create_pass_json/' + uuidToStr(uuid), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(truer),
  });
  if (!res.ok) {
    return {result: null, error: res.statusText};
  }
  const result = await res.json();
  return {result: result, error: null};
}

export async function delete_pass(uuid: Uuid, uuid2: Uuid, client: Client) {
  const res = await fetch(API_URL + 'delete_pass_json/' + uuidToStr(uuid) + '/' + uuidToStr(uuid2));
  if (!res.ok) {
    return {result: null, error: res.statusText};
  }
  const result = await res.json();
  return {result: result, error: null};
}
