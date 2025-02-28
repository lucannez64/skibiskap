import {
  type Client,
  decodePassword,
  encodePassword,
  type EP,
  type Password,
  type Uuid,
  uuidToStr,
  type ClientEx,
  type CK,
  type KyPublicKey,
  type DiPublicKey
} from "./decoder.js";
import { BincodeEncoder, type ClientEx as ClientEx2, type Client as Client2, encodeExampleClientEx } from "./decoder2";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem";
import { blake3 } from "@noble/hashes/blake3";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { parse as uuidParse } from 'uuid';

// Utiliser une URL relative pour que le proxy Vite fonctionne correctement
const API_URL = "/api/";

/**
 * Structure pour un mot de passe partagé
 */
interface SharedPass {
  kem_ct: Uint8Array;
  ep: EP;
}

interface ReceivedCK {
  email: string;
  id: string | null;
  ky_p: {bytes: Uint8Array};
  di_p: {bytes: Uint8Array};
}

/**
 * Crée un nouveau compte utilisateur
 * @param email Email de l'utilisateur
 * @returns Un objet contenant le ClientEx généré et un fichier à télécharger, ou une erreur
 */
export async function create_account(email: string) {
  try {
    // Générer les clés pour le client
    const ky_p = ml_kem1024.keygen();
    const ky_q = ml_kem1024.keygen();
    const { publicKey: di_p, secretKey: di_q } = ml_dsa87.keygen(randomBytes(32));
    const secret = randomBytes(32);

    // Créer un UUID pour l'utilisateur
    // Créer le client
    const client: Client2 = {
      ky_p: {data: ky_p.publicKey},
      ky_q: {data: ky_q.secretKey},
      di_p: {data: di_p},
      di_q: {data: di_q},
      secret
    };

    const client2: Client = {
      ky_p: ky_p.publicKey,
      ky_q: ky_q.secretKey,
      di_p: di_p,
      di_q: di_q,
      secret
    };

    // Créer le ClientEx
    const clientEx: ClientEx2 = {
      c: client,
      id: {
        email,
        id: null,
        ky_p: {data: ky_p.publicKey},
        di_p: {data: di_p}
      }
    };

    // Encoder le ClientEx pour le téléchargement

    
    // Créer l'objet CK selon le format attendu par le serveur
    // Notez que dans le modèle Rust, id est Option<Uuid>, donc nous pouvons l'envoyer directement
    const cK = {
      email,
      id: null,
      ky_p: {bytes: Array.from(ky_p.publicKey)},
      di_p: {bytes: Array.from(di_p)}
    }
    
    // Enregistrer l'utilisateur sur le serveur
    const response = await fetch(API_URL + "create_user_json/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(cK),
    });
    const encoder = new BincodeEncoder();

    const r: ReceivedCK = await response.json();
    const clientEx2: ClientEx2 = {
      c: client,
      id: {
        email,
        id: BincodeEncoder.createUuid(r.id!),
        ky_p: {data: r.ky_p.bytes},
        di_p: {data: r.di_p.bytes}
      }
    }

    const clientEx3: ClientEx = {
      c: client2,
      id: {
        email,
        id: {bytes: BincodeEncoder.createUuid(r.id!).bytes},
        ky_p: r.ky_p.bytes,
        di_p: r.di_p.bytes
      }
    }
    console.log(clientEx2);

    if (!response.ok) {
      return { 
        clientEx: null, 
        encodedFile: null, 
        error: `Erreur lors de l'enregistrement: ${response.statusText}` 
      };
    }
  
    const encodedClientEx = encoder.encodeClientEx(clientEx2);
    console.log(encodeExampleClientEx());
    console.log(encodedClientEx);
    return { 
      clientEx: clientEx3, 
      encodedFile: encodedClientEx, 
      error: null 
    };
  } catch (error) {
    return { 
      clientEx: null, 
      encodedFile: null, 
      error: `Erreur lors de la création du compte: ${error instanceof Error ? error.message : String(error)}` 
    };
  }
}

export async function auth(uuid: Uuid, client: Client) {
  const response = await fetch(API_URL + "challenge_json/" + uuidToStr(uuid));
  if (!response.ok) {
    return { result: null, client: null, error: response.statusText };
  }
  const challenge = await response.json();

  const challengeBytes = Uint8Array.from(challenge);
  const signature = ml_dsa87.sign(client.di_q, challengeBytes);
  const signArray = Array.from(signature);
  const response2 = await fetch(API_URL + "verify_json/" + uuidToStr(uuid), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(signArray),
  });
  if (!response2.ok) {
    return { result: null, client: null, error: response2.statusText };
  }
  const response3 = await fetch(API_URL + "sync_json/" + uuidToStr(uuid));
  if (!response3.ok) {
    return { result: null, shared: null, error: response3.statusText };
  }
  const result2 = Uint8Array.from(await response3.json());
  const shared = ml_kem1024.decapsulate(result2, client.ky_q);
  client.secret = shared;

  return { result: response2, client: client, error: null };
}

export async function get_all(uuid: Uuid, client: Client): Promise<{result: [Password[], Uuid[]]|null, shared: [Password[], Uuid[], Uuid[]]|null, error: string|null}> {
  const response = await fetch(API_URL + "send_all_json/" + uuidToStr(uuid));
  if (!response.ok) {
    return { result: null, shared: null, error: response.statusText };
  }
  const result = await response.json();
  console.log(result);
  const secretKey = client.secret && blake3(client.secret).slice(0, 32);
  const kyqKey = blake3(client.ky_q).slice(0, 32);
  const passwordsPromises = result.map(async (item: [EP, Uuid]) => {
    const [ep, uuid] = item;
    const { result: decrypted, error} = decryptCredential(ep, secretKey, kyqKey);
    if (error) {
      console.error(error);
    }
    return [decrypted, uuid];
  });
  const passwords = await Promise.all(passwordsPromises);
  
  const sharedResponse = await fetch(API_URL + "get_shared_pass_json/" + uuidToStr(uuid));
  if (!sharedResponse.ok) {
    return { 
      result: [passwords.map(p => p[0]), passwords.map(p => p[1])] as [Password[], Uuid[]], 
      shared: null, 
      error: sharedResponse.statusText 
    };
  }
  
  const sharedResult = await sharedResponse.json();
  const sharedPasswordsPromises = sharedResult.map(async (item: [SharedPass, Uuid, Uuid]) => {
    const [sharedPass, ownerUuid, passUuid] = item;
    
    const sharedPassObj: SharedPass = {
      kem_ct: Uint8Array.from(sharedPass.kem_ct),
      ep: {
        ciphertext: Uint8Array.from(sharedPass.ep.ciphertext),
        nonce: Uint8Array.from(sharedPass.ep.nonce),
        nonce2: sharedPass.ep.nonce2 ? Uint8Array.from(sharedPass.ep.nonce2) : null
      }
    };
    
    const { result: decrypted, error } = decrypt_shared(sharedPassObj, client);
    if (error) {
      console.error(error);
    }
    return [decrypted, ownerUuid, passUuid];
  });
  
  const sharedPasswords = await Promise.all(sharedPasswordsPromises);
  
  return { 
    result: [passwords.map(p => p[0]), passwords.map(p => p[1])] as [Password[], Uuid[]], 
    shared: [
      sharedPasswords.map(p => p[0]), 
      sharedPasswords.map(p => p[1]), 
      sharedPasswords.map(p => p[2])
    ] as [Password[], Uuid[], Uuid[]], 
    error: null 
  };
}

function decryptCredential(ep: EP, secretKey: Uint8Array | null, kyqKey: Uint8Array): { result: Password | null, error: string | null } {
  if (!secretKey) {
    return { result: null, error: "Missing client.secret" };
  }
  if (!ep.nonce2) {
    return { result: null, error: "Missing nonce2" };
  }
  const nonce2 = ep.nonce2 instanceof Uint8Array ? ep.nonce2.slice(0, 24) : Uint8Array.from(ep.nonce2).slice(0, 24);
  const chacha = xchacha20poly1305(secretKey, nonce2);
  const ciphertext1 = ep.ciphertext instanceof Uint8Array ? ep.ciphertext : Uint8Array.from(ep.ciphertext);
  const decryptedIntermediate = chacha.decrypt(ciphertext1);
  const nonce = ep.nonce instanceof Uint8Array ? ep.nonce : Uint8Array.from(ep.nonce);
  const cipher = xchacha20poly1305(kyqKey, nonce);
  const finalDecrypted = cipher.decrypt(decryptedIntermediate);
  const decoded = decodePassword(finalDecrypted);
  return decoded ? { result: decoded, error: null } : { result: null, error: "Decoding failed" };
}

function send(ep: EP, client: Client) {
  const secret = client.secret;
  if (!secret) {
    return { result: null, error: null };
  }
  const hash = blake3(secret);
  const key = hash.slice(0, 32);
  if (!ep.nonce) {
    return { result: null, error: null };
  }
  const nonce = randomBytes(24);
  const cipher = xchacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(Uint8Array.from(ep.ciphertext));
  const epr: EP = {
    ciphertext: ciphertext,
    nonce: ep.nonce,
    nonce2: nonce,
  };
  return { result: epr, error: null };
}

function encrypt(pass: Password, client: Client) {
  const passb = encodePassword(pass);
  if (!passb) {
    return { result: null, error: "Invalid password" };
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
  };
  return { result: ep, error: null };
}

export async function update_pass(
  uuid: Uuid,
  uuid2: Uuid,
  pass: Password,
  client: Client,
) {
  const encrypted = encrypt(pass, client);
  if (!encrypted.result) {
    return { result: null, error: encrypted.error };
  }
  const eq = send(encrypted.result, client);
  if (!eq.result) {
    return { result: null, error: eq.error };
  }
  const truer = {
    ciphertext: Array.from(eq.result.ciphertext),
    nonce: Array.from(eq.result.nonce),
    nonce2: Array.from(eq.result.nonce2!),
  };
  const res = await fetch(
    API_URL + "update_pass_json/" + uuidToStr(uuid) + "/" + uuidToStr(uuid2),
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(truer),
    },
  );
  if (!res.ok) {
    return { result: null, error: res.statusText };
  }
  const result = await res.json();
  return { result: result, error: null };
}

export async function create_pass(uuid: Uuid, pass: Password, client: Client) {
  const encrypted = encrypt(pass, client);
  if (!encrypted.result) {
    return { result: null, error: encrypted.error };
  }
  const eq = send(encrypted.result, client);
  if (!eq.result) {
    return { result: null, error: eq.error };
  }
  const truer = {
    ciphertext: Array.from(eq.result.ciphertext),
    nonce: Array.from(eq.result.nonce),
    nonce2: Array.from(eq.result.nonce2!),
  };
  const res = await fetch(API_URL + "create_pass_json/" + uuidToStr(uuid), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(truer),
  });
  if (!res.ok) {
    return { result: null, error: res.statusText };
  }
  const result = await res.json();
  return { result: result, error: null };
}

export async function delete_pass(uuid: Uuid, uuid2: Uuid, client: Client) {
  const res = await fetch(
    API_URL + "delete_pass_json/" + uuidToStr(uuid) + "/" + uuidToStr(uuid2),
  );
  if (!res.ok) {
    return { result: null, error: res.statusText };
  }
  const result = await res.json();
  return { result: result, error: null };
}

/**
 * Chiffre un mot de passe pour le partage avec un autre utilisateur
 * @param {Password} password - Le mot de passe à partager
 * @param {Uint8Array} recipientPublicKey - La clé publique du destinataire
 * @param {Client} client - Le client actuel
 * @returns {SharedPass|null} Le mot de passe partagé chiffré ou null en cas d'erreur
 */
function share_encrypt(password: Password, recipientPublicKey: Uint8Array, client: Client): { result: SharedPass | null, error: string | null } {
  try {
    // Chiffrer le mot de passe avec la clé privée du client
    const { result: encryptedPass, error } = encrypt(password, client);
    if (!encryptedPass || error) {
      return { result: null, error: error || "Échec du chiffrement du mot de passe" };
    }

    // Générer une clé partagée avec la clé publique du destinataire
    const { cipherText, sharedSecret } = ml_kem1024.encapsulate(recipientPublicKey);
    
    // Chiffrer le mot de passe avec la clé partagée
    const secretKey = blake3(sharedSecret).slice(0, 32);
    const nonce = randomBytes(24);
    const cipher = xchacha20poly1305(secretKey, nonce);
    
    // Convertir l'EP en tableau d'octets pour le chiffrement
    const epBytes = encodePassword(password);
    if (!epBytes) {
      return { result: null, error: "Échec de l'encodage du mot de passe" };
    }
    
    const ciphertextEP = cipher.encrypt(epBytes);
    
    // Créer l'EP chiffré
    const sharedEP: EP = {
      ciphertext: ciphertextEP,
      nonce: nonce,
      nonce2: null
    };
    
    // Créer le SharedPass
    const sharedPass: SharedPass = {
      kem_ct: cipherText,
      ep: sharedEP
    };
    
    return { result: sharedPass, error: null };
  } catch (e) {
    return { result: null, error: e instanceof Error ? e.message : "Erreur inconnue" };
  }
}

/**
 * Déchiffre un mot de passe partagé
 * @param {SharedPass} sharedPass - Le mot de passe partagé chiffré
 * @param {Client} client - Le client actuel
 * @returns {Password|null} Le mot de passe déchiffré ou null en cas d'erreur
 */
function decrypt_shared(sharedPass: SharedPass, client: Client): { result: Password | null, error: string | null } {
  try {
    // Décapsuler la clé partagée avec la clé privée du client
    const sharedSecret = ml_kem1024.decapsulate(sharedPass.kem_ct, client.ky_q);
    
    // Dériver la clé de chiffrement
    const secretKey = blake3(sharedSecret).slice(0, 32);
    
    // Déchiffrer l'EP
    if (!sharedPass.ep.nonce) {
      return { result: null, error: "Nonce manquant dans l'EP partagé" };
    }
    
    const nonce = sharedPass.ep.nonce instanceof Uint8Array 
      ? sharedPass.ep.nonce 
      : Uint8Array.from(sharedPass.ep.nonce);
    
    const cipher = xchacha20poly1305(secretKey, nonce);
    const ciphertext = sharedPass.ep.ciphertext instanceof Uint8Array 
      ? sharedPass.ep.ciphertext 
      : Uint8Array.from(sharedPass.ep.ciphertext);
    
    const decryptedBytes = cipher.decrypt(ciphertext);
    
    // Décoder le mot de passe
    const password = decodePassword(decryptedBytes);
    if (!password) {
      return { result: null, error: "Échec du décodage du mot de passe partagé" };
    }
    
    return { result: password, error: null };
  } catch (e) {
    return { result: null, error: e instanceof Error ? e.message : "Erreur inconnue" };
  }
}

/**
 * Partage un mot de passe avec un autre utilisateur
 * @param {Uuid} ownerUuid - UUID du propriétaire du mot de passe
 * @param {Uuid} passUuid - UUID du mot de passe à partager
 * @param {Uuid} recipientUuid - UUID du destinataire
 * @param {Client} client - Le client actuel
 * @param {Uint8Array} recipientPublicKey - La clé publique du destinataire
 * @param {Password} password - Le mot de passe à partager
 * @returns {Promise<{result: string|null, error: string|null}>} Résultat de l'opération
 */
export async function share_pass(
  ownerUuid: Uuid,
  passUuid: Uuid,
  recipientUuid: Uuid,
  client: Client,
  recipientPublicKey: Uint8Array,
  password: Password
): Promise<{result: string|null, error: string|null}> {
  // Chiffrer le mot de passe pour le partage
  const { result: sharedPass, error } = share_encrypt(password, recipientPublicKey, client);
  if (!sharedPass || error) {
    return { result: null, error: error || "Échec du chiffrement pour le partage" };
  }
  
  // Convertir le SharedPass en format JSON pour l'API
  const sharedPassJson = {
    kem_ct: Array.from(sharedPass.kem_ct),
    ep: {
      ciphertext: Array.from(sharedPass.ep.ciphertext),
      nonce: Array.from(sharedPass.ep.nonce),
      nonce2: sharedPass.ep.nonce2 ? Array.from(sharedPass.ep.nonce2) : null
    }
  };
  
  // Envoyer la requête au serveur
  const res = await fetch(
    API_URL + "share_pass_json/" + 
    uuidToStr(ownerUuid) + "/" + 
    uuidToStr(passUuid) + "/" + 
    uuidToStr(recipientUuid),
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(sharedPassJson),
    }
  );
  
  if (!res.ok) {
    return { result: null, error: res.statusText };
  }
  
  const result = await res.json();
  return { result, error: null };
}

/**
 * Annule le partage d'un mot de passe
 * @param {Uuid} ownerUuid - UUID du propriétaire du mot de passe
 * @param {Uuid} passUuid - UUID du mot de passe
 * @param {Uuid} recipientUuid - UUID du destinataire
 * @returns {Promise<{result: string|null, error: string|null}>} Résultat de l'opération
 */
export async function unshare_pass(
  ownerUuid: Uuid,
  passUuid: Uuid,
  recipientUuid: Uuid
): Promise<{result: string|null, error: string|null}> {
  const res = await fetch(
    API_URL + "unshare_pass_json/" + 
    uuidToStr(ownerUuid) + "/" + 
    uuidToStr(passUuid) + "/" + 
    uuidToStr(recipientUuid),
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      }
    }
  );
  
  if (!res.ok) {
    return { result: null, error: res.statusText };
  }
  
  const result = await res.json();
  return { result, error: null };
}

/**
 * Récupère un mot de passe partagé
 * @param {Uuid} recipientUuid - UUID du destinataire
 * @param {Uuid} ownerUuid - UUID du propriétaire du mot de passe
 * @param {Uuid} passUuid - UUID du mot de passe
 * @param {Client} client - Le client actuel
 * @returns {Promise<{result: Password|null, error: string|null}>} Le mot de passe déchiffré ou une erreur
 */
export async function get_shared_pass(
  recipientUuid: Uuid,
  ownerUuid: Uuid,
  passUuid: Uuid,
  client: Client
): Promise<{result: Password|null, error: string|null}> {
  const res = await fetch(
    API_URL + "get_shared_pass_json/" + 
    uuidToStr(recipientUuid) + "/" + 
    uuidToStr(ownerUuid) + "/" + 
    uuidToStr(passUuid)
  );
  
  if (!res.ok) {
    return { result: null, error: res.statusText };
  }
  
  const sharedPassJson = await res.json();
  
  // Convertir le JSON en SharedPass
  const sharedPass: SharedPass = {
    kem_ct: Uint8Array.from(sharedPassJson.kem_ct),
    ep: {
      ciphertext: Uint8Array.from(sharedPassJson.ep.ciphertext),
      nonce: Uint8Array.from(sharedPassJson.ep.nonce),
      nonce2: sharedPassJson.ep.nonce2 ? Uint8Array.from(sharedPassJson.ep.nonce2) : null
    }
  };
  
  // Déchiffrer le mot de passe partagé
  const { result, error } = decrypt_shared(sharedPass, client);
  return { result, error };
}
