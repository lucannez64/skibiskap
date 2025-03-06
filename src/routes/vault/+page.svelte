<script lang="ts">
  // Our sample list of credentials
  import { onMount, onDestroy } from "svelte";
  import { goto } from "$app/navigation";
  import { clientex, client } from "../stores";
  import { get_all, update_pass, delete_pass, create_pass, share_pass, get_shared_by_user, get_shared_by_user_emails, get_emails_from_uuids, get_uuid_from_email, unshare_pass, ShareStatus, accept_shared_pass, reject_shared_pass } from "$lib/client";
  import { from_uri, generate } from "$lib/otp";
  import * as pkg from "uuid-tool";
  import Plus from "lucide-svelte/icons/plus";
  import SecureLS from "secure-ls";
  import X from "lucide-svelte/icons/x";
  import { zxcvbn } from '@zxcvbn-ts/core';
  import { writable, get, derived } from "svelte/store";
  import Search from "lucide-svelte/icons/search";
  import Upload from "lucide-svelte/icons/upload";
  import { translations, currentLang, t } from "$lib/i18n";
  const { Uuid } = pkg;
	import { uuidToStr, type Password, type Uuid as UuidType } from "$lib/decoder";
  import type { SharedByUserEmail } from "$lib/client";

  // Store pour la langue actuelle
  let lang: 'fr' | 'en' = 'fr'; // Valeur par défaut
  
  // S'abonner aux changements de langue
  currentLang.subscribe((value) => {
    lang = value;
  });
  
  // Fonction pour changer de langue
  function toggleLanguage() {
    currentLang.update(current => current === 'fr' ? 'en' : 'fr');
  }

  // Définition des types
  interface Credential {
    id: number;
    service: string;
    username: string;
    uuid: string;
    password: string;
    otp: string | null;
    twoFA: string | null;
    intervalId?: number | NodeJS.Timeout | null;
    sharedBy?: string;
    owneremail?: string;
    favicon?: string;
    pending?: boolean;
    ownerUuid?: any;
    passUuid?: any;
  }

  interface EditedRecord {
    id?: number;
    service?: string;
    username?: string;
    uuid?: string;
    password?: string;
    otp?: string | null;
    twoFA?: string | null;
  }

  interface PendingCredential {
    owneremail: string;
    passUuid: UuidType;
    ownerUuid: UuidType;
    credential: Credential;
  }

  interface PendingTask {
    [key: number]: (result: {url: string, passwordStrength: any}) => void;
  }

  // Configuration du générateur de mot de passe
  interface PasswordGeneratorConfig {
    length: number;
    includeUppercase: boolean;
    includeLowercase: boolean;
    includeNumbers: boolean;
    includeSymbols: boolean;
    excludeSimilarChars: boolean;
  }

  // Valeurs par défaut pour le générateur de mot de passe
  const defaultPasswordConfig: PasswordGeneratorConfig = {
    length: 16,
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    includeSymbols: true,
    excludeSimilarChars: false
  };

  // Configuration actuelle du générateur
  let passwordConfig = { ...defaultPasswordConfig };
  
  // Fonction pour générer un mot de passe aléatoire
  function generatePassword(config: PasswordGeneratorConfig): string {
    const uppercaseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercaseChars = 'abcdefghijklmnopqrstuvwxyz';
    const numberChars = '0123456789';
    const symbolChars = '!@#$%^&*()_+~`|}{[]:;?><,./-=';
    const similarChars = 'il1Lo0O';
    
    let availableChars = '';
    
    if (config.includeUppercase) availableChars += uppercaseChars;
    if (config.includeLowercase) availableChars += lowercaseChars;
    if (config.includeNumbers) availableChars += numberChars;
    if (config.includeSymbols) availableChars += symbolChars;
    
    if (config.excludeSimilarChars) {
      for (const char of similarChars) {
        availableChars = availableChars.replace(char, '');
      }
    }
    
    if (availableChars.length === 0) {
      // Si aucun caractère n'est sélectionné, utiliser les lettres minuscules par défaut
      availableChars = lowercaseChars;
    }
    
    let password = '';
    const availableCharsLength = availableChars.length;
    
    for (let i = 0; i < config.length; i++) {
      const randomIndex = Math.floor(Math.random() * availableCharsLength);
      password += availableChars[randomIndex];
    }
    
    return password;
  }
  
  // Fonction pour évaluer la force du mot de passe
  function evaluatePasswordStrength(password: string): { score: number, color: string, text: string } {
    if (!password) {
      return { score: 0, color: '#e53e3e', text: t('passwordStrengthVeryWeak', lang) || 'Très faible' };
    }
    
    const result = zxcvbn(password);
    const score = result.score; // 0-4
    
    let color = '';
    let text = '';
    
    switch (score) {
      case 0:
        color = '#e53e3e'; // Rouge
        text = t('passwordStrengthVeryWeak', lang) || 'Très faible';
        break;
      case 1:
        color = '#dd6b20'; // Orange
        text = t('passwordStrengthWeak', lang) || 'Faible';
        break;
      case 2:
        color = '#d69e2e'; // Jaune
        text = t('passwordStrengthMedium', lang) || 'Moyen';
        break;
      case 3:
        color = '#38a169'; // Vert clair
        text = t('passwordStrengthStrong', lang) || 'Fort';
        break;
      case 4:
        color = '#2f855a'; // Vert foncé
        text = t('passwordStrengthVeryStrong', lang) || 'Très fort';
        break;
    }
    
    return { score, color, text };
  }
  
  // Variables pour le générateur de mot de passe
  let showPasswordGenerator = false;
  let showEditPasswordGenerator = false;
  let generatedPassword = '';
  let passwordStrength = { score: 0, color: '#e53e3e', text: t('passwordStrengthVeryWeak', lang) || 'Très faible' };

  // Création d'un store pour les identifiants
  const credentialsStore = writable<Credential[]>([]);
  const pendingCredentialsStore = writable<PendingCredential[]>([]);
  // Création d'un store dérivé pour les identifiants filtrés
  let searchTerm = "";
  const filteredCredentialsStore = derived(
    [credentialsStore, writable(searchTerm)],
    ([$credentials, $searchTerm]) => {
      return $credentials
        .sort((a, b) => a.service.localeCompare(b.service) || a.username.localeCompare(b.username))
        .filter((c) => c.service.toLowerCase().includes($searchTerm.toLowerCase()) || c.username.toLowerCase().includes($searchTerm.toLowerCase()));
    }
  );

  let credentials: Credential[] = [];
  $: filteredCredentials = credentials
    .sort((a, b) => a.service.localeCompare(b.service) || a.username.localeCompare(b.username))
    .filter((c) => {
      // Extraire les filtres spéciaux et le terme de recherche réel
      const hasSharedFilter = searchTerm.includes("!s");
      const hasSharedByMeFilter = searchTerm.includes("!m");
      
      // Extraire le terme de recherche après avoir retiré les filtres
      let actualSearchTerm = searchTerm
        .replace("!s", "")
        .replace("!m", "")
        .trim()
        .toLowerCase();
      
      // Si aucun filtre spécial, recherche normale
      if (!hasSharedFilter && !hasSharedByMeFilter) {
        return c.service.toLowerCase().includes(actualSearchTerm) || c.username.toLowerCase().includes(actualSearchTerm);
      }
      
      // Filtre pour mots de passe partagés avec l'utilisateur
      if (hasSharedFilter && !hasSharedByMeFilter) {
        return c.sharedBy && c.service.toLowerCase().includes(actualSearchTerm);
      }
      
      // Filtre pour mots de passe partagés par l'utilisateur
      if (hasSharedByMeFilter && !hasSharedFilter) {
        return !c.sharedBy && 
               sharedPasswordEmails.has(c.uuid) && 
               (sharedPasswordEmails.get(c.uuid)?.emails?.length ?? 0) > 0 &&
               c.service.toLowerCase().includes(actualSearchTerm);
      }
      
      // Les deux filtres ensemble
      return ((c.sharedBy) || 
             (!c.sharedBy && sharedPasswordEmails.has(c.uuid) && 
             (sharedPasswordEmails.get(c.uuid)?.emails?.length ?? 0) > 0)) &&
             c.service.toLowerCase().includes(actualSearchTerm);
    });
    
  // Pour éviter l'erreur du linter concernant undefined
  function getSharedEmails(uuid: string): string[] {
    return sharedPasswordEmails.get(uuid)?.emails || [];
  }

  let intervals: {[key: number]: number | NodeJS.Timeout} = {}; // Store intervals for each credential
  let loading = true;
  let showAddForm = false;
  let newRecord = {
    service: "",
    username: "",
    password: "",
    otp: "",
    uuid: "",
    twoFA: null,
  };
  
  // Dictionnaire pour stocker les emails avec lesquels chaque mot de passe a été partagé
  let sharedPasswordEmails: Map<string, SharedByUserEmail> = new Map();

  // Variables pour l'importation de fichier JSON
  let importingFile = false;
  let importProgress = 0;
  let importTotal = 0;
  let importError = '';
  let fileInput: HTMLInputElement;

  // Fonction utilitaire pour convertir un UUID en format bytes
  function uuidToBytes(uuidStr: string) {
    try {
      const uuid = new Uuid(uuidStr);
      return {
        bytes: new Uint8Array(uuid.toBytes()),
      };
    } catch (error) {
      console.error("Erreur lors de la conversion de l'UUID", error);
      return null;
    }
  }

  // Fonction memoïsée pour éviter des conversions répétées d'UUID
  const uuidCache = new Map<string, {bytes: Uint8Array}>();
  function memoizedUuidToBytes(uuidStr: string) {
    if (!uuidCache.has(uuidStr)) {
      const result = uuidToBytes(uuidStr);
      if (result) {
        uuidCache.set(uuidStr, result);
      }
      return result;
    }
    return uuidCache.get(uuidStr);
  }

  // Fonction pour vérifier si le client est valide
  function isClientValid() {
    return $clientex && $clientex.id && $clientex.id.id && $client && $client.secret;
  }

  // Pool de workers pour l'évaluation des mots de passe
  class WorkerPool {
    private workers: Worker[] = [];
    private taskId = 0;
    private pendingTasks: PendingTask = {};
    
    constructor(numWorkers: number) {
      for (let i = 0; i < numWorkers; i++) {
        const worker = new Worker("passwordWorker.js", { type: "module" });
        worker.onmessage = this.handleMessage.bind(this);
        this.workers.push(worker);
      }
    }
    
    private handleMessage(event: MessageEvent) {
      const { taskId, url, passwordStrength } = event.data;
      if (this.pendingTasks[taskId]) {
        this.pendingTasks[taskId]({url, passwordStrength});
        delete this.pendingTasks[taskId];
      }
    }
    
    evaluatePassword(password: string, url: string) {
      return new Promise<{url: string, passwordStrength: any}>((resolve) => {
        const currentTaskId = this.taskId++;
        this.pendingTasks[currentTaskId] = resolve;
        const worker = this.workers[Math.floor(Math.random() * this.workers.length)];
        worker.postMessage({ taskId: currentTaskId, password, url });
      });
    }
    
    terminate() {
      this.workers.forEach(worker => worker.terminate());
      this.workers = [];
      this.pendingTasks = {};
    }
  }

  onMount (async () => {
    if (navigator.language.startsWith("fr") || navigator.language.startsWith("en")) {
      if (navigator.language.startsWith("fr")) {
        currentLang.set('fr');
      } else {
        currentLang.set('en');
      }
    }


    // Initialisation du client
    if (!isClientValid()) {
      const ls = new SecureLS({ encodingType: "aes" });
      const sessionclient = ls.get("clientex");
      if (sessionclient) {
        const p = sessionclient;
        const cc = {
          ky_p: Uint8Array.from(p.c.ky_p),
          ky_q: Uint8Array.from(p.c.ky_q),
          di_p: Uint8Array.from(p.c.di_p),
          di_q: Uint8Array.from(p.c.di_q),
          secret: Uint8Array.from(p.c.secret),
        }
        const id = {
          email: p.id.email,
          id: {
            bytes: Uint8Array.from(p.id.id.bytes),
          },
          ky_p: Uint8Array.from(p.id.ky_p),
          di_p: p.id.di_p ? Uint8Array.from(p.id.di_p) : new Uint8Array(0),
        }
        const clieex = {
          c: cc,
          id: id
        }
        clientex.set(clieex);
        client.set(cc);
        if (!isClientValid()) {
          goto('/'); 
          return;
        }
      } else {
        goto('/');
        return;
      }
    }
    
    if (!$clientex || !$clientex.id || !$clientex.id.id) {
      disconnect();
      return;
    }
    
    try {
      const {result: encryptedCredentials, shared: sharedCredentials, error} = await get_all($clientex.id.id, $client!);
      if (error) {
        console.error(error);
        disconnect();
        return;
      }
      if (!encryptedCredentials) {
        disconnect();
        return;
      }

      // Initialisation du pool de workers
      const workerPool = new WorkerPool(4);

      // Traiter les mots de passe normaux
      if (encryptedCredentials[0].length === 0 && (sharedCredentials === null || sharedCredentials[0].length === 0)) {
        loading = false;
        return;
      }
      
      const passwords = encryptedCredentials[0];
      const uuids = encryptedCredentials[1];
      const passwordsAndUuids: [Password, UuidType][] = passwords.map((password, index) => [password, uuids[index]]);

      const processedCredentials = await Promise.all(
        passwordsAndUuids
          .map(async (item, index) => {
            const uuid = item[1];
            const cred = item[0];
            const uuidstr = uuidToStr(uuid);
            if (!cred || typeof cred !== 'object') return null;
            
            // Vérifier que cred est de type Password
            const password = 'password' in cred ? cred.password : '';
            const url = 'url' in cred ? cred.url : '';
            const username = 'username' in cred ? cred.username : '';
            const otp = 'otp' in cred ? cred.otp : null;
            
            try {
              // Évaluation du mot de passe en arrière-plan
              workerPool.evaluatePassword(password, url!).then(({ passwordStrength }) => {
                // Mise à jour silencieuse, pas besoin de mettre à jour l'interface
              }).catch(err => {
                console.error("Erreur d'évaluation du mot de passe:", err);
              });
            } catch (e) {
              console.error("Erreur lors de l'évaluation du mot de passe:", e);
            }
            
            return {
              id: index,
              service: url,
              username,
              uuid: typeof uuidstr === 'string' ? uuidstr : '',
              password,
              otp,
              twoFA: null,
              favicon: getFaviconUrl(url || ''),
              pending: false,
              ownerUuid: null,
              passUuid: null
            } as Credential;
          })
          .filter((item): item is Promise<Credential | null> => item !== null)
      );

      // Traiter les mots de passe partagés si disponibles
      let processedSharedCredentials: Credential[] = [];
      if (sharedCredentials) {
        // Récupérer tous les emails en une seule requête
        const ownerUuids = sharedCredentials[2].map(uuid => {
          const uuidstr = uuidToStr(uuid);
          const uuid3 = new Uuid(uuidstr);
          return {
            bytes: new Uint8Array(uuid3.toBytes()),
          };
        });
        
        const allEmails = await get_emails_from_uuids(ownerUuids);
        const emails = new Map<string, string>();
        
        if (allEmails) {
          sharedCredentials[2].forEach((uuid, index) => {
            const uuidstr = uuidToStr(uuid);
            if (allEmails[index]) {
              emails.set(uuidstr, allEmails[index]);
            }
          });
        }
        
        processedSharedCredentials = sharedCredentials[0]
          .map((cred, index) => {
            if (!cred) return null;
            if (sharedCredentials[3][index] === ShareStatus.Pending) {              // Montrer les informations de base et les boutons pour accepter/rejeter
              const ownerUuid = sharedCredentials[2][index];
              const passUuid = sharedCredentials[1][index];
              const passuuidstr = uuidToStr(passUuid);
              const owneruuidstr = uuidToStr(ownerUuid);
              const owneremail = emails.get(owneruuidstr) || "Utilisateur inconnu";
              const url = 'url' in cred ? cred.url : '';
              const otp = 'otp' in cred ? cred.otp : null;

              pendingCredentialsStore.update(pendingCredentials => [
                ...pendingCredentials,
                {
                  owneremail: owneremail,
                  passUuid: passUuid,
                  ownerUuid: ownerUuid,
                  credential: {
                    service: url!,
                    username: cred.username,
                    uuid: passuuidstr,
                    password: cred.password,
                    otp: otp,
                    twoFA: null,
                    id: index,
                    favicon: getFaviconUrl(url || ''),
                    pending: true,
                    ownerUuid: ownerUuid,
                    passUuid: passUuid
                  }
                }
              ]);
              return null;
            } else if (sharedCredentials[3][index] === ShareStatus.Rejected) {
              return null;
            }
            const ownerUuid = sharedCredentials[2][index];
            const passUuid = sharedCredentials[1][index];
            
            // Vérifier que cred est de type Password
            const password = 'password' in cred ? cred.password : '';
            const url = 'url' in cred ? cred.url : '';
            const username = 'username' in cred ? cred.username : '';
            const otp = 'otp' in cred ? cred.otp : null;
            const passuuidstr = uuidToStr(passUuid);
            const owneruuidstr = uuidToStr(ownerUuid);
            const owneremail = emails.get(owneruuidstr);
            return {
              id: processedCredentials.length + index, // Éviter les conflits d'ID
              service: url,
              username,
              uuid: typeof passuuidstr === 'string' ? passuuidstr : '',
              password,
              otp,
              twoFA: null,
              sharedBy: typeof owneruuidstr === 'string' ? owneruuidstr : '',
              owneremail: typeof owneremail === 'string' ? owneremail : '',
              favicon: getFaviconUrl(url || ''),
              pending: false,
              ownerUuid: ownerUuid,
              passUuid: passUuid
            } as Credential;
          })
          .filter((item): item is Credential => item !== null);
      }

      // Combiner les mots de passe normaux et partagés
      console.log("processedCredentials");
      console.log(processedCredentials);
      console.log("processedSharedCredentials");
      console.log(processedSharedCredentials);
      credentials = [...processedCredentials.filter(Boolean) as Credential[], ...processedSharedCredentials];
      credentialsStore.set(credentials);
      
      // Récupérer les emails partagés
      const sharedByUserEmails = await get_shared_by_user_emails($clientex.id.id!);
      if (sharedByUserEmails) {
        // Remplir le dictionnaire des emails partagés
        sharedByUserEmails.forEach(item => {
          sharedPasswordEmails.set(uuidToStr(item.pass_id), item);
        });
      }
    } catch (error) {
      console.error("Erreur lors de la récupération des données:", error);
      showToast(t('fetchError', lang) || "Erreur lors de la récupération des données");
    } finally {
      loading = false;
    }
  });

  onDestroy(() => {
    // Clear all intervals when the component is unmounted
    Object.values(intervals).forEach((intervalId) => clearInterval(intervalId));
  });
  
  // For inline editing state
  let editingId: number | null = null;
  let editedRecord: EditedRecord = {};

  // Helper: Copy any text to the clipboard
  function copyText(text: string | null) {
    if (text === null) return;
    navigator.clipboard.writeText(text).then(() => {
      showToast(t('copiedToClipboard', lang));
    });
  }

  // Start editing a credential record
  function startEdit(record: Credential) {
    editingId = record.id;
    // Create a shallow copy so the original doesn't change until saved.
    editedRecord = { ...record };
    // Réinitialiser le générateur de mot de passe
    showEditPasswordGenerator = false;
    passwordConfig = { ...defaultPasswordConfig };
    // Évaluer la force du mot de passe actuel
    if (record.password) {
      passwordStrength = evaluatePasswordStrength(record.password);
    }
  }

  // Fonction pour valider le format de l'URL
  function validateUrl(url: string): boolean {
    // Formats acceptés:
    // - domaine simple: google.com
    // - sous-domaine: osu.ppy.sh, casa.klyt.eu
    // - IP avec port: 192.168.1.167:8181, 192.168.1.167:3000
    const urlRegex = /^(([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?)$/;
    return urlRegex.test(url);
  }

  // Save the edited record back into our credentials array
  async function saveEdit() {
    if (editingId === null || !editedRecord.service || !editedRecord.username || !editedRecord.password) {
      return;
    }
    
    // Valider le format de l'URL
    if (!validateUrl(editedRecord.service)) {
      showToast(t('invalidUrl', lang));
      return;
    }
    
    const credential = credentials.find(item => item.id === editingId);
    if (!credential || !credential.uuid) {
      console.error("Identifiant ou UUID manquant");
      return;
    }
    
    const uuid2 = memoizedUuidToBytes(credential.uuid);
    if (!uuid2 || !isClientValid()) {
      console.error("UUID invalide ou client non initialisé");
      return;
    }
    
    const passwordData = {
      password: editedRecord.password || '',
      otp: editedRecord.otp ? editedRecord.otp : null,
      username: editedRecord.username || '',
      url: editedRecord.service || '',
      description: null,
      app_id: null,
    };
    
    try {
      // Mettre à jour le mot de passe
      const response = await update_pass($clientex!.id.id!, uuid2, passwordData, $client!);
      if (response.error) {
        console.error(response.error);
        showToast(t('updateError', lang) + ": " + response.error);
        return;
      }
      
      // Mettre à jour les partages si nécessaire
      if (sharedPasswordEmails.has(credential.uuid)) {
        const sharedInfo = sharedPasswordEmails.get(credential.uuid);
        if (sharedInfo && sharedInfo.emails.length > 0) {
          // Traiter tous les partages en parallèle
          await Promise.all(sharedInfo.emails.map(async (email) => {
            try {
              const recipientUuidStr = await get_uuid_from_email(email);
              if (!recipientUuidStr) return;
              
              const recipientUuid = memoizedUuidToBytes(recipientUuidStr);
              if (!recipientUuid) return;
              
              // Annuler le partage puis le recréer avec les nouvelles données
              await share_pass($clientex!.id.id!, uuid2, email, $client!, passwordData);
            } catch (error) {
              console.error(`Erreur lors de la mise à jour du partage avec ${email}:`, error);
            }
          }));
        }
      }
      
      // Mettre à jour l'interface
      credentials = credentials.map((item) => {
        if (item.id === editingId) {
          return {
            ...item,
            service: editedRecord.service || '',
            username: editedRecord.username || '',
            password: editedRecord.password || '',
            otp: editedRecord.otp || null,
            favicon: getFaviconUrl(editedRecord.service || '')
          };
        }
        return item;
      });
      credentialsStore.set(credentials);
      
      showToast(t('credentialUpdated', lang));
    } catch (error) {
      console.error("Erreur lors de la mise à jour:", error);
      showToast(t('updateError', lang));
    } finally {
      editingId = null;
      editedRecord = {};
    }
  }

  // Cancel the editing process
  function cancelEdit() {
    editingId = null;
    editedRecord = {};
    showEditPasswordGenerator = false;
  }

  async function deleteEdit() {
    if (!editedRecord.uuid || editingId === null) {
      return;
    }
    
    const uuid2 = memoizedUuidToBytes(editedRecord.uuid);
    if (!uuid2 || !isClientValid()) {
      console.error("UUID invalide ou client non initialisé");
      return;
    }
    
    try {
      const response = await delete_pass($clientex!.id.id!, uuid2, $client!);
      if (response.error) {
        console.error(response.error);
        showToast(t('deleteError', lang) + ": " + response.error);
        return;
      }

      credentials = credentials.filter((item) => item.id !== editingId && item.uuid !== editedRecord.uuid);
      credentialsStore.set(credentials);
      showToast(t('credentialDeleted', lang));
    } catch (error) {
      console.error("Erreur lors de la suppression:", error);
      showToast(t('deleteError', lang));
    } finally {
      editingId = null;
      editedRecord = {};
    }
  }

  // Generate a simple 6-digit code for 2FA demonstration
  function generate2FACode(otp: string | null): [string, number] {
    if (!otp) return ["000000", 30]; // Valeur par défaut
    
    const ot2p = from_uri(otp);
    if (!ot2p) return ["000000", 30]; // Valeur par défaut si null
    
    return [generate(ot2p as any), ot2p.period || 30];
  }

  // Variable pour stocker le temps restant pour chaque code OTP
  let remainingTimes: Record<string, number> = {};
  // Variable pour stocker la période de chaque code OTP
  let otpPeriods: Record<string, number> = {};

  // Toggle the two-factor authentication for a record
  function toggle2FA(record: Credential) {
    if (record.twoFA) {
      // Disable 2FA
      if (record.id in intervals) {
        clearInterval(intervals[record.id]);
        delete intervals[record.id];
        delete remainingTimes[record.id];
        delete otpPeriods[record.id];
      }
      
      credentials = credentials.map((item) => 
        item.id === record.id ? { ...item, twoFA: null, intervalId: null } : item
      );
    } else {
      // Enable 2FA
      const [code, period] = generate2FACode(record.otp);
      const periodNum = typeof period === 'number' ? period : 30;
      
      // Stocker la période pour ce code OTP
      otpPeriods[record.id] = periodNum;
      
      // Calculer le temps restant initial
      const initialRemainingTime = (periodNum * 1000) - (Date.now() % (periodNum * 1000));
      remainingTimes[record.id] = Math.floor(initialRemainingTime / 1000);
      
      const intervalId = setInterval(() => {
        const remainingTime = (periodNum * 1000) - (Date.now() % (periodNum * 1000));
        remainingTimes[record.id] = Math.floor(remainingTime / 1000);
        
        if (remainingTime/1000 > periodNum-5) {
          credentials = credentials.map((cred) =>
            cred.id === record.id ? { ...cred, twoFA: generate2FACode(cred.otp)[0] } : cred
          );
        }
      }, 1000);
      
      intervals[record.id] = intervalId;
      
      credentials = credentials.map((item) => 
        item.id === record.id ? { ...item, twoFA: code, intervalId } : item
      );
    }
    
    credentialsStore.set(credentials);
  }
  
  function disconnect() {
    localStorage.clear();
    client.set(undefined);
    clientex.set(undefined);
    goto("/");
  }
  
  // Save a new credential. Adjust this function to integrate your backend logic.
  async function saveNewCredential() {
    // Valider le format de l'URL
    if (!validateUrl(newRecord.service)) {
      showToast(t('invalidUrl', lang));
      return;
    }
    
    if (!isClientValid()) {
      console.error("Client non initialisé");
      return;
    }
    
    const passwordData = {
      password: newRecord.password,
      otp: newRecord.otp ? newRecord.otp : null,
      username: newRecord.username,
      url: newRecord.service,
      description: null,
      app_id: null,
    };
    
    try {
      const response = await create_pass($clientex!.id.id!, passwordData, $client!);
      if (response.error) {
        console.error(response.error);
        showToast(t('createError', lang) + ": " + response.error);
        return;
      }
      
      // Create a new credential with an arbitrary new id
      const newId = credentials.length
        ? Math.max(...credentials.map((cred) => cred.id)) + 1
        : 0;
      
      const newItem: Credential = {
        id: newId,
        service: newRecord.service,
        username: newRecord.username,
        password: newRecord.password,
        otp: newRecord.otp,
        uuid: new Uuid(response.result.bytes).toString(),
        twoFA: null,
        favicon: getFaviconUrl(newRecord.service),
      };
      
      credentials = [...credentials, newItem];
      credentialsStore.set(credentials);
      
      // Reset the form
      newRecord = { 
        service: "",
        username: "",
        password: "",
        otp: "",
        uuid: "",
        twoFA: null
      } as typeof newRecord;
      
      showAddForm = false;
      showToast(t('credentialCreated', lang));
    } catch (error) {
      console.error("Erreur lors de la création:", error);
      showToast(t('createError', lang));
    }
  }
  
  // Variables pour le partage de mot de passe
  let showingShareModal = false;
  let shareUserId = '';
  let shareError = '';
  let isSharing = false;
  let isUnsharing = false;
  let unsharingEmail = ''; // Email en cours d'annulation de partage
  let sharingCredential: Credential | null = null;
  let notificationMessage = '';
  let showNotification = false;
  
  // Fonction pour afficher une notification
  function showToast(message: string) {
    notificationMessage = message;
    showNotification = true;
    setTimeout(() => {
      showNotification = false;
    }, 3000);
  }

  // Fonction pour afficher le modal de partage
  function showShareModal(credential: Credential) {
    sharingCredential = credential;
    showingShareModal = true;
    shareUserId = '';
    shareError = '';
  }
  
  // Fonction pour fermer le modal de partage
  function closeShareModal() {
    showingShareModal = false;
    sharingCredential = null;
  }
  
  // Fonction pour partager un mot de passe
  async function sharePassword() {
    if (!sharingCredential || !shareUserId || shareUserId.trim() === '') {
      shareError = t('invalidEmail', lang);
      return;
    }
    
    isSharing = true;
    shareError = '';
    
    try {
      if (!isClientValid()) {
        throw new Error(t('clientNotInitialized', lang));
      }
      
      const uuid2 = memoizedUuidToBytes(sharingCredential.uuid);
      if (!uuid2) {
        throw new Error(t('invalidUuid', lang));
      }
      
      const passwordData = {
        password: sharingCredential.password,
        otp: sharingCredential.otp,
        username: sharingCredential.username,
        url: sharingCredential.service,
        description: null,
        app_id: null,
      };
      
      const { result, error } = await share_pass(
        $clientex!.id.id!,
        uuid2,
        shareUserId.trim(),
        $client!,
        passwordData
      );
      
      if (error) {
        shareError = error;
        return;
      }
      
      // Mettre à jour la liste des emails partagés
      const currentSharedInfo = sharedPasswordEmails.get(sharingCredential.uuid);
      if (currentSharedInfo) {
        if (!currentSharedInfo.emails.includes(shareUserId.trim())) {
          const updatedEmails = [...currentSharedInfo.emails, shareUserId.trim()];
          const updatedStatuses = [...(currentSharedInfo.statuses || []), ShareStatus.Pending];
          sharedPasswordEmails.set(sharingCredential.uuid, {
            ...currentSharedInfo,
            emails: updatedEmails,
            statuses: updatedStatuses
          });
        }
      } else {
        sharedPasswordEmails.set(sharingCredential.uuid, {
          pass_id: {
            bytes: new Uint8Array(new Uuid(sharingCredential.uuid).toBytes())
          },
          emails: [shareUserId.trim()],
          statuses: [ShareStatus.Pending]
        });
      }
      // Forcer la mise à jour de l'interface
      sharedPasswordEmails = new Map(sharedPasswordEmails);
      
      closeShareModal();
      showToast(t('passwordShared', lang));
    } catch (error) {
      console.error("Erreur lors du partage:", error);
      shareError = t('shareError', lang) + ": " + (error instanceof Error ? error.message : "Erreur inconnue");
    } finally {
      isSharing = false;
    }
  }

  // Fonction pour annuler le partage d'un mot de passe
  async function unsharePassword(email: string) {
    if (!sharingCredential) {
      return;
    }
    
    isUnsharing = true;
    unsharingEmail = email;
    shareError = '';
    
    try {
      if (!isClientValid()) {
        throw new Error(t('clientNotInitialized', lang));
      }
      
      const uuid2 = memoizedUuidToBytes(sharingCredential.uuid);
      if (!uuid2) {
        throw new Error(t('invalidUuid', lang));
      }
      
      // Récupérer l'UUID du destinataire à partir de son email
      const recipientUuidStr = await get_uuid_from_email(email);
      if (!recipientUuidStr) {
        throw new Error(t('userNotFound', lang) + ": " + email);
      }
      
      const recipientUuid = memoizedUuidToBytes(recipientUuidStr);
      if (!recipientUuid) {
        throw new Error(t('invalidRecipientUuid', lang));
      }
      
      // Appeler la fonction d'annulation de partage
      const { result, error } = await unshare_pass(
        $clientex!.id.id!,
        uuid2,
        recipientUuid
      );
      
      if (error) {
        shareError = error;
        return;
      }
      
      // Mettre à jour la liste des emails partagés
      const currentSharedInfo = sharedPasswordEmails.get(sharingCredential.uuid);
      if (currentSharedInfo) {
        const emailIndex = currentSharedInfo.emails.indexOf(email);
        if (emailIndex !== -1) {
          const updatedEmails = currentSharedInfo.emails.filter(e => e !== email);
          const updatedStatuses = currentSharedInfo.statuses ? 
            [...currentSharedInfo.statuses.slice(0, emailIndex), ...currentSharedInfo.statuses.slice(emailIndex + 1)] : 
            [];
          
          if (updatedEmails.length === 0) {
            sharedPasswordEmails.delete(sharingCredential.uuid);
          } else {
            sharedPasswordEmails.set(sharingCredential.uuid, {
              ...currentSharedInfo,
              emails: updatedEmails,
              statuses: updatedStatuses
            });
          }
          
          // Forcer la mise à jour de l'interface
          sharedPasswordEmails = new Map(sharedPasswordEmails);
        }
      }
      
      showToast(t('unshareSuccess', lang) + ": " + email);
    } catch (error) {
      console.error("Erreur lors de l'annulation du partage:", error);
      shareError = t('unshareError', lang) + ": " + (error instanceof Error ? error.message : "Erreur inconnue");
    } finally {
      isUnsharing = false;
      unsharingEmail = '';
    }
  }

  // Fonction pour importer des mots de passe depuis un fichier JSON ou CSV
  async function importPasswords(event: Event) {
    const target = event.target as HTMLInputElement;
    if (!target.files || target.files.length === 0) return;
    
    const file = target.files[0];
    if (!file) return;
    
    try {
      const fileContent = await file.text();
      let passwords: Array<{
        username: string;
        password: string;
        url: string;
        otp: string | null;
      }> = [];
      
      // Déterminer le type de fichier par son extension
      const fileType = file.name.toLowerCase().endsWith('.csv') ? 'csv' : 'json';
      
      if (fileType === 'json') {
        // Traitement du fichier JSON
        const jsonPasswords = JSON.parse(fileContent) as Array<{
          username: string;
          mdp: string;
          name: string;
          otp: string;
        }>;
        
        if (!Array.isArray(jsonPasswords)) {
          throw new Error(t('invalidFileFormat', lang));
        }
        
        // Convertir les mots de passe JSON au format standard
        passwords = jsonPasswords.map(json => ({
          username: json.username,
          password: json.mdp,
          url: json.name,
          otp: json.otp && json.otp.length > 0 ? json.otp : null
        }));
      } else {
        // Traitement du fichier CSV (format Chrome)
        const lines = fileContent.split('\n');
        
        // Vérifier l'en-tête pour s'assurer qu'il s'agit d'un CSV Chrome
        const header = lines[0].toLowerCase();
        if (!header.includes('name') || !header.includes('url') || !header.includes('username') || !header.includes('password')) {
          throw new Error(t('invalidCsvFormat', lang));
        }
        
        // Déterminer les indices des colonnes
        const headerCols = lines[0].split(',');
        const nameIndex = headerCols.findIndex(col => col.toLowerCase().includes('name'));
        const urlIndex = headerCols.findIndex(col => col.toLowerCase().includes('url'));
        const usernameIndex = headerCols.findIndex(col => col.toLowerCase().includes('username'));
        const passwordIndex = headerCols.findIndex(col => col.toLowerCase().includes('password'));
        
        // Parcourir les lignes (en sautant l'en-tête)
        for (let i = 1; i < lines.length; i++) {
          if (!lines[i].trim()) continue; // Ignorer les lignes vides
          
          // Analyser la ligne CSV (gestion des virgules dans les champs entre guillemets)
          const values = parseCSVLine(lines[i]);
          // Convert URL to our url format by extracting domain
          let url = values[urlIndex] || values[nameIndex];
          
          // Remove protocol if present
          if (url.includes('://')) {
            url = url.split('://')[1];
          }
          
          // Remove path and query params if present
          if (url.includes('/')) {
            url = url.split('/')[0];
          }
          
          // Remove port if present
          if (url.includes(':')) {
            const parts = url.split(':');
            // Keep port only if it's an IP address
            if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parts[0])) {
              url = parts[0];
            }
          }
          
          // Validate against our URL format
          const urlRegex = /^(([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?)$/;
          if (!urlRegex.test(url)) {
            // If invalid, try to extract domain
            const domainMatch = url.match(/([a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]\.[a-zA-Z]{2,})/);
            if (domainMatch) {
              url = domainMatch[1];
            }
          }
          if (values.length >= Math.max(nameIndex, urlIndex, usernameIndex, passwordIndex) + 1) {
            passwords.push({
              username: values[usernameIndex],
              password: values[passwordIndex],
              url: values[urlIndex] || values[nameIndex], // Utiliser l'URL ou le nom si l'URL est vide
              otp: null // Chrome n'exporte pas les OTP
            });
          }
        }
      }
      
      if (!isClientValid()) {
        throw new Error(t('clientNotInitialized', lang));
      }
      
      importingFile = true;
      importTotal = passwords.length;
      importProgress = 0;
      
      // Convertir les mots de passe au format Password pour l'API
      const passwordsForApi = passwords.map(pwd => ({
        username: pwd.username,
        password: pwd.password,
        app_id: null,
        description: null,
        url: pwd.url,
        otp: pwd.otp
      }));
      
      // Importer chaque mot de passe
      for (const passwordData of passwordsForApi) {
        try {
          const response = await create_pass($clientex!.id.id!, passwordData, $client!);
          if (response.error) {
            console.error(response.error);
            continue;
          }
          
          // Ajouter le mot de passe importé à la liste
          const newId = credentials.length
            ? Math.max(...credentials.map((cred) => cred.id)) + 1
            : 0;
          
          const newItem: Credential = {
            id: newId,
            service: passwordData.url || '',
            username: passwordData.username,
            password: passwordData.password,
            otp: passwordData.otp,
            uuid: new Uuid(response.result.bytes).toString(),
            twoFA: null,
            favicon: getFaviconUrl(passwordData.url || ''),
          };
          
          credentials = [...credentials, newItem];
        } catch (error) {
          console.error("Erreur lors de l'importation d'un mot de passe:", error);
        }
        
        importProgress++;
      }
      
      credentialsStore.set(credentials);
      showToast(t('importSuccess', lang) + ": " + importProgress + " mot(s) de passe importé(s)");
    } catch (error) {
      console.error("Erreur lors de l'importation:", error);
      importError = t('importError', lang) + ": " + (error instanceof Error ? error.message : "Erreur inconnue");
      showToast(t('importError', lang));
    } finally {
      importingFile = false;
      if (fileInput) fileInput.value = '';
    }
  }
  
  // Fonction pour analyser une ligne CSV en tenant compte des guillemets
  function parseCSVLine(line: string): string[] {
    const result: string[] = [];
    let current = '';
    let inQuotes = false;
    
    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      
      if (char === '"') {
        // Si on trouve un guillemet, on bascule l'état "inQuotes"
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        // Si on trouve une virgule et qu'on n'est pas entre guillemets, on ajoute la valeur courante au résultat
        result.push(current);
        current = '';
      } else {
        // Sinon, on ajoute le caractère à la valeur courante
        current += char;
      }
    }
    
    // Ajouter la dernière valeur
    result.push(current);
    
    return result;
  }

  // Fonction pour obtenir l'URL de l'icône d'un site web
  function getFaviconUrl(domain: string): string {
    // Nettoyer l'URL pour extraire le domaine
    let cleanDomain = domain;
    
    // Supprimer le protocole s'il existe
    if (cleanDomain.includes('://')) {
      cleanDomain = cleanDomain.split('://')[1];
    }
    
    // Supprimer le chemin s'il existe
    if (cleanDomain.includes('/')) {
      cleanDomain = cleanDomain.split('/')[0];
    }
    
    // Utiliser Google Favicon service pour récupérer l'icône
    return `https://www.google.com/s2/favicons?domain=${cleanDomain}&sz=32`;
  }
  
  // Fonction pour gérer les erreurs de chargement d'image
  function handleImageError(event: Event) {
    const target = event.target as HTMLImageElement;
    target.src = 'https://www.google.com/s2/favicons?domain=default&sz=32';
  }

  // Fonction pour gérer la récupération des données
  async function fetchCredentials() {
    if (!client) return;
    
    const clientValue = $client;
    const clientexValue = $clientex;
    if (!clientValue || !clientexValue) return;
    
    loading = true;
    try {
      const {result: encryptedCredentials, shared: sharedCredentials, error} = await get_all(clientexValue.id.id!, clientValue);
      if (error) {
        console.error(error);
        disconnect();
        return;
      }
      if (!encryptedCredentials) {
        disconnect();
        return;
      }

      // Initialisation du pool de workers
      const workerPool = new WorkerPool(4);

      // Traiter les mots de passe normaux
      if (encryptedCredentials[0].length === 0 && (sharedCredentials === null || sharedCredentials[0].length === 0)) {
        loading = false;
        return;
      }
      
      const passwords = encryptedCredentials[0];
      const uuids = encryptedCredentials[1];
      const passwordsAndUuids: [Password, UuidType][] = passwords.map((password, index) => [password, uuids[index]]);

      const processedCredentials = await Promise.all(
        passwordsAndUuids
          .map(async (item, index) => {
            const uuid = item[1];
            const cred = item[0];
            const uuidstr = uuidToStr(uuid);
            if (!cred || typeof cred !== 'object') return null;
            
            // Vérifier que cred est de type Password
            const password = 'password' in cred ? cred.password : '';
            const url = 'url' in cred ? cred.url : '';
            const username = 'username' in cred ? cred.username : '';
            const otp = 'otp' in cred ? cred.otp : null;
            
            try {
              // Évaluation du mot de passe en arrière-plan
              workerPool.evaluatePassword(password, url!).then(({ passwordStrength }) => {
                // Mise à jour silencieuse, pas besoin de mettre à jour l'interface
              }).catch(err => {
                console.error("Erreur d'évaluation du mot de passe:", err);
              });
            } catch (e) {
              console.error("Erreur lors de l'évaluation du mot de passe:", e);
            }
            
            return {
              id: index,
              service: url,
              username,
              uuid: typeof uuidstr === 'string' ? uuidstr : '',
              password,
              otp,
              twoFA: null,
              favicon: getFaviconUrl(url || ''),
              pending: false,
              ownerUuid: null,
              passUuid: null
            } as Credential;
          })
          .filter((item): item is Promise<Credential | null> => item !== null)
      );

      // Traiter les mots de passe partagés si disponibles
      let processedSharedCredentials: Credential[] = [];
      if (sharedCredentials) {
        // Récupérer tous les emails en une seule requête
        const ownerUuids = sharedCredentials[2].map(uuid => {
          const uuidstr = uuidToStr(uuid);
          const uuid3 = new Uuid(uuidstr);
          return {
            bytes: new Uint8Array(uuid3.toBytes()),
          };
        });
        
        const allEmails = await get_emails_from_uuids(ownerUuids);
        const emails = new Map<string, string>();
        
        if (allEmails) {
          sharedCredentials[2].forEach((uuid, index) => {
            const uuidstr = uuidToStr(uuid);
            if (allEmails[index]) {
              emails.set(uuidstr, allEmails[index]);
            }
          });
        }
        
        processedSharedCredentials = sharedCredentials[0]
          .map((cred, index) => {
            if (!cred) return null;
            if (sharedCredentials[3][index] === ShareStatus.Pending) {
              console.log("Pending");
              // Montrer les informations de base et les boutons pour accepter/rejeter
              const ownerUuid = sharedCredentials[2][index];
              const passUuid = sharedCredentials[1][index];
              const passuuidstr = uuidToStr(passUuid);
              const owneruuidstr = uuidToStr(ownerUuid);
              const owneremail = emails.get(owneruuidstr) || "Utilisateur inconnu";
              const url = 'url' in cred ? cred.url : '';
              const otp = 'otp' in cred ? cred.otp : null;

              pendingCredentialsStore.update(pendingCredentials => [
                ...pendingCredentials,
                {
                  owneremail: owneremail,
                  passUuid: passUuid,
                  ownerUuid: ownerUuid,
                  credential: {
                    service: url!,
                    username: cred.username,
                    uuid: passuuidstr,
                    password: cred.password,
                    otp: otp,
                    twoFA: null,
                    id: index,
                    favicon: getFaviconUrl(url || ''),
                    pending: true,
                    ownerUuid: ownerUuid,
                    passUuid: passUuid
                  }
                }
              ]);
              return null;
            }
            const ownerUuid = sharedCredentials[2][index];
            const passUuid = sharedCredentials[1][index];
            
            // Vérifier que cred est de type Password
            const password = 'password' in cred ? cred.password : '';
            const url = 'url' in cred ? cred.url : '';
            const username = 'username' in cred ? cred.username : '';
            const otp = 'otp' in cred ? cred.otp : null;
            const passuuidstr = uuidToStr(passUuid);
            const owneruuidstr = uuidToStr(ownerUuid);
            const owneremail = emails.get(owneruuidstr);
            return {
              id: processedCredentials.length + index, // Éviter les conflits d'ID
              service: url,
              username,
              uuid: typeof passuuidstr === 'string' ? passuuidstr : '',
              password,
              otp,
              twoFA: null,
              sharedBy: typeof owneruuidstr === 'string' ? owneruuidstr : '',
              owneremail: typeof owneremail === 'string' ? owneremail : '',
              favicon: getFaviconUrl(url || ''),
              pending: false,
              ownerUuid: ownerUuid,
              passUuid: passUuid
            } as Credential;
          })
          .filter((item): item is Credential => item !== null);
      }

      // Combiner les mots de passe normaux et partagés
      console.log("processedCredentials");
      console.log(processedCredentials);
      console.log("processedSharedCredentials");
      console.log(processedSharedCredentials);
      credentials = [...processedCredentials.filter(Boolean) as Credential[], ...processedSharedCredentials];
      credentialsStore.set(credentials);
      
      // Récupérer les emails partagés
      const sharedByUserEmails = await get_shared_by_user_emails(clientexValue.id.id!);
      if (sharedByUserEmails) {
        // Remplir le dictionnaire des emails partagés
        sharedByUserEmails.forEach(item => {
          sharedPasswordEmails.set(uuidToStr(item.pass_id), item);
        });
      }
      showToast(t('dataUpdated', lang) || "Données mises à jour");
    } catch (error) {
      console.error("Erreur lors de la récupération des données:", error);
      showToast(t('fetchError', lang) || "Erreur lors de la récupération des données");
    } finally {
      loading = false;
    }
  }

  // Fonction pour accepter un mot de passe partagé
  async function handleAcceptSharedPass(credential: any) {
    if (!credential.ownerUuid || !credential.passUuid || !$client) return;
    
    loading = true;
    try {
      let {error} = await accept_shared_pass($clientex!.id.id!, credential.ownerUuid, credential.passUuid);
      if (error) {
        console.error(t('acceptError', lang), error);
        showToast(t('acceptError', lang) || "Erreur lors de l'acceptation du mot de passe");
        return;
      }
      pendingCredentialsStore.update(pendingCredentials => pendingCredentials.filter(pendingCredential => pendingCredential.passUuid !== credential.passUuid));
      // Rafraîchir les données
      await fetchCredentials();
      showToast(t('passwordAccepted', lang) || "Mot de passe accepté");
    } catch (error) {
      console.error("Erreur lors de l'acceptation du mot de passe:", error);
      showToast(t('acceptError', lang) || "Erreur lors de l'acceptation du mot de passe");
    } finally {
      loading = false;
    }
  }

  // Fonction pour rejeter un mot de passe partagé
  async function handleRejectSharedPass(credential: any) {
    if (!credential.ownerUuid || !credential.passUuid || !$client) return;
    
    loading = true;
    try {
      await reject_shared_pass($clientex!.id.id!, credential.ownerUuid, credential.passUuid);
      
      // Rafraîchir les données
      pendingCredentialsStore.update(pendingCredentials => pendingCredentials.filter(pendingCredential => pendingCredential.passUuid !== credential.passUuid));
      await fetchCredentials();
      showToast(t('passwordRejected', lang) || "Mot de passe rejeté");
    } catch (error) {
      console.error("Erreur lors du rejet du mot de passe:", error);
      showToast(t('rejectError', lang) || "Erreur lors du rejet du mot de passe");
    } finally {
      loading = false;
    }
  }
</script>
<svelte:head>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous">
  <link href="https://fonts.googleapis.com/css2?family=Raleway:wght@400;500;600;700&family=Work+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
</svelte:head>

<style>
  .spinner {
    border: 4px solid rgba(0, 0, 0, 0.1);
    width: 36px;
    height: 36px;
    border-radius: 50%;
    border-left-color: #f2c3c2;
    animation: spin 1s linear infinite;
    margin: auto;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  /* Styles personnalisés pour correspondre à la page principale */
  :global(body) {
    font-family: 'Work Sans', sans-serif;
  }

  h1, h2, h3, button {
    font-family: 'Raleway', sans-serif;
  }

  .card {
    background-color: #ced7e1;
    border-radius: 0.5rem;
    overflow: hidden;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    transition: transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out;
  }
  
  .card:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 8px rgba(0, 0, 0, 0.15);
  }

  .primary-btn {
    background-color: #f2c3c2;
    color: #1d1b21;
    transition: all 0.2s ease-in-out;
  }

  .primary-btn:hover {
    opacity: 0.9;
    transform: translateY(-1px);
  }

  .secondary-btn {
    background-color: #a7f3ae;
    color: #1d1b21;
    transition: all 0.2s ease-in-out;
  }

  .secondary-btn:hover {
    opacity: 0.9;
    transform: translateY(-1px);
  }

  .danger-btn {
    background-color: #b00e0b;
    color: white;
    transition: all 0.2s ease-in-out;
  }

  .danger-btn:hover {
    opacity: 0.9;
    transform: translateY(-1px);
  }

  .neutral-btn {
    background-color: #474b4f;
    color: white;
    transition: all 0.2s ease-in-out;
  }

  .neutral-btn:hover {
    opacity: 0.9;
    transform: translateY(-1px);
  }

  input:focus {
    outline: none;
    box-shadow: 0 0 0 2px #a7f3ae;
  }
  
  .notification {
    animation: fadeInOut 3s ease-in-out;
  }
  
  @keyframes fadeInOut {
    0% { opacity: 0; transform: translateY(-20px); }
    10% { opacity: 1; transform: translateY(0); }
    90% { opacity: 1; transform: translateY(0); }
    100% { opacity: 0; transform: translateY(-20px); }
  }
  
  .copy-btn {
    opacity: 0.6;
    transition: opacity 0.2s ease-in-out;
  }
  
  .copy-btn:hover {
    opacity: 1;
  }
  
  @keyframes pulse {
    0% {
      transform: scale(1);
      opacity: 1;
    }
    50% {
      transform: scale(1.1);
      opacity: 0.8;
    }
    100% {
      transform: scale(1);
      opacity: 1;
    }
  }
  
  .pulse-animation {
    animation: pulse 1s infinite;
  }

  /* Styles responsives */
  @media (max-width: 768px) {
    .max-w-3xl {
      width: 100%;
      padding: 0 10px;
    }
    
    .card {
      padding: 12px !important;
    }
    
    .absolute.top-4.right-4 {
      position: relative;
      top: 0;
      right: 0;
      display: flex;
      justify-content: flex-end;
      margin-bottom: 1rem;
    }
    
    h1.text-3xl {
      font-size: 1.5rem;
      margin-top: 1rem;
    }
    
    .grid-cols-2 {
      grid-template-columns: 1fr;
    }
  }
  
  @media (max-width: 640px) {
    .flex.justify-between.items-start {
      flex-direction: column;
    }
    
    .flex.flex-col.items-end {
      align-items: flex-start;
      margin-top: 1rem;
      width: 100%;
    }
    
    .flex.space-x-2.mt-4 {
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    
    .flex.space-x-3.mt-4 {
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    
    .flex.space-x-2 button {
      flex: 1;
      min-width: 120px;
    }
    
    .fixed.bottom-4.right-4 {
      bottom: 1rem;
      right: 1rem;
    }
    
    .fixed.bottom-4.right-20 {
      bottom: 1rem;
      right: 5rem;
    }
    
    .notification {
      width: calc(100% - 2rem);
      right: 1rem;
      text-align: center;
    }
  }
  
  /* Ajustements pour les petits écrans */
  @media (max-width: 480px) {
    .p-4 {
      padding: 0.5rem;
    }
    
    .card {
      padding: 10px !important;
    }
    
    h3.text-lg {
      font-size: 1rem;
    }
    
    .text-sm {
      font-size: 0.75rem;
    }
    
    .px-4.py-2 {
      padding: 0.5rem 0.75rem;
    }
    
    .flex.items-center.mt-2 {
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    
    .w-10.h-10 {
      width: 2rem;
      height: 2rem;
    }
    
    .card .flex.space-x-2 {
      margin-top: 0.5rem;
    }
    
    .fixed.inset-0 .card {
      width: 90%;
      max-width: none;
    }
  }
</style>

<div class="min-h-screen p-4" style="background-color: #1d1b21; font-family: 'Work Sans', sans-serif;">
  <div class="max-w-3xl mx-auto">
    <!-- Disconnect Button -->
    <div class="absolute top-4 right-4 flex space-x-2">
      <button
        on:click={toggleLanguage}
        class="px-3 py-1 rounded-md text-sm font-medium transition-all duration-200 ease-in-out"
        style="background-color: #474b4f; color: white;"
      >
        {lang === 'fr' ? 'Français' : 'English'}
      </button>
      <button
        on:click={disconnect}
        class="px-3 py-1 rounded-md text-sm font-medium transition-all duration-200 ease-in-out"
        style="background-color: #b00e0b; color: white;"
      >
        {t('logout', lang)}
      </button>
    </div>
    <h1 class="text-3xl font-bold text-center mb-6 text-white" style="font-family: 'Raleway', sans-serif;">
      {t('vault', lang)}
    </h1>

    
    <!-- Loading Animation -->
    {#if loading}
      <div class="flex items-center justify-center my-8">
        <div class="spinner"></div>
      </div>
    {/if}

    {#if !loading}
    <!-- Search -->
    <div class="mb-6">
      <div class="relative">
        <input
          type="text"
          bind:value={searchTerm}
          placeholder={t('search', lang)}
          class="w-full border rounded-lg
                focus:outline-none focus:ring-2 focus:ring-blue-500 pl-10"
          style="background-color: white; border-color: #474b4f; color: #1d1b21;"
        />
        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <Search class="w-5 h-5 text-gray-400" />
        </div>
      </div>
      <div class="text-xs text-white mt-1 italic px-2">
        {t('searchTip', lang) || `Astuce: Utilisez !shared pour voir les mots de passe partagés avec vous, !sharedbyme pour ceux que vous avez partagés.`}
      </div>
      <!-- Boutons de filtre -->
      <div class="flex flex-wrap gap-2 mt-2">
        <button
          on:click={() => {
            if (searchTerm.includes("!s")) {
              searchTerm = searchTerm.replace("!s", "").trim();
            } else {
              searchTerm = (searchTerm + " !s").trim();
            }
          }}
          class="px-3 py-1 rounded-md text-sm font-medium transition-all duration-200 ease-in-out"
          style="background-color: {searchTerm.includes('!s') ? '#a7f3ae' : '#474b4f'}; color: {searchTerm.includes('!s') ? '#1d1b21' : 'white'};"
        >
          {t('sharedWithMe', lang) || 'Partagés avec moi'}
        </button>
        <button
          on:click={() => {
            if (searchTerm.includes("!m")) {
              searchTerm = searchTerm.replace("!m", "").trim();
            } else {
              searchTerm = (searchTerm + " !m").trim();
            }
          }}
          class="px-3 py-1 rounded-md text-sm font-medium transition-all duration-200 ease-in-out"
          style="background-color: {searchTerm.includes('!m') ? '#a7f3ae' : '#474b4f'}; color: {searchTerm.includes('!m') ? '#1d1b21' : 'white'};"
        >
          {t('sharedByMe', lang) || 'Partagés par moi'}
        </button>
      </div>
    </div>

    <!-- Add Credential Button -->
    <div class="mb-6">
      <button
        on:click={() => {
          showAddForm = !showAddForm; 
          if (showAddForm) {
            goto("#add-credential-form");
            // Réinitialiser le générateur de mot de passe
            showPasswordGenerator = false;
            passwordConfig = { ...defaultPasswordConfig };
            passwordStrength = { score: 0, color: '#e53e3e', text: t('passwordStrengthVeryWeak', lang) || 'Très faible' };
          }
        }}
        class="fixed bottom-4 right-4 h-14 w-14 rounded-full shadow-lg transition-transform hover:scale-110 z-10"
        style="background-color: #f2c3c2;"
      >
        <div
          class="flex items-center justify-center h-full w-full rounded-full"
        >
        {#if showAddForm}
          <X class="w-6 h-6 text-zinc-800" />
        {:else}
          <Plus class="w-6 h-6 text-zinc-800" />
        {/if}
        </div>
      </button>
      
      <!-- Bouton d'importation -->
      <button
        on:click={() => fileInput?.click()}
        class="fixed bottom-4 right-20 h-14 w-14 rounded-full shadow-lg transition-transform hover:scale-110 z-10"
        style="background-color: #a7f3ae;"
        title={t('importFromJson', lang)}
      >
        <div class="flex items-center justify-center h-full w-full rounded-full">
          <Upload class="w-6 h-6 text-zinc-800" />
        </div>
      </button>
      <input 
        type="file" 
        accept=".json,.csv" 
        style="display: none;" 
        on:change={importPasswords}
        bind:this={fileInput}
      />
    </div>

    <!-- Add Credential Form -->
    {#if showAddForm}
      <div id="add-credential-form" class="card p-4 mb-6">
        <div class="mb-2">
          <label class="block text-sm font-medium" style="color: #1d1b21;" for="newService">
            {t('service', lang)}
          </label>
          <input
            id="newService"
            type="text"
            bind:value={newRecord.service}
            class="mt-1 block w-full border rounded-lg p-2
                   focus:outline-none focus:ring-2"
            style="border-color: #474b4f;"
          />
        </div>
        <div class="mb-2">
          <label
            class="block text-sm font-medium"
            style="color: #1d1b21;"
            for="newUsername"
          >
            {t('username', lang)}
          </label>
          <input
            id="newUsername"
            type="text"
            bind:value={newRecord.username}
            class="mt-1 block w-full border rounded-lg p-2
                   focus:outline-none focus:ring-2"
            style="border-color: #474b4f;"
          />
        </div>
        <div class="mb-2">
          <label
            class="block text-sm font-medium"
            style="color: #1d1b21;"
            for="newPassword"
          >
            {t('password', lang)}
          </label>
          <div class="flex">
            <input
              id="newPassword"
              type={showPasswordGenerator ? "text" : "password"}
              bind:value={newRecord.password}
              class="mt-1 block w-full border rounded-lg p-2
                     focus:outline-none focus:ring-2"
              style="border-color: #474b4f;"
              on:input={() => {
                if (newRecord.password) {
                  passwordStrength = evaluatePasswordStrength(newRecord.password);
                }
              }}
            />
            <button
              type="button"
              on:click={() => showPasswordGenerator = !showPasswordGenerator}
              class="ml-2 mt-1 px-3 py-2 rounded-lg"
              style="background-color: #f2c3c2; color: #1d1b21;"
              title={showPasswordGenerator ? t('hideGenerator', lang) || "Masquer le générateur" : t('showGenerator', lang) || "Afficher le générateur"}
            >
              {showPasswordGenerator ? "✕" : "⚙️"}
            </button>
          </div>
          
          <!-- Indicateur de force du mot de passe -->
          {#if newRecord.password}
            <div class="mt-1">
              <div class="w-full h-2 bg-gray-200 rounded-full overflow-hidden">
                <div 
                  class="h-full rounded-full" 
                  style="width: {(passwordStrength.score + 1) * 20}%; background-color: {passwordStrength.color};"
                ></div>
              </div>
              <div class="text-xs mt-1" style="color: {passwordStrength.color};">
                {passwordStrength.text}
              </div>
            </div>
          {/if}
          
          <!-- Générateur de mot de passe -->
          {#if showPasswordGenerator}
            <div class="mt-3 p-3 rounded-lg" style="background-color: #f0f0f0;">
              <h4 class="font-medium mb-2" style="color: #1d1b21;">{t('passwordGenerator', lang) || "Générateur de mot de passe"}</h4>
              
              <div class="mb-3">
                <label class="block text-sm" style="color: #474b4f;">{t('passwordLength', lang) || "Longueur"}: {passwordConfig.length}</label>
                <input 
                  type="range" 
                  min="8" 
                  max="32" 
                  step="1" 
                  bind:value={passwordConfig.length}
                  class="w-full"
                />
              </div>
              
              <div class="grid grid-cols-2 gap-2 mb-3 sm:grid-cols-1">
                <label class="flex items-center">
                  <input 
                    type="checkbox" 
                    bind:checked={passwordConfig.includeUppercase}
                    class="mr-2"
                  />
                  <span class="text-sm" style="color: #474b4f;">{t('uppercase', lang) || "Majuscules"}</span>
                </label>
                
                <label class="flex items-center">
                  <input 
                    type="checkbox" 
                    bind:checked={passwordConfig.includeLowercase}
                    class="mr-2"
                  />
                  <span class="text-sm" style="color: #474b4f;">{t('lowercase', lang) || "Minuscules"}</span>
                </label>
                
                <label class="flex items-center">
                  <input 
                    type="checkbox" 
                    bind:checked={passwordConfig.includeNumbers}
                    class="mr-2"
                  />
                  <span class="text-sm" style="color: #474b4f;">{t('numbers', lang) || "Chiffres"}</span>
                </label>
                
                <label class="flex items-center">
                  <input 
                    type="checkbox" 
                    bind:checked={passwordConfig.includeSymbols}
                    class="mr-2"
                  />
                  <span class="text-sm" style="color: #474b4f;">{t('symbols', lang) || "Symboles"}</span>
                </label>
                
                <label class="flex items-center col-span-2 sm:col-span-1">
                  <input 
                    type="checkbox" 
                    bind:checked={passwordConfig.excludeSimilarChars}
                    class="mr-2"
                  />
                  <span class="text-sm" style="color: #474b4f;">{t('excludeSimilarChars', lang) || "Exclure les caractères similaires (i, l, 1, L, o, 0, O)"}</span>
                </label>
              </div>
              
              <div class="flex flex-wrap gap-2">
                <button
                  type="button"
                  on:click={() => {
                    generatedPassword = generatePassword(passwordConfig);
                    newRecord.password = generatedPassword;
                    passwordStrength = evaluatePasswordStrength(generatedPassword);
                  }}
                  class="px-3 py-1 rounded-lg text-sm"
                  style="background-color: #a7f3ae; color: #1d1b21;"
                >
                  {t('generate', lang) || "Générer"}
                </button>
                
                <button
                  type="button"
                  on:click={() => {
                    passwordConfig = { ...defaultPasswordConfig };
                  }}
                  class="px-3 py-1 rounded-lg text-sm"
                  style="background-color: #ced7e1; color: #1d1b21;"
                >
                  {t('reset', lang) || "Réinitialiser"}
                </button>
              </div>
            </div>
          {/if}
        </div>
        <div class="mb-2">
          <label class="block text-sm font-medium" style="color: #1d1b21;" for="newOTP">
            {t('otpUri', lang)}
          </label>
          <input
            id="newOTP"
            type="text"
            bind:value={newRecord.otp}
            class="mt-1 block w-full border rounded-lg p-2
                   focus:outline-none focus:ring-2"
            style="border-color: #474b4f;"
          />
        </div>
        <div class="flex flex-wrap gap-2 mt-4">
          <button
            on:click={saveNewCredential}
            class="secondary-btn px-4 py-2 rounded-lg flex-1"
          >
            {t('save', lang)}
          </button>
          <button
            on:click={() => {
              newRecord = {
                service: "",
                username: "", 
                password: "",
                otp: "",
                uuid: "",
                twoFA: null
              };
              showAddForm = false;
              showPasswordGenerator = false;
            }}
            class="neutral-btn px-4 py-2 rounded-lg flex-1"
          >
            {t('cancel', lang)}
          </button>
        </div>
      </div>
    {/if}
    {#each $pendingCredentialsStore as pendingCredential}
      <div class="card p-4 mb-4">
        <div class="flex justify-between items-start flex-col">
          <div class="w-full">
            <h3 class="text-lg font-semibold flex items-center flex-wrap gap-2" style="color: #1d1b21; font-family: 'Raleway', sans-serif;">
              {#if pendingCredential.credential.favicon}
                <img src={pendingCredential.credential.favicon} alt="Favicon" class="w-5 h-5 mr-1" on:error={handleImageError} />
              {/if}
              <span class="break-all">{pendingCredential.credential.service}</span>
              <span class="text-xs bg-yellow-200 text-yellow-800 px-2 py-1 rounded-full">
                {t('pending', lang) || 'En attente'}
              </span>
            </h3>
            <div class="mt-1 flex items-center flex-wrap">
              <span class="mr-2" style="color: #474b4f;">{t('username', lang)}:</span>
              <span class="font-medium break-all" style="color: #1d1b21;">{pendingCredential.credential.username}</span>
            </div>
            <div class="mt-2 text-sm text-purple-700">
              {t('sharedBy', lang)} {pendingCredential.owneremail}
            </div>
            <div class="mt-4 text-sm italic" style="color: #474b4f;">
              {t('pendingDescription', lang) || "Ce mot de passe a été partagé avec vous. Acceptez pour y accéder ou refusez pour le rejeter."}
            </div>
          </div>
        </div>
        
        <div class="flex flex-wrap gap-2 mt-4">
          <button
            on:click={() => handleAcceptSharedPass(pendingCredential.credential)}
            class="secondary-btn px-4 py-2 rounded-lg flex-1"
            style="background-color: #a7f3ae;"
          >
            {t('accept', lang) || 'Accepter'}
          </button>
          <button
            on:click={() => handleRejectSharedPass(pendingCredential.credential)}
            class="danger-btn px-4 py-2 rounded-lg flex-1"
            style="background-color: #b00e0b; color: white;"
          >
            {t('reject', lang) || 'Refuser'}
          </button>
        </div>
      </div>
    {/each}
    <!-- Credentials list -->
    {#each filteredCredentials as credential (credential.id)}
      <div class="card p-4 mb-4">
        {#if editingId === credential.id}
          <!-- Edit Mode -->
          <div class="mb-2">
            <label class="block text-sm font-medium" style="color: #1d1b21;" for="editService">
              {t('service', lang)}
            </label>
            <input
              id="editService"
              type="text"
              bind:value={editedRecord.service}
              class="mt-1 block w-full border rounded-lg p-2
                     focus:outline-none focus:ring-2"
              style="border-color: #474b4f;"
            />
          </div>
          <div class="mb-2">
            <label class="block text-sm font-medium" style="color: #1d1b21;" for="editUsername">
              {t('username', lang)}
            </label>
            <input
              type="text"
              id="editUsername"
              bind:value={editedRecord.username}
              class="mt-1 block w-full border rounded-lg p-2
                     focus:outline-none focus:ring-2"
              style="border-color: #474b4f;"
            />
          </div>
          <div class="mb-2">
            <label class="block text-sm font-medium" style="color: #1d1b21;" for="editPassword">
              {t('password', lang)}
            </label>
            <div class="flex">
              <input
                id = "editPassword"
                type={showEditPasswordGenerator ? "text" : "password"}
                bind:value={editedRecord.password}
                class="mt-1 block w-full border rounded-lg p-2
                       focus:outline-none focus:ring-2"
                style="border-color: #474b4f;"
                on:input={() => {
                  if (editedRecord.password) {
                    passwordStrength = evaluatePasswordStrength(editedRecord.password);
                  }
                }}
              />
              <button
                type="button"
                on:click={() => showEditPasswordGenerator = !showEditPasswordGenerator}
                class="ml-2 mt-1 px-3 py-2 rounded-lg"
                style="background-color: #1d1b21; color: #f2c3c2;"
                title={showEditPasswordGenerator ? t('hideGenerator', lang) || "Masquer le générateur" : t('showGenerator', lang) || "Afficher le générateur"}
              >
                {showEditPasswordGenerator ? "✕" : "⚙️"}
              </button>
            </div>
            
            <!-- Indicateur de force du mot de passe -->
            {#if editedRecord.password}
              <div class="mt-1">
                <div class="w-full h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div 
                    class="h-full rounded-full" 
                    style="width: {(passwordStrength.score + 1) * 20}%; background-color: {passwordStrength.color};"
                  ></div>
                </div>
                <div class="text-xs mt-1" style="color: {passwordStrength.color};">
                  {passwordStrength.text}
                </div>
              </div>
            {/if}
            
            <!-- Générateur de mot de passe -->
            {#if showEditPasswordGenerator}
              <div class="mt-3 p-3 rounded-lg" style="background-color: #f0f0f0;">
                <h4 class="font-medium mb-2" style="color: #1d1b21;">{t('passwordGenerator', lang) || "Générateur de mot de passe"}</h4>
                
                <div class="mb-3">
                  <label class="block text-sm" style="color: #474b4f;">{t('passwordLength', lang) || "Longueur"}: {passwordConfig.length}</label>
                  <input 
                    type="range" 
                    min="8" 
                    max="32" 
                    step="1" 
                    bind:value={passwordConfig.length}
                    class="w-full"
                  />
                </div>
                
                <div class="grid grid-cols-2 gap-2 mb-3 sm:grid-cols-1">
                  <label class="flex items-center">
                    <input 
                      type="checkbox" 
                      bind:checked={passwordConfig.includeUppercase}
                      class="mr-2"
                    />
                    <span class="text-sm" style="color: #474b4f;">{t('uppercase', lang) || "Majuscules"}</span>
                  </label>
                  
                  <label class="flex items-center">
                    <input 
                      type="checkbox" 
                      bind:checked={passwordConfig.includeLowercase}
                      class="mr-2"
                    />
                    <span class="text-sm" style="color: #474b4f;">{t('lowercase', lang) || "Minuscules"}</span>
                  </label>
                  
                  <label class="flex items-center">
                    <input 
                      type="checkbox" 
                      bind:checked={passwordConfig.includeNumbers}
                      class="mr-2"
                    />
                    <span class="text-sm" style="color: #474b4f;">{t('numbers', lang) || "Chiffres"}</span>
                  </label>
                  
                  <label class="flex items-center">
                    <input 
                      type="checkbox" 
                      bind:checked={passwordConfig.includeSymbols}
                      class="mr-2"
                    />
                    <span class="text-sm" style="color: #474b4f;">{t('symbols', lang) || "Symboles"}</span>
                  </label>
                  
                  <label class="flex items-center col-span-2 sm:col-span-1">
                    <input 
                      type="checkbox" 
                      bind:checked={passwordConfig.excludeSimilarChars}
                      class="mr-2"
                    />
                    <span class="text-sm" style="color: #474b4f;">{t('excludeSimilarChars', lang) || "Exclure les caractères similaires (i, l, 1, L, o, 0, O)"}</span>
                  </label>
                </div>
                
                <div class="flex flex-wrap gap-2">
                  <button
                    type="button"
                    on:click={() => {
                      generatedPassword = generatePassword(passwordConfig);
                      editedRecord.password = generatedPassword;
                      passwordStrength = evaluatePasswordStrength(generatedPassword);
                    }}
                    class="px-3 py-1 rounded-lg text-sm"
                    style="background-color: #a7f3ae; color: #1d1b21;"
                  >
                    {t('generate', lang) || "Générer"}
                  </button>
                  
                  <button
                    type="button"
                    on:click={() => {
                      passwordConfig = { ...defaultPasswordConfig };
                    }}
                    class="px-3 py-1 rounded-lg text-sm"
                    style="background-color: #ced7e1; color: #1d1b21;"
                  >
                    {t('reset', lang) || "Réinitialiser"}
                  </button>
                </div>
              </div>
            {/if}
          </div>
          <div class="mb-2">
            <label class="block text-sm font-medium" style="color: #1d1b21;" for="editOTPURI">
              {t('otpUri', lang)}
            </label>
            <input
              id = "editOTPURI"
              type="text"
              bind:value={editedRecord.otp}
              class="mt-1 block w-full border rounded-lg p-2
                     focus:outline-none focus:ring-2"
              style="border-color: #474b4f;"
            />
          </div>
          <div class="flex flex-wrap gap-2 mt-4">
            <button
              on:click={saveEdit}
              class="secondary-btn px-4 py-2 rounded-lg flex-1"
            >
              {t('save', lang)}
            </button>
            <button
              on:click={deleteEdit}
              class="danger-btn px-4 py-2 rounded-lg flex-1"
            >
              {t('delete', lang)}
            </button>
            <button
              on:click={cancelEdit}
              class="neutral-btn px-4 py-2 rounded-lg flex-1"
            >
              {t('cancel', lang)}
            </button>
          </div>
        {:else}
          <!-- View Mode -->
          <div class="flex justify-between items-start flex-col sm:flex-row">
            <div class="w-full sm:w-auto">
              <h3 class="text-lg font-semibold flex items-center flex-wrap gap-2" style="color: #1d1b21; font-family: 'Raleway', sans-serif;">
                {#if credential.favicon}
                  <img src={credential.favicon} alt="Favicon" class="w-5 h-5 mr-1" on:error={handleImageError} />
                {/if}
                <span class="break-all">{credential.service}</span>
                <div class="flex flex-wrap gap-1">
                  {#if credential.sharedBy}
                    <span class="text-xs bg-purple-200 text-purple-800 px-2 py-1 rounded-full">
                      {t('shared', lang)}
                    </span>
                  {/if}
                  {#if !credential.sharedBy && sharedPasswordEmails.has(credential.uuid) && getSharedEmails(credential.uuid).length > 0}
                    <span class="text-xs bg-blue-200 text-blue-800 px-2 py-1 rounded-full">
                      {t('sharedByMe', lang)}
                    </span>
                  {/if}
                </div>
              </h3>
              <div class="mt-1 flex items-center flex-wrap">
                <span class="mr-2" style="color: #474b4f;">{t('username', lang)}:</span>
                <span class="font-medium break-all" style="color: #1d1b21;">{credential.username.length > 40 ? credential.username.slice(0, 40) + "..." : credential.username}</span>
                <button
                  on:click={() => copyText(credential.username)}
                  class="ml-2 text-blue-500 hover:text-blue-700 copy-btn"
                  title={t('copiedToClipboard', lang)}
                >
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    class="h-4 w-4"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"
                    />
                  </svg>
                </button>
              </div>
              <div class="mt-1 flex items-center">
                <span class="mr-2" style="color: #474b4f;">{t('password', lang)}:</span>
                <span class="font-medium" style="color: #1d1b21;">••••••••</span>
                <button
                  on:click={() => copyText(credential.password)}
                  class="ml-2 text-blue-500 hover:text-blue-700 copy-btn"
                  title={t('copiedToClipboard', lang)}
                >
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    class="h-4 w-4"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"
                    />
                  </svg>
                </button>
              </div>
              {#if credential.owneremail}
                <div class="mt-2 text-xs text-purple-700">
                  {t('sharedBy', lang)} {credential.owneremail}
                </div>
              {/if}
            </div>
            <div class="flex flex-col items-start sm:items-end space-y-2 mt-3 sm:mt-0 w-full sm:w-auto">
              <div class="flex space-x-2 w-full sm:w-auto justify-start sm:justify-end">
                {#if !credential.sharedBy}
                  <button
                    on:click={() => startEdit(credential)}
                    class="text-blue-500 hover:text-blue-700"
                    title="Modifier"
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      class="h-5 w-5"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"
                      />
                    </svg>
                  </button>
                  <button
                    on:click={() => showShareModal(credential)}
                    class="text-purple-500 hover:text-purple-700"
                    title="Partager"
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      class="h-5 w-5"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z"
                      />
                    </svg>
                  </button>
                {/if}
                {#if credential.sharedBy}
                  <button
                    on:click={() => handleRejectSharedPass(credential)}
                    class="text-red-500 hover:text-red-700"
                    title={t('deleteShared', lang) || "Supprimer ce partage"}
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      class="h-5 w-5"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                      />
                    </svg>
                  </button>
                {/if}
                {#if !credential.sharedBy && !credential.ownerUuid}
                  <div class="w-5 h-5"></div>
                {/if}
              </div>
              
              {#if credential.otp}
                {#if credential.twoFA}
                  <div class="flex items-center flex-wrap gap-2 mt-2 w-full sm:w-auto justify-start sm:justify-end">
                    <span style="color: #474b4f;">{t('twoFaCode', lang)}</span>
                    <span class="font-mono px-2 py-1 rounded" style="background-color: #f2c3c2; color: #1d1b21;">
                      {credential.twoFA}
                    </span>
                                        
                    <!-- Indicateur circulaire du temps restant -->
                    {#if credential.id in remainingTimes}
                      {@const period = otpPeriods[credential.id] || 30}
                      {@const percentage = 100 - (remainingTimes[credential.id] / period * 100)}
                      {@const dashArray = `${percentage}, 100`}
                      {@const timeLeft = remainingTimes[credential.id]}
                      {@const isLow = timeLeft <= 5}
                      {@const isVeryLow = timeLeft <= 3}
                      {@const circleColor = isLow ? "#b00e0b" : "#a7f3ae"}
                      {@const textColor = isLow ? "#ffffff" : "#1d1b21"}
                      {@const bgColor = isLow ? "rgba(176, 14, 11, 0.2)" : "transparent"}
                      <div class="relative w-10 h-10 {isVeryLow ? 'pulse-animation' : ''}">
                        <svg class="w-10 h-10" viewBox="0 0 36 36">
                          <circle cx="18" cy="18" r="16" fill={bgColor} stroke="#e0e0e0" stroke-width="2"></circle>
                          <circle 
                            cx="18" 
                            cy="18" 
                            r="16" 
                            fill="none" 
                            stroke={circleColor} 
                            stroke-width="3" 
                            stroke-dasharray={dashArray} 
                            stroke-linecap="round" 
                            transform="rotate(-90 18 18)"
                          ></circle>
                          <g>
                            <text 
                              x="18" 
                              y="18" 
                              text-anchor="middle" 
                              alignment-baseline="central" 
                              fill={textColor} 
                              font-size="18" 
                              font-family="'Raleway', sans-serif"
                              dy=".35em"
                            >
                              {timeLeft}
                            </text>
                          </g>
                        </svg>
                      </div>
                    {/if}
                    <button
                      on:click={() => copyText(credential.twoFA)}
                      class="text-blue-500 hover:text-blue-700 copy-btn"
                      title={t('copiedToClipboard', lang)}
                    >
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        class="h-4 w-4"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"
                        />
                      </svg>
                    </button>

                  </div>
                {/if}
                <button
                  on:click={() => toggle2FA(credential)}
                  class="text-sm px-2 py-1 rounded w-full sm:w-auto text-center"
                  style="background-color: #a7f3ae; color: #1d1b21;"
                >
                  {credential.twoFA ? t('disableTwoFa', lang) : t('enableTwoFa', lang)}
                </button>
              {/if}
            </div>
          </div>
        {/if}
      </div>
    {:else}
      <div class="text-center py-8 text-white">
        {searchTerm ? t('noSearchResults', lang) : t('noCredentials', lang)}
      </div>
    {/each}
  {/if}
  </div>
</div>

<!-- Modal de partage -->
{#if showingShareModal}
  <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
    <div class="card p-4 sm:p-6 w-full max-w-md mx-auto">
      <h2 class="text-xl font-semibold mb-4" style="font-family: 'Raleway', sans-serif; color: #1d1b21;">{t('sharePassword', lang)}</h2>
      <p class="mb-4 text-sm sm:text-base" style="color: #474b4f;">{t('shareDescription', lang)}</p>
      
      <div class="mb-4">
        <label for="shareUserId" class="block font-medium mb-1 text-sm sm:text-base" style="color: #1d1b21;">{t('email', lang)}</label>
        <input
          type="email"
          id="shareUserId"
          bind:value={shareUserId}
          class="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 text-sm sm:text-base"
          style="border-color: #474b4f;"
          placeholder={t('emailPlaceholder', lang)}
          required
        />
      </div>
      
      {#if shareError}
        <p class="text-red-500 mb-4 text-xs sm:text-sm">{shareError}</p>
      {/if}
      
      <!-- Afficher les emails avec lesquels ce mot de passe a déjà été partagé -->
      {#if sharingCredential && sharedPasswordEmails.has(sharingCredential.uuid)}
        <div class="mb-4">
          <h3 class="text-sm font-medium mb-2" style="color: #1d1b21;">{t('alreadySharedWith', lang)}</h3>
          <ul class="p-2 rounded-md max-h-32 overflow-y-auto" style="background-color: #1d1b21;">
            {#each sharedPasswordEmails.get(sharingCredential.uuid)?.emails || [] as email, index}
              <li class="flex justify-between items-center text-sm py-1 px-2 border-b border-zinc-700 last:border-b-0 flex-wrap gap-1">
                <div class="flex items-center flex-wrap gap-1 break-all">
                  <span style="color: #ced7e1;">{email}</span>
                  
                  <!-- Afficher le statut du partage -->
                  {#if sharedPasswordEmails.get(sharingCredential.uuid)?.statuses && index < (sharedPasswordEmails.get(sharingCredential.uuid)?.statuses?.length || 0)}
                    {#if sharedPasswordEmails.get(sharingCredential.uuid)?.statuses?.[index] === ShareStatus.Pending}
                      <span class="text-xs bg-yellow-200 text-yellow-800 px-2 py-0.5 rounded-full">
                        {t('pending', lang) || 'En attente'}
                      </span>
                    {:else if sharedPasswordEmails.get(sharingCredential.uuid)?.statuses?.[index] === ShareStatus.Accepted}
                      <span class="text-xs bg-green-200 text-green-800 px-2 py-0.5 rounded-full">
                        {t('accepted', lang) || 'Accepté'}
                      </span>
                    {:else if sharedPasswordEmails.get(sharingCredential.uuid)?.statuses?.[index] === ShareStatus.Rejected}
                      <span class="text-xs bg-red-200 text-red-800 px-2 py-0.5 rounded-full">
                        {t('rejected', lang) || 'Rejeté'}
                      </span>
                    {/if}
                  {/if}
                </div>
                <button 
                  on:click={() => unsharePassword(email)}
                  class="text-red-500 hover:text-red-700 ml-2 flex items-center"
                  title={t('unshare', lang)}
                  disabled={isUnsharing}
                >
                  {#if isUnsharing && unsharingEmail === email}
                    <div class="w-4 h-4 border-2 border-red-500 border-t-transparent rounded-full animate-spin mr-1"></div>
                  {:else}
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  {/if}
                </button>
              </li>
            {/each}
          </ul>
        </div>
      {/if}
      
      <div class="flex flex-wrap gap-2 justify-end">
        <button
        on:click={sharePassword}
        class="secondary-btn px-4 py-2 rounded-md flex items-center flex-1 sm:flex-none justify-center"
        disabled={isSharing}
        >
          {#if isSharing}
            <div class="w-4 h-4 border-2 border-zinc-800 border-t-transparent rounded-full animate-spin mr-2"></div>
            {t('sharing', lang)}
          {:else}
            {t('share', lang)}
          {/if}
        </button>
        <button
          on:click={closeShareModal}
          class="primary-btn px-4 py-2 rounded-md flex-1 sm:flex-none text-center"
        >
          {t('cancel', lang)}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Composant de notification -->
{#if showNotification}
  <div class="fixed top-4 right-4 px-4 py-2 rounded-md shadow-md z-50 notification" style="background-color: #a7f3ae; color: #1d1b21;">
    {notificationMessage}
  </div>
{/if}

<!-- Modal d'importation -->
{#if importingFile}
  <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
    <div class="card p-4 sm:p-6 w-full max-w-md mx-auto">
      <h2 class="text-xl font-semibold mb-4" style="font-family: 'Raleway', sans-serif; color: #1d1b21;">{t('importing', lang)}</h2>
      <div class="w-full bg-gray-200 rounded-full h-4 mb-4">
        <div class="bg-green-500 h-4 rounded-full" style="width: {(importProgress / importTotal) * 100}%"></div>
      </div>
      <p class="text-center text-sm sm:text-base" style="color: #474b4f;">
        {importProgress} {t('importedOf', lang)} {importTotal} {t('passwordsImported', lang)}
      </p>
      {#if importError}
        <p class="text-red-500 mt-2 text-xs sm:text-sm">{importError}</p>
      {/if}
    </div>
  </div>
{/if}
