The error `ReferenceError: document is not defined` typically occurs in SvelteKit applications when client-side specific APIs like `document`, `window`, or `localStorage` are accessed during the server-side rendering (SSR) phase.

While many of your `document` interactions are correctly placed within `onMount` blocks (which run only on the client), there's a subtle point: The SvelteKit build process, during SSR, can still encounter global objects if they are imported or accessed directly at the top level of the `<script>` block, even if their intended use is within `onMount`.

The specific line numbers in your error trace (`/home/hirew/Projects/skibiskap/src/routes/vault/+page.svelte:1954:5`) suggest that the issue might be related to the `document.addEventListener('keydown', handleKeyDown);` line that was added later in the code.

Even if wrapped in `onMount`, if a function like `handleKeyDown` (which directly interacts with `event.target` which could be an `HTMLInputElement`) is defined, the mere existence of `document.addEventListener` can sometimes cause issues during SSR if Svelte's compiler processes it in a context where `document` is not yet available.

The most robust way to ensure client-side only code runs exclusively in the browser is to wrap any browser-specific API calls inside an `if (browser)` block, provided by SvelteKit.

Let's apply this principle to the relevant parts of your code.

**Reasoning for the fix:**
Even though `onMount` conceptually runs on the client, the Svelte compiler might perform some static analysis or initial setup during SSR. Explicitly checking `if (browser)` for direct global object interactions provides an extra layer of safety against SSR issues.

**Proposed Changes:**

1.  **Wrap `navigator.language` access in `onMount` with `if (browser)`:**
    Although inside `onMount`, it's a good practice for `navigator`.
2.  **Wrap `SecureLS` initialization in `onMount` with `if (browser)`:**
    `SecureLS` uses `localStorage` internally, which is client-side.
3.  **Wrap `document.addEventListener` calls in `onMount` with `if (browser)`:**
    While `onMount` generally handles this, explicitly guarding `document` interactions can prevent edge cases during SSR.
4.  **Import `browser` from `'$app/environment'`:**

```diff
<script lang="ts">
  // Our sample list of credentials
  import { onMount, onDestroy } from "svelte";
  import { goto } from "$app/navigation";
+ import { browser } from "$app/environment";
  import { clientex, client } from "../stores";
  import { get_all, update_pass, delete_pass, create_pass, share_pass, get_shared_by_user, get_shared_by_user_emails, get_emails_from_uuids, get_uuid_from_email, unshare_pass, ShareStatus, accept_shared_pass, reject_shared_pass, exportPasswords, exportPasswordsCSV, exportPasswordsText } from "$lib/client";
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
  import { fly } from 'svelte/transition';
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

  // Variables pour l'exportation
  let exportFormat = 'json'; // Format d'exportation par défaut: 'json', 'csv', ou 'txt'
  let showExportDialog = false;

  // Fonction pour exporter les mots de passe
  function handleExport() {
    if (!isClientValid() || !credentials.length) {
      showToast(t('noCredentialsToExport', lang) || "Aucun mot de passe à exporter");
      return;
    }

    try {
      // Convertir les identifiants au format Password accepté par les fonctions d'export
      const passwordsToExport = credentials.map(cred => ({
        username: cred.username,
        password: cred.password,
        app_id: cred.service, // Utiliser le champ service comme app_id
        description: null,
        url: null,
        otp: cred.otp
      }));

      // Convertir les UUIDs des mots de passe
      const passwordUuids = credentials.map(cred => {
        const uuid = memoizedUuidToBytes(cred.uuid);
        if (!uuid) {
          throw new Error(t('uuidConversionError', lang));
        }
        return uuid;
      });

      let fileContent = '';
      let filename = `passwords_export_${new Date().toISOString().slice(0, 10)}`;
      let mimeType = '';

      // Générer le contenu selon le format choisi
      switch (exportFormat) {
        case 'json':
          fileContent = exportPasswords($clientex!.id.id!, passwordsToExport, passwordUuids);
          filename += '.json';
          mimeType = 'application/json';
          break;
        case 'csv':
          fileContent = exportPasswordsCSV($clientex!.id.id!, passwordsToExport);
          filename += '.csv';
          mimeType = 'text/csv';
          break;
        case 'txt':
          fileContent = exportPasswordsText($clientex!.id.id!, passwordsToExport);
          filename += '.txt';
          mimeType = 'text/plain';
          break;
        default:
          throw new Error('Format d\'exportation non valide');
      }

      // Créer un blob et déclencher le téléchargement
+      if (browser) {
        const blob = new Blob([fileContent], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
+      }

      showToast(t('exportSuccess', lang) || "Mots de passe exportés avec succès");
    } catch (error) {
      console.error("Erreur lors de l'exportation:", error);
      showToast(t('exportError', lang) || "Erreur lors de l'exportation");
    } finally {
      showExportDialog = false;
    }
  }

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
+      if (browser) { // Ensure Worker is only instantiated in the browser
        for (let i = 0; i < numWorkers; i++) {
          const worker = new Worker("passwordWorker.js", { type: "module" });
          worker.onmessage = this.handleMessage.bind(this);
          this.workers.push(worker);
        }
+      }
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
+        if (this.workers.length > 0) { // Check if workers were actually created
          const worker = this.workers[Math.floor(Math.random() * this.workers.length)];
          worker.postMessage({ taskId: currentTaskId, password, url });
+        } else {
+          // Fallback if workers are not available (e.g., during SSR or if browser check failed)
+          resolve({ url, passwordStrength: evaluatePasswordStrength(password) });
+        }
      });
    }

    terminate() {
      this.workers.forEach(worker => worker.terminate());
      this.workers = [];
      this.pendingTasks = {};
    }
  }

  onMount (async () => {
+    if (browser) {
      if (navigator.language.startsWith("fr") || navigator.language.startsWith("en")) {
        if (navigator.language.startsWith("fr")) {
          currentLang.set('fr');
        } else {
          currentLang.set('en');
        }
      }
+    }

    // Initialisation du client
-    if (!isClientValid()) {
-      const ls = new SecureLS({ encodingType: "aes" });
-      const sessionclient = ls.get("clientex");
-      if (sessionclient) {
-        const p = sessionclient;
-        const cc = {
-          ky_p: Uint8Array.from(p.c.ky_p),
-          ky_q: Uint8Array.from(p.c.ky_q),
-          di_p: Uint8Array.from(p.c.di_p),
-          di_q: Uint8Array.from(p.c.di_q),
-          secret: Uint8Array.from(p.c.secret),
-        }
-        const id = {
-          email: p.id.email,
-          id: {
-            bytes: Uint8Array.from(p.id.id.bytes),
-          },
-          ky_p: Uint8Array.from(p.id.ky_p),
-          di_p: p.id.di_p ? Uint8Array.from(p.id.di_p) : new Uint8Array(0),
-        }
-        const clieex = {
-          c: cc,
-          id: id
-        }
-        clientex.set(clieex);
-        client.set(cc);
-        if (!isClientValid()) {
-          goto('/');
-          return;
-        }
-      } else {
-        goto('/');
-        return;
-      }
-    }
+    // This block should also be browser-guarded because of `SecureLS`
+    if (!isClientValid() && browser) {
+      const ls = new SecureLS({ encodingType: "aes" });
+      const sessionclient = ls.get("clientex");
+      if (sessionclient) {
+        const p = sessionclient;
+        const cc = {
+          ky_p: Uint8Array.from(p.c.ky_p),
+          ky_q: Uint8Array.from(p.c.ky_q),
+          di_p: Uint8Array.from(p.c.di_p),
+          di_q: Uint8Array.from(p.c.di_q),
+          secret: Uint8Array.from(p.c.secret),
+        };
+        const id = {
+          email: p.id.email,
+          id: {
+            bytes: Uint8Array.from(p.id.id.bytes),
+          },
+          ky_p: Uint8Array.from(p.id.ky_p),
+          di_p: p.id.di_p ? Uint8Array.from(p.id.di_p) : new Uint8Array(0),
+        };
+        const clieex = {
+          c: cc,
+          id: id,
+        };
+        clientex.set(clieex);
+        client.set(cc);
+        if (!isClientValid()) {
+          goto("/");
+          return;
+        }
+      } else {
+        goto("/");
+        return;
+      }
+    } else if (!isClientValid() && !browser) {
+      // If not valid on server, it means no session, just let SSR continue without client data
+      // or handle redirection if necessary for server-side
+      // goto('/') might not work directly here on server, consider what this path implies
+      return; // Exit on SSR if no valid client
+    }

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
-      const workerPool = new WorkerPool(4);
+      const workerPool = browser ? new WorkerPool(4) : null;

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
-              workerPool.evaluatePassword(password, url!).then(({ passwordStrength }) => {
-                // Mise à jour silencieuse, pas besoin de mettre à jour l'interface
-              }).catch(err => {
-                console.error("Erreur d'évaluation du mot de passe:", err);
-              });
+              if (workerPool) { // Only evaluate password if workerPool exists (i.e., in browser)
+                workerPool.evaluatePassword(password, url!).then(({ passwordStrength }) => {
+                  // Mise à jour silencieuse, pas besoin de mettre à jour l'interface
+                }).catch(err => {
+                  console.error("Erreur d'évaluation du mot de passe:", err);
+                });
+              }
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
-      document.addEventListener('keydown', handleKeyDown);
+      if (browser) {
+        document.addEventListener('keydown', handleKeyDown);
+      }
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
+    if (browser) {
+      document.removeEventListener('keydown', handleKeyDown);
+    }
   });

   // For inline editing state
   let editingId: number | null = null;
   let editedRecord: EditedRecord = {};

   // Helper: Copy any text to the clipboard
   function copyText(text: string | null | undefined) {
     if (text === null || text === undefined) return;
+    if (browser) {
      navigator.clipboard.writeText(text).then(() => {
        showToast(t('copiedToClipboard', lang));
      });
+    }
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
+      if (browser) { // Date.now() is available, but the whole mechanism relies on client-side updates
        const initialRemainingTime = (periodNum * 1000) - (Date.now() % (periodNum * 1000));
        remainingTimes[record.id] = Math.floor(initialRemainingTime / 1000);
-
-      const intervalId = setInterval(() => {
-        const remainingTime = (periodNum * 1000) - (Date.now() % (periodNum * 1000));
-        remainingTimes[record.id] = Math.floor(remainingTime / 1000);
-
-        if (remainingTime/1000 > periodNum-5) {
-          credentials = credentials.map((cred) =>
-            cred.id === record.id ? { ...cred, twoFA: generate2FACode(cred.otp)[0] } : cred
-          );
-        }
-      }, 1000);
-
-      intervals[record.id] = intervalId;
-
-      credentials = credentials.map((item) =>
-        item.id === record.id ? { ...item, twoFA: code, intervalId } : item
-      );
+      }
+
+      // Only set up intervals in the browser
+      if (browser) {
+        const intervalId = setInterval(() => {
+          const remainingTime = (periodNum * 1000) - (Date.now() % (periodNum * 1000));
+          remainingTimes[record.id] = Math.floor(remainingTime / 1000);
+
+          if (remainingTime/1000 > periodNum-5) {
+            credentials = credentials.map((cred) =>
+              cred.id === record.id ? { ...cred, twoFA: generate2FACode(cred.otp)[0] } : cred
+            );
+          }
+        }, 1000);
+
+        intervals[record.id] = intervalId;
+
+        credentials = credentials.map((item) =>
+          item.id === record.id ? { ...item, twoFA: code, intervalId } : item
+        );
+      } else {
+        // On server, set 2FA code once without interval
+        credentials = credentials.map((item) =>
+          item.id === record.id ? { ...item, twoFA: code, intervalId: null } : item
+        );
+      }
     }

     credentialsStore.set(credentials);
   }

   function disconnect() {
-    localStorage.clear();
+    if (browser) { // localStorage is client-side
+      localStorage.clear();
+    }
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
     loading = true;
     errorMessage = "";

     try {
       const clientexValue = get(clientex);
       const clientValue = get(client);
       if (!clientexValue || !clientValue) {
         errorMessage = t('clientNotInitialized', lang) as string;
         loading = false;
         return;
       }

       const {result: encryptedCredentials, shared: sharedCredentials, error} = await get_all(clientexValue.id.id!, clientValue);

       if (error) {
         console.error(error);
         errorMessage = `${t('fetchError', lang)}: ${error}`;
         loading = false;
         return;
       }

       await processCredentials(encryptedCredentials, sharedCredentials);

       // Activer automatiquement le 2FA pour tous les credentials avec OTP
       setTimeout(() => {
         credentials.forEach(credential => {
           if (credential.otp && !credential.twoFA) {
             toggle2FA(credential);
           }
         });
       }, 500);

     } catch (err) {
       console.error(err);
       errorMessage = `${t('fetchError', lang)}: ${err instanceof Error ? err.message : String(err)}`;
     }

         loading = false;
   }

   // Fonction pour traiter les identifiants (utilisée dans l'audit)
   async function processCredentials(encryptedCredentials: any, sharedCredentials: any): Promise<void> {
     credentials = []; // Réinitialiser les identifiants

     // Traiter les identifiants chiffrés
     if (encryptedCredentials && Array.isArray(encryptedCredentials)) {
       for (const encryptedCredential of encryptedCredentials) {
         try {
           // Décryptage et traitement des identifiants (implémentation simplifiée)
           credentials.push(encryptedCredential);
             } catch (e) {
           console.error("Erreur lors du traitement de l'identifiant", e);
         }
       }
     }

     // Traiter les identifiants partagés
     if (sharedCredentials && Array.isArray(sharedCredentials)) {
       for (const sharedCredential of sharedCredentials) {
         try {
           // Traitement des identifiants partagés (implémentation simplifiée)
           credentials.push(sharedCredential);
         } catch (e) {
           console.error("Erreur lors du traitement de l'identifiant partagé", e);
         }
       }
     }

     // Trier les identifiants par service et nom d'utilisateur
     credentials.sort((a, b) => {
       const serviceCompare = (a.service || '').localeCompare(b.service || '');
       if (serviceCompare !== 0) return serviceCompare;
       return (a.username || '').localeCompare(b.username || '');
     });
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

   // Variables pour le menu contextuel
   let contextMenu = {
     show: false,
     x: 0,
     y: 0,
     credential: null as Credential | null
   };

   // Fonction pour afficher le menu contextuel
   function showContextMenu(event: MouseEvent, credential: Credential) {
     event.preventDefault();
     event.stopPropagation();
     console.log(event);

+    if (!browser) return; // Ensure document is available for dimensions

     // Obtenir les dimensions de la fenêtre
     const windowWidth = window.innerWidth;
     const windowHeight = window.innerHeight;

     // Obtenir la position du clic par rapport à la page
     const x = event.clientX;
     const y = event.clientY;

     // Dimensions du menu contextuel (approximatives)
     const menuWidth = 200;
     const menuHeight = 200; // Hauteur approximative basée sur le nombre d'options

     // Calculer la position finale en tenant compte des limites de la fenêtre
     let finalX = x;
     let finalY = y;

     // Ajuster la position horizontale si le menu dépasserait la fenêtre
     if (x + menuWidth > windowWidth) {
       finalX = windowWidth - menuWidth;
     }

     // Ajuster la position verticale si le menu dépasserait la fenêtre
     if (y + menuHeight > windowHeight) {
       finalY = windowHeight - menuHeight;
     }

     contextMenu = {
       show: true,
       x: finalX,
       y: finalY,
       credential
     };
   }

   // Fonction pour fermer le menu contextuel
   function closeContextMenu() {
     contextMenu.show = false;
     contextMenu.credential = null;
   }

   // Fermer le menu contextuel lors d'un clic en dehors
   function handleClickOutside(event: MouseEvent) {
     if (contextMenu.show) {
       closeContextMenu();
     }
   }

   onMount(() => {
+    if (browser) {
      document.addEventListener('click', handleClickOutside);
      return () => {
        document.removeEventListener('click', handleClickOutside);
      };
+    }
   });

   // Rendre l'activation du 2FA automatique au chargement de la page
   onMount(() => {
     // ... existing code ...

     // Activer automatiquement le 2FA pour tous les credentials avec OTP
     setTimeout(() => {
       filteredCredentials.forEach(credential => {
         if (credential.otp && !credential.twoFA) {
           toggle2FA(credential);
         }
       });
     }, 500);
   });

   // Activer automatiquement le 2FA pour tous les identifiants avec OTP après le chargement
   onMount(() => {
     // Attendre que les données soient chargées
     const intervalId = setInterval(() => {
       if (credentials.length > 0 && !loading) {
         clearInterval(intervalId);

         // Activer le 2FA pour tous les identifiants avec OTP
         setTimeout(() => {
           credentials.forEach(credential => {
             if (credential.otp && !credential.twoFA) {
               toggle2FA(credential);
             }
           });
         }, 1000);
       }
     }, 500);

     // Nettoyage
     return () => {
       clearInterval(intervalId);
     };
   });

   // Variable pour le menu contextuel du profil
   let showProfileMenu = false;

   // Fonction pour afficher/masquer le menu contextuel du profil
   function toggleProfileMenu(event: MouseEvent) {
     event.preventDefault();
     event.stopPropagation();
     showProfileMenu = !showProfileMenu;
   }

   // Fonction pour fermer le menu contextuel du profil lors d'un clic en dehors
   function handleClickOutsideProfile(event: MouseEvent) {
     if (showProfileMenu) {
+      if (!browser) return; // Ensure document is available
       const target = event.target as HTMLElement;
       const profileMenu = document.getElementById("profile-menu");
       const profileButton = document.getElementById("profile-button");

       if (profileMenu && !profileMenu.contains(target) &&
           profileButton && !profileButton.contains(target)) {
         showProfileMenu = false;
       }
     }
   }

   // Ajouter l'événement de clic pour fermer le menu contextuel du profil
   onMount(() => {
+    if (browser) {
      document.addEventListener('click', handleClickOutsideProfile);
      return () => {
        document.removeEventListener('click', handleClickOutsideProfile);
      };
+    }
   });

   // Variables pour l'audit des mots de passe
   let showAuditModal = false;
   let weakPasswords: Credential[] = [];
   let reusedPasswords: {credential: Credential, count: number}[] = [];
   let breachedPasswords: Credential[] = [];
   let isCheckingBreaches = false;
   let haveibeenpwnedError = "";
   let overallScore = 0;
   let errorMessage = ""; // Variable pour les messages d'erreur

   // Fonction pour hacher un mot de passe avec SHA-1 (pour l'API haveibeenpwned)
   async function sha1(password: string): Promise<string> {
+    if (!browser) return password; // Return original password or handle gracefully on server
     const msgBuffer = new TextEncoder().encode(password);
     const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
     const hashArray = Array.from(new Uint8Array(hashBuffer));
     return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
   }

   // Fonction pour vérifier si un mot de passe a été compromis via haveibeenpwned
   async function checkPasswordBreached(password: string): Promise<boolean> {
+    if (!browser) return false; // Don't check external APIs on server
     try {
       const hash = await sha1(password);
       const prefix = hash.substring(0, 5);
       const suffix = hash.substring(5).toUpperCase();

       const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);

       if (!response.ok) {
         throw new Error(`HTTP error! Status: ${response.status}`);
       }

       const text = await response.text();
       const lines = text.split('\n');

       for (const line of lines) {
         const [hashSuffix, count] = line.split(':');
         if (hashSuffix.trim() === suffix) {
           return true;
         }
       }

       return false;
     } catch (error) {
       console.error("Error checking haveibeenpwned:", error);
       haveibeenpwnedError = String(error);
       return false;
     }
   }

   // Fonction pour calculer le score global de sécurité
   function calculateOverallScore(totalPasswords: number): number {
     if (totalPasswords === 0) return 100;

     const weakCount = weakPasswords.length;
     const reusedCount = reusedPasswords.length / 2; // Compter chaque groupe une seule fois
     const breachedCount = breachedPasswords.length;

     // Pénalités pour chaque type de problème
     const weakPenalty = 40 * (weakCount / totalPasswords);
     const reusedPenalty = 30 * (reusedCount / totalPasswords);
     const breachedPenalty = 30 * (breachedCount / totalPasswords);

     // Calculer le score final (100 - pénalités)
     let score = 100 - (weakPenalty + reusedPenalty + breachedPenalty);

     // Limiter le score entre 0 et 100
     score = Math.max(0, Math.min(100, score));

     return Math.round(score);
   }

   // Fonction pour obtenir la qualification du score
   function getScoreRating(score: number): string {
     if (score >= 90) return t('excellent', lang);
     if (score >= 70) return t('good', lang);
     if (score >= 50) return t('moderate', lang);
     if (score >= 30) return t('poor', lang);
     return t('critical', lang);
   }

   // Fonction pour obtenir la couleur du score
   function getScoreColor(score: number): string {
     if (score >= 90) return "#a7f3ae"; // Vert vif - excellent
     if (score >= 70) return "#a7f3ae99"; // Vert clair - bon
     if (score >= 50) return "#f8d88a"; // Jaune - moyen
     if (score >= 30) return "#f2c3c2"; // Rose - faible
     return "#e53e3e"; // Rouge - critique
   }

   // Fonction pour auditer tous les mots de passe
   async function auditAllPasswords() {
     // Réinitialiser les résultats précédents
     weakPasswords = [];
     reusedPasswords = [];
     breachedPasswords = [];
     isCheckingBreaches = true;
     haveibeenpwnedError = "";

     // Ouvrir le modal immédiatement pour montrer le chargement
     showAuditModal = true;

     // Vérifier les mots de passe faibles (score < 3)
     weakPasswords = credentials.filter(cred => {
       if (!cred.password) return false;
       const result = evaluatePasswordStrength(cred.password);
       return result.score < 3;
     });

     // Vérifier les mots de passe réutilisés
     const passwordMap = new Map<string, number>();
     const passwordCredMap = new Map<string, Credential[]>();

     credentials.forEach(cred => {
       if (!cred.password) return;

       // Compter les occurrences du mot de passe
       const count = passwordMap.get(cred.password) || 0;
       passwordMap.set(cred.password, count + 1);

       // Associer le mot de passe à ses credentials
       const creds = passwordCredMap.get(cred.password) || [];
       creds.push(cred);
       passwordCredMap.set(cred.password, creds);
     });

     // Collecter les mots de passe réutilisés
     passwordMap.forEach((count, password) => {
       if (count > 1) {
         const creds = passwordCredMap.get(password) || [];
         creds.forEach(cred => {
           reusedPasswords.push({ credential: cred, count });
         });
       }
     });

     // Vérifier les mots de passe compromis via haveibeenpwned
     const uniquePasswords = new Set<string>();
     const breachCheckPromises: Promise<void>[] = [];

     for (const cred of credentials) {
       if (!cred.password || uniquePasswords.has(cred.password)) continue;

       uniquePasswords.add(cred.password);

       const promise = checkPasswordBreached(cred.password).then(isBreached => {
         if (isBreached) {
           // Trouver tous les credentials avec ce mot de passe
           credentials.forEach(c => {
             if (c.password === cred.password) {
               breachedPasswords.push(c);
             }
           });
         }
       });

       breachCheckPromises.push(promise);
     }

     // Attendre que toutes les vérifications soient terminées
     await Promise.all(breachCheckPromises);

     // Calculer le score global
     overallScore = calculateOverallScore(credentials.length);

     isCheckingBreaches = false;
   }

   // Fonction pour fermer le modal d'audit
   function closeAuditModal() {
     showAuditModal = false;
   }

   // Fonction pour éditer un identifiant depuis l'audit
   function editFromAudit(cred: Credential) {
     // Fermer le modal d'audit
     showAuditModal = false;

     // Commencer l'édition de l'identifiant
     startEdit(cred);

     // Utiliser setTimeout pour attendre que le DOM soit mis à jour
-    setTimeout(() => {
-      // Trouver l'élément à faire défiler jusqu'à
-      const element = document.querySelector(`[data-password-id="${cred.id}"]`);
-      if (element) {
-        // Faire défiler jusqu'à l'élément
-        element.scrollIntoView({ behavior: 'smooth', block: 'center' });
-      }
-    }, 100);
+    if (browser) {
+      setTimeout(() => {
+        // Trouver l'élément à faire défiler jusqu'à
+        const element = document.querySelector(`[data-password-id="${cred.id}"]`);
+        if (element) {
+          // Faire défiler jusqu'à l'élément
+          element.scrollIntoView({ behavior: 'smooth', block: 'center' });
+        }
+      }, 100);
+    }
   }

   // ... existing code ...

   // Variables pour la navigation au clavier
   let focusedCredentialIndex = -1;
   let searchInputRef: HTMLInputElement;
   let showKeyboardHelp = false;

   // Fonction pour copier du texte dans le presse-papiers
   function copyToClipboard(text: string) {
     if (!text) return;
-    navigator.clipboard.writeText(text)
-      .then(() => {
-        showToast(t('copiedToClipboard', lang));
-      })
-      .catch(err => {
-        console.error('Erreur lors de la copie dans le presse-papiers:', err);
-      });
+    if (browser) { // navigator.clipboard is a browser API
+      navigator.clipboard.writeText(text)
+        .then(() => {
+          showToast(t('copiedToClipboard', lang));
+        })
+        .catch(err => {
+          console.error('Erreur lors de la copie dans le presse-papiers:', err);
+        });
+    }
   }

   // Fonction pour gérer les raccourcis clavier globaux
   function handleKeyDown(event: KeyboardEvent) {
     // Ne pas intercepter les événements clavier lors de la saisie dans un input/textarea
     if (event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement) {
       // Si la touche Escape est pressée dans le champ de recherche, effacer le champ
       if (event.key === 'Escape' && event.target === searchInputRef) {
         searchTerm = '';
         event.target.blur();
         event.preventDefault();
       }
       return;
     }

     // Raccourcis clavier globaux
     switch (event.key) {
       case '/': // Raccourci pour la recherche
         if (searchInputRef) {
           searchInputRef.focus();
           event.preventDefault();
         }
         break;
       case 'n': // Nouveau mot de passe
         if (!showAddForm && !showExportDialog && !importingFile) {
           showAddForm = true;
           goto("#add-credential-form");
         }
         event.preventDefault();
         break;
       case 'e': // Exporter
         if (!showAddForm && !showExportDialog && !importingFile) {
           showExportDialog = true;
         }
         event.preventDefault();
         break;
       case 'i': // Importer
         if (!showAddForm && !showExportDialog && !importingFile) {
-          fileInput?.click();
+          if (fileInput && browser) { // fileInput.click() is client-side
+            fileInput.click();
+          }
         }
         event.preventDefault();
         break;
       case 'Escape': // Fermer les modales ou formulaires
         if (showExportDialog) {
           showExportDialog = false;
           event.preventDefault();
         } else if (showAddForm) {
           showAddForm = false;
           event.preventDefault();
         } else if (showKeyboardHelp) {
           showKeyboardHelp = false;
           event.preventDefault();
         }
         break;
       // Navigation avec les touches vim
       case 'j': // Comme flèche bas
       case 'ArrowDown': // Navigation vers le bas dans la liste
         if (filteredCredentials.length > 0) {
           focusedCredentialIndex = Math.min(focusedCredentialIndex + 1, filteredCredentials.length - 1);
           scrollToCredential(focusedCredentialIndex);
           event.preventDefault();
         }
         break;
       case 'k': // Comme flèche haut
       case 'ArrowUp': // Navigation vers le haut dans la liste
         if (filteredCredentials.length > 0) {
           focusedCredentialIndex = Math.max(focusedCredentialIndex - 1, 0);
           scrollToCredential(focusedCredentialIndex);
           event.preventDefault();
         }
         break;
       case 'h': // Déplacer vers la gauche/revenir en arrière
         // À implémenter selon besoin
         break;
       case 'l': // Déplacer vers la droite/avancer
         // À implémenter selon besoin
         break;
       case 'Enter': // Sélectionner l'élément en cours
         if (focusedCredentialIndex >= 0 && focusedCredentialIndex < filteredCredentials.length) {
           const credential = filteredCredentials[focusedCredentialIndex];
           // Ouvrir/copier/etc selon le contexte
           handleCredentialSelection(credential);
           event.preventDefault();
         }
         break;
       // Raccourcis de copie
       case 'u': // Copier nom d'utilisateur (username)
         if (focusedCredentialIndex >= 0 && focusedCredentialIndex < filteredCredentials.length) {
           const credential = filteredCredentials[focusedCredentialIndex];
           copyToClipboard(credential.username);
           event.preventDefault();
         }
         break;
       case 'p': // Copier mot de passe (password)
         if (focusedCredentialIndex >= 0 && focusedCredentialIndex < filteredCredentials.length) {
           const credential = filteredCredentials[focusedCredentialIndex];
           copyToClipboard(credential.password);
           event.preventDefault();
         }
         break;
       case 'o': // Copier code OTP
         if (focusedCredentialIndex >= 0 && focusedCredentialIndex < filteredCredentials.length) {
           const credential = filteredCredentials[focusedCredentialIndex];
           if (credential.twoFA) {
             copyToClipboard(credential.twoFA);
             event.preventDefault();
           }
         }
         break;
       case '?': // Afficher l'aide des raccourcis clavier
         showKeyboardHelp = !showKeyboardHelp;
         event.preventDefault();
         break;
     }
   }

   // Fonction pour faire défiler vers l'élément sélectionné
   function scrollToCredential(index: number) {
     if (index >= 0) {
+      if (!browser) return; // document.getElementById is a browser API
       const element = document.getElementById(`credential-${index}`);
       if (element) {
         element.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
       }
     }
   }

   // Fonction pour gérer la sélection d'un identifiant via le clavier
   function handleCredentialSelection(credential: any) {
     // Copier le mot de passe par défaut
     copyToClipboard(credential.password);
   }

   onDestroy(() => {
+    if (browser) {
      document.removeEventListener('keydown', handleKeyDown);
+    }
   });
 </script>
```

By adding `if (browser)` checks, you explicitly tell SvelteKit that these parts of the code should only run when the component is hydrated in a browser environment, thus preventing `document is not defined` errors during server-side rendering.
