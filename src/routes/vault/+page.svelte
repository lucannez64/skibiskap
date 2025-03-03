<script lang="ts">
  // Our sample list of credentials
  import { onMount, onDestroy } from "svelte";
  import { goto } from "$app/navigation";
  import { clientex, client } from "../stores";
  import { get_all, update_pass, delete_pass, create_pass, share_pass, get_shared_by_user, get_shared_by_user_emails, get_emails_from_uuids, get_uuid_from_email, unshare_pass } from "$lib/client";
  import { from_uri, generate } from "$lib/otp";
  import * as pkg from "uuid-tool";
  import Plus from "lucide-svelte/icons/plus";
  import SecureLS from "secure-ls";
  import X from "lucide-svelte/icons/x";
  import { zxcvbn } from '@zxcvbn-ts/core';
  import { writable, get, derived } from "svelte/store";
  import Search from "lucide-svelte/icons/search";
  const { Uuid } = pkg;
	import { uuidToStr, type Password, type Uuid as UuidType } from "$lib/decoder";


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

  interface PendingTask {
    [key: number]: (result: {url: string, passwordStrength: any}) => void;
  }

  // Création d'un store pour les identifiants
  const credentialsStore = writable<Credential[]>([]);
  // Création d'un store dérivé pour les identifiants filtrés
  let searchTerm = "";
  const filteredCredentialsStore = derived(
    [credentialsStore, writable(searchTerm)],
    ([$credentials, $searchTerm]) => {
      return $credentials
        .sort((a, b) => a.service.localeCompare(b.service))
        .filter((c) => c.service.toLowerCase().includes($searchTerm.toLowerCase()));
    }
  );

  let credentials: Credential[] = [];
  $: filteredCredentials = credentials
    .sort((a, b) => a.service.localeCompare(b.service))
    .filter((c) => c.service.toLowerCase().includes(searchTerm.toLowerCase()));

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
  let sharedPasswordEmails: Map<string, string[]> = new Map();

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
      if (encryptedCredentials[0].length === 0) {
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
            } as Credential;
          })
          .filter((item): item is Credential => item !== null);
      }

      // Combiner les mots de passe normaux et partagés
      credentials = [...processedCredentials.filter(Boolean) as Credential[], ...processedSharedCredentials];
      credentialsStore.set(credentials);
      
      // Récupérer les emails partagés
      const sharedByUserEmails = await get_shared_by_user_emails($clientex.id.id);
      if (sharedByUserEmails) {
        // Remplir le dictionnaire des emails partagés
        sharedByUserEmails.forEach(item => {
          sharedPasswordEmails.set(uuidToStr(item.pass_id), item.emails);
        });
      }
    } catch (error) {
      console.error("Erreur lors du chargement des identifiants:", error);
      disconnect();
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
      showToast("Copié dans le presse-papiers");
    });
  }

  // Start editing a credential record
  function startEdit(record: Credential) {
    editingId = record.id;
    // Create a shallow copy so the original doesn't change until saved.
    editedRecord = { ...record };
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
      showToast("Format d'URL invalide. Utilisez des formats comme: google.com, osu.ppy.sh, 192.168.1.167:8181");
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
        showToast("Erreur lors de la mise à jour: " + response.error);
        return;
      }
      
      // Mettre à jour les partages si nécessaire
      if (sharedPasswordEmails.has(credential.uuid)) {
        const emails = sharedPasswordEmails.get(credential.uuid);
        if (emails && emails.length > 0) {
          // Traiter tous les partages en parallèle
          await Promise.all(emails.map(async (email) => {
            try {
              const recipientUuidStr = await get_uuid_from_email(email);
              if (!recipientUuidStr) return;
              
              const recipientUuid = memoizedUuidToBytes(recipientUuidStr);
              if (!recipientUuid) return;
              
              // Annuler le partage puis le recréer avec les nouvelles données
              await unshare_pass($clientex!.id.id!, uuid2, recipientUuid);
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
            otp: editedRecord.otp || null
          };
        }
        return item;
      });
      credentialsStore.set(credentials);
      
      showToast("Identifiant mis à jour avec succès");
    } catch (error) {
      console.error("Erreur lors de la mise à jour:", error);
      showToast("Erreur lors de la mise à jour");
    } finally {
      editingId = null;
      editedRecord = {};
    }
  }

  // Cancel the editing process
  function cancelEdit() {
    editingId = null;
    editedRecord = {};
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
        showToast("Erreur lors de la suppression: " + response.error);
        return;
      }

      credentials = credentials.filter((item) => item.id !== editingId && item.uuid !== editedRecord.uuid);
      credentialsStore.set(credentials);
      showToast("Identifiant supprimé avec succès");
    } catch (error) {
      console.error("Erreur lors de la suppression:", error);
      showToast("Erreur lors de la suppression");
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

  // Toggle the two-factor authentication for a record
  function toggle2FA(record: Credential) {
    if (record.twoFA) {
      // Disable 2FA
      if (record.id in intervals) {
        clearInterval(intervals[record.id]);
        delete intervals[record.id];
      }
      
      credentials = credentials.map((item) => 
        item.id === record.id ? { ...item, twoFA: null, intervalId: null } : item
      );
    } else {
      // Enable 2FA
      const [code, period] = generate2FACode(record.otp);
      const periodNum = typeof period === 'number' ? period : 30;
      
      const intervalId = setInterval(() => {
        const remainingTime = (periodNum * 1000) - (Date.now() % (periodNum * 1000));
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
      showToast("Format d'URL invalide. Utilisez des formats comme: google.com, osu.ppy.sh, 192.168.1.167:8181");
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
        showToast("Erreur lors de la création: " + response.error);
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
      showToast("Identifiant créé avec succès");
    } catch (error) {
      console.error("Erreur lors de la création:", error);
      showToast("Erreur lors de la création");
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
      shareError = "Veuillez entrer une adresse email valide";
      return;
    }
    
    isSharing = true;
    shareError = '';
    
    try {
      if (!isClientValid()) {
        throw new Error("Client non initialisé");
      }
      
      const uuid2 = memoizedUuidToBytes(sharingCredential.uuid);
      if (!uuid2) {
        throw new Error("UUID invalide");
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
      const currentEmails = sharedPasswordEmails.get(sharingCredential.uuid) || [];
      if (!currentEmails.includes(shareUserId.trim())) {
        const updatedEmails = [...currentEmails, shareUserId.trim()];
        sharedPasswordEmails.set(sharingCredential.uuid, updatedEmails);
        // Forcer la mise à jour de l'interface
        sharedPasswordEmails = new Map(sharedPasswordEmails);
      }
      
      closeShareModal();
      showToast("Mot de passe partagé avec succès");
    } catch (error) {
      console.error("Erreur lors du partage:", error);
      shareError = `Erreur: ${error instanceof Error ? error.message : "Erreur inconnue"}`;
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
        throw new Error("Client non initialisé");
      }
      
      const uuid2 = memoizedUuidToBytes(sharingCredential.uuid);
      if (!uuid2) {
        throw new Error("UUID invalide");
      }
      
      // Récupérer l'UUID du destinataire à partir de son email
      const recipientUuidStr = await get_uuid_from_email(email);
      if (!recipientUuidStr) {
        throw new Error(`Impossible de trouver l'utilisateur avec l'email ${email}`);
      }
      
      const recipientUuid = memoizedUuidToBytes(recipientUuidStr);
      if (!recipientUuid) {
        throw new Error("UUID du destinataire invalide");
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
      const currentEmails = sharedPasswordEmails.get(sharingCredential.uuid) || [];
      const updatedEmails = currentEmails.filter(e => e !== email);
      
      if (updatedEmails.length === 0) {
        sharedPasswordEmails.delete(sharingCredential.uuid);
      } else {
        sharedPasswordEmails.set(sharingCredential.uuid, updatedEmails);
      }
      
      // Forcer la mise à jour de l'interface
      sharedPasswordEmails = new Map(sharedPasswordEmails);
      
      showToast(`Partage annulé avec ${email}`);
    } catch (error) {
      console.error("Erreur lors de l'annulation du partage:", error);
      shareError = `Erreur: ${error instanceof Error ? error.message : "Erreur inconnue"}`;
    } finally {
      isUnsharing = false;
      unsharingEmail = '';
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
</style>

<div class="min-h-screen p-4" style="background-color: #1d1b21; font-family: 'Work Sans', sans-serif;">
  <div class="max-w-3xl mx-auto">
    <!-- Disconnect Button -->
    <button
      on:click={disconnect}
      class="absolute top-4 right-4 danger-btn
             px-4 py-2 rounded-lg shadow-md"
    >
      Déconnexion
    </button>
    <h1 class="text-3xl font-bold text-center mb-6 text-white" style="font-family: 'Raleway', sans-serif;">
      Coffre-fort
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
          placeholder="Rechercher des identifiants..."
          class="w-full px-4 py-2 border rounded-lg
                focus:outline-none focus:ring-2 focus:ring-blue-500 pl-10"
          style="background-color: white; border-color: #474b4f; color: #1d1b21;"
        />
        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <Search class="w-5 h-5 text-gray-400" />
        </div>
      </div>
    </div>

    <!-- Add Credential Button -->
    <div class="mb-6">
      <button
        on:click={() => {showAddForm = !showAddForm; if (showAddForm) {goto("#add-credential-form")}}}
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
    </div>

    <!-- Add Credential Form -->
    {#if showAddForm}
      <div id="add-credential-form" class="card p-4 mb-6">
        <div class="mb-2">
          <label class="block text-sm font-medium" style="color: #1d1b21;" for="newService">
            Service
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
            Nom d'utilisateur
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
            Mot de passe
          </label>
          <input
            id="newPassword"
            type="text"
            bind:value={newRecord.password}
            class="mt-1 block w-full border rounded-lg p-2
                   focus:outline-none focus:ring-2"
            style="border-color: #474b4f;"
          />
        </div>
        <div class="mb-2">
          <label class="block text-sm font-medium" style="color: #1d1b21;" for="newOTP">
            URI OTP
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
        <div class="flex space-x-2 mt-4">
          <button
            on:click={saveNewCredential}
            class="secondary-btn px-4 py-2 rounded-lg"
          >
            Enregistrer
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
            }}
            class="neutral-btn px-4 py-2 rounded-lg"
          >
            Annuler
          </button>
        </div>
      </div>
    {/if}
    <!-- Credentials list -->
    {#each filteredCredentials as credential (credential.id)}
      <div class="card p-4 mb-4">
        {#if editingId === credential.id}
          <!-- Edit Mode -->
          <div class="mb-2">
            <label class="block text-sm font-medium" style="color: #1d1b21;" for="editService">
              Service
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
              Nom d'utilisateur
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
              Mot de passe
            </label>
            <input
              id = "editPassword"
              type="text"
              bind:value={editedRecord.password}
              class="mt-1 block w-full border rounded-lg p-2
                     focus:outline-none focus:ring-2"
              style="border-color: #474b4f;"
            />
          </div>
          <div class="mb-2">
            <label class="block text-sm font-medium" style="color: #1d1b21;" for="editOTPURI">
              URI OTP 
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
          <div class="flex space-x-2 mt-4">
            <button
              on:click={saveEdit}
              class="secondary-btn px-4 py-2 rounded-lg"
            >
              Enregistrer
            </button>
            <button
              on:click={deleteEdit}
              class="danger-btn px-4 py-2 rounded-lg"
            >
              Supprimer
            </button>
            <button
              on:click={cancelEdit}
              class="neutral-btn px-4 py-2 rounded-lg"
            >
              Annuler
            </button>
          </div>
        {:else}
          <!-- View Mode -->
          <div class="flex justify-between items-start">
            <div>
              <h3 class="text-lg font-semibold" style="color: #1d1b21; font-family: 'Raleway', sans-serif;">
                {credential.service}
                {#if credential.sharedBy}
                  <span class="text-xs bg-purple-200 text-purple-800 px-2 py-1 rounded-full ml-2">
                    Partagé
                  </span>
                {/if}
              </h3>
              <div class="mt-1 flex items-center">
                <span class="mr-2" style="color: #474b4f;">Nom d'utilisateur:</span>
                <span class="font-medium" style="color: #1d1b21;">{credential.username}</span>
                <button
                  on:click={() => copyText(credential.username)}
                  class="ml-2 text-blue-500 hover:text-blue-700 copy-btn"
                  title="Copier le nom d'utilisateur"
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
                <span class="mr-2" style="color: #474b4f;">Mot de passe:</span>
                <span class="font-medium" style="color: #1d1b21;">••••••••</span>
                <button
                  on:click={() => copyText(credential.password)}
                  class="ml-2 text-blue-500 hover:text-blue-700 copy-btn"
                  title="Copier le mot de passe"
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
              {#if credential.otp}
                <div class="mt-2">
                  {#if credential.twoFA}
                    <div class="flex items-center">
                      <span class="mr-2" style="color: #474b4f;">Code 2FA:</span>
                      <span class="font-mono px-2 py-1 rounded" style="background-color: #f2c3c2; color: #1d1b21;">
                        {credential.twoFA}
                      </span>
                      <button
                        on:click={() => copyText(credential.twoFA)}
                        class="ml-2 text-blue-500 hover:text-blue-700 copy-btn"
                        title="Copier le code 2FA"
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
                    class="mt-1 text-sm px-2 py-1 rounded"
                    style="background-color: #a7f3ae; color: #1d1b21;"
                  >
                    {credential.twoFA ? "Désactiver 2FA" : "Activer 2FA"}
                  </button>
                </div>
              {/if}
              {#if credential.owneremail}
                <div class="mt-2 text-xs text-purple-700">
                  Partagé par: {credential.owneremail}
                </div>
              {/if}
            </div>
            <div class="flex space-x-2">
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
            </div>
          </div>
        {/if}
      </div>
    {:else}
      <div class="text-center py-8 text-white">
        {searchTerm ? "Aucun identifiant ne correspond à votre recherche." : "Aucun identifiant enregistré. Cliquez sur le bouton + pour en ajouter."}
      </div>
    {/each}
  {/if}
  </div>
</div>

<!-- Modal de partage -->
{#if showingShareModal}
  <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
    <div class="card p-6 w-full max-w-md">
      <h2 class="text-xl font-semibold mb-4" style="font-family: 'Raleway', sans-serif; color: #1d1b21;">Partager le mot de passe</h2>
      <p class="mb-4" style="color: #474b4f;">Entrez l'adresse email de l'utilisateur avec qui vous souhaitez partager ce mot de passe.</p>
      
      <div class="mb-4">
        <label for="shareUserId" class="block font-medium mb-1" style="color: #1d1b21;">Email</label>
        <input
          type="email"
          id="shareUserId"
          bind:value={shareUserId}
          class="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2"
          style="border-color: #474b4f;"
          placeholder="exemple@email.com"
          required
        />
      </div>
      
      {#if shareError}
        <p class="text-red-500 mb-4 text-sm">{shareError}</p>
      {/if}
      
      <!-- Afficher les emails avec lesquels ce mot de passe a déjà été partagé -->
      {#if sharingCredential && sharedPasswordEmails.has(sharingCredential.uuid)}
        <div class="mb-4">
          <h3 class="text-sm font-medium mb-2" style="color: #1d1b21;">Déjà partagé avec :</h3>
          <ul class="p-2 rounded-md max-h-32 overflow-y-auto" style="background-color: #1d1b21;">
            {#each sharedPasswordEmails.get(sharingCredential.uuid) || [] as email}
              <li class="flex justify-between items-center text-sm py-1 px-2 border-b border-zinc-700 last:border-b-0">
                <span style="color: #ced7e1;">{email}</span>
                <button 
                  on:click={() => unsharePassword(email)}
                  class="text-red-500 hover:text-red-700 ml-2 flex items-center"
                  title="Annuler le partage"
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
      
      <div class="flex justify-end space-x-2">
        <button
        on:click={sharePassword}
        class="secondary-btn px-4 py-2 rounded-md flex items-center"
        disabled={isSharing}
        >
          {#if isSharing}
            <div class="w-4 h-4 border-2 border-zinc-800 border-t-transparent rounded-full animate-spin mr-2"></div>
            Partage en cours...
          {:else}
            Partager
          {/if}
        </button>
        <button
          on:click={closeShareModal}
          class="primary-btn px-4 py-2 rounded-md"
        >
          Annuler
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
