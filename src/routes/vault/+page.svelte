<script lang="ts">
  // Our sample list of credentials
  import { onMount, onDestroy } from "svelte";
  import { goto } from "$app/navigation";
  import { clientex, client } from "../stores";
  import { get_all, update_pass, delete_pass, create_pass } from "$lib/client";
  import { from_uri, generate } from "$lib/otp";
  import * as pkg from "uuid-tool";
  import Plus from "lucide-svelte/icons/plus";
  import SecureLS from "secure-ls";
  import X from "lucide-svelte/icons/x";
  import { zxcvbn } from '@zxcvbn-ts/core';
  import { writable, get } from "svelte/store";
  import Search from "lucide-svelte/icons/search";
  const { Uuid } = pkg;

  // Définition des types
  interface Credential {
    id: number;
    service: string;
    username: string;
    uuid: string;
    password: string;
    otp: string | null;
    twoFA: string | null;
    intervalId?: number | null;
    sharedBy?: string;
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

  let credentials: Credential[] = [];
  let intervals: {[key: number]: number} = {}; // Store intervals for each credential
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

  onMount (async () => {
    if ($clientex === undefined || $client === undefined || $client.secret === undefined) {
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
        if ($clientex === undefined || $client === undefined || $client.secret === undefined) {
          goto('/'); 
        }
      } else {
        goto('/');
      }
    }
    
    if (!$clientex || !$clientex.id || !$clientex.id.id) {
      disconnect();
      return;
    }
    
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

    const NUM_WORKERS = 4;
    const workers: Worker[] = [];
    for (let i = 0; i < NUM_WORKERS; i++) {
      workers.push(new Worker("passwordWorker.js", { type: "module" }));
    }

    const getWorker = () =>
      workers[
        Math.floor(Math.random() * NUM_WORKERS)
      ];

    let taskId = 0;
    const pendingTasks: PendingTask = {};
    workers.forEach((worker) => {
      worker.onmessage = (event) => {
        const { taskId, url, passwordStrength } = event.data;
        if (pendingTasks[taskId]) {
          pendingTasks[taskId]({url, passwordStrength});
          delete pendingTasks[taskId];
        }
      };
    });

    // Traiter les mots de passe normaux
    const processedCredentials = encryptedCredentials
      .map((item, index) => {
        const uuid = item[1];
        const cred = item[0];
        if (!cred || typeof cred !== 'object') return null;
        
        // Vérifier que cred est de type Password
        const password = 'password' in cred ? cred.password : '';
        const url = 'url' in cred ? cred.url : '';
        const username = 'username' in cred ? cred.username : '';
        const otp = 'otp' in cred ? cred.otp : null;
        
        function evaluatePasswordWithWorker(password: string, url: string) {
          return new Promise<{url: string, passwordStrength: any}>((resolve) => {
            const currentTaskId = taskId++;
            pendingTasks[currentTaskId] = resolve;
            const worker = getWorker();
            worker.postMessage({ taskId: currentTaskId, password, url });
          });
        }
        
        evaluatePasswordWithWorker(password, url!).then(({ url, passwordStrength }) => {
          console.log(url, passwordStrength);
        });
        
        return {
          id: index,
          service: url,
          username,
          uuid: typeof uuid === 'string' ? uuid : '',
          password,
          otp,
          twoFA: null,
        } as Credential;
      })
      .filter((item): item is Credential => item !== null);

    // Traiter les mots de passe partagés si disponibles
    let processedSharedCredentials: Credential[] = [];
    if (sharedCredentials) {
      processedSharedCredentials = sharedCredentials[0]
        .map((cred, index) => {
          if (!cred) return null;
          
          const ownerUuid = sharedCredentials[1][index];
          const passUuid = sharedCredentials[2][index];
          
          // Vérifier que cred est de type Password
          const password = 'password' in cred ? cred.password : '';
          const url = 'url' in cred ? cred.url : '';
          const username = 'username' in cred ? cred.username : '';
          const otp = 'otp' in cred ? cred.otp : null;
          
          return {
            id: processedCredentials.length + index, // Éviter les conflits d'ID
            service: url ? `${url} (Partagé)` : 'Partagé',
            username,
            uuid: typeof passUuid === 'string' ? passUuid : '',
            password,
            otp,
            twoFA: null,
            sharedBy: typeof ownerUuid === 'string' ? ownerUuid : '',
          } as Credential;
        })
        .filter((item): item is Credential => item !== null);
    }

    // Combiner les mots de passe normaux et partagés
    credentials = [...processedCredentials, ...processedSharedCredentials];
    loading = false;
  });

  onDestroy(() => {
    // Clear all intervals when the component is unmounted
    Object.values(intervals).forEach((intervalId) => clearInterval(intervalId));
  });
  
  // For the search input
  let searchTerm = "";

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

  // Save the edited record back into our credentials array
  function saveEdit() {
    if (editingId === null || !editedRecord.service || !editedRecord.username || !editedRecord.password) {
      return;
    }
    
    credentials = credentials.map((item) => {
      if (item.id === editingId) {
        const a = {
          password: editedRecord.password || '',
          otp: editedRecord.otp ? editedRecord.otp : null,
          username: editedRecord.username || '',
          url: editedRecord.service || '',
          description: null,
          app_id: null,
        }
        
        if (!item.uuid) {
          console.error("UUID manquant");
          return item;
        }
        
        try {
          const uuid = new Uuid(item.uuid);
          const uuid2 = {
            bytes: new Uint8Array(uuid.toBytes()),
          };
          
          if (!$clientex || !$clientex.id || !$clientex.id.id || !$client) {
            console.error("Client ou ID manquant");
            return item;
          }
          
          update_pass($clientex.id.id, uuid2, a, $client).then((response) => {
            if (response.error) {
              console.error(response.error);
            }
          });
        } catch (error) {
          console.error("Erreur lors de la création de l'UUID", error);
        }
        
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
    
    editingId = null;
    editedRecord = {};
  }

  // Cancel the editing process
  function cancelEdit() {
    editingId = null;
    editedRecord = {};
  }

  function deleteEdit() {
    if (!editedRecord.uuid || editingId === null) {
      return;
    }
    
    try {
      const uuid = new Uuid(editedRecord.uuid);
      const uuid2 = {
        bytes: new Uint8Array(uuid.toBytes()),
      };
      
      if (!$clientex || !$clientex.id || !$clientex.id.id || !$client) {
        console.error("Client ou ID manquant");
        return;
      }
      
      delete_pass($clientex.id.id, uuid2, $client).then((response) => {
        if (response.error) {
          console.error(response.error);
        }
        credentials = credentials.filter((item) => item.id !== editingId);
        editingId = null;
        editedRecord = {};
      });
    } catch (error) {
      console.error("Erreur lors de la création de l'UUID", error);
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
    credentials = credentials.map((item) => {
      if (item.id === record.id) {
        if (item.twoFA) {
          // Disable 2FA
          if (item.id in intervals) {
            clearInterval(intervals[item.id]);
            delete intervals[item.id];
          }
          return { ...item, twoFA: null, intervalId: null };
        } else {
          // Enable 2FA
          const [code, period] = generate2FACode(record.otp);
          const periodNum = typeof period === 'number' ? period : 30;
          
          const intervalId = setInterval(() => {
            const remainingTime = (periodNum * 1000) - (Date.now() % (periodNum * 1000));
            if (remainingTime/1000 > periodNum-5) {
              credentials = credentials.map((cred) =>
                cred.id === item.id ? { ...cred, twoFA: generate2FACode(cred.otp)[0] } : cred
              );
            }
          }, 1000);
          
          intervals[item.id] = intervalId;
          return { ...item, twoFA: code, intervalId };
        }
      }
      return item;
    }) as Credential[];
  }
  
  function disconnect() {
    localStorage.clear();
    client.set(undefined);
    clientex.set(undefined);
    goto("/");
  }
  
  // Save a new credential. Adjust this function to integrate your backend logic.
  function saveNewCredential() {
    // Create a new credential with an arbitrary new id
    // In an actual application, this would likely involve an API call.
    const newId = credentials.length
      ? Math.max(...credentials.map((cred) => cred.id)) + 1
      : 0;
    const newItem: Credential = {
      id: newId,
      service: newRecord.service,
      username: newRecord.username,
      password: newRecord.password,
      otp: newRecord.otp,
      uuid: new Uuid().toString(),
      twoFA: null,
    };

    // TODO: Replace this with your API call to add the new credential on your
    // backend.
    const a = {
      password: newItem.password,
      otp: newItem.otp ? newItem.otp : null,
      username: newItem.username,
      url: newItem.service,
      description: null,
      app_id: null,
    }
    
    if (!$clientex || !$clientex.id || !$clientex.id.id || !$client) {
      console.error("Client ou ID manquant");
      return;
    }
    
    create_pass($clientex.id.id, a, $client).then((response) => {
      if (response.error) {
        console.error(response.error);
        return;
      }
      credentials = [...credentials, newItem];

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
    });
  }
  
  // Computed array of credentials filtered by the search term.
  $: filteredCredentials = credentials.sort((a, b) => a.service.localeCompare(b.service)).filter((c) =>
    {
      return c.service.toLowerCase().includes(searchTerm.toLowerCase())
    }
  );

  // Variables pour le partage de mot de passe
  let showingShareModal = false;
  let shareUserId = '';
  let shareError = '';
  let isSharing = false;
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
      shareError = "Veuillez entrer un ID utilisateur valide";
      return;
    }
    
    isSharing = true;
    shareError = '';
    
    try {
      // Convertir l'ID en UUID si nécessaire
      const userId = shareUserId.trim();
      
      // Vérifier que le client est défini
      const clientValue = get(client);
      if (!clientValue) {
        throw new Error("Client non initialisé");
      }
      
      // Appeler la fonction de partage du client
      // @ts-ignore - La fonction share_pass existe dans le client mais TypeScript ne la reconnaît pas
      const result = await clientValue.share_pass(
        sharingCredential.id,
        userId
      );
      
      if (result === true) {
        // Partage réussi
        closeShareModal();
        showToast("Mot de passe partagé avec succès");
      } else {
        // Erreur lors du partage
        shareError = "Erreur lors du partage du mot de passe";
      }
    } catch (error) {
      console.error("Erreur lors du partage:", error);
      shareError = `Erreur: ${error instanceof Error ? error.message : "Erreur inconnue"}`;
    } finally {
      isSharing = false;
    }
  }
</script>
<style>
  .spinner {
    border: 4px solid rgba(0, 0, 0, 0.1);
    width: 36px;
    height: 36px;
    border-radius: 50%;
    border-left-color: #09f;
    animation: spin 1s linear infinite;
    margin: auto;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>

<div class="min-h-screen bg-zinc-900 p-4">
  <div class="max-w-3xl mx-auto">
    <!-- Disconnect Button -->
    <button
      on:click={disconnect}
      class="absolute top-4 right-4 bg-red-500 hover:bg-red-600 text-white
             px-4 py-2 rounded-lg shadow-md"
    >
      Disconnect
    </button>
    <h1 class="text-3xl font-bold text-center mb-6 text-white">
      Vault
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
      <input
        type="text"
        bind:value={searchTerm}
        placeholder="Search credentials..."
        class="w-full px-4 py-2 border border-zinc-300 rounded-lg
               focus:outline-none focus:ring-2 focus:ring-blue-500 bg-zinc-100"
      />
    </div>

    <!-- Add Credential Button -->
    <div class="mb-6">
      <button
        on:click={() => {showAddForm = !showAddForm; if (showAddForm) {goto("#add-credential-form")}}}
        class="fixed bottom-4 right-4 h-14 w-14 rounded-full shadow-lg transition-transform hover:scale-110 bg-zinc-600"
      >
        <div
          class="flex items-center justify-center h-full w-full rounded-full"
        >
        {#if showAddForm}
          <X class="w-6 h-6 text-green-600" />
        {:else}
          <Plus class="w-6 h-6 text-green-600" />
        {/if}
        </div>
      </button>
    </div>

    <!-- Add Credential Form -->
    {#if showAddForm}
      <div id="add-credential-form" class="bg-blue-100 shadow-md rounded-lg p-4 mb-6">
        <div class="mb-2">
          <label class="block text-sm font-medium text-zinc-700" for="newService">
            Service
          </label>
          <input
            id="newService"
            type="text"
            bind:value={newRecord.service}
            class="mt-1 block w-full border border-zinc-300 rounded-lg p-2
                   focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div class="mb-2">
          <label
            class="block text-sm font-medium text-zinc-700"
            for="newUsername"
          >
            Username
          </label>
          <input
            id="newUsername"
            type="text"
            bind:value={newRecord.username}
            class="mt-1 block w-full border border-zinc-300 rounded-lg p-2
                   focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div class="mb-2">
          <label
            class="block text-sm font-medium text-zinc-700"
            for="newPassword"
          >
            Password
          </label>
          <input
            id="newPassword"
            type="text"
            bind:value={newRecord.password}
            class="mt-1 block w-full border border-zinc-300 rounded-lg p-2
                   focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div class="mb-2">
          <label class="block text-sm font-medium text-zinc-700" for="newOTP">
            OTP URI
          </label>
          <input
            id="newOTP"
            type="text"
            bind:value={newRecord.otp}
            class="mt-1 block w-full border border-zinc-300 rounded-lg p-2
                   focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div class="flex space-x-2 mt-4">
          <button
            on:click={saveNewCredential}
            class="bg-green-300 hover:bg-green-400 text-black px-4 py-2 rounded-lg"
          >
            Save Credential
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
            class="bg-zinc-600 hover:bg-zinc-700 text-white px-4 py-2 rounded-lg"
          >
            Cancel
          </button>
        </div>
      </div>
    {/if}
    <!-- Credentials list -->
    {#each filteredCredentials as credential (credential.id)}
      <div class="bg-blue-100 shadow-md rounded-lg p-4 mb-4">
        {#if editingId === credential.id}
          <!-- Edit Mode -->
          <div class="mb-2">
            <label class="block text-sm font-medium text-zinc-700" for="editService">
              Service
            </label>
            <input
              id="editService"
              type="text"
              bind:value={editedRecord.service}
              class="mt-1 block w-full border border-zinc-300 rounded-lg p-2
                     focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div class="mb-2">
            <label class="block text-sm font-medium text-zinc-700" for="editUsername">
              Username
            </label>
            <input
              type="text"
              id="editUsername"
              bind:value={editedRecord.username}
              class="mt-1 block w-full border border-zinc-300 rounded-lg p-2
                     focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div class="mb-2">
            <label class="block text-sm font-medium text-zinc-700" for="editPassword">
              Password
            </label>
            <input
              id = "editPassword"
              type="text"
              bind:value={editedRecord.password}
              class="mt-1 block w-full border border-zinc-300 rounded-lg p-2
                     focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div class="mb-2">
            <label class="block text-sm font-medium text-zinc-700" for="editOTPURI">
              OTPURI 
            </label>
            <input
              id = "editOTPURI"
              type="text"
              bind:value={editedRecord.otp}
              class="mt-1 block w-full border border-zinc-300 rounded-lg p-2
                     focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div class="flex space-x-2 mt-4">
            <button
              on:click={saveEdit}
              class="bg-green-300 hover:bg-green-400 text-black px-4 py-2 rounded-lg"
            >
              Save
            </button>
            <button
              on:click={deleteEdit}
              class="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg"
            >
              Delete
            </button>
            <button
              on:click={cancelEdit}
              class="bg-zinc-600 hover:bg-zinc-700 text-white px-4 py-2 rounded-lg"
            >
              Cancel
            </button>
          </div>
        {:else}
          <!-- View Mode -->
          <div class="flex justify-between items-start">
            <div>
              <h3 class="text-lg font-semibold text-zinc-800">
                {credential.service}
                {#if credential.sharedBy}
                  <span class="text-xs bg-purple-200 text-purple-800 px-2 py-1 rounded-full ml-2">
                    Partagé
                  </span>
                {/if}
              </h3>
              <div class="mt-1 flex items-center">
                <span class="text-zinc-600 mr-2">Username:</span>
                <span class="font-medium">{credential.username}</span>
                <button
                  on:click={() => copyText(credential.username)}
                  class="ml-2 text-blue-500 hover:text-blue-700"
                  title="Copy username"
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
                <span class="text-zinc-600 mr-2">Password:</span>
                <span class="font-medium">••••••••</span>
                <button
                  on:click={() => copyText(credential.password)}
                  class="ml-2 text-blue-500 hover:text-blue-700"
                  title="Copy password"
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
                      <span class="text-zinc-600 mr-2">2FA Code:</span>
                      <span class="font-mono bg-zinc-200 px-2 py-1 rounded">
                        {credential.twoFA}
                      </span>
                      <button
                        on:click={() => copyText(credential.twoFA)}
                        class="ml-2 text-blue-500 hover:text-blue-700"
                        title="Copy 2FA code"
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
                    class="mt-1 text-sm bg-zinc-200 hover:bg-zinc-300 text-zinc-800 px-2 py-1 rounded"
                  >
                    {credential.twoFA ? "Disable 2FA" : "Enable 2FA"}
                  </button>
                </div>
              {/if}
              {#if credential.sharedBy}
                <div class="mt-2 text-xs text-purple-700">
                  Partagé par: {credential.sharedBy}
                </div>
              {/if}
            </div>
            <div class="flex space-x-2">
              {#if !credential.sharedBy}
                <button
                  on:click={() => startEdit(credential)}
                  class="text-blue-500 hover:text-blue-700"
                  title="Edit"
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
    {/each}
  {/if}
  </div>
</div>

<!-- Ajouter le modal de partage -->
{#if showingShareModal}
  <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
    <div class="bg-white rounded-lg p-6 w-full max-w-md">
      <h2 class="text-xl font-semibold mb-4">Partager le mot de passe</h2>
      <p class="mb-4">Entrez l'identifiant de l'utilisateur avec qui vous souhaitez partager ce mot de passe.</p>
      
      <div class="mb-4">
        <label for="shareUserId" class="block text-zinc-700 font-medium mb-1">ID Utilisateur</label>
        <input
          type="text"
          id="shareUserId"
          bind:value={shareUserId}
          class="w-full px-3 py-2 border border-zinc-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          placeholder="Entrez l'ID utilisateur"
          required
        />
      </div>
      
      {#if shareError}
        <p class="text-red-500 mb-4">{shareError}</p>
      {/if}
      
      <div class="flex justify-end space-x-2">
        <button
          on:click={closeShareModal}
          class="bg-zinc-300 hover:bg-zinc-400 text-zinc-800 px-4 py-2 rounded-md"
        >
          Annuler
        </button>
        <button
          on:click={sharePassword}
          class="bg-purple-500 hover:bg-purple-600 text-white px-4 py-2 rounded-md"
          disabled={isSharing}
        >
          {isSharing ? 'Partage en cours...' : 'Partager'}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Ajouter le composant de notification -->
{#if showNotification}
  <div class="fixed top-4 right-4 bg-blue-500 text-white px-4 py-2 rounded-md shadow-md z-50 transition-opacity duration-300">
    {notificationMessage}
  </div>
{/if}
