<script>
  // Our sample list of credentials
  import { onMount, onDestroy } from "svelte";
  import { goto } from "$app/navigation";
  import { clientex, client } from "../stores.ts";
  import { get_all, update_pass, delete_pass, create_pass } from "$lib/client.ts";
  import { from_uri, generate } from "$lib/otp.ts";
  import * as pkg from "uuid-tool";
  import Plus from "lucide-svelte/icons/plus";
  import SecureLS from "secure-ls";
  import X from "lucide-svelte/icons/x";
  const { Uuid } = pkg;

  let credentials = [];
  let intervals = {}; // Store intervals for each credential
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

    let credential2s = await get_all($clientex.id.id, $client);
    if (credentials.error) {
      console.error(credentials.error);
    }
    const cred3 = credential2s.result.map((credential, index) => {
      return {
        id: index,
        service: credential[0].url,
        username: credential[0].username,
        uuid: credential[1],
        password: credential[0].password,
        otp: credential[0].otp,
        twoFA: null,

      };
    });
    loading=false;
    credentials = cred3;

  });

  onDestroy(() => {
    // Clear all intervals when the component is unmounted
    Object.values(intervals).forEach((intervalId) => clearInterval(intervalId));
  });
  // For the search input
  let searchTerm = "";

  // For inline editing state
  let editingId = null;
  let editedRecord = {};

  // Helper: Copy any text to the clipboard
  function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
    });
  }

  // Start editing a credential record
  function startEdit(record) {
    editingId = record.id;
    // Create a shallow copy so the original doesn't change until saved.
    editedRecord = { ...record };
  }

  // Save the edited record back into our credentials array
  function saveEdit() {
    credentials = credentials.map((item) =>
      {
        if (item.id === editingId) {
          const a = {
            password: editedRecord.password,
            otp: editedRecord.otp ? editedRecord.otp : null,
            username: editedRecord.username,
            url: editedRecord.service,
            description: null,
            app_id: null,
          }
          const uuid = new Uuid(item.uuid);
          const uuid2 = {
            bytes: uuid.toBytes(),
          };
          update_pass($clientex.id.id, uuid2, a, $client).then((response) => {
            if (response.error) {
              console.error(response.error);
            }
          })
          return editedRecord;
        }
        return item;
      }
    );
    editingId = null;
    editedRecord = {};
  }

  // Cancel the editing process
  function cancelEdit() {
    editingId = null;
    editedRecord = {};
  }

  function deleteEdit() {
    const uuid = new Uuid(editedRecord.uuid);
    const uuid2 = {
      bytes: uuid.toBytes(),
    };
    delete_pass($clientex.id.id, uuid2, $client).then((response) => {
      if (response.error) {
        console.error(response.error);
      }
      credentials = credentials.filter((item) => item.id !== editingId);
      editingId = null;
      editedRecord = {};
    })
  }


  // Generate a simple 6-digit code for 2FA demonstration
  function generate2FACode(otp) {
    const ot2p = from_uri(otp);
    return [generate(ot2p), ot2p.period];
  }

  // Toggle the two-factor authentication for a record
  function toggle2FA(record) {
    credentials = credentials.map((item) => {
      if (item.id === record.id) {
        if (item.twoFA) {
          // Disable 2FA
          clearInterval(intervals[item.id]);
          delete intervals[item.id];
          return { ...item, twoFA: null, intervalId: null };
        } else {
          // Enable 2FA
          const [code, period] = generate2FACode(record.otp);
          const intervalId = setInterval(() => {
            const remainingTime = (period * 1000) - (Date.now() % (period * 1000));
            if (remainingTime/1000 > period-5) {
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
    });
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
    const newItem = {
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
    create_pass($clientex.id.id, a, $client).then((response) => {
      if (response.error) {
        console.error(response.error);
        return;
      }
      credentials = [...credentials, newItem];

      // Reset the form
      newRecord = { service: "", username: "", password: "", otp: "" };
      showAddForm = false;
    })


  }
  // Computed array of credentials filtered by the search term.
  $: filteredCredentials = credentials.sort((a, b) => a.service.localeCompare(b.service)).filter((c) =>
    {
      return c.service.toLowerCase().includes(searchTerm.toLowerCase())
    }
  );
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
                otp: ""
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
          <!-- Display Mode -->
          <div class="flex justify-between items-center">
            <div>
              <h2 class="text-xl font-semibold text-black">{credential.service}</h2>
              <p class="text-zinc-600">
                <span class="font-medium">Username:</span> {credential.username}
              </p>
              <p class="text-zinc-600">
                <span class="font-medium">Password:</span> ******* 
              </p>
              {#if credential.twoFA}
                <p class="text-zinc-600">
                  <span class="font-medium">2FA Code:</span> {credential.twoFA}
                </p>
              {/if}
            </div>
            <div class="flex space-x-2">
              <button
                on:click={() => copyText(credential.password)}
                class="bg-green-300 hover:bg-green-200 text-black px-3 py-1 rounded"
              >
                Copy Password
              </button>
              <button
                on:click={() => startEdit(credential)}
                class="bg-yellow-500 hover:bg-yellow-600 text-black px-3 py-1 rounded"
              >
                Edit
              </button>
              {#if credential.otp}
              <button
                on:click={() => toggle2FA(credential)}
                class="bg-purple-500 hover:bg-purple-600 text-black px-3 py-1 rounded"
              >
                {credential.twoFA ? "Disable 2FA" : "Enable 2FA"}
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
