<script lang="ts">
  import { z } from "zod";
  import { decodeClientEx } from "$lib/decoder.js";
  import { auth } from "$lib/client.ts";
  import { clientex, client, token } from "./stores.ts";
  import { goto } from "$app/navigation";
  import SecureLS from "secure-ls";

  // Define the validation schema with Zod.
  const formSchema = z.object({
    email: z.string().email({
      message: "Please enter a valid email address.",
    }),
    file: z
      .instanceof(File)
      .refine((file) => file.size <= 5000000, "Max file size is 5MB."),
  });

  // Reactive form state variables.
  let email = "";
  let file: File | null = null;
  let errors: { email?: string; file?: string } = {};

  // State for loading and submission status.
  let isLoading = false;
  let submitStatus: "success" | "error" | null = null;

  // Handle file input changes.
  function handleFileChange(e: Event) {
    const target = e.target as HTMLInputElement;
    if (target.files && target.files.length > 0) {
      file = target.files[0];
    }
  }

  // Handle form submission.
  async function onSubmit(event: Event) {
    event.preventDefault();
    // Reset errors and submission status.
    errors = {};
    submitStatus = null;

    // Validate the form data.
    const result = formSchema.safeParse({ email, file });
    if (!result.success) {
      const zodErrors = result.error.flatten();
      if (zodErrors.fieldErrors.email)
        errors.email = zodErrors.fieldErrors.email.join(", ");
      if (zodErrors.fieldErrors.file)
        errors.file = zodErrors.fieldErrors.file.join(", ");
      return;
    }

    isLoading = true;

    // Simulate an API call (replace with your actual API call).

    // Decode the file using decodeClientEx function.
    const arrayBuffer = await file!.arrayBuffer();
    const uint8Array = new Uint8Array(arrayBuffer);
    const decodedFile = await decodeClientEx(uint8Array);
    const uuid = decodedFile.id.id!;
    const { result: tok , client: sharedva, error} = await auth(uuid, decodedFile.c);
    
    // API call

    if (error == null) {
      submitStatus = "success";
      console.log({ email, file });
      const ls = new SecureLS({ encodingType: "aes" });
      clientex.set(decodedFile);
      client.set(sharedva);
      token.set(tok);
      const clientez = $clientex;
      const clie = {
        ky_p: Array.from(clientez.c.ky_p),
        ky_q: Array.from(clientez.c.ky_q),
        di_p: Array.from(clientez.c.di_p),
        di_q: Array.from(clientez.c.di_q),
        secret: Array.from(clientez.c.secret),
      }
      const id = {
        email: clientez.id.email,
        id: {
          bytes: Array.from(clientez.id.id.bytes),
        },
        ky_p: Array.from(clientez.id.ky_p),
      }
      const clientexz = {
        c: clie,
        id: id
      }
      ls.set("clientex", clientexz);
      goto("/vault");
    } else {
      submitStatus = "error";
      console.error(error);
    }

    isLoading = false;
  }
</script>

<div class="flex items-center justify-center min-h-screen bg-zinc-700">
  <div class="w-full max-w-md bg-blue-100 rounded shadow overflow-hidden">
    <!-- Card Header -->
    <div class="p-4 border-b">
      <h2 class="text-xl text-zinc-800 font-bold">Login</h2>
      <p class="text-sm text-zinc-500">
        Enter your email and upload a file to login.
      </p>
    </div>

    <!-- Card Content (Form) -->
    <div class="p-4">
      <form on:submit={onSubmit} class="space-y-6">
        <!-- Email Field -->
        <div>
          <label class="block text-sm font-medium text-zinc-700" for="email">
            Email
          </label>
          <input
            id="email"
            type="email"
            bind:value={email}
            placeholder="your@email.com"
            class="mt-1 block w-full border border-zinc-300 rounded p-2 focus:ring-blue-500 focus:border-blue-500"
          />
          <p class="text-xs text-zinc-500">We'll never share your email.</p>
          {#if errors.email}
            <p class="mt-1 text-xs text-red-500">{errors.email}</p>
          {/if}
        </div>

        <!-- File Field -->
        <div>
          <label class="block text-sm font-medium text-zinc-700" for="file">
            File
          </label>
          <input
            id="file"
            type="file"
            on:change={handleFileChange}
            class="mt-1 block w-full text-sm text-zinc-500
              file:bg-zinc-600
              file:mr-4 file:py-2 file:px-4
              file:rounded file:border-0
              file:text-sm file:font-semibold
              file:text-green-400
              hover:file:bg-zinc-700"
          />
          <p class="text-xs text-zinc-500">
            Upload a file (max 5MB, .pdf, .jpeg, or .png)
          </p>
          {#if errors.file}
            <p class="mt-1 text-xs text-red-500">{errors.file}</p>
          {/if}
        </div>

        <!-- Submit Button -->
        <button
          type="submit"
          class="w-full bg-blue-600 text-white py-2 px-4 rounded disabled:opacity-50"
          disabled={isLoading}
        >
          {#if isLoading}
            Logging in...
          {:else}
            Login
          {/if}
        </button>
      </form>
    </div>

    <!-- Card Footer (Alerts) -->
    <div class="p-4 border-t">
      {#if submitStatus === "success"}
        <div class="flex items-center p-2 bg-green-50 border border-green-200 rounded">
          <!-- Check icon -->
          <svg
            class="h-4 w-4 text-green-600 mr-2"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M5 13l4 4L19 7"
            />
          </svg>
          <div>
            <p class="font-bold text-green-700">Success</p>
            <p class="text-sm text-green-600">
              You have successfully logged in.
            </p>
          </div>
        </div>
      {:else if submitStatus === "error"}
        <div class="flex items-center p-2 bg-red-50 border border-red-200 rounded">
          <!-- Error icon -->
          <svg
            class="h-4 w-4 text-red-600 mr-2"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          <div>
            <p class="font-bold text-red-700">Error</p>
            <p class="text-sm text-red-600">
              There was a problem logging in. Please try again.
            </p>
          </div>
        </div>
      {/if}
    </div>
  </div>
</div>
