<script lang="ts">
  import { z } from "zod";
  import { decodeClientEx } from "$lib/decoder.js";
  import { auth, create_account } from "$lib/client";
  import { onMount } from "svelte";
  import { clientex, client, token } from "./stores";
  import { goto } from "$app/navigation";
  import SecureLS from "secure-ls";

  let language: "fr" | "en" = "en";


  // Define the validation schema with Zod.
  const loginFormSchema = z.object({
    email: z.string().email({
      message: (language as "fr" | "en") === "fr" 
        ? "Veuillez entrer une adresse email valide." 
        : "Please enter a valid email address.",
    }),
    file: z
      .instanceof(File)
      .refine((file) => file.size <= 5000000, (language as "fr" | "en") === "fr" 
        ? "Taille maximale du fichier: 5MB." 
        : "Maximum file size: 5MB."),
  });

  const registerFormSchema = z.object({
    email: z.string().email({
      message: (language as "fr" | "en") === "fr" 
        ? "Veuillez entrer une adresse email valide." 
        : "Please enter a valid email address.",
    }),
  });

  onMount(() => {
    if (navigator.language.startsWith("fr") || navigator.language.startsWith("en-US") || navigator.language.startsWith("en") || navigator.language.startsWith("en-GB")) {
      language = navigator.language.startsWith("fr") ? "fr" : "en";
    }
  });

  // Define translation type
  type TranslationKey = 
    | "login" 
    | "createAccount" 
    | "createAccountDesc" 
    | "loginDesc" 
    | "email" 
    | "keyFile" 
    | "loading" 
    | "connect" 
    | "loginSuccess" 
    | "loginError" 
    | "creating" 
    | "create" 
    | "registerSuccess" 
    | "registerError" 
    | "alreadyAccount" 
    | "noAccount" 
    | "error";

  type Translations = {
    [key in "fr" | "en"]: {
      [k in TranslationKey]: string;
    }
  };

  // Translations
  const translations: Translations = {
    fr: {
      login: "Connexion",
      createAccount: "Créer un compte",
      createAccountDesc: "Créez un compte pour commencer à utiliser l'application.",
      loginDesc: "Entrez votre email et téléchargez votre fichier de clé pour vous connecter.",
      email: "Email",
      keyFile: "Fichier de clé",
      loading: "Chargement...",
      connect: "Se connecter",
      loginSuccess: "Connexion réussie!",
      loginError: "Erreur de connexion. Veuillez vérifier vos informations.",
      creating: "Création en cours...",
      create: "Créer un compte",
      registerSuccess: "Compte créé avec succès! Veuillez télécharger et conserver votre fichier de clé en lieu sûr.",
      registerError: "Erreur: ",
      alreadyAccount: "Déjà un compte? Se connecter",
      noAccount: "Pas encore de compte? S'inscrire",
      error: "Une erreur est survenue"
    },
    en: {
      login: "Login",
      createAccount: "Create Account",
      createAccountDesc: "Create an account to start using the application.",
      loginDesc: "Enter your email and upload your key file to log in.",
      email: "Email",
      keyFile: "Key File",
      loading: "Loading...",
      connect: "Log in",
      loginSuccess: "Login successful!",
      loginError: "Login error. Please check your information.",
      creating: "Creating account...",
      create: "Create Account",
      registerSuccess: "Account created successfully! Please download and keep your key file in a safe place.",
      registerError: "Error: ",
      alreadyAccount: "Already have an account? Log in",
      noAccount: "Don't have an account? Sign up",
      error: "An error occurred"
    }
  };

  // Reactive form state variables.
  let email = "";
  let file: File | null = null;
  let errors: { email?: string; file?: string } = {};
  let showRegisterForm = false;
  let registerEmail = "";
  let registerErrors: { email?: string } = {};

  // State for loading and submission status.
  let isLoading = false;
  let submitStatus: "success" | "error" | null = null;
  let registerStatus: "success" | "error" | null = null;
  let registerMessage = "";

  // Handle file input changes.
  function handleFileChange(e: Event) {
    const target = e.target as HTMLInputElement;
    if (target.files && target.files.length > 0) {
      file = target.files[0];
    }
  }

  // Handle login form submission.
  async function onLoginSubmit(event: Event) {
    event.preventDefault();
    // Reset errors and submission status.
    errors = {};
    submitStatus = null;

    // Validate the form data.
    const result = loginFormSchema.safeParse({ email, file });
    if (!result.success) {
      const zodErrors = result.error.flatten();
      if (zodErrors.fieldErrors.email)
        errors.email = zodErrors.fieldErrors.email.join(", ");
      if (zodErrors.fieldErrors.file)
        errors.file = zodErrors.fieldErrors.file.join(", ");
      return;
    }

    isLoading = true;

    // Decode the file using decodeClientEx function.
    const arrayBuffer = await file!.arrayBuffer();
    const uint8Array = new Uint8Array(arrayBuffer);
    const decodedFile = await decodeClientEx(uint8Array);
    console.log(decodedFile);
    
    if (!decodedFile || !decodedFile.id || !decodedFile.id.id || !decodedFile.c) {
      submitStatus = "error";
      console.error(language === "fr" ? "Fichier décodé invalide" : "Invalid decoded file");
      console.log(decodedFile);
      isLoading = false;
      return;
    }
    
    const uuid = decodedFile.id.id;
    const { result: tok, client: sharedva, error } = await auth(uuid, decodedFile.c);
    
    // API call
    if (error == null) {
      submitStatus = "success";
      console.log({ email, file });
      const ls = new SecureLS({ encodingType: "aes" });
      clientex.set(decodedFile);
      client.set(sharedva);
      token.set(String(tok));
      
      const clientez = $clientex;
      if (!clientez || !clientez.c || !clientez.id || !clientez.id.id) {
        submitStatus = "error";
        console.error(language === "fr" ? "Données client invalides" : "Invalid client data");
        isLoading = false;
        return;
      }
      
      if (!clientez.c.ky_p || !clientez.c.ky_q || !clientez.c.di_p || 
          !clientez.c.di_q || !clientez.c.secret || !clientez.id.ky_p || 
          !clientez.id.id.bytes) {
        submitStatus = "error";
        console.error(language === "fr" ? "Données client incomplètes" : "Incomplete client data");
        isLoading = false;
        return;
      }
      
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

  // Handle register form submission
  async function onRegisterSubmit(event: Event) {
    event.preventDefault();
    // Reset errors and submission status
    registerErrors = {};
    registerStatus = null;
    registerMessage = "";

    // Validate the form data
    const result = registerFormSchema.safeParse({ email: registerEmail });
    if (!result.success) {
      const zodErrors = result.error.flatten();
      if (zodErrors.fieldErrors.email)
        registerErrors.email = zodErrors.fieldErrors.email.join(", ");
      return;
    }

    isLoading = true;

    try {
      // Create account
      const { clientEx, encodedFile, error } = await create_account(registerEmail);
      
      if (error) {
        registerStatus = "error";
        registerMessage = error;
        console.error(error);
      } else if (encodedFile) {
        // Create a download link for the file
        const blob = new Blob([encodedFile], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${registerEmail.replace('@', '_at_')}_skibiskap.key`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        registerStatus = "success";
        registerMessage = translations[language].registerSuccess;
      }
    } catch (error) {
      registerStatus = "error";
      registerMessage = error instanceof Error ? error.message : translations[language].error;
      console.error(error);
    }

    isLoading = false;
  }

  // Toggle between login and register forms
  function toggleForm() {
    showRegisterForm = !showRegisterForm;
    // Reset form states
    errors = {};
    registerErrors = {};
    submitStatus = null;
    registerStatus = null;
    registerMessage = "";
  }
  
  // Toggle language
  function toggleLanguage() {
    language = language === "fr" ? "en" : "fr";
  }
</script>

<svelte:head>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous">
  <link href="https://fonts.googleapis.com/css2?family=Raleway:wght@400;500;600;700&family=Work+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
</svelte:head>

<div class="flex items-center justify-center min-h-screen px-4 py-8 sm:px-6 md:py-12" style="background-color: #1d1b21; font-family: 'Work Sans', sans-serif;">
  <!-- Language Selector -->
  <div class="absolute top-4 right-4 z-10">
    <button 
      on:click={toggleLanguage}
      class="px-2 py-1 sm:px-3 sm:py-1 rounded-md text-xs sm:text-sm font-medium transition-all duration-200 ease-in-out"
      style="background-color: #474b4f; color: white;"
    >
      {language === "fr" ? "Français" : "English"}
    </button>
  </div>

  <div class="w-full max-w-xs sm:max-w-sm md:max-w-md rounded-[0.5rem] shadow-lg overflow-hidden mx-auto" style="background-color: #ced7e1;">
    <!-- Card Header -->
    <div class="p-3 sm:p-4 md:p-6 border-b" style="border-color: #474b4f;">
      <h2 class="text-lg sm:text-xl md:text-2xl lg:text-[2.125rem] font-bold mb-1 sm:mb-2" style="font-family: 'Raleway', sans-serif; color: #1d1b21;">
        {showRegisterForm ? translations[language].createAccount : translations[language].login}
      </h2>
      <p class="text-xs sm:text-[0.8125rem]" style="color: #474b4f;">
        {showRegisterForm 
          ? translations[language].createAccountDesc
          : translations[language].loginDesc}
      </p>
    </div>

    <!-- Card Content (Form) -->
    <div class="p-3 sm:p-4 md:p-6">
      {#if !showRegisterForm}
        <!-- Login Form -->
        <form on:submit={onLoginSubmit} class="space-y-3 sm:space-y-4 md:space-y-6">
          <!-- Email Field -->
          <div>
            <label class="block text-xs sm:text-sm md:text-[0.875rem] font-medium mb-1 sm:mb-2" style="color: #1d1b21;" for="email">
              {translations[language].email}
            </label>
            <input
              id="email"
              type="email"
              bind:value={email}
              placeholder="example@email.com"
              class="mt-1 block w-full border p-2 sm:p-3 rounded-[0.35714285714285715rem] focus:outline-none focus:ring-2"
              style="background-color: white; border-color: #474b4f; color: #1d1b21; font-family: 'Work Sans', sans-serif; font-size: 0.875rem; focus-ring-color: #f2c3c2;"
            />
            {#if errors.email}
              <p class="mt-1 sm:mt-2 text-xs sm:text-[0.8125rem]" style="color: #b00e0b;">{errors.email}</p>
            {/if}
          </div>

          <!-- File Upload Field -->
          <div>
            <label class="block text-xs sm:text-sm md:text-[0.875rem] font-medium mb-1 sm:mb-2" style="color: #1d1b21;" for="file">
              {translations[language].keyFile}
            </label>
            <div class="relative">
              <input
                id="file"
                type="file"
                on:change={handleFileChange}
                class="block w-full text-xs sm:text-[0.8125rem] file:mr-2 sm:file:mr-4 file:py-1 sm:file:py-2 file:px-2 sm:file:px-4
                      file:rounded-[0.21428571428571427rem] file:border-0 file:text-xs sm:file:text-[0.8125rem] file:font-semibold
                      hover:file:opacity-90 cursor-pointer"
                style="color: #474b4f; file-background-color: #f2c3c2; file-color: #1d1b21;"
              />
            </div>
            {#if errors.file}
              <p class="mt-1 sm:mt-2 text-xs sm:text-[0.8125rem]" style="color: #b00e0b;">{errors.file}</p>
            {/if}
          </div>

          <!-- Submit Button -->
          <button
            name="login"
            type="submit"
            disabled={isLoading}
            class="w-full py-2 sm:py-3 px-4 border-0 rounded-[0.35714285714285715rem] shadow-md text-xs sm:text-sm md:text-[0.875rem] font-medium transition-all duration-200 ease-in-out hover:opacity-90 focus:outline-none focus:ring-2 disabled:opacity-50"
            style="background-color: #f2c3c2; color: #1d1b21; font-family: 'Raleway', sans-serif; focus-ring-color: #a7f3ae;"
          >
            {isLoading ? translations[language].loading : translations[language].connect}
          </button>

          <!-- Status Messages -->
          {#if submitStatus === "success"}
            <div class="mt-3 sm:mt-4 p-2 sm:p-3 rounded-[0.35714285714285715rem] text-xs sm:text-[0.8125rem]" style="background-color: #a7f3ae; color: #1d1b21;">
              {translations[language].loginSuccess}
            </div>
          {:else if submitStatus === "error"}
            <div class="mt-3 sm:mt-4 p-2 sm:p-3 rounded-[0.35714285714285715rem] text-xs sm:text-[0.8125rem]" style="background-color: #b00e0b96; color: #1d1b21;">
              {translations[language].loginError}
            </div>
          {/if}
        </form>
      {:else}
        <!-- Register Form -->
        <form on:submit={onRegisterSubmit} class="space-y-3 sm:space-y-4 md:space-y-6">
          <!-- Email Field -->
          <div>
            <label class="block text-xs sm:text-sm md:text-[0.875rem] font-medium mb-1 sm:mb-2" style="color: #1d1b21;" for="registerEmail">
              {translations[language].email}
            </label>
            <input
              id="registerEmail"
              type="email"
              bind:value={registerEmail}
              placeholder="example@email.com"
              class="mt-1 block w-full border p-2 sm:p-3 rounded-[0.35714285714285715rem] focus:outline-none focus:ring-2"
              style="background-color: white; border-color: #474b4f; color: #1d1b21; font-family: 'Work Sans', sans-serif; font-size: 0.875rem; focus-ring-color: #f2c3c2;"
            />
            {#if registerErrors.email}
              <p class="mt-1 sm:mt-2 text-xs sm:text-[0.8125rem]" style="color: #b00e0b;">{registerErrors.email}</p>
            {/if}
          </div>

          <!-- Submit Button -->
          <button
            type="submit"
            disabled={isLoading}
            name="register"
            class="w-full py-2 sm:py-3 px-4 border-0 rounded-[0.35714285714285715rem] shadow-md text-xs sm:text-sm md:text-[0.875rem] font-medium transition-all duration-200 ease-in-out hover:opacity-90 focus:outline-none focus:ring-2 disabled:opacity-50"
            style="background-color: #a7f3ae; color: #1d1b21; font-family: 'Raleway', sans-serif; focus-ring-color: #f2c3c2;"
          >
            {isLoading ? translations[language].creating : translations[language].create}
          </button>

          <!-- Status Messages -->
          {#if registerStatus === "success"}
            <div class="mt-3 sm:mt-4 p-2 sm:p-3 rounded-[0.35714285714285715rem] text-xs sm:text-[0.8125rem]" style="background-color: #a7f3ae; color: #1d1b21;">
              {registerMessage}
            </div>
          {:else if registerStatus === "error"}
            <div class="mt-3 sm:mt-4 p-2 sm:p-3 rounded-[0.35714285714285715rem] text-xs sm:text-[0.8125rem]" style="background-color: #b00e0b96; color: #1d1b21;">
              {translations[language].registerError} {registerMessage}
            </div>
          {/if}
        </form>
      {/if}

      <!-- Toggle Form Link -->
      <div class="mt-3 sm:mt-4 md:mt-6 text-center">
        <button
          on:click={toggleForm}
          class="text-xs sm:text-sm md:text-[0.875rem] font-medium transition-all duration-200 ease-in-out hover:opacity-80 focus:outline-none"
          style="color: #1d1b21; font-family: 'Raleway', sans-serif;"
        >
          {showRegisterForm 
            ? translations[language].alreadyAccount
            : translations[language].noAccount}
        </button>
      </div>
    </div>
  </div>
</div>

<style>
  /* Personnalisation du bouton de téléchargement de fichier */
  input[type="file"]::file-selector-button {
    background-color: #1d1b21;
    color: #f2c3c2;
    font-family: 'Raleway', sans-serif;
    border: none;
    transition: all 0.2s ease-in-out;
  }
  
  input[type="file"]::file-selector-button:hover {
    opacity: 0.9;
  }
  
  /* Focus styles */
  input[type="email"]:focus {
    outline: none;
    box-shadow: 0 0 0 2px #a7f3ae;
  }

  button[name="register"]:focus {
    outline: none;
    box-shadow: 0 0 0 2px #866b6b;
  }
  
  /* Responsive styles */
  @media (max-width: 640px) {
    input[type="file"]::file-selector-button {
      padding: 0.25rem 0.5rem;
      font-size: 0.75rem;
    }
    
    input[type="email"] {
      font-size: 0.875rem;
      padding: 0.375rem 0.75rem;
    }
    
    button[type="submit"] {
      font-size: 0.875rem;
      padding: 0.375rem 0.75rem;
    }
  }
  
  @media (max-width: 480px) {
    input[type="file"]::file-selector-button {
      padding: 0.2rem 0.4rem;
      font-size: 0.7rem;
    }
    
    input[type="email"] {
      font-size: 0.8rem;
      padding: 0.3rem 0.6rem;
    }
    
    button[type="submit"] {
      font-size: 0.8rem;
      padding: 0.3rem 0.6rem;
    }
  }
  
  @media (max-width: 360px) {
    input[type="file"]::file-selector-button {
      padding: 0.15rem 0.3rem;
      font-size: 0.65rem;
    }
    
    input[type="email"] {
      font-size: 0.75rem;
      padding: 0.25rem 0.5rem;
    }
    
    button[type="submit"] {
      font-size: 0.75rem;
      padding: 0.25rem 0.5rem;
    }
  }
  
  /* Amélioration pour les appareils tactiles */
  @media (hover: none) {
    button, input[type="file"]::file-selector-button {
      padding-top: 0.5rem;
      padding-bottom: 0.5rem;
    }
  }
  
  /* Orientation landscape pour les mobiles */
  @media (max-height: 480px) and (orientation: landscape) {
    .min-h-screen {
      min-height: 100%;
      padding-top: 1rem;
      padding-bottom: 1rem;
    }
    
    .space-y-3 > * + *, .space-y-4 > * + *, .space-y-6 > * + * {
      margin-top: 0.5rem;
    }
  }
</style>
