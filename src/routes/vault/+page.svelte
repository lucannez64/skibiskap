<script lang="ts">
	// Our sample list of credentials
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { browser } from '$app/environment';
	import { clientex, client } from '../stores';
	import {
		get_all,
		update_pass,
		delete_pass,
		create_pass,
		share_pass,
		get_shared_by_user,
		get_shared_by_user_emails,
		get_emails_from_uuids,
		get_uuid_from_email,
		unshare_pass,
		ShareStatus,
		accept_shared_pass,
		reject_shared_pass,
		exportPasswords,
		exportPasswordsCSV,
		exportPasswordsText
	} from '$lib/client';
	import { from_uri, generate } from '$lib/otp';
	import * as pkg from 'uuid-tool';
	import Plus from 'lucide-svelte/icons/plus';
	import SecureLS from 'secure-ls';
	import X from 'lucide-svelte/icons/x';
	import { zxcvbn } from '@zxcvbn-ts/core';
	import { writable, get, derived } from 'svelte/store';
	import Search from 'lucide-svelte/icons/search';
	import Upload from 'lucide-svelte/icons/upload';
	import { translations, currentLang, t } from '$lib/i18n';
	import { fly } from 'svelte/transition';
	const { Uuid } = pkg;
	import { uuidToStr, type Password, type Uuid as UuidType } from '$lib/decoder';
	import type { SharedByUserEmail } from '$lib/client';

	// Store pour la langue actuelle
	let lang: 'fr' | 'en' = 'fr'; // Valeur par défaut

	// S'abonner aux changements de langue
	currentLang.subscribe((value) => {
		lang = value;
	});

	// Fonction pour changer de langue
	function toggleLanguage() {
		currentLang.update((current) => (current === 'fr' ? 'en' : 'fr'));
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
		[key: number]: (result: { url: string; passwordStrength: any }) => void;
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
	function evaluatePasswordStrength(password: string): {
		score: number;
		color: string;
		text: string;
	} {
		if (!password) {
			return {
				score: 0,
				color: '#e53e3e',
				text: t('passwordStrengthVeryWeak', lang) || 'Très faible'
			};
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
	let passwordStrength = {
		score: 0,
		color: '#e53e3e',
		text: t('passwordStrengthVeryWeak', lang) || 'Très faible'
	};

	// Création d'un store pour les identifiants
	const credentialsStore = writable<Credential[]>([]);
	const pendingCredentialsStore = writable<PendingCredential[]>([]);
	// Création d'un store dérivé pour les identifiants filtrés
	let searchTerm = '';
	const filteredCredentialsStore = derived(
		[credentialsStore, writable(searchTerm)],
		([$credentials, $searchTerm]) => {
			return $credentials
				.sort((a, b) => a.service.localeCompare(b.service) || a.username.localeCompare(b.username))
				.filter(
					(c) =>
						c.service.toLowerCase().includes($searchTerm.toLowerCase()) ||
						c.username.toLowerCase().includes($searchTerm.toLowerCase())
				);
		}
	);

	let credentials: Credential[] = [];
	$: filteredCredentials = credentials
		.sort((a, b) => a.service.localeCompare(b.service) || a.username.localeCompare(b.username))
		.filter((c) => {
			// Extraire les filtres spéciaux et le terme de recherche réel
			const hasSharedFilter = searchTerm.includes('!s');
			const hasSharedByMeFilter = searchTerm.includes('!m');

			// Extraire le terme de recherche après avoir retiré les filtres
			let actualSearchTerm = searchTerm.replace('!s', '').replace('!m', '').trim().toLowerCase();

			// Si aucun filtre spécial, recherche normale
			if (!hasSharedFilter && !hasSharedByMeFilter) {
				return (
					c.service.toLowerCase().includes(actualSearchTerm) ||
					c.username.toLowerCase().includes(actualSearchTerm)
				);
			}

			// Filtre pour mots de passe partagés avec l'utilisateur
			if (hasSharedFilter && !hasSharedByMeFilter) {
				return c.sharedBy && c.service.toLowerCase().includes(actualSearchTerm);
			}

			// Filtre pour mots de passe partagés par l'utilisateur
			if (hasSharedByMeFilter && !hasSharedFilter) {
				return (
					!c.sharedBy &&
					sharedPasswordEmails.has(c.uuid) &&
					(sharedPasswordEmails.get(c.uuid)?.emails?.length ?? 0) > 0 &&
					c.service.toLowerCase().includes(actualSearchTerm)
				);
			}

			// Les deux filtres ensemble
			return (
				(c.sharedBy ||
					(!c.sharedBy &&
						sharedPasswordEmails.has(c.uuid) &&
						(sharedPasswordEmails.get(c.uuid)?.emails?.length ?? 0) > 0)) &&
				c.service.toLowerCase().includes(actualSearchTerm)
			);
		});

	// Pour éviter l'erreur du linter concernant undefined
	function getSharedEmails(uuid: string): string[] {
		return sharedPasswordEmails.get(uuid)?.emails || [];
	}

	let intervals: { [key: number]: number | NodeJS.Timeout } = {}; // Store intervals for each credential
	let loading = true;
	let showAddForm = false;
	let newRecord = {
		service: '',
		username: '',
		password: '',
		otp: '',
		uuid: '',
		twoFA: null
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
			showToast(t('noCredentialsToExport', lang) || 'Aucun mot de passe à exporter');
			return;
		}

		try {
			// Convertir les identifiants au format Password accepté par les fonctions d'export
			const passwordsToExport = credentials.map((cred) => ({
				username: cred.username,
				password: cred.password,
				app_id: cred.service, // Utiliser le champ service comme app_id
				description: null,
				url: null,
				otp: cred.otp
			}));

			// Convertir les UUIDs des mots de passe
			const passwordUuids = credentials.map((cred) => {
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
					throw new Error("Format d'exportation non valide");
			}

			// Créer un blob et déclencher le téléchargement
			if (browser) {
				const blob = new Blob([fileContent], { type: mimeType });
				const url = URL.createObjectURL(blob);
				const a = document.createElement('a');
				a.href = url;
				a.download = filename;
				document.body.appendChild(a);
				a.click();
				document.body.removeChild(a);
				URL.revokeObjectURL(url);
			}

			showToast(t('exportSuccess', lang) || 'Mots de passe exportés avec succès');
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
				bytes: new Uint8Array(uuid.toBytes())
			};
		} catch (error) {
			console.error("Erreur lors de la conversion de l'UUID", error);
			return null;
		}
	}

	// Fonction memoïsée pour éviter des conversions répétées d'UUID
	const uuidCache = new Map<string, { bytes: Uint8Array }>();
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
			if (browser) {
				for (let i = 0; i < numWorkers; i++) {
					const worker = new Worker('passwordWorker.js', { type: 'module' });
					worker.onmessage = this.handleMessage.bind(this);
					this.workers.push(worker);
				}
			}
		}

		private handleMessage(event: MessageEvent) {
			const { taskId, url, passwordStrength } = event.data;
			if (this.pendingTasks[taskId]) {
				this.pendingTasks[taskId]({ url, passwordStrength });
				delete this.pendingTasks[taskId];
			}
		}

		evaluatePassword(password: string, url: string) {
			return new Promise<{ url: string; passwordStrength: any }>((resolve) => {
				const currentTaskId = this.taskId++;
				this.pendingTasks[currentTaskId] = resolve;
				if (this.workers.length > 0) {
					const worker = this.workers[Math.floor(Math.random() * this.workers.length)];
					worker.postMessage({ taskId: currentTaskId, password, url });
				} else {
					resolve({ url, passwordStrength: evaluatePassword(password, url) });
				}
			});
		}

		terminate() {
			this.workers.forEach((worker) => worker.terminate());
			this.workers = [];
			this.pendingTasks = {};
		}
	}

	onMount(async () => {
		if (browser) {
			if (navigator.language.startsWith('fr') || navigator.language.startsWith('en')) {
				if (navigator.language.startsWith('fr')) {
					currentLang.set('fr');
				} else {
					currentLang.set('en');
				}
			}
		}

		// Initialisation du client
		if (!isClientValid() && browser) {
			const ls = new SecureLS({ encodingType: 'aes' });
			const sessionclient = ls.get('clientex');
			if (sessionclient) {
				const p = sessionclient;
				const cc = {
					ky_p: Uint8Array.from(p.c.ky_p),
					ky_q: Uint8Array.from(p.c.ky_q),
					di_p: Uint8Array.from(p.c.di_p),
					di_q: Uint8Array.from(p.c.di_q),
					secret: Uint8Array.from(p.c.secret)
				};
				const id = {
					email: p.id.email,
					id: {
						bytes: Uint8Array.from(p.id.id.bytes)
					},
					ky_p: Uint8Array.from(p.id.ky_p),
					di_p: p.id.di_p ? Uint8Array.from(p.id.di_p) : new Uint8Array(0)
				};
				const clieex = {
					c: cc,
					id: id
				};
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
		} else if (!browser && !isClientValid()) {
			return;
		}

		if (!$clientex || !$clientex.id || !$clientex.id.id) {
			disconnect();
			return;
		}

		try {
			const {
				result: encryptedCredentials,
				shared: sharedCredentials,
				error
			} = await get_all($clientex.id.id, $client!);
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
			const workerPool = browser ? new WorkerPool(4) : null;

			// Traiter les mots de passe normaux
			if (
				encryptedCredentials[0].length === 0 &&
				(sharedCredentials === null || sharedCredentials[0].length === 0)
			) {
				loading = false;
				return;
			}

			const passwords = encryptedCredentials[0];
			const uuids = encryptedCredentials[1];
			const passwordsAndUuids: [Password, UuidType][] = passwords.map((password, index) => [
				password,
				uuids[index]
			]);

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
							if (workerPool) {
								workerPool
									.evaluatePassword(password, url!)
									.then(({ passwordStrength }) => {
										// Mise à jour silencieuse, pas besoin de mettre à jour l'interface
									})
									.catch((err) => {
										console.error("Erreur d'évaluation du mot de passe:", err);
									});
							}
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
				const ownerUuids = sharedCredentials[2].map((uuid) => {
					const uuidstr = uuidToStr(uuid);
					const uuid3 = new Uuid(uuidstr);
					return {
						bytes: new Uint8Array(uuid3.toBytes())
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
							// Montrer les informations de base et les boutons pour accepter/rejeter
							const ownerUuid = sharedCredentials[2][index];
							const passUuid = sharedCredentials[1][index];
							const passuuidstr = uuidToStr(passUuid);
							const owneruuidstr = uuidToStr(ownerUuid);
							const owneremail = emails.get(owneruuidstr) || 'Utilisateur inconnu';
							const url = 'url' in cred ? cred.url : '';
							const otp = 'otp' in cred ? cred.otp : null;

							pendingCredentialsStore.update((pendingCredentials) => [
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
			console.log('processedCredentials');
			console.log(processedCredentials);
			console.log('processedSharedCredentials');
			console.log(processedSharedCredentials);
			credentials = [
				...(processedCredentials.filter(Boolean) as Credential[]),
				...processedSharedCredentials
			];
			credentialsStore.set(credentials);

			// Récupérer les emails partagés
			const sharedByUserEmails = await get_shared_by_user_emails($clientex.id.id!);
			if (sharedByUserEmails) {
				// Remplir le dictionnaire des emails partagés
				sharedByUserEmails.forEach((item) => {
					sharedPasswordEmails.set(uuidToStr(item.pass_id), item);
				});
			}
			if (browser) {
				document.addEventListener('keydown', handleKeyDown);
			}
		} catch (error) {
			console.error('Erreur lors de la récupération des données:', error);
			showToast(t('fetchError', lang) || 'Erreur lors de la récupération des données');
		} finally {
			loading = false;
		}
	});

	onDestroy(() => {
		// Clear all intervals when the component is unmounted
		Object.values(intervals).forEach((intervalId) => clearInterval(intervalId));
		if (browser) {
			document.removeEventListener('keydown', handleKeyDown);
		}
	});

	// For inline editing state
	let editingId: number | null = null;
	let editedRecord: EditedRecord = {};

	// Helper: Copy any text to the clipboard
	function copyText(text: string | null | undefined) {
		if (text === null || text === undefined || !browser) return;
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
		const urlRegex =
			/^(([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?)$/;
		return urlRegex.test(url);
	}

	// Save the edited record back into our credentials array
	async function saveEdit() {
		if (
			editingId === null ||
			!editedRecord.service ||
			!editedRecord.username ||
			!editedRecord.password
		) {
			return;
		}

		// Valider le format de l'URL
		if (!validateUrl(editedRecord.service)) {
			showToast(t('invalidUrl', lang));
			return;
		}

		const credential = credentials.find((item) => item.id === editingId);
		if (!credential || !credential.uuid) {
			console.error('Identifiant ou UUID manquant');
			return;
		}

		const uuid2 = memoizedUuidToBytes(credential.uuid);
		if (!uuid2 || !isClientValid()) {
			console.error('UUID invalide ou client non initialisé');
			return;
		}

		const passwordData = {
			password: editedRecord.password || '',
			otp: editedRecord.otp ? editedRecord.otp : null,
			username: editedRecord.username || '',
			url: editedRecord.service || '',
			description: null,
			app_id: null
		};

		try {
			// Mettre à jour le mot de passe
			const response = await update_pass($clientex!.id.id!, uuid2, passwordData, $client!);
			if (response.error) {
				console.error(response.error);
				showToast(t('updateError', lang) + ': ' + response.error);
				return;
			}

			// Mettre à jour les partages si nécessaire
			if (sharedPasswordEmails.has(credential.uuid)) {
				const sharedInfo = sharedPasswordEmails.get(credential.uuid);
				if (sharedInfo && sharedInfo.emails.length > 0) {
					// Traiter tous les partages en parallèle
					await Promise.all(
						sharedInfo.emails.map(async (email) => {
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
						})
					);
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
			console.error('Erreur lors de la mise à jour:', error);
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
			console.error('UUID invalide ou client non initialisé');
			return;
		}

		try {
			const response = await delete_pass($clientex!.id.id!, uuid2, $client!);
			if (response.error) {
				console.error(response.error);
				showToast(t('deleteError', lang) + ': ' + response.error);
				return;
			}

			credentials = credentials.filter(
				(item) => item.id !== editingId && item.uuid !== editedRecord.uuid
			);
			credentialsStore.set(credentials);
			showToast(t('credentialDeleted', lang));
		} catch (error) {
			console.error('Erreur lors de la suppression:', error);
			showToast(t('deleteError', lang));
		} finally {
			editingId = null;
			editedRecord = {};
		}
	}

	// Generate a simple 6-digit code for 2FA demonstration
	function generate2FACode(otp: string | null): [string, number] {
		if (!otp) return ['000000', 30]; // Valeur par défaut

		const ot2p = from_uri(otp);
		if (!ot2p) return ['000000', 30]; // Valeur par défaut si null

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
			if (browser) {
				const initialRemainingTime = periodNum * 1000 - (Date.now() % (periodNum * 1000));
				remainingTimes[record.id] = Math.floor(initialRemainingTime / 1000);
			}
			if (browser) {
				const intervalId = setInterval(() => {
					const remainingTime = periodNum * 1000 - (Date.now() % (periodNum * 1000));
					remainingTimes[record.id] = Math.floor(remainingTime / 1000);

					if (remainingTime / 1000 > periodNum - 5) {
						credentials = credentials.map((cred) =>
							cred.id === record.id ? { ...cred, twoFA: generate2FACode(cred.otp)[0] } : cred
						);
					}
				}, 1000);

				intervals[record.id] = intervalId;

				credentials = credentials.map((item) =>
					item.id === record.id ? { ...item, twoFA: code, intervalId } : item
				);
			} else {
				credentials = credentials.map((item) =>
					item.id === record.id ? { ...item, twoFA: code, intervalId: null } : item
				);
			}
		}

		credentialsStore.set(credentials);
	}

	function disconnect() {
		if (browser) {
			localStorage.clear();
		}
		client.set(undefined);
		clientex.set(undefined);
		goto('/');
	}

	// Save a new credential. Adjust this function to integrate your backend logic.
	async function saveNewCredential() {
		// Valider le format de l'URL
		if (!validateUrl(newRecord.service)) {
			showToast(t('invalidUrl', lang));
			return;
		}

		if (!isClientValid()) {
			console.error('Client non initialisé');
			return;
		}

		const passwordData = {
			password: newRecord.password,
			otp: newRecord.otp ? newRecord.otp : null,
			username: newRecord.username,
			url: newRecord.service,
			description: null,
			app_id: null
		};

		try {
			const response = await create_pass($clientex!.id.id!, passwordData, $client!);
			if (response.error) {
				console.error(response.error);
				showToast(t('createError', lang) + ': ' + response.error);
				return;
			}

			// Create a new credential with an arbitrary new id
			const newId = credentials.length ? Math.max(...credentials.map((cred) => cred.id)) + 1 : 0;

			const newItem: Credential = {
				id: newId,
				service: newRecord.service,
				username: newRecord.username,
				password: newRecord.password,
				otp: newRecord.otp,
				uuid: new Uuid(response.result.bytes).toString(),
				twoFA: null,
				favicon: getFaviconUrl(newRecord.service)
			};

			credentials = [...credentials, newItem];
			credentialsStore.set(credentials);

			// Reset the form
			newRecord = {
				service: '',
				username: '',
				password: '',
				otp: '',
				uuid: '',
				twoFA: null
			} as typeof newRecord;

			showAddForm = false;
			showToast(t('credentialCreated', lang));
		} catch (error) {
			console.error('Erreur lors de la création:', error);
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
				app_id: null
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
			console.error('Erreur lors du partage:', error);
			shareError =
				t('shareError', lang) + ': ' + (error instanceof Error ? error.message : 'Erreur inconnue');
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
				throw new Error(t('userNotFound', lang) + ': ' + email);
			}

			const recipientUuid = memoizedUuidToBytes(recipientUuidStr);
			if (!recipientUuid) {
				throw new Error(t('invalidRecipientUuid', lang));
			}

			// Appeler la fonction d'annulation de partage
			const { result, error } = await unshare_pass($clientex!.id.id!, uuid2, recipientUuid);

			if (error) {
				shareError = error;
				return;
			}

			// Mettre à jour la liste des emails partagés
			const currentSharedInfo = sharedPasswordEmails.get(sharingCredential.uuid);
			if (currentSharedInfo) {
				const emailIndex = currentSharedInfo.emails.indexOf(email);
				if (emailIndex !== -1) {
					const updatedEmails = currentSharedInfo.emails.filter((e) => e !== email);
					const updatedStatuses = currentSharedInfo.statuses
						? [
								...currentSharedInfo.statuses.slice(0, emailIndex),
								...currentSharedInfo.statuses.slice(emailIndex + 1)
							]
						: [];

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

			showToast(t('unshareSuccess', lang) + ': ' + email);
		} catch (error) {
			console.error("Erreur lors de l'annulation du partage:", error);
			shareError =
				t('unshareError', lang) +
				': ' +
				(error instanceof Error ? error.message : 'Erreur inconnue');
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
				passwords = jsonPasswords.map((json) => ({
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
				if (
					!header.includes('name') ||
					!header.includes('url') ||
					!header.includes('username') ||
					!header.includes('password')
				) {
					throw new Error(t('invalidCsvFormat', lang));
				}

				// Déterminer les indices des colonnes
				const headerCols = lines[0].split(',');
				const nameIndex = headerCols.findIndex((col) => col.toLowerCase().includes('name'));
				const urlIndex = headerCols.findIndex((col) => col.toLowerCase().includes('url'));
				const usernameIndex = headerCols.findIndex((col) => col.toLowerCase().includes('username'));
				const passwordIndex = headerCols.findIndex((col) => col.toLowerCase().includes('password'));

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
					const urlRegex =
						/^(([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?)$/;
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
			const passwordsForApi = passwords.map((pwd) => ({
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
						favicon: getFaviconUrl(passwordData.url || '')
					};

					credentials = [...credentials, newItem];
				} catch (error) {
					console.error("Erreur lors de l'importation d'un mot de passe:", error);
				}

				importProgress++;
			}

			credentialsStore.set(credentials);
			showToast(t('importSuccess', lang) + ': ' + importProgress + ' mot(s) de passe importé(s)');
		} catch (error) {
			console.error("Erreur lors de l'importation:", error);
			importError =
				t('importError', lang) +
				': ' +
				(error instanceof Error ? error.message : 'Erreur inconnue');
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
		errorMessage = '';

		try {
			const clientexValue = get(clientex);
			const clientValue = get(client);
			if (!clientexValue || !clientValue) {
				errorMessage = t('clientNotInitialized', lang) as string;
				loading = false;
				return;
			}

			const {
				result: encryptedCredentials,
				shared: sharedCredentials,
				error
			} = await get_all(clientexValue.id.id!, clientValue);

			if (error) {
				console.error(error);
				errorMessage = `${t('fetchError', lang)}: ${error}`;
				loading = false;
				return;
			}

			await processCredentials(encryptedCredentials, sharedCredentials);

			// Activer automatiquement le 2FA pour tous les credentials avec OTP
			setTimeout(() => {
				credentials.forEach((credential) => {
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
	async function processCredentials(
		encryptedCredentials: any,
		sharedCredentials: any
	): Promise<void> {
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
			let { error } = await accept_shared_pass(
				$clientex!.id.id!,
				credential.ownerUuid,
				credential.passUuid
			);
			if (error) {
				console.error(t('acceptError', lang), error);
				showToast(t('acceptError', lang) || "Erreur lors de l'acceptation du mot de passe");
				return;
			}
			pendingCredentialsStore.update((pendingCredentials) =>
				pendingCredentials.filter(
					(pendingCredential) => pendingCredential.passUuid !== credential.passUuid
				)
			);
			// Rafraîchir les données
			await fetchCredentials();
			showToast(t('passwordAccepted', lang) || 'Mot de passe accepté');
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
			pendingCredentialsStore.update((pendingCredentials) =>
				pendingCredentials.filter(
					(pendingCredential) => pendingCredential.passUuid !== credential.passUuid
				)
			);
			await fetchCredentials();
			showToast(t('passwordRejected', lang) || 'Mot de passe rejeté');
		} catch (error) {
			console.error('Erreur lors du rejet du mot de passe:', error);
			showToast(t('rejectError', lang) || 'Erreur lors du rejet du mot de passe');
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
		if (!browser) return;
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
		if (browser) {
			document.addEventListener('click', handleClickOutside);
			return () => {
				document.removeEventListener('click', handleClickOutside);
			};
		}
	});

	// Rendre l'activation du 2FA automatique au chargement de la page
	onMount(() => {
		// ... existing code ...

		// Activer automatiquement le 2FA pour tous les credentials avec OTP
		setTimeout(() => {
			filteredCredentials.forEach((credential) => {
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
					credentials.forEach((credential) => {
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
			if (!browser) return;
			const target = event.target as HTMLElement;
			const profileMenu = document.getElementById('profile-menu');
			const profileButton = document.getElementById('profile-button');

			if (
				profileMenu &&
				!profileMenu.contains(target) &&
				profileButton &&
				!profileButton.contains(target)
			) {
				showProfileMenu = false;
			}
		}
	}

	// Ajouter l'événement de clic pour fermer le menu contextuel du profil
	onMount(() => {
		if (browser) {
			document.addEventListener('click', handleClickOutsideProfile);
			return () => {
				document.removeEventListener('click', handleClickOutsideProfile);
			};
		}
	});

	// Variables pour l'audit des mots de passe
	let showAuditModal = false;
	let weakPasswords: Credential[] = [];
	let reusedPasswords: { credential: Credential; count: number }[] = [];
	let breachedPasswords: Credential[] = [];
	let isCheckingBreaches = false;
	let haveibeenpwnedError = '';
	let overallScore = 0;
	let errorMessage = ''; // Variable pour les messages d'erreur

	// Fonction pour hacher un mot de passe avec SHA-1 (pour l'API haveibeenpwned)
	async function sha1(password: string): Promise<string> {
		if (!browser) return password;
		const msgBuffer = new TextEncoder().encode(password);
		const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
	}

	// Fonction pour vérifier si un mot de passe a été compromis via haveibeenpwned
	async function checkPasswordBreached(password: string): Promise<boolean> {
		if (!browser) return false;
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
			console.error('Error checking haveibeenpwned:', error);
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
		if (score >= 90) return '#a7f3ae'; // Vert vif - excellent
		if (score >= 70) return '#a7f3ae99'; // Vert clair - bon
		if (score >= 50) return '#f8d88a'; // Jaune - moyen
		if (score >= 30) return '#f2c3c2'; // Rose - faible
		return '#e53e3e'; // Rouge - critique
	}

	// Fonction pour auditer tous les mots de passe
	async function auditAllPasswords() {
		// Réinitialiser les résultats précédents
		weakPasswords = [];
		reusedPasswords = [];
		breachedPasswords = [];
		isCheckingBreaches = true;
		haveibeenpwnedError = '';

		// Ouvrir le modal immédiatement pour montrer le chargement
		showAuditModal = true;

		// Vérifier les mots de passe faibles (score < 3)
		weakPasswords = credentials.filter((cred) => {
			if (!cred.password) return false;
			const result = evaluatePasswordStrength(cred.password);
			return result.score < 3;
		});

		// Vérifier les mots de passe réutilisés
		const passwordMap = new Map<string, number>();
		const passwordCredMap = new Map<string, Credential[]>();

		credentials.forEach((cred) => {
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
				creds.forEach((cred) => {
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

			const promise = checkPasswordBreached(cred.password).then((isBreached) => {
				if (isBreached) {
					// Trouver tous les credentials avec ce mot de passe
					credentials.forEach((c) => {
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
		setTimeout(() => {
			// Trouver l'élément à faire défiler jusqu'à
			const element = document.querySelector(`[data-password-id="${cred.id}"]`);
			if (element) {
				// Faire défiler jusqu'à l'élément
				element.scrollIntoView({ behavior: 'smooth', block: 'center' });
			}
		}, 100);
	}

	// ... existing code ...

	// Variables pour la navigation au clavier
	let focusedCredentialIndex = -1;
	let searchInputRef: HTMLInputElement;
	let showKeyboardHelp = false;
	let lastKeypressTime = 0;
	let lastKey = '';

	// Fonction pour copier du texte dans le presse-papiers
	function copyToClipboard(text: string) {
		if (!text) return;
		navigator.clipboard
			.writeText(text)
			.then(() => {
				showToast(t('copiedToClipboard', lang));
			})
			.catch((err) => {
				console.error('Erreur lors de la copie dans le presse-papiers:', err);
			});
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

		const now = Date.now();
		const timeSinceLastKeypress = now - lastKeypressTime;

		if (event.key === 'g' && lastKey === 'g' && timeSinceLastKeypress < 400) {
			if (filteredCredentials.length > 0) {
				focusedCredentialIndex = 0;
				scrollToCredential(focusedCredentialIndex);
				event.preventDefault();
			}
			lastKey = ''; // Reset after sequence
			lastKeypressTime = 0;
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
					goto('#add-credential-form');
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
					fileInput?.click();
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
					focusedCredentialIndex = Math.min(
						focusedCredentialIndex + 1,
						filteredCredentials.length - 1
					);
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
			case 'G':
				if (filteredCredentials.length > 0) {
					focusedCredentialIndex = filteredCredentials.length - 1;
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

		lastKey = event.key;
		lastKeypressTime = now;
	}

	// Fonction pour faire défiler vers l'élément sélectionné
	function scrollToCredential(index: number) {
		if (!browser) return; // document.getElementById is a browser API
		if (index >= 0) {
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
		if (!browser) return;
		document.removeEventListener('keydown', handleKeyDown);
	});
</script>

<svelte:head>
	<link rel="preconnect" href="https://fonts.googleapis.com" />
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous" />
	<link
		href="https://fonts.googleapis.com/css2?family=Raleway:wght@400;500;600;700&family=Work+Sans:wght@300;400;500;600&display=swap"
		rel="stylesheet"
	/>
</svelte:head>

<div
	class="min-h-screen p-4"
	style="background-color: #1d1b21; font-family: 'Work Sans', sans-serif;"
>
	<div class="max-w-3xl mx-auto">
		<!-- Bouton de profil avec menu contextuel -->
		<div class="absolute top-4 right-4">
			<button
				id="profile-button"
				on:click={toggleProfileMenu}
				class="w-10 h-10 rounded-full flex items-center justify-center transition-all duration-200 ease-in-out"
				style="background-color: #474b4f; color: white;"
			>
				<svg
					xmlns="http://www.w3.org/2000/svg"
					class="h-6 w-6"
					fill="none"
					viewBox="0 0 24 24"
					stroke="currentColor"
				>
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width="2"
						d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"
					/>
				</svg>
			</button>

			<!-- Menu contextuel du profil -->
			{#if showProfileMenu}
				<div
					id="profile-menu"
					class="absolute right-0 mt-2 rounded-lg shadow-lg py-2 z-[100] min-w-[150px]"
					style="background-color: #1d1b21; border: 2px solid #ced7e1;"
				>
					<div class="px-4 py-2 border-b border-gray-700">
						<span class="text-sm font-medium" style="color: #ced7e1;">{t('profile', lang)}</span>
					</div>
					<button
						class="w-full px-4 py-2 text-left hover-bg flex items-center"
						on:click={auditAllPasswords}
						style="color: #ced7e1;"
					>
						<svg
							xmlns="http://www.w3.org/2000/svg"
							class="h-4 w-4 mr-2"
							fill="none"
							viewBox="0 0 24 24"
							stroke="currentColor"
						>
							<path
								stroke-linecap="round"
								stroke-linejoin="round"
								stroke-width="2"
								d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
							/>
						</svg>
						{t('auditPasswords', lang)}
					</button>
					<button
						class="w-full px-4 py-2 text-left hover-bg flex items-center"
						on:click={toggleLanguage}
						style="color: #ced7e1;"
					>
						<svg
							xmlns="http://www.w3.org/2000/svg"
							class="h-4 w-4 mr-2"
							fill="none"
							viewBox="0 0 24 24"
							stroke="currentColor"
						>
							<path
								stroke-linecap="round"
								stroke-linejoin="round"
								stroke-width="2"
								d="M3 5h12M9 3v2m1.048 9.5A18.022 18.022 0 016.412 9m6.088 9h7M11 21l5-10 5 10M12.751 5C11.783 10.77 8.07 15.61 3 18.129"
							/>
						</svg>
						{lang === 'fr' ? 'Français' : 'English'}
					</button>
					<button
						class="w-full px-4 py-2 text-left hover-bg flex items-center"
						on:click={disconnect}
						style="color: #e53e3e;"
					>
						<svg
							xmlns="http://www.w3.org/2000/svg"
							class="h-4 w-4 mr-2"
							fill="none"
							viewBox="0 0 24 24"
							stroke="currentColor"
						>
							<path
								stroke-linecap="round"
								stroke-linejoin="round"
								stroke-width="2"
								d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
							/>
						</svg>
						{t('logout', lang)}
					</button>
				</div>
			{/if}
		</div>
		<h1
			class="text-3xl font-bold text-center mb-6 text-white"
			style="font-family: 'Raleway', sans-serif;"
		>
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
					<div class="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
						<Search class="w-5 h-5 text-gray-500" />
					</div>
					<input
						type="text"
						bind:this={searchInputRef}
						bind:value={searchTerm}
						placeholder={t('search', lang)}
						class="w-full py-2 pl-10 pr-4 text-sm text-gray-700 border rounded-lg focus:outline-none focus:border-blue-400"
					/>
					<div
						class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-xs text-gray-500"
					>
						/
					</div>
				</div>
				<div class="text-xs text-white mt-1 italic px-2">
					{t('searchTip', lang) ||
						`Astuce: Utilisez !shared pour voir les mots de passe partagés avec vous, !sharedbyme pour ceux que vous avez partagés.`}
				</div>
				<!-- Boutons de filtre -->
				<div class="flex flex-wrap gap-2 mt-2">
					<button
						on:click={() => {
							if (searchTerm.includes('!s')) {
								searchTerm = searchTerm.replace('!s', '').trim();
							} else {
								searchTerm = (searchTerm + ' !s').trim();
							}
						}}
						class="px-3 py-1 rounded-md text-sm font-medium transition-all duration-200 ease-in-out"
						style="background-color: {searchTerm.includes('!s')
							? '#a7f3ae'
							: '#474b4f'}; color: {searchTerm.includes('!s') ? '#1d1b21' : 'white'};"
					>
						{t('sharedWithMe', lang) || 'Partagés avec moi'}
					</button>
					<button
						on:click={() => {
							if (searchTerm.includes('!m')) {
								searchTerm = searchTerm.replace('!m', '').trim();
							} else {
								searchTerm = (searchTerm + ' !m').trim();
							}
						}}
						class="px-3 py-1 rounded-md text-sm font-medium transition-all duration-200 ease-in-out"
						style="background-color: {searchTerm.includes('!m')
							? '#a7f3ae'
							: '#474b4f'}; color: {searchTerm.includes('!m') ? '#1d1b21' : 'white'};"
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
							goto('#add-credential-form');
							// Réinitialiser le générateur de mot de passe
							showPasswordGenerator = false;
							passwordConfig = { ...defaultPasswordConfig };
							passwordStrength = {
								score: 0,
								color: '#e53e3e',
								text: t('passwordStrengthVeryWeak', lang) || 'Très faible'
							};
						}
					}}
					class="fixed bottom-4 right-4 h-14 w-14 rounded-full shadow-lg transition-transform hover:scale-110 z-10"
					style="background-color: #f2c3c2;"
				>
					<div class="flex items-center justify-center h-full w-full rounded-full">
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

				<!-- Bouton d'exportation -->
				<button
					on:click={() => (showExportDialog = true)}
					class="fixed bottom-4 right-36 h-14 w-14 rounded-full shadow-lg transition-transform hover:scale-110 z-10"
					style="background-color: #c3f2f7;"
					title={t('exportPasswords', lang)}
				>
					<div class="flex items-center justify-center h-full w-full rounded-full">
						<svg
							xmlns="http://www.w3.org/2000/svg"
							class="w-6 h-6 text-zinc-800"
							viewBox="0 0 24 24"
							fill="none"
							stroke="currentColor"
							stroke-width="2"
							stroke-linecap="round"
							stroke-linejoin="round"
						>
							<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
							<polyline points="7 10 12 15 17 10"></polyline>
							<line x1="12" y1="15" x2="12" y2="3"></line>
						</svg>
					</div>
				</button>

				<!-- Bouton d'aide clavier -->
				<button
					on:click={() => (showKeyboardHelp = true)}
					class="fixed bottom-4 right-52 h-14 w-14 rounded-full shadow-lg transition-transform hover:scale-110 z-10"
					style="background-color: #f3d9a7;"
					title={t('keyboardShortcuts', lang)}
				>
					<div class="flex items-center justify-center h-full w-full rounded-full">
						<svg
							xmlns="http://www.w3.org/2000/svg"
							class="w-6 h-6 text-zinc-800"
							viewBox="0 0 24 24"
							fill="none"
							stroke="currentColor"
							stroke-width="2"
							stroke-linecap="round"
							stroke-linejoin="round"
						>
							<rect x="2" y="4" width="20" height="16" rx="2" ry="2"></rect>
							<path d="M6 8h.01"></path>
							<path d="M10 8h.01"></path>
							<path d="M14 8h.01"></path>
							<path d="M18 8h.01"></path>
							<path d="M6 12h.01"></path>
							<path d="M10 12h.01"></path>
							<path d="M14 12h.01"></path>
							<path d="M18 12h.01"></path>
							<path d="M6 16h12"></path>
						</svg>
					</div>
				</button>
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
						<label class="block text-sm font-medium" style="color: #1d1b21;" for="newUsername">
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
						<label class="block text-sm font-medium" style="color: #1d1b21;" for="newPassword">
							{t('password', lang)}
						</label>
						<div class="flex">
							<input
								id="newPassword"
								type={showPasswordGenerator ? 'text' : 'password'}
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
								on:click={() => (showPasswordGenerator = !showPasswordGenerator)}
								class="ml-2 mt-1 px-3 py-2 rounded-lg"
								style="background-color: #f2c3c2; color: #1d1b21;"
								title={showPasswordGenerator
									? t('hideGenerator', lang) || 'Masquer le générateur'
									: t('showGenerator', lang) || 'Afficher le générateur'}
							>
								{showPasswordGenerator ? '✕' : '⚙️'}
							</button>
						</div>

						<!-- Indicateur de force du mot de passe -->
						{#if newRecord.password}
							<div class="mt-1">
								<div class="w-full h-2 bg-gray-200 rounded-full overflow-hidden">
									<div
										class="h-full rounded-full"
										style="width: {(passwordStrength.score + 1) *
											20}%; background-color: {passwordStrength.color};"
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
								<h4 class="font-medium mb-2" style="color: #1d1b21;">
									{t('passwordGenerator', lang) || 'Générateur de mot de passe'}
								</h4>

								<div class="mb-3">
									<label class="block text-sm" style="color: #474b4f;"
										>{t('passwordLength', lang) || 'Longueur'}: {passwordConfig.length}</label
									>
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
										<span class="text-sm" style="color: #474b4f;"
											>{t('uppercase', lang) || 'Majuscules'}</span
										>
									</label>

									<label class="flex items-center">
										<input
											type="checkbox"
											bind:checked={passwordConfig.includeLowercase}
											class="mr-2"
										/>
										<span class="text-sm" style="color: #474b4f;"
											>{t('lowercase', lang) || 'Minuscules'}</span
										>
									</label>

									<label class="flex items-center">
										<input
											type="checkbox"
											bind:checked={passwordConfig.includeNumbers}
											class="mr-2"
										/>
										<span class="text-sm" style="color: #474b4f;"
											>{t('numbers', lang) || 'Chiffres'}</span
										>
									</label>

									<label class="flex items-center">
										<input
											type="checkbox"
											bind:checked={passwordConfig.includeSymbols}
											class="mr-2"
										/>
										<span class="text-sm" style="color: #474b4f;"
											>{t('symbols', lang) || 'Symboles'}</span
										>
									</label>

									<label class="flex items-center col-span-2 sm:col-span-1">
										<input
											type="checkbox"
											bind:checked={passwordConfig.excludeSimilarChars}
											class="mr-2"
										/>
										<span class="text-sm" style="color: #474b4f;"
											>{t('excludeSimilarChars', lang) ||
												'Exclure les caractères similaires (i, l, 1, L, o, 0, O)'}</span
										>
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
										{t('generate', lang) || 'Générer'}
									</button>

									<button
										type="button"
										on:click={() => {
											passwordConfig = { ...defaultPasswordConfig };
										}}
										class="px-3 py-1 rounded-lg text-sm"
										style="background-color: #ced7e1; color: #1d1b21;"
									>
										{t('reset', lang) || 'Réinitialiser'}
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
						<button on:click={saveNewCredential} class="secondary-btn px-4 py-2 rounded-lg flex-1">
							{t('save', lang)}
						</button>
						<button
							on:click={() => {
								newRecord = {
									service: '',
									username: '',
									password: '',
									otp: '',
									uuid: '',
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
							<h3
								class="text-lg font-semibold flex items-center flex-wrap gap-2"
								style="color: #1d1b21; font-family: 'Raleway', sans-serif;"
							>
								{#if pendingCredential.credential.favicon}
									<img
										src={pendingCredential.credential.favicon}
										alt="Favicon"
										class="w-5 h-5 mr-1"
										on:error={handleImageError}
									/>
								{/if}
								<span class="break-all">{pendingCredential.credential.service}</span>
								<span class="text-xs bg-yellow-200 text-yellow-800 px-2 py-1 rounded-full">
									{t('pending', lang) || 'En attente'}
								</span>
							</h3>
							<div class="mt-1 flex items-center flex-wrap">
								<span class="mr-2" style="color: #474b4f;">{t('username', lang)}:</span>
								<span class="font-medium break-all" style="color: #1d1b21;"
									>{pendingCredential.credential.username}</span
								>
							</div>
							<div class="mt-2 text-sm text-purple-700">
								{t('sharedBy', lang)}
								{pendingCredential.owneremail}
							</div>
							<div class="mt-4 text-sm italic" style="color: #474b4f;">
								{t('pendingDescription', lang) ||
									'Ce mot de passe a été partagé avec vous. Acceptez pour y accéder ou refusez pour le rejeter.'}
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
							style="background-color: #e53e3e; color: white;"
						>
							{t('reject', lang) || 'Refuser'}
						</button>
					</div>
				</div>
			{/each}
			<!-- Credentials list -->
			{#each filteredCredentials as credential, i}
				<div
					id="credential-{i}"
					data-password-id={credential.id}
					class="card rounded-lg p-4 mb-4 transition-colors duration-200 hover:bg-gray-100 relative group"
					class:highlight={focusedCredentialIndex === i}
					tabindex="0"
					on:keydown={(e) => {
						if (e.key === 'Enter') {
							handleCredentialSelection(credential);
						}
					}}
					aria-selected={focusedCredentialIndex === i}
				>
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
									id="editPassword"
									type={showEditPasswordGenerator ? 'text' : 'password'}
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
									on:click={() => (showEditPasswordGenerator = !showEditPasswordGenerator)}
									class="ml-2 mt-1 px-3 py-2 rounded-lg"
									style="background-color: #1d1b21; color: #f2c3c2;"
									title={showEditPasswordGenerator
										? t('hideGenerator', lang) || 'Masquer le générateur'
										: t('showGenerator', lang) || 'Afficher le générateur'}
								>
									{showEditPasswordGenerator ? '✕' : '⚙️'}
								</button>
							</div>

							<!-- Indicateur de force du mot de passe -->
							{#if editedRecord.password}
								<div class="mt-1">
									<div class="w-full h-2 bg-gray-200 rounded-full overflow-hidden">
										<div
											class="h-full rounded-full"
											style="width: {(passwordStrength.score + 1) *
												20}%; background-color: {passwordStrength.color};"
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
									<h4 class="font-medium mb-2" style="color: #1d1b21;">
										{t('passwordGenerator', lang) || 'Générateur de mot de passe'}
									</h4>

									<div class="mb-3">
										<label class="block text-sm" style="color: #474b4f;"
											>{t('passwordLength', lang) || 'Longueur'}: {passwordConfig.length}</label
										>
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
											<span class="text-sm" style="color: #474b4f;"
												>{t('uppercase', lang) || 'Majuscules'}</span
											>
										</label>

										<label class="flex items-center">
											<input
												type="checkbox"
												bind:checked={passwordConfig.includeLowercase}
												class="mr-2"
											/>
											<span class="text-sm" style="color: #474b4f;"
												>{t('lowercase', lang) || 'Minuscules'}</span
											>
										</label>

										<label class="flex items-center">
											<input
												type="checkbox"
												bind:checked={passwordConfig.includeNumbers}
												class="mr-2"
											/>
											<span class="text-sm" style="color: #474b4f;"
												>{t('numbers', lang) || 'Chiffres'}</span
											>
										</label>

										<label class="flex items-center">
											<input
												type="checkbox"
												bind:checked={passwordConfig.includeSymbols}
												class="mr-2"
											/>
											<span class="text-sm" style="color: #474b4f;"
												>{t('symbols', lang) || 'Symboles'}</span
											>
										</label>

										<label class="flex items-center col-span-2 sm:col-span-1">
											<input
												type="checkbox"
												bind:checked={passwordConfig.excludeSimilarChars}
												class="mr-2"
											/>
											<span class="text-sm" style="color: #474b4f;"
												>{t('excludeSimilarChars', lang) ||
													'Exclure les caractères similaires (i, l, 1, L, o, 0, O)'}</span
											>
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
											{t('generate', lang) || 'Générer'}
										</button>

										<button
											type="button"
											on:click={() => {
												passwordConfig = { ...defaultPasswordConfig };
											}}
											class="px-3 py-1 rounded-lg text-sm"
											style="background-color: #ced7e1; color: #1d1b21;"
										>
											{t('reset', lang) || 'Réinitialiser'}
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
								id="editOTPURI"
								type="text"
								bind:value={editedRecord.otp}
								class="mt-1 block w-full border rounded-lg p-2
                     focus:outline-none focus:ring-2"
								style="border-color: #474b4f;"
							/>
						</div>
						<div class="flex flex-wrap gap-2 mt-4">
							<button on:click={saveEdit} class="secondary-btn px-4 py-2 rounded-lg flex-1">
								{t('save', lang)}
							</button>
							<button on:click={deleteEdit} class="danger-btn px-4 py-2 rounded-lg flex-1">
								{t('delete', lang)}
							</button>
							<button on:click={cancelEdit} class="neutral-btn px-4 py-2 rounded-lg flex-1">
								{t('cancel', lang)}
							</button>
						</div>
					{:else}
						<!-- View Mode -->
						<div class="flex justify-between items-start flex-col sm:flex-row">
							<div class="w-full sm:w-auto">
								<h3
									class="text-lg font-semibold flex items-center flex-wrap gap-2"
									style="color: #1d1b21; font-family: 'Raleway', sans-serif;"
								>
									{#if credential.favicon}
										<img
											src={credential.favicon}
											alt="Favicon"
											class="w-5 h-5 mr-1"
											on:error={handleImageError}
										/>
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

								<!-- Nom d'utilisateur et code 2FA sur la même ligne -->
								<div class="mt-2 flex items-center flex-wrap justify-between">
									<div class="flex-grow">
										<span class="font-medium break-all" style="color: #1d1b21;"
											>{credential.username.length > 40
												? credential.username.slice(0, 40) + '...'
												: credential.username}</span
										>
									</div>

									{#if credential.otp && credential.twoFA}
										<div class="flex items-center ml-2">
											<div class="relative flex items-center">
												<span
													class="font-mono px-2 py-1 rounded flex items-center otp-code"
													style="background-color: #1d1b21; color: #a7f3ae;"
												>
													{credential.twoFA}
												</span>
												<button
													class="ml-2 text-gray-500 hover:text-gray-700 p-1 rounded-full hover:bg-gray-100 copy-button"
													on:click={() => copyText(credential.twoFA || '')}
													title={t('copyToClipboard', lang) || 'Copier le code'}
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
											{#if credential.id in remainingTimes}
												{@const period = otpPeriods[credential.id] || 30}
												{@const percentage = 100 - (remainingTimes[credential.id] / period) * 100}
												{@const dashArray = `${percentage}, 100`}
												{@const timeLeft = remainingTimes[credential.id]}
												{@const isLow = timeLeft <= 5}
												{@const isVeryLow = timeLeft <= 3}
												{@const circleColor = isLow ? '#e53e3e' : '#a7f3ae'}
												{@const textColor = isLow ? '#ffffff' : '#a7f3ae'}
												{@const bgColor = isLow ? '#1d1b21' : '#1d1b21'}
												<div class="relative w-8 h-8 ml-1 {isVeryLow ? 'pulse-animation' : ''}">
													<svg class="w-8 h-8" viewBox="0 0 36 36">
														<circle
															cx="18"
															cy="18"
															r="16"
															fill={bgColor}
															stroke="#474b4f"
															stroke-width="1"
														></circle>
														<circle
															cx="18"
															cy="18"
															r="16"
															fill="none"
															stroke={circleColor}
															stroke-width="2"
															stroke-dasharray={dashArray}
															stroke-linecap="round"
															transform="rotate(-90 18 18)"
															class="timer-circle"
														></circle>
														<text
															x="18"
															y="19"
															text-anchor="middle"
															dominant-baseline="central"
															fill={textColor}
															font-size="12"
															font-weight="bold"
														>
															{timeLeft}
														</text>
													</svg>
												</div>
											{/if}
										</div>
									{/if}
								</div>

								{#if credential.owneremail}
									<div class="mt-2 text-xs text-purple-700">
										{t('sharedBy', lang)}
										{credential.owneremail}
									</div>
								{/if}
							</div>
							<div
								class="flex flex-col items-start sm:items-end space-y-2 mt-3 sm:mt-0 w-full sm:w-auto"
							>
								<button
									on:click={(event) => showContextMenu(event, credential)}
									class="text-gray-500 hover:text-gray-700 p-2 rounded-full hover:bg-gray-100"
									title={t('showActions', lang) || 'Afficher les actions'}
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
											d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z"
										/>
									</svg>
								</button>
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
			<h2
				class="text-xl font-semibold mb-4"
				style="font-family: 'Raleway', sans-serif; color: #1d1b21;"
			>
				{t('sharePassword', lang)}
			</h2>
			<p class="mb-4 text-sm sm:text-base" style="color: #474b4f;">{t('shareDescription', lang)}</p>

			<div class="mb-4">
				<label
					for="shareUserId"
					class="block font-medium mb-1 text-sm sm:text-base"
					style="color: #1d1b21;">{t('email', lang)}</label
				>
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
					<h3 class="text-sm font-medium mb-2" style="color: #1d1b21;">
						{t('alreadySharedWith', lang)}
					</h3>
					<ul class="p-2 rounded-md max-h-32 overflow-y-auto" style="background-color: #1d1b21;">
						{#each sharedPasswordEmails.get(sharingCredential.uuid)?.emails || [] as email, index}
							<li
								class="flex justify-between items-center text-sm py-1 px-2 border-b border-zinc-700 last:border-b-0 flex-wrap gap-1"
							>
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
										<div
											class="w-4 h-4 border-2 border-red-500 border-t-transparent rounded-full animate-spin mr-1"
										></div>
									{:else}
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
												d="M6 18L18 6M6 6l12 12"
											/>
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
						<div
							class="w-4 h-4 border-2 border-zinc-800 border-t-transparent rounded-full animate-spin mr-2"
						></div>
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
	<div
		class="fixed top-4 right-4 px-4 py-2 rounded-md shadow-md z-50 notification"
		style="background-color: #a7f3ae; color: #1d1b21;"
	>
		{notificationMessage}
	</div>
{/if}

<!-- Modal d'importation -->
{#if importingFile}
	<div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
		<div class="card p-4 sm:p-6 w-full max-w-md mx-auto bg-gray-100">
			<h2
				class="text-xl font-semibold mb-4"
				style="font-family: 'Raleway', sans-serif; color: #1d1b21;"
			>
				{t('importing', lang)}
			</h2>
			<div class="w-full bg-gray-200 rounded-full h-4 mb-4">
				<div
					class="bg-green-500 h-4 rounded-full"
					style="width: {(importProgress / importTotal) * 100}%"
				></div>
			</div>
			<p class="text-center text-sm sm:text-base" style="color: #474b4f;">
				{importProgress}
				{t('importedOf', lang)}
				{importTotal}
				{t('passwordsImported', lang)}
			</p>
			{#if importError}
				<p class="text-red-500 mt-2 text-xs sm:text-sm">{importError}</p>
			{/if}
		</div>
	</div>
{/if}

<!-- Dialogue d'exportation -->
{#if showExportDialog}
	<div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
		<div class="card p-4 sm:p-6 w-full max-w-md mx-auto bg-gray-100">
			<h2
				class="text-xl font-semibold mb-4"
				style="font-family: 'Raleway', sans-serif; color: #1d1b21;"
			>
				{t('exportPasswords', lang) || 'Exporter les mots de passe'}
			</h2>

			<p class="mb-4" style="color: #474b4f;">
				{t('exportDescription', lang) ||
					"Choisissez le format d'exportation pour vos mots de passe."}
			</p>

			<div class="mb-4">
				<label class="block text-sm font-medium mb-2" style="color: #474b4f;">
					{t('exportFormat', lang) || "Format d'exportation"}
				</label>

				<div class="mt-2 space-y-2">
					<label class="flex items-center">
						<input type="radio" bind:group={exportFormat} value="json" class="mr-2" />
						<span>JSON</span>
					</label>

					<label class="flex items-center">
						<input type="radio" bind:group={exportFormat} value="csv" class="mr-2" />
						<span>CSV</span>
					</label>

					<label class="flex items-center">
						<input type="radio" bind:group={exportFormat} value="txt" class="mr-2" />
						<span>{t('plainText', lang) || 'Texte brut'}</span>
					</label>
				</div>
			</div>

			<div class="flex flex-wrap justify-end gap-2 mt-6">
				<button
					on:click={() => (showExportDialog = false)}
					class="px-4 py-2 rounded transition-colors"
					style="background-color: #e6e6e6; color: #1d1b21;"
				>
					{t('cancel', lang) || 'Annuler'}
				</button>

				<button
					on:click={handleExport}
					class="px-4 py-2 rounded transition-colors"
					style="background-color: #c3f2f7; color: #1d1b21;"
				>
					{t('export', lang) || 'Exporter'}
				</button>
			</div>
		</div>
	</div>
{/if}

<!-- Menu contextuel -->
{#if contextMenu.show && contextMenu.credential}
	<div
		class="fixed rounded-lg shadow-lg py-2 z-[100] min-w-[200px]"
		style="left: {contextMenu.x}px; top: {contextMenu.y}px; background-color: #1d1b21;border: 2px solid #ced7e1;"
	>
		<button
			class="w-full px-4 py-2 text-left hover-bg flex items-center"
			on:click={() => {
				if (contextMenu.credential?.username) {
					copyText(contextMenu.credential.username);
				}
				closeContextMenu();
			}}
			style="color: #ced7e1;"
		>
			<svg
				xmlns="http://www.w3.org/2000/svg"
				class="h-4 w-4 mr-2"
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
			{t('copyUsername', lang) || "Copier le nom d'utilisateur"}
		</button>
		<button
			class="w-full px-4 py-2 text-left hover-bg flex items-center"
			on:click={() => {
				if (contextMenu.credential?.password) {
					copyText(contextMenu.credential.password);
				}
				closeContextMenu();
			}}
			style="color: #ced7e1;"
		>
			<svg
				xmlns="http://www.w3.org/2000/svg"
				class="h-4 w-4 mr-2"
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
			{t('copyPassword', lang) || 'Copier le mot de passe'}
		</button>
		{#if !contextMenu.credential.sharedBy}
			<button
				class="w-full px-4 py-2 text-left hover-bg flex items-center"
				on:click={() => {
					startEdit(contextMenu.credential!);
					closeContextMenu();
				}}
				style="color: #ced7e1;"
			>
				<svg
					xmlns="http://www.w3.org/2000/svg"
					class="h-4 w-4 mr-2"
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
				{t('edit', lang) || 'Modifier'}
			</button>
			<button
				class="w-full px-4 py-2 text-left hover-bg flex items-center"
				on:click={() => {
					showShareModal(contextMenu.credential!);
					closeContextMenu();
				}}
				style="color: #ced7e1;"
			>
				<svg
					xmlns="http://www.w3.org/2000/svg"
					class="h-4 w-4 mr-2"
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
				{t('share', lang) || 'Partager'}
			</button>
		{/if}
		{#if contextMenu.credential.sharedBy}
			<button
				class="w-full px-4 py-2 text-left hover-bg flex items-center"
				on:click={() => {
					handleRejectSharedPass(contextMenu.credential!);
					closeContextMenu();
				}}
				style="color: #e53e3e;"
			>
				<svg
					xmlns="http://www.w3.org/2000/svg"
					class="h-4 w-4 mr-2"
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
				{t('deleteShared', lang) || 'Supprimer ce partage'}
			</button>
		{/if}
	</div>
{/if}

<!-- Modal d'audit des mots de passe -->
{#if showAuditModal}
	<div
		class="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4 overflow-y-auto"
	>
		<div
			class="rounded-lg shadow-xl border w-full max-w-4xl max-h-[90vh]"
			style="background-color: #1d1b21; border-color: #474b4f;"
		>
			<div class="p-4 border-b" style="border-color: #474b4f;">
				<div class="flex justify-between items-center">
					<h2
						class="text-xl font-semibold"
						style="color: #ced7e1; font-family: 'Raleway', sans-serif;"
					>
						{t('passwordAudit', lang)}
					</h2>
					<button on:click={closeAuditModal} class="hover:text-gray-300" style="color: #ced7e1;">
						<svg
							xmlns="http://www.w3.org/2000/svg"
							class="h-6 w-6"
							fill="none"
							viewBox="0 0 24 24"
							stroke="currentColor"
						>
							<path
								stroke-linecap="round"
								stroke-linejoin="round"
								stroke-width="2"
								d="M6 18L18 6M6 6l12 12"
							/>
						</svg>
					</button>
				</div>
			</div>

			<!-- Score global -->
			<div class="p-6 border-b" style="border-color: #474b4f;">
				<div class="flex flex-col sm:flex-row items-center gap-6">
					<div
						class="w-28 h-28 rounded-full flex items-center justify-center border-4"
						style="border-color: {getScoreColor(overallScore)}"
					>
						<span
							class="text-4xl font-bold"
							style="color: #ced7e1; font-family: 'Raleway', sans-serif;">{overallScore}</span
						>
					</div>
					<div class="text-center sm:text-left">
						<h3
							class="text-xl font-semibold mb-2"
							style="color: #ced7e1; font-family: 'Raleway', sans-serif;"
						>
							{t('overallScore', lang)}
						</h3>
						<p class="text-lg mb-2" style="color: #ced7e1; font-weight: 500;">
							{getScoreRating(overallScore)}
						</p>
						<p class="text-sm" style="color: #ced7e1;">{t('scoreExplanation', lang)}</p>
					</div>
				</div>
			</div>

			{#if isCheckingBreaches}
				<div class="p-6 flex justify-center items-center min-h-[300px]">
					<div class="flex flex-col items-center">
						<div
							class="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 mb-4"
							style="border-color: #f2c3c2;"
						></div>
						<span class="text-lg" style="color: #ced7e1;">{t('checkingBreaches', lang)}</span>
					</div>
				</div>
			{:else}
				<div
					class="p-6 overflow-y-auto max-h-[calc(90vh-240px)]"
					style="background-color: #1d1b21;"
				>
					<div class="grid grid-cols-1 md:grid-cols-3 gap-6">
						<!-- Mots de passe faibles -->
						<div
							class="border rounded-lg overflow-hidden"
							style="border-color: #474b4f; background-color: #1d1b21;"
						>
							<div class="p-4" style="background-color: rgba(229, 62, 62, 0.1);">
								<h3
									class="text-lg font-semibold flex items-center"
									style="color: #ced7e1; font-family: 'Raleway', sans-serif;"
								>
									<svg
										xmlns="http://www.w3.org/2000/svg"
										class="h-5 w-5 mr-2"
										style="color: #e53e3e;"
										viewBox="0 0 20 20"
										fill="currentColor"
									>
										<path
											fill-rule="evenodd"
											d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
											clip-rule="evenodd"
										/>
									</svg>
									{t('weakPasswords', lang)} ({weakPasswords.length})
								</h3>
							</div>

							<div class="px-4 py-3">
								{#if weakPasswords.length === 0}
									<p class="py-8 text-center" style="color: #ced7e1; font-style: italic;">
										{t('noWeakPasswords', lang)}
									</p>
								{:else}
									<div class="space-y-3 max-h-[250px] overflow-y-auto pr-2 custom-scrollbar">
										{#each weakPasswords as cred}
											<div
												class="rounded-md p-3"
												style="background-color: #2a2831; border: 1px solid #474b4f;"
											>
												<div class="flex justify-between items-center">
													<div class="overflow-hidden max-w-[75%]">
														<div
															class="font-semibold truncate"
															style="color: #ced7e1;"
															title={cred.service}
														>
															{cred.service}
														</div>
														<div
															class="text-sm truncate"
															style="color: #ced7e1; opacity: 0.7;"
															title={cred.username || ''}
														>
															{cred.username || ''}
														</div>
													</div>
													<button
														on:click={() => editFromAudit(cred)}
														class="hover:opacity-75 transition-opacity flex-shrink-0"
														style="color: #1d1b21; background-color: #a7f3ae; border-radius: 9999px; padding: 4px;"
													>
														<svg
															xmlns="http://www.w3.org/2000/svg"
															class="h-5 w-5"
															viewBox="0 0 20 20"
															fill="currentColor"
														>
															<path
																d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z"
															/>
														</svg>
													</button>
												</div>
												<div class="mt-2">
													<div class="w-full rounded-full h-2" style="background-color: #474b4f;">
														{#if cred.password}
															<div
																class="h-2 rounded-full"
																style="width: {Math.max(
																	5,
																	evaluatePasswordStrength(cred.password).score * 25
																)}%; background-color: {evaluatePasswordStrength(cred.password)
																	.color}"
															></div>
														{/if}
													</div>
												</div>
											</div>
										{/each}
									</div>
								{/if}
							</div>
						</div>

						<!-- Mots de passe réutilisés -->
						<div
							class="border rounded-lg overflow-hidden"
							style="border-color: #474b4f; background-color: #1d1b21;"
						>
							<div class="p-4" style="background-color: rgba(214, 158, 46, 0.1);">
								<h3
									class="text-lg font-semibold flex items-center"
									style="color: #ced7e1; font-family: 'Raleway', sans-serif;"
								>
									<svg
										xmlns="http://www.w3.org/2000/svg"
										class="h-5 w-5 mr-2"
										style="color: #d69e2e;"
										viewBox="0 0 20 20"
										fill="currentColor"
									>
										<path
											fill-rule="evenodd"
											d="M3 6a3 3 0 013-3h10a1 1 0 01.8 1.6L14.25 8l2.55 3.4A1 1 0 0116 13H6a1 1 0 00-1 1v3a1 1 0 11-2 0V6z"
											clip-rule="evenodd"
										/>
									</svg>
									{t('reusedPasswords', lang)} ({reusedPasswords.length})
								</h3>
							</div>

							<div class="px-4 py-3">
								{#if reusedPasswords.length === 0}
									<p class="py-8 text-center" style="color: #ced7e1; font-style: italic;">
										{t('noReusedPasswords', lang)}
									</p>
								{:else}
									<div class="space-y-3 max-h-[250px] overflow-y-auto pr-2 custom-scrollbar">
										{#each reusedPasswords as { credential, count }}
											<div
												class="rounded-md p-3"
												style="background-color: #2a2831; border: 1px solid #474b4f;"
											>
												<div class="flex justify-between items-center">
													<div class="overflow-hidden max-w-[75%]">
														<div
															class="font-semibold truncate"
															style="color: #ced7e1;"
															title={credential.service}
														>
															{credential.service}
														</div>
														<div
															class="text-sm truncate"
															style="color: #ced7e1; opacity: 0.7;"
															title={credential.username || ''}
														>
															{credential.username || ''}
														</div>
													</div>
													<div class="flex items-center flex-shrink-0">
														<span
															class="text-sm mr-2 px-2 py-1 rounded"
															style="color: #1d1b21; background-color: #f8d88a;">{count}x</span
														>
														<button
															on:click={() => editFromAudit(credential)}
															class="hover:opacity-75 transition-opacity"
															style="color: #1d1b21; background-color: #a7f3ae; border-radius: 9999px; padding: 4px;"
														>
															<svg
																xmlns="http://www.w3.org/2000/svg"
																class="h-5 w-5"
																viewBox="0 0 20 20"
																fill="currentColor"
															>
																<path
																	d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z"
																/>
															</svg>
														</button>
													</div>
												</div>
											</div>
										{/each}
									</div>
								{/if}
							</div>
						</div>

						<!-- Mots de passe compromis -->
						<div
							class="border rounded-lg overflow-hidden"
							style="border-color: #474b4f; background-color: #1d1b21;"
						>
							<div class="p-4" style="background-color: rgba(176, 14, 11, 0.1);">
								<h3
									class="text-lg font-semibold flex items-center"
									style="color: #ced7e1; font-family: 'Raleway', sans-serif;"
								>
									<svg
										xmlns="http://www.w3.org/2000/svg"
										class="h-5 w-5 mr-2"
										style="color: #e53e3e;"
										viewBox="0 0 20 20"
										fill="currentColor"
									>
										<path
											fill-rule="evenodd"
											d="M18 8a6 6 0 01-7.743 5.743L10 14l-1 1-1 1H6v-1l1-1 1-1 .257-.257A6 6 0 1118 8zm-6-4a1 1 0 100 2h2a1 1 0 100-2h-2z"
											clip-rule="evenodd"
										/>
									</svg>
									{t('breachedPasswords', lang)} ({breachedPasswords.length})
								</h3>
							</div>

							<div class="px-4 py-3">
								{#if haveibeenpwnedError}
									<p class="py-3" style="color: #e53e3e;">
										{t('apiError', lang)}: {haveibeenpwnedError}
									</p>
								{:else if breachedPasswords.length === 0}
									<p class="py-8 text-center" style="color: #ced7e1; font-style: italic;">
										{t('noBreachedPasswords', lang)}
									</p>
								{:else}
									<div class="space-y-3 max-h-[250px] overflow-y-auto pr-2 custom-scrollbar">
										{#each breachedPasswords as cred}
											<div
												class="rounded-md p-3"
												style="background-color: #2a2831; border: 1px solid #474b4f;"
											>
												<div class="flex justify-between items-center">
													<div class="overflow-hidden max-w-[75%]">
														<div
															class="font-semibold truncate"
															style="color: #ced7e1;"
															title={cred.service}
														>
															{cred.service}
														</div>
														<div
															class="text-sm truncate"
															style="color: #ced7e1; opacity: 0.7;"
															title={cred.username || ''}
														>
															{cred.username || ''}
														</div>
													</div>
													<button
														on:click={() => editFromAudit(cred)}
														class="hover:opacity-75 transition-opacity flex-shrink-0"
														style="color: #1d1b21; background-color: #a7f3ae; border-radius: 9999px; padding: 4px;"
													>
														<svg
															xmlns="http://www.w3.org/2000/svg"
															class="h-5 w-5"
															viewBox="0 0 20 20"
															fill="currentColor"
														>
															<path
																d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z"
															/>
														</svg>
													</button>
												</div>
											</div>
										{/each}
									</div>
								{/if}
							</div>
						</div>
					</div>
				</div>
			{/if}
		</div>
	</div>
{/if}

<!-- À ajouter à la fin de la page, juste avant </main> -->
<!-- Modal d'aide pour les raccourcis clavier -->
{#if showKeyboardHelp}
	<div
		class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
		on:click={() => (showKeyboardHelp = false)}
		on:keydown={(e) => {
			if (e.key === 'Escape') {
				showKeyboardHelp = false;
				e.preventDefault();
			}
		}}
		tabindex="-1"
	>
		<div class="card p-4 sm:p-6 w-full max-w-md mx-auto bg-gray-100" on:click|stopPropagation>
			<h2
				class="text-xl font-semibold mb-4"
				style="font-family: 'Raleway', sans-serif; color: #1d1b21;"
			>
				{t('keyboardShortcuts', lang)}
			</h2>

			<div class="grid grid-cols-2 gap-y-2">
				<div class="flex items-center">
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">/</kbd>
					<span>{t('shortcutSearch', lang)}</span>
				</div>
				<div class="flex items-center">
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">n</kbd>
					<span>{t('shortcutNew', lang)}</span>
				</div>
				<div class="flex items-center">
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">e</kbd>
					<span>{t('shortcutExport', lang)}</span>
				</div>
				<div class="flex items-center">
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">i</kbd>
					<span>{t('shortcutImport', lang)}</span>
				</div>

				<!-- Navigation Vim -->
				<div class="flex items-center col-span-2 mt-2 mb-1 border-t pt-2">
					<span class="font-medium">{t('shortcutVimNavigation', lang)}</span>
				</div>
				<div class="flex items-center">
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">j</kbd>
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">↓</kbd>
					<span>{t('shortcutNavigate', lang)} ↓</span>
				</div>
				<div class="flex items-center">
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">k</kbd>
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">↑</kbd>
					<span>{t('shortcutNavigate', lang)} ↑</span>
				</div>

				<!-- Raccourcis de copie -->
				<div class="flex items-center col-span-2 mt-2 mb-1 border-t pt-2">
					<span class="font-medium">{t('copyToClipboard', lang)}</span>
				</div>
				<div class="flex items-center">
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">u</kbd>
					<span>{t('shortcutCopyUsername', lang)}</span>
				</div>
				<div class="flex items-center">
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">p</kbd>
					<span>{t('shortcutCopyPassword', lang)}</span>
				</div>
				<div class="flex items-center">
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">o</kbd>
					<span>{t('shortcutCopyOtp', lang)}</span>
				</div>

				<!-- Autres raccourcis -->
				<div class="flex items-center col-span-2 mt-2 mb-1 border-t pt-2">
					<span class="font-medium">{t('other', lang) || 'Autres'}</span>
				</div>
				<div class="flex items-center">
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">Enter</kbd>
					<span>{t('shortcutSelect', lang)}</span>
				</div>
				<div class="flex items-center">
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">Esc</kbd>
					<span>{t('shortcutEscape', lang)}</span>
				</div>
				<div class="flex items-center">
					<kbd class="px-2 py-1 bg-gray-200 rounded-md text-xs mr-2">?</kbd>
					<span>{t('shortcutHelp', lang)}</span>
				</div>
			</div>

			<div class="mt-6 flex justify-between items-center">
				<span class="text-xs text-gray-500 italic">
					<kbd class="px-1 py-0.5 bg-gray-200 rounded-md text-xs">Esc</kbd>
					{t('toClose', lang) || 'pour fermer'}
				</span>
				<button
					on:click={() => (showKeyboardHelp = false)}
					class="px-4 py-2 rounded transition-colors"
					style="background-color: #f3d9a7; color: #1d1b21;"
				>
					{t('close', lang) || 'Fermer'}
				</button>
			</div>
		</div>
	</div>
{/if}

<!-- Fin du modal d'aide -->

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

	.hover-bg:hover {
		background-color: #a7f3ae54;
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

	h1,
	h2,
	h3,
	button {
		font-family: 'Raleway', sans-serif;
	}

	.card {
		background-color: #ced7e1;
		border-radius: 0.5rem;
		overflow: hidden;
		box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
		transition:
			transform 0.2s ease-in-out,
			box-shadow 0.2s ease-in-out;
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
		background-color: #e53e3e;
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
		0% {
			opacity: 0;
			transform: translateY(-20px);
		}
		10% {
			opacity: 1;
			transform: translateY(0);
		}
		90% {
			opacity: 1;
			transform: translateY(0);
		}
		100% {
			opacity: 0;
			transform: translateY(-20px);
		}
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

	/* Style pour le code 2FA */
	.otp-code {
		font-family: 'Courier New', monospace;
		font-weight: bold;
		letter-spacing: 1px;
		padding: 4px 8px;
		border-radius: 4px;
		box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15);
		transition: all 0.2s ease;
	}

	.otp-code:hover {
		box-shadow: 0 3px 6px rgba(0, 0, 0, 0.25);
	}

	/* Style pour le bouton de copie */
	.copy-button {
		opacity: 0.7;
		transition: opacity 0.2s ease;
	}

	.copy-button:hover {
		opacity: 1;
	}

	/* Animation du timer */
	.timer-circle {
		transition: stroke-dashoffset 1s linear;
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

	/* Style pour le menu du profil */
	.hover-bg:hover {
		background-color: rgba(255, 255, 255, 0.1);
	}

	/* Personnalisation de la barre de défilement */
	.custom-scrollbar::-webkit-scrollbar {
		width: 8px;
	}

	.custom-scrollbar::-webkit-scrollbar-track {
		background: rgba(71, 75, 79, 0.3);
		border-radius: 4px;
	}

	.custom-scrollbar::-webkit-scrollbar-thumb {
		background: #474b4f;
		border-radius: 4px;
	}

	.custom-scrollbar::-webkit-scrollbar-thumb:hover {
		background: #5a5f64;
	}

	/* Style pour .highlight */
	.highlight {
		background-color: #f9f5eb;
		border: 2px solid #f3d9a7 !important;
		box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
	}

	/* Style pour les kbd */
	kbd {
		background-color: #f3f3f3;
		border: 1px solid #d0d0d0;
		box-shadow: 0 1px 1px rgba(0, 0, 0, 0.1);
	}
</style>
