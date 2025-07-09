import { writable } from 'svelte/store';
// Store pour la langue actuelle
let currentLang2: 'fr' | 'en' = 'en';

export const currentLang = writable<'fr' | 'en'>(currentLang2);

// Traductions pour la page vault
export const translations = {
	fr: {
		// Titres et boutons principaux
		vault: 'Coffre-fort',
		logout: 'Déconnexion',
		search: 'Rechercher des identifiants...',
		language: 'Langue',
		profile: 'Profil',

		// Formulaire d'ajout
		service: 'Service',
		url: 'URL',
		appId: 'ID Application',
		description: 'Description',
		username: "Nom d'utilisateur",
		password: 'Mot de passe',
		otpUri: 'URI OTP',
		urlPlaceholder: 'https://exemple.com',
		appIdPlaceholder: 'Nom ou identifiant de l\'application',
		descriptionPlaceholder: 'Description optionnelle',
		save: 'Enregistrer',
		cancel: 'Annuler',
		delete: 'Supprimer',

		// Messages
		noCredentials: 'Aucun identifiant enregistré. Cliquez sur le bouton + pour en ajouter.',
		noSearchResults: 'Aucun identifiant ne correspond à votre recherche.',
		copiedToClipboard: 'Copié dans le presse-papiers',
		credentialUpdated: 'Identifiant mis à jour avec succès',
		credentialDeleted: 'Identifiant supprimé avec succès',
		credentialCreated: 'Identifiant créé avec succès',

		// Validation
		invalidUrl:
			"Format d'URL invalide. Utilisez des formats comme: google.com, osu.ppy.sh, 192.168.1.167:8181",
		requireUrlOrAppId: 'Veuillez fournir soit une URL soit un ID d\'application',

		// 2FA
		twoFaCode: 'Code 2FA:',
		enableTwoFa: 'Activer 2FA',
		disableTwoFa: 'Désactiver 2FA',

		// Partage
		shared: 'Partagé',
		sharePassword: 'Partager le mot de passe',
		shareDescription:
			"Entrez l'adresse email de l'utilisateur avec qui vous souhaitez partager ce mot de passe.",
		email: 'Email',
		emailPlaceholder: 'exemple@email.com',
		alreadySharedWith: 'Déjà partagé avec :',
		share: 'Partager',
		sharing: 'Partage en cours...',
		sharedBy: 'Partagé par:',
		passwordShared: 'Mot de passe partagé avec succès',

		// Importation
		importing: 'Importation en cours',
		importedOf: 'sur',
		passwordsImported: 'mots de passe importés',
		importSuccess: 'mot(s) de passe importé(s) avec succès',
		importFromJson: 'Importer des mots de passe depuis un fichier JSON ou CSV',
		invalidFileFormat: 'Format de fichier JSON invalide',
		invalidCsvFormat: 'Format de fichier CSV invalide ou non reconnu (format Chrome attendu)',
		clientNotInitialized: 'Client non initialisé',
		importError: "Erreur lors de l'importation du fichier",

		// Exportation
		exportPasswords: 'Exporter les mots de passe',
		exportDescription: "Choisissez le format d'exportation pour vos mots de passe.",
		exportFormat: "Format d'exportation",
		export: 'Exporter',
		exportSuccess: 'Mots de passe exportés avec succès',
		exportError: "Erreur lors de l'exportation",
		plainText: 'Texte brut',
		noCredentialsToExport: 'Aucun mot de passe à exporter',

		// Erreurs
		error: 'Erreur:',
		updateError: 'Erreur lors de la mise à jour',
		deleteError: 'Erreur lors de la suppression',
		createError: 'Erreur lors de la création',
		shareError: 'Erreur lors du partage',
		passwordEvalError: "Erreur lors de l'évaluation du mot de passe",
		uuidConversionError: "Erreur lors de la conversion de l'UUID",

		// Autres messages spécifiques
		invalidEmail: 'Veuillez entrer une adresse email valide',
		invalidUuid: 'UUID invalide',
		userNotFound: "Impossible de trouver l'utilisateur avec l'email",
		invalidRecipientUuid: 'UUID du destinataire invalide',
		unshareSuccess: 'Partage annulé avec',
		unshareError: "Erreur lors de l'annulation du partage",
		updateSuccess: 'Identifiant mis à jour avec succès',
		deleteSuccess: 'Identifiant supprimé avec succès',
		creationSuccess: 'Identifiant créé avec succès',
		creationError: 'Erreur lors de la création',
		shareSuccess: 'Mot de passe partagé avec succès',
		sharedWith: 'Déjà partagé avec :',
		unshare: 'Annuler le partage',
		sharedWithMe: 'Partagés avec moi',
		sharedByMe: 'Partagés par moi',
		searchTip:
			'Astuce: Utilisez !s pour voir les mots de passe partagés avec vous, !m pour ceux que vous avez partagés.',
		accept: 'Accepter',
		reject: 'Rejeter',
		// Nouvelles traductions
		dataUpdated: 'Données mises à jour avec succès',
		pendingDescription:
			'Ce mot de passe a été partagé avec vous. Acceptez pour y accéder ou refusez pour le rejeter.',
		fetchError: 'Erreur lors de la récupération des données',
		passwordAccepted: 'Mot de passe accepté avec succès',
		acceptError: "Erreur lors de l'acceptation du mot de passe",
		passwordRejected: 'Mot de passe rejeté avec succès',
		rejectError: 'Erreur lors du rejet du mot de passe',
		pending: 'En attente',
		accepted: 'Accepté',
		rejected: 'Rejeté',
		deleteShared: 'Supprimer ce partage',

		// Générateur de mot de passe
		passwordGenerator: 'Générateur de mot de passe',
		passwordLength: 'Longueur du mot de passe',
		includeUppercase: 'Inclure des majuscules (A-Z)',
		includeLowercase: 'Inclure des minuscules (a-z)',
		includeNumbers: 'Inclure des chiffres (0-9)',
		includeSymbols: 'Inclure des symboles (!@#$%^&*)',
		excludeSimilarChars: 'Exclure les caractères similaires (i, l, 1, L, o, 0, O)',
		generatePassword: 'Générer un mot de passe',
		resetOptions: 'Réinitialiser les options',
		showPasswordGenerator: 'Afficher le générateur de mot de passe',
		hidePasswordGenerator: 'Masquer le générateur de mot de passe',
		passwordStrengthVeryWeak: 'Très faible',
		passwordStrengthWeak: 'Faible',
		passwordStrengthMedium: 'Moyen',
		passwordStrengthStrong: 'Fort',
		passwordStrengthVeryStrong: 'Très fort',
		passwordStrength: 'Force du mot de passe',
		generate: 'Générer',
		reset: 'Réinitialiser',
		showGenerator: 'Afficher le générateur',
		hideGenerator: 'Masquer le générateur',
		uppercase: 'Majuscules',
		lowercase: 'Minuscules',
		numbers: 'Chiffres',
		symbols: 'Symboles',

		// Menu contextuel
		copyUsername: "Copier le nom d'utilisateur",
		copyPassword: 'Copier le mot de passe',
		copyToClipboard: 'Copier le code',
		edit: 'Modifier',

		// Audit des mots de passe
		auditPasswords: 'Audit des mots de passe',
		passwordAudit: 'Audit de sécurité des mots de passe',
		weakPasswords: 'Mots de passe faibles',
		reusedPasswords: 'Mots de passe réutilisés',
		oldPasswords: 'Mots de passe anciens',
		noWeakPasswords: 'Aucun mot de passe faible détecté',
		noReusedPasswords: 'Aucun mot de passe réutilisé détecté',
		noOldPasswords: 'Aucun mot de passe ancien détecté',
		passwordsStrength: 'Force des mots de passe',
		closeAudit: "Fermer l'audit",
		startAudit: 'Analyser les mots de passe',
		breachedPasswords: 'Mots de passe compromis',
		noBreachedPasswords: 'Aucun mot de passe compromis détecté',
		breachedPasswordsDescription:
			'Ces mots de passe ont été trouvés dans des fuites de données connues',
		overallScore: 'Score global de sécurité',
		excellent: 'Excellent',
		good: 'Bon',
		moderate: 'Moyen',
		poor: 'Faible',
		critical: 'Critique',
		outOf100: 'sur 100',
		checkingBreaches: 'Vérification des fuites de données...',
		passwordsToImprove: 'mots de passe à améliorer',
		totalPasswords: 'mots de passe au total',
		haveibeenpwnedError: 'Erreur lors de la vérification des fuites de données',
		scoreExplanation:
			'Ce score est calculé en fonction de la faiblesse, de la réutilisation et des compromissions de vos mots de passe.',

		// Navigation au clavier
		keyboardShortcuts: 'Raccourcis clavier',
		shortcutSearch: 'Rechercher',
		shortcutNew: 'Nouvel identifiant',
		shortcutExport: 'Exporter',
		shortcutImport: 'Importer',
		shortcutNavigate: 'Naviguer dans la liste',
		shortcutSelect: "Sélectionner l'identifiant",
		shortcutEscape: 'Fermer / Annuler',
		shortcutCopyUsername: "Copier le nom d'utilisateur",
		shortcutCopyPassword: 'Copier le mot de passe',
		shortcutCopyOtp: 'Copier le code OTP',
		shortcutHelp: "Afficher l'aide",
		shortcutVimNavigation: 'Navigation style Vim',
		shortcutGoToFirst: 'Aller au premier',
		shortcutGoToLast: 'Aller au dernier',

		// Autres traductions
		close: 'Fermer',
		other: 'Autres',
		toClose: 'pour fermer'
	},
	en: {
		// Main titles and buttons
		vault: 'Vault',
		logout: 'Logout',
		search: 'Search credentials...',
		language: 'Language',
		profile: 'Profile',

		// Formulaire d'ajout
		service: 'Service',
		url: 'URL',
		appId: 'App ID',
		description: 'Description',
		username: 'Username',
		password: 'Password',
		otpUri: 'OTP URI',
		urlPlaceholder: 'https://example.com',
		appIdPlaceholder: 'Application name or identifier',
		descriptionPlaceholder: 'Optional description',
		save: 'Save',
		cancel: 'Cancel',
		delete: 'Delete',

		// Messages
		noCredentials: 'No credentials saved. Click the + button to add one.',
		noSearchResults: 'No credentials match your search.',
		copiedToClipboard: 'Copied to clipboard',
		credentialUpdated: 'Credential updated successfully',
		credentialDeleted: 'Credential deleted successfully',
		credentialCreated: 'Credential created successfully',

		// Validation
		invalidUrl: 'Invalid URL format. Use formats like: google.com, osu.ppy.sh, 192.168.1.167:8181',
		requireUrlOrAppId: 'Please provide either a URL or an App ID',

		// 2FA
		twoFaCode: '2FA Code:',
		enableTwoFa: 'Enable 2FA',
		disableTwoFa: 'Disable 2FA',

		// Sharing
		shared: 'Shared',
		sharePassword: 'Share Password',
		shareDescription: 'Enter the email address of the user you want to share this password with.',
		email: 'Email',
		emailPlaceholder: 'example@email.com',
		alreadySharedWith: 'Already shared with:',
		share: 'Share',
		sharing: 'Sharing...',
		sharedBy: 'Shared by:',
		passwordShared: 'Password shared successfully',
		sharedByMe: 'Shared by me',
		sharedWithMe: 'Shared with me',
		// Importing
		importing: 'Importing',
		importedOf: 'of',
		passwordsImported: 'passwords imported',
		importSuccess: 'password(s) imported successfully',
		importFromJson: 'Import passwords from JSON or CSV file',
		invalidFileFormat: 'Invalid JSON file format',
		invalidCsvFormat: 'Invalid or unrecognized CSV file format (Chrome format expected)',
		clientNotInitialized: 'Client not initialized',
		importError: 'Error importing file',

		// Exporting
		exportPasswords: 'Export passwords',
		exportDescription: 'Choose the export format for your passwords.',
		exportFormat: 'Export format',
		export: 'Export',
		exportSuccess: 'Passwords exported successfully',
		exportError: 'Error during export',
		plainText: 'Plain text',
		noCredentialsToExport: 'No passwords to export',

		// Errors
		error: 'Error:',
		updateError: 'Error updating',
		deleteError: 'Error deleting',
		createError: 'Error creating',
		shareError: 'Error sharing',
		passwordEvalError: 'Error evaluating password',
		uuidConversionError: 'Error converting UUID',

		// Other specific messages
		invalidEmail: 'Please enter a valid email address',
		invalidUuid: 'Invalid UUID',
		userNotFound: 'User not found with email',
		invalidRecipientUuid: 'Invalid recipient UUID',
		unshareSuccess: 'Sharing canceled with',
		unshareError: 'Error unsharing',
		updateSuccess: 'Credential updated successfully',
		deleteSuccess: 'Credential deleted successfully',
		creationSuccess: 'Credential created successfully',
		creationError: 'Error creating credential',
		shareSuccess: 'Password shared successfully',
		sharedWith: 'Already shared with:',
		unshare: 'Cancel sharing',
		searchTip: "Tip: Use !s to see passwords shared with you, !m for those you've shared with.",
		accept: 'Accept',
		reject: 'Reject',
		// New translations
		dataUpdated: 'Data updated successfully',
		pendingDescription:
			'This password has been shared with you. Accept to access it or reject to decline.',
		fetchError: 'Error retrieving data',
		passwordAccepted: 'Password accepted successfully',
		acceptError: 'Error accepting password',
		passwordRejected: 'Password rejected successfully',
		rejectError: 'Error rejecting password',
		pending: 'Pending',
		accepted: 'Accepted',
		rejected: 'Rejected',
		deleteShared: 'Delete this share',

		// Password Generator
		passwordGenerator: 'Password Generator',
		passwordLength: 'Password Length',
		includeUppercase: 'Include Uppercase (A-Z)',
		includeLowercase: 'Include Lowercase (a-z)',
		includeNumbers: 'Include Numbers (0-9)',
		includeSymbols: 'Include Symbols (!@#$%^&*)',
		excludeSimilarChars: 'Exclude Similar Characters (i, l, 1, L, o, 0, O)',
		generatePassword: 'Generate Password',
		resetOptions: 'Reset Options',
		showPasswordGenerator: 'Show Password Generator',
		hidePasswordGenerator: 'Hide Password Generator',
		passwordStrengthVeryWeak: 'Very Weak',
		passwordStrengthWeak: 'Weak',
		passwordStrengthMedium: 'Medium',
		passwordStrengthStrong: 'Strong',
		passwordStrengthVeryStrong: 'Very Strong',
		passwordStrength: 'Password Strength',
		generate: 'Generate',
		reset: 'Reset',
		showGenerator: 'Show Generator',
		hideGenerator: 'Hide Generator',
		uppercase: 'Uppercase',
		lowercase: 'Lowercase',
		numbers: 'Numbers',
		symbols: 'Symbols',

		// Context menu
		copyUsername: 'Copy username',
		copyPassword: 'Copy password',
		copyToClipboard: 'Copy code',
		edit: 'Edit',

		// Password audit
		auditPasswords: 'Password Audit',
		passwordAudit: 'Password Security Audit',
		weakPasswords: 'Weak Passwords',
		reusedPasswords: 'Reused Passwords',
		oldPasswords: 'Old Passwords',
		noWeakPasswords: 'No weak passwords detected',
		noReusedPasswords: 'No reused passwords detected',
		noOldPasswords: 'No old passwords detected',
		passwordsStrength: 'Password Strength',
		closeAudit: 'Close Audit',
		startAudit: 'Analyze Passwords',
		breachedPasswords: 'Breached Passwords',
		noBreachedPasswords: 'No breached passwords detected',
		breachedPasswordsDescription: 'These passwords were found in known data breaches',
		overallScore: 'Overall Security Score',
		excellent: 'Excellent',
		good: 'Good',
		moderate: 'Moderate',
		poor: 'Poor',
		critical: 'Critical',
		outOf100: 'out of 100',
		checkingBreaches: 'Checking for data breaches...',
		passwordsToImprove: 'passwords to improve',
		totalPasswords: 'total passwords',
		haveibeenpwnedError: 'Error checking for data breaches',
		scoreExplanation:
			'This score is calculated based on the weakness, reuse, and compromises of your passwords.',

		// Keyboard navigation
		keyboardShortcuts: 'Keyboard shortcuts',
		shortcutSearch: 'Search',
		shortcutNew: 'New credential',
		shortcutExport: 'Export',
		shortcutImport: 'Import',
		shortcutNavigate: 'Navigate list',
		shortcutSelect: 'Select credential',
		shortcutEscape: 'Close / Cancel',
		shortcutCopyUsername: 'Copy username',
		shortcutCopyPassword: 'Copy password',
		shortcutCopyOtp: 'Copy OTP code',
		shortcutHelp: 'Show help',
		shortcutVimNavigation: 'Vim-style navigation',
		shortcutGoToFirst: 'Go to first',
		shortcutGoToLast: 'Go to last',

		// Other translations
		close: 'Close',
		other: 'Others',
		toClose: 'to close'
	}
};

// Fonction pour obtenir une traduction
export function t(key: string, lang: 'fr' | 'en'): string {
	const langData = translations[lang];
	return key.split('.').reduce((obj, i) => obj && obj[i], langData as any) || key;
}
