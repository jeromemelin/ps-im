/**
 * Orchestrateur JavaScript Client
 * Télécharge et exécute le script PowerShell cloudflare_deploy.ps1
 * Compatible avec le navigateur et Netlify
 */

class CloudflareOrchestrator {
    constructor() {
        this.psUrl = 'https://raw.githubusercontent.com/jeromemelin/ps-im/refs/heads/main/cloudflare_deploy.ps1';
        this.launcherUrl = 'https://raw.githubusercontent.com/jeromemelin/CloudflarePSinfo/main/launcher.js';
        this.tempDir = null;
        this.logs = [];
    }

    /**
     * Enregistre un message de log
     */
    log(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = `[${timestamp}] [${type.toUpperCase()}] ${message}`;
        this.logs.push(logEntry);
        console.log(logEntry);
    }

    /**
     * Télécharge un fichier depuis une URL
     */
    async downloadFile(url, filename) {
        try {
            this.log(`Téléchargement de ${filename}...`, 'info');
            
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const blob = await response.blob();
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(link.href);

            this.log(`${filename} téléchargé avec succès (${blob.size} bytes)`, 'success');
            return blob;
        } catch (error) {
            this.log(`Erreur lors du téléchargement de ${filename}: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Télécharge le script PowerShell
     */
    async downloadPowerShell() {
        try {
            this.log('Étape 1: Téléchargement du script PowerShell...', 'info');
            await this.downloadFile(this.psUrl, 'cloudflare_deploy.ps1');
            this.log('Script PowerShell téléchargé', 'success');
            return true;
        } catch (error) {
            this.log(`Impossible de télécharger le PowerShell: ${error.message}`, 'error');
            return false;
        }
    }

    /**
     * Télécharge le launcher JScript
     */
    async downloadLauncher() {
        try {
            this.log('Étape 2: Téléchargement du launcher...', 'info');
            await this.downloadFile(this.launcherUrl, 'launcher.js');
            this.log('Launcher téléchargé', 'success');
            return true;
        } catch (error) {
            this.log(`Impossible de télécharger le launcher: ${error.message}`, 'error');
            return false;
        }
    }

    /**
     * Exécute l'orchestration complète
     */
    async execute() {
        try {
            this.log('=== Démarrage de l\'orchestration Cloudflare ===', 'info');
            
            // Étape 1: Télécharger le PowerShell
            const psDone = await this.downloadPowerShell();
            if (!psDone) {
                throw new Error('Impossible de télécharger le PowerShell');
            }

            // Étape 2: Télécharger le launcher
            const launcherDone = await this.downloadLauncher();
            if (!launcherDone) {
                this.log('Avertissement: Launcher non disponible, le PowerShell devra être exécuté manuellement', 'warning');
            }

            this.log('=== Orchestration terminée avec succès ===', 'success');
            this.log(`Total: 2 fichiers téléchargés`, 'success');
            
            return {
                success: true,
                filesDownloaded: 2,
                logs: this.logs
            };

        } catch (error) {
            this.log(`Erreur critique: ${error.message}`, 'error');
            return {
                success: false,
                error: error.message,
                logs: this.logs
            };
        }
    }

    /**
     * Affiche les logs dans la console
     */
    displayLogs() {
        console.group('📋 Logs d\'Orchestration');
        this.logs.forEach(log => console.log(log));
        console.groupEnd();
    }
}

// Export pour utilisation
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CloudflareOrchestrator;
}
