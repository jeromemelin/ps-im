/**
 * Script orchestrateur principal
 * Télécharge et exécute 5 scripts PowerShell dans l'ordre
 * Compatible Windows
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

// Configuration des scripts à télécharger et exécuter
const scripts = [
    {
        name: 'script1.ps1',
        url: 'https://raw.githubusercontent.com/votre-repo/scripts/main/script1.ps1',
        description: 'Script d\'initialisation'
    },
    {
        name: 'script2.ps1',
        url: 'https://raw.githubusercontent.com/votre-repo/scripts/main/script2.ps1',
        description: 'Script de configuration'
    },
    {
        name: 'script3.ps1',
        url: 'https://raw.githubusercontent.com/votre-repo/scripts/main/script3.ps1',
        description: 'Script de traitement'
    },
    {
        name: 'script4.ps1',
        url: 'https://raw.githubusercontent.com/votre-repo/scripts/main/script4.ps1',
        description: 'Script de validation'
    },
    {
        name: 'script5.ps1',
        url: 'https://raw.githubusercontent.com/votre-repo/scripts/main/script5.ps1',
        description: 'Script de finalisation'
    }
];

// Dossier de destination pour les scripts téléchargés
const scriptsDir = path.join(__dirname, 'scripts');
const logsDir = path.join(__dirname, 'logs');

/**
 * Crée les dossiers nécessaires s'ils n'existent pas
 */
function ensureDirectories() {
    if (!fs.existsSync(scriptsDir)) {
        fs.mkdirSync(scriptsDir, { recursive: true });
        console.log(`✓ Dossier créé: ${scriptsDir}`);
    }
    if (!fs.existsSync(logsDir)) {
        fs.mkdirSync(logsDir, { recursive: true });
        console.log(`✓ Dossier créé: ${logsDir}`);
    }
}

/**
 * Télécharge un fichier depuis une URL
 */
function downloadFile(url, destination) {
    return new Promise((resolve, reject) => {
        const protocol = url.startsWith('https') ? https : http;
        const file = fs.createWriteStream(destination);
        
        protocol.get(url, (response) => {
            if (response.statusCode === 301 || response.statusCode === 302) {
                // Gestion des redirections
                return downloadFile(response.headers.location, destination)
                    .then(resolve)
                    .catch(reject);
            }
            
            if (response.statusCode !== 200) {
                reject(new Error(`Erreur HTTP: ${response.statusCode}`));
                return;
            }
            
            response.pipe(file);
            
            file.on('finish', () => {
                file.close();
                resolve();
            });
        }).on('error', (err) => {
            fs.unlink(destination, () => {});
            reject(err);
        });
    });
}

/**
 * Exécute un script PowerShell
 */
async function executePowerShellScript(scriptPath, scriptName) {
    const logFile = path.join(logsDir, `${scriptName}.log`);
    const timestamp = new Date().toISOString();
    
    console.log(`\n[${timestamp}] Exécution de ${scriptName}...`);
    
    try {
        // Commande PowerShell avec gestion des erreurs
        const command = `powershell.exe -ExecutionPolicy Bypass -File "${scriptPath}" 2>&1 | Tee-Object -FilePath "${logFile}"`;
        
        const { stdout, stderr } = await execAsync(command, {
            maxBuffer: 1024 * 1024 * 10, // 10MB buffer
            encoding: 'utf8'
        });
        
        if (stderr && !stderr.includes('Warning')) {
            throw new Error(stderr);
        }
        
        console.log(`✓ ${scriptName} exécuté avec succès`);
        console.log(`  Logs sauvegardés dans: ${logFile}`);
        
        return { success: true, output: stdout };
    } catch (error) {
        console.error(`✗ Erreur lors de l'exécution de ${scriptName}:`, error.message);
        fs.appendFileSync(logFile, `\n[ERROR] ${error.message}\n`);
        throw error;
    }
}

/**
 * Fonction principale
 */
async function main() {
    console.log('='.repeat(60));
    console.log('ORCHESTRATEUR DE SCRIPTS POWERSHELL');
    console.log('='.repeat(60));
    
    ensureDirectories();
    
    const results = [];
    
    try {
        // Téléchargement et exécution séquentielle des scripts
        for (let i = 0; i < scripts.length; i++) {
            const script = scripts[i];
            const scriptPath = path.join(scriptsDir, script.name);
            
            console.log(`\n[${i + 1}/${scripts.length}] ${script.description}`);
            console.log(`  URL: ${script.url}`);
            
            // Vérification si le script existe localement, sinon téléchargement
            if (fs.existsSync(scriptPath)) {
                console.log(`  ✓ Script local trouvé: ${scriptPath}`);
            } else {
                // Téléchargement depuis l'URL
                try {
                    console.log(`  Téléchargement en cours depuis ${script.url}...`);
                    await downloadFile(script.url, scriptPath);
                    console.log(`  ✓ Téléchargé: ${scriptPath}`);
                } catch (error) {
                    throw new Error(`Impossible de télécharger ${script.name} et script local introuvable: ${error.message}`);
                }
            }
            
            // Exécution
            const result = await executePowerShellScript(scriptPath, script.name);
            results.push({
                script: script.name,
                success: result.success,
                description: script.description
            });
            
            // Pause entre les scripts (optionnel)
            if (i < scripts.length - 1) {
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }
        
        // Résumé final
        console.log('\n' + '='.repeat(60));
        console.log('RÉSUMÉ DE L\'EXÉCUTION');
        console.log('='.repeat(60));
        
        results.forEach((result, index) => {
            const status = result.success ? '✓' : '✗';
            console.log(`${status} [${index + 1}] ${result.script} - ${result.description}`);
        });
        
        const successCount = results.filter(r => r.success).length;
        console.log(`\nTotal: ${successCount}/${scripts.length} scripts exécutés avec succès`);
        
        if (successCount === scripts.length) {
            console.log('\n✓ Tous les scripts ont été exécutés avec succès!');
            process.exit(0);
        } else {
            console.log('\n⚠ Certains scripts ont échoué. Vérifiez les logs.');
            process.exit(1);
        }
        
    } catch (error) {
        console.error('\n✗ ERREUR CRITIQUE:', error.message);
        console.error(error.stack);
        process.exit(1);
    }
}

// Gestion des erreurs non capturées
process.on('unhandledRejection', (error) => {
    console.error('Erreur non gérée:', error);
    process.exit(1);
});

// Lancement du script principal
main();

