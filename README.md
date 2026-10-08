# Intune (Microsoft Graph) Simulator

Démonstrateur **Cortex XSIAM Exposure Management → Microsoft Intune** : une vulnérabilité détectée sur un poste utilisateur est corrigée par un playbook XSIAM qui pilote Intune, sans avoir besoin d'un tenant Microsoft.

Le kit contient :

1. **Un simulateur de l'API Microsoft Graph** (Entra ID + Intune), à déployer sur Cloud Run, avec une **console web façon Intune** pour montrer le résultat au client en direct.
2. **Une intégration XSIAM « Intune (Demo) »** qui expose la même commande que l'intégration officielle *Microsoft Graph API* (`msgraph-api-request`, mêmes arguments, même contexte `MicrosoftGraph`).
3. **Un playbook « EM - Intune Patch Remediation »** volontairement épuré (5 étapes, une seule décision) et trois automatisations qui portent la plomberie Graph.

Le playbook ne dépend que de `msgraph-api-request`. Pour passer en production, il suffit de configurer l'intégration officielle *Microsoft Graph API* et de désactiver « Intune (Demo) » : **le playbook ne change pas**.

Basé sur [xsiam-simulator-template](https://github.com/JCourtemanche/xsiam-simulator-template) et [xsiam-shared-personas](https://github.com/JCourtemanche/xsiam-shared-personas), avec les mêmes personas Business Corp que les autres simulateurs. Ce kit complète le kit [demo-exposure](https://github.com/JCourtemanche/demo-exposure).

## Le scénario

Le playbook tient en 5 étapes métier et une seule décision, pour rester lisible par un public non technique :

```
1. Identifier le poste et la vulnérabilité ──> 2. Valider le déploiement du correctif ? ──Non──> Done
                                                     │ Oui
                                              3. Déployer le correctif via Intune
                                              4. Suivre l'installation sur le poste
                                              5. Clôturer l'issue ──> Done
```

Ce que fait chaque étape côté Intune (simulé) :

| Étape | Automatisation | Appels Microsoft Graph |
|---|---|---|
| 1. Identifier le poste et la vulnérabilité | `EMIntuneIdentifyDevice` | lit l'issue (poste, CVE, KB) puis `GET managedDevices?$filter=deviceName eq '...'` |
| 2. Valider le déploiement du correctif ? | tâche manuelle Oui / Non | aucun |
| 3. Déployer le correctif via Intune | `EMIntuneDeployPatch` | `GET groups`, `GET devices`, `POST groups/{id}/members/$ref`, `POST syncDevice` |
| 4. Suivre l'installation sur le poste | `EMIntuneWaitForPatch` | `GET managedDevices/{id}` jusqu'à osVersion 19045.4651 → 19045.4780 et poste conforme |
| 5. Clôturer l'issue | `closeInvestigation` | aucun |

C'est un démonstrateur : les cas d'erreur ne sont pas tous traités par des branches. Si le poste n'est pas géré par Intune (un serveur par exemple) ou si le correctif n'est pas confirmé dans le délai, la tâche concernée s'arrête en erreur avec un message explicite dans le War Room.

Principe : **XSIAM orchestre, Intune patche**. XSIAM ne pousse pas de binaire, il place le poste dans un groupe Entra ID déjà ciblé par une stratégie de mise à jour Intune (profil Windows *expedite*, stratégie de mise à jour macOS / iOS). C'est le fonctionnement le plus proche de la production : le client garde ses stratégies, ses anneaux et ses fenêtres de maintenance.

## Parc simulé

| Appareil | Utilisateur | OS | Version initiale (vulnérable) | Après correctif |
|---|---|---|---|---|
| BSNS-WIN-ALICE | Alice Dupont | Windows 10 22H2 | 10.0.19045.4651 (juillet 2024) | 10.0.19045.4780 (KB5041580) |
| BSNS-WIN-CHARLIE | Charlie Durant | Windows 11 23H2 | 10.0.22631.3880 | 10.0.22631.4037 (KB5041585) |
| BSNS-WIN-DAVID | David Lefebvre | Windows 10 22H2 | 10.0.19045.4651 | 10.0.19045.4780 (KB5041580) |
| BSNS-MAC-BOB | Bob Martin | macOS 13 Ventura | 13.6.1 | 13.6.3 |
| BSNS-MAC-EMMA | Emma Leroy | macOS 14 Sonoma | 14.1.1 | 14.1.2 |
| BSNS-MOB-FLORA | Flora Moreau | iOS 17 | 17.1.1 | 17.1.2 |

Ces versions correspondent aux correctifs que Cortex Vulnerability Intelligence remonte dans les issues (`xdmvulnerabilityfixversions`) : KB d'août 2024 pour CVE-2024-38063, 14.1.2 / 17.1.2 pour CVE-2023-42917 (WebKit).

Le parc contient aussi 24 appareils de remplissage déjà à jour. Les serveurs `srv-*.business.org` ne sont volontairement **pas** dans Intune : l'étape 1 s'arrête alors avec le message « not managed by Intune: remediation goes to the asset owner ».

Groupes de remédiation : `XSIAM-Remediation-Windows-Expedite`, `XSIAM-Remediation-macOS-Update`, `XSIAM-Remediation-iOS-Update`.

## Contrat API reproduit

- **Auth** : client credentials Entra ID, `POST /<tenant_id>/oauth2/v2.0/token`, puis `Authorization: Bearer <token>`
- **Format** : JSON Graph (`@odata.context`, `value`, erreurs `{"error": {"code", "message"}}`)
- **OData** : `$filter` (`eq`, `ne`, `startswith`, `and`), `$select`, `$top`
- **Préfixes** : `/v1.0/...` et `/beta/...`

| Méthode | Endpoint | Usage dans le playbook |
|---|---|---|
| POST | `/<tenant_id>/oauth2/v2.0/token` | Jeton (test de l'instance) |
| GET | `/v1.0/deviceManagement/managedDevices?$filter=deviceName eq '...'` | Trouver le poste |
| GET | `/v1.0/deviceManagement/managedDevices/<id>` | Suivre `osVersion` / `complianceState` |
| POST | `/v1.0/deviceManagement/managedDevices/<id>/syncDevice` | Forcer le check-in |
| GET | `/v1.0/devices?$filter=deviceId eq '<azureADDeviceId>'` | Objet Entra ID du poste |
| GET | `/v1.0/groups?$filter=displayName eq '...'` | Groupe de remédiation |
| GET | `/v1.0/groups/<id>/members` | (contrôle) |
| POST | `/v1.0/groups/<id>/members/$ref` | Ajouter le poste au groupe |
| DELETE | `/v1.0/groups/<id>/members/<object_id>/$ref` | (nettoyage) |
| GET | `/beta/deviceManagement/windowsQualityUpdateProfiles` | Profil Windows expedite (contrôle) |
| GET | `/console` | Console de démo (sans auth) |
| POST | `/console/api/reset` | Remise à zéro du parc |
| GET | `/health` | Health check (sans auth) |

Cycle d'un poste ajouté à un groupe de remédiation : *assigné, en attente de check-in* → *téléchargement* → *installation* → *redémarrage en attente* → *à jour*. Le check-in démarre au `syncDevice`, ou tout seul après `CHECKIN_FALLBACK_SECONDS`.

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `SIM_TENANT_ID` | `00000000-0000-0000-0000-000000000000` | Tenant ID factice |
| `SIM_CLIENT_ID` | `11111111-1111-1111-1111-111111111111` | Application (client) ID factice |
| `SIM_CLIENT_SECRET` | `change-me-intune-simulator-secret` | Secret de l'application (à changer) |
| `PATCH_DURATION_SECONDS` | `150` | Durée check-in → poste à jour |
| `CHECKIN_FALLBACK_SECONDS` | `300` | Check-in automatique sans `syncDevice` |
| `SYNC_ACTION_SECONDS` | `10` | Durée de l'action `syncDevice` (pending → done) |
| `FILLER_DEVICES` | `24` | Appareils de remplissage |

**Important : le parc est en mémoire.** Le conteneur tourne avec un seul worker gunicorn (`-w 1 --threads 8`) et le service Cloud Run doit avoir `--max-instances 1`. Avec plusieurs workers ou instances, chacun aurait son propre parc. Un redémarrage (cold start) remet le parc à zéro : le jour de la démo, déployer avec `--min-instances 1`.

## Lancer en local

```bash
cd simulator
pip install -r requirements.txt
python app.py            # http://localhost:8080/console
```

## Déployer sur Cloud Run

```bash
git clone https://github.com/JCourtemanche/intune-simul.git && cd intune-simul
cp .env.example .env              # renseigner SIM_* et GCP_* (optionnel, sinon valeurs par défaut)
bash deploy-cloudrun.sh           # le jour de la démo : MIN_INSTANCES=1 bash deploy-cloudrun.sh
```

Le script lit `.env` s'il existe, construit l'image (Artifact Registry `intune-simulator`) et déploie le service avec `--max-instances 1`.

**Le script ne configure pas l'accès au service Cloud Run** (qui peut l'invoquer) : à régler à la main selon la politique du projet GCP. Le service doit être joignable depuis XSIAM ; l'authentification applicative est faite par le simulateur via le secret client.

## Côté XSIAM

Le contenu importable est généré dans `xsiam/dist/` par `python xsiam/build.py` (les sources sont dans `xsiam/integrations`, `xsiam/scripts`, et le playbook est décrit dans `build.py`).

Ordre d'import :

1. **Intégration** `xsiam/dist/integration-IntuneDemo.yml` (Settings → Data Sources & Integrations → importer une intégration custom), puis créer une instance :
   - Server URL : URL Cloud Run du simulateur
   - Tenant ID / Application ID / Application Secret : `SIM_TENANT_ID` / `SIM_CLIENT_ID` / `SIM_CLIENT_SECRET`
   - Test : doit répondre `ok`
2. **Automatisations** `automation-EMIntuneIdentifyDevice.yml`, `automation-EMIntuneDeployPatch.yml` et `automation-EMIntuneWaitForPatch.yml` (Scripts → Import).
3. **Playbook** `playbook-EM_-_Intune_Patch_Remediation.yml` (Playbooks → Import).

Dépendances déjà présentes sur un tenant XSIAM : script `DeleteContext`, commande `closeInvestigation`.

Les fichiers de `xsiam/dist/` sont assemblés comme le ferait `demisto-sdk unify` : les imports de développement (`demistomock`, `CommonServerPython`) sont retirés, la plateforme les injecte elle-même. Les importer depuis les sources (`xsiam/integrations`, `xsiam/scripts`) provoque `ModuleNotFoundError: No module named 'demistomock'`.

Si l'intégration officielle *Microsoft Graph API* est aussi configurée sur le tenant, les tâches `msgraph-api-request` s'exécuteraient sur les deux instances : n'en garder qu'une active.

### Préparer le tenant avant la démo

**Les issues de vulnérabilité sont souvent déjà fermées.** Sur un tenant où une règle d'automatisation exécute le playbook générique *Posture Issues Entity Enrichment - Generic v3*, chaque issue de vulnérabilité est enrichie puis clôturée automatiquement (note « Enriched and closed »). Or un playbook ne peut être lancé que sur une issue **ouverte** (`setPlaybook` renvoie sinon `reopen_inv_id`).

Avant la démo :

1. Ouvrir l'issue hero et **la rouvrir** : changer son statut en *Under Investigation*. Si `setPlaybook` répond encore `reopen_inv_id`, attendre quelques secondes et relancer.
2. Ou choisir une issue crédible encore ouverte, par exemple **CVE-2023-42917 vulnerability at BSNS-MAC-EMMA** (WebKit, macOS 14.1.1 → 14.1.2). Le playbook utilise alors le groupe `XSIAM-Remediation-macOS-Update`.
3. Après une répétition, l'issue est clôturée par le playbook : la rouvrir de la même façon et cliquer **Réinitialiser la démo** dans la console du simulateur.

Paires issue / poste crédibles pour ce scénario (les autres CVE des postes Business Corp sont attribuées au hasard par le simulateur Rapid7 et ne correspondent pas toujours à l'OS) :

| Issue | Plateforme | Groupe de remédiation |
|---|---|---|
| CVE-2024-38063 at BSNS-WIN-ALICE / CHARLIE / DAVID | Windows (KB d'août 2024) | XSIAM-Remediation-Windows-Expedite |
| CVE-2023-42917 at BSNS-MAC-EMMA | macOS | XSIAM-Remediation-macOS-Update |
| CVE-2023-42917 at BSNS-MOB-FLORA | iOS | XSIAM-Remediation-iOS-Update |

### Lancer la démo

1. Ouvrir la console du simulateur (`<URL>/console`), cliquer **Réinitialiser la démo**.
2. Dans XSIAM, ouvrir l'issue **CVE-2024-38063 vulnerability at BSNS-WIN-ALICE** (Vulnerability Issues, filtre sur le groupe `EM-demo-grp-Business-Corp`), rouverte comme indiqué ci-dessus.
3. Exécuter le playbook **EM - Intune Patch Remediation** sur l'issue (War Room : `!setPlaybook name="EM - Intune Patch Remediation"`, ou depuis l'onglet Resolution / Work Plan).
4. Dans le Work Plan, répondre **Oui** à « 2. Valider le déploiement du correctif ? ».
5. Montrer la console Intune : ajout au groupe, check-in, téléchargement, installation, poste conforme (environ 2 min 30 avec la valeur par défaut).
6. Revenir sur l'issue : clôturée avec la note de remédiation (versions avant / après).

Pour montrer qu'un serveur n'est pas traité par Intune, lancer le même playbook sur une issue de serveur (ex. `srv-web-01.business.org`) : l'étape 1 s'arrête avec un message explicite.

### Dépannage

| Symptôme | Cause probable | Action |
|---|---|---|
| `setPlaybook` répond `reopen_inv_id` | Issue fermée | La rouvrir (statut *Under Investigation*), patienter quelques secondes, relancer |
| Test de l'instance « Intune (Demo) » en échec `AADSTS7000215` | Secret différent de `SIM_CLIENT_SECRET` | Aligner le secret de l'instance sur la variable du service Cloud Run |
| Test de l'instance en échec réseau / 403 | Accès au service Cloud Run non ouvert à XSIAM | Revoir l'accès au service côté GCP |
| `ModuleNotFoundError: No module named 'demistomock'` | Intégration ou script importé depuis les sources | Importer les fichiers de `xsiam/dist/` (régénérés par `python xsiam/build.py`) |
| Étape 1 en erreur « No hostname found » | Nom d'issue inattendu | Le hostname est lu dans le nom de l'issue (`... vulnerability at <HOST>`) ; il peut être passé en argument `hostname` |
| Étape 1 en erreur « not managed by Intune » sur un poste | Le nom du poste ne correspond à aucun appareil du simulateur | Vérifier le hostname (`BSNS-WIN-ALICE`…) dans la console |
| Tâches `msgraph-api-request` exécutées deux fois | Intégration officielle Graph API aussi active | Désactiver l'une des deux instances |
| Console revenue à l'état initial en pleine démo | Cold start Cloud Run | Déployer avec `MIN_INSTANCES=1` |
| Étape 4 en erreur « Fix not confirmed » | `PatchTimeoutSeconds` inférieur à `PATCH_DURATION_SECONDS` + check-in | Augmenter l'entrée du playbook ou réduire `PATCH_DURATION_SECONDS` |

### Passage en production

- Créer une app registration Entra ID (client credentials) avec les permissions Graph *Application* : `DeviceManagementManagedDevices.Read.All`, `DeviceManagementManagedDevices.PrivilegedOperations.All` (syncDevice), `Device.Read.All`, `GroupMember.ReadWrite.All`.
- Créer les trois groupes Entra ID et les cibler dans Intune par les stratégies de mise à jour (profil *Windows quality update* en mode expedite, stratégies de mise à jour Apple).
- Configurer l'intégration officielle **Microsoft Graph API** (self-deployed, Tenant ID, Application ID, secret) et désactiver « Intune (Demo) ».
- Ajouter une règle d'automatisation (Investigation & Response → Automation → Automation Rules) sur les issues de vulnérabilité des postes, placée **avant** la règle qui exécute le playbook d'enrichissement générique (seule la première règle correspondante s'exécute).
- Protéger les postes critiques via l'Automation Exclusion Center ou un asset group exclu du filtre de la règle.

## Structure

```
intune-simul/
├── simulator/
│   ├── app.py, config.py, auth.py, state.py   # Flask, auth Entra ID, parc + moteur de patch
│   ├── generators/fleet.py                    # parc déterministe (personas + remplissage)
│   ├── routes/oauth.py, graph.py, console.py  # token, Graph, console de démo
│   └── templates/console.html                 # console façon Intune admin center
├── xsiam/
│   ├── integrations/IntuneDemo/               # intégration Intune (Demo)
│   ├── scripts/EMIntuneIdentifyDevice/        # étape 1 : issue (poste, CVE, KB) + poste Intune
│   ├── scripts/EMIntuneDeployPatch/           # étape 3 : groupe de remédiation + synchronisation
│   ├── scripts/EMIntuneWaitForPatch/          # étape 4 : suivi de l'installation
│   ├── build.py                               # génère xsiam/dist/ (dont le playbook)
│   └── dist/                                  # fichiers à importer dans XSIAM
├── docs/talk-track-fr.md                      # déroulé de démo
├── deployment/Dockerfile, app.yaml
├── cloudbuild.yaml
└── deploy-cloudrun.sh                         # build + déploiement Cloud Run (accès au service : manuel)
```
