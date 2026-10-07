# Intune (Microsoft Graph) Simulator

Démonstrateur **Cortex XSIAM Exposure Management → Microsoft Intune** : une vulnérabilité détectée sur un poste utilisateur est corrigée par un playbook XSIAM qui pilote Intune, sans avoir besoin d'un tenant Microsoft.

Le kit contient :

1. **Un simulateur de l'API Microsoft Graph** (Entra ID + Intune), à déployer sur Cloud Run, avec une **console web façon Intune** pour montrer le résultat au client en direct.
2. **Une intégration XSIAM « Intune (Demo) »** qui expose la même commande que l'intégration officielle *Microsoft Graph API* (`msgraph-api-request`, mêmes arguments, même contexte `MicrosoftGraph`).
3. **Un playbook « EM - Intune Patch Remediation »** et deux automatisations.

Le playbook ne dépend que de `msgraph-api-request`. Pour passer en production, il suffit de configurer l'intégration officielle *Microsoft Graph API* et de désactiver « Intune (Demo) » : **le playbook ne change pas**.

Basé sur [xsiam-simulator-template](https://github.com/JCourtemanche/xsiam-simulator-template) et [xsiam-shared-personas](https://github.com/JCourtemanche/xsiam-shared-personas), avec les mêmes personas Business Corp que les autres simulateurs. Ce kit complète le kit [demo-exposure](https://github.com/JCourtemanche/demo-exposure).

## Le scénario

```
Issue Exposure Management                 Playbook XSIAM                              Intune (simulé)
"CVE-2024-38063 vulnerability    ->  1. lit l'asset, la CVE, les KB correctifs
 at BSNS-WIN-ALICE"                  2. cherche le poste dans Intune          ->  GET managedDevices
                                     3. serveur ? -> remédiation par l'owner
                                     4. approbation de l'analyste
                                     5. ajoute le poste au groupe              ->  POST groups/{id}/members/$ref
                                        de remédiation (stratégie expedite)        (stratégie de mise à jour assignée)
                                     6. force la synchronisation               ->  POST syncDevice
                                     7. suit l'installation                    ->  osVersion 19045.4651 -> 19045.4780
                                     8. clôture l'issue avec une note              conformité : conforme
```

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

Le parc contient aussi 24 appareils de remplissage déjà à jour. Les serveurs `srv-*.business.org` ne sont volontairement **pas** dans Intune : le playbook montre alors la branche « asset hors Intune, remédiation par l'owner ».

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
2. **Automatisations** `automation-EMIntuneParseIssue.yml` et `automation-EMIntuneWaitForPatch.yml` (Scripts → Import).
3. **Playbook** `playbook-EM_-_Intune_Patch_Remediation.yml` (Playbooks → Import).

Dépendances déjà présentes sur un tenant XSIAM : `Cortex Core - IR` (`core-get-asset-details`), scripts `DeleteContext`, `Set`, `Print`, commande `closeInvestigation`.

Si l'intégration officielle *Microsoft Graph API* est aussi configurée sur le tenant, les tâches `msgraph-api-request` s'exécuteraient sur les deux instances : n'en garder qu'une active.

### Lancer la démo

1. Ouvrir la console du simulateur (`<URL>/console`), cliquer **Réinitialiser la démo**.
2. Dans XSIAM, ouvrir l'issue **CVE-2024-38063 vulnerability at BSNS-WIN-ALICE** (Vulnerability Issues, filtre sur le groupe `EM-demo-grp-Business-Corp`).
3. Exécuter le playbook **EM - Intune Patch Remediation** sur l'issue (War Room : `!setPlaybook name="EM - Intune Patch Remediation"`, ou depuis l'onglet Resolution / Work Plan).
4. Dans le Work Plan, répondre **Oui** à « Approuver le déploiement du correctif via Intune ? ».
5. Montrer la console Intune : ajout au groupe, check-in, téléchargement, installation, poste conforme (environ 2 min 30 avec la valeur par défaut).
6. Revenir sur l'issue : clôturée avec la note de remédiation (versions avant / après).

Pour montrer la branche « hors Intune », lancer le même playbook sur une issue d'un serveur (ex. `srv-web-01.business.org`).

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
│   ├── scripts/EMIntuneParseIssue/            # lecture de l'issue (hostname, CVE, KB)
│   ├── scripts/EMIntuneWaitForPatch/          # suivi de l'installation
│   ├── build.py                               # génère xsiam/dist/ (dont le playbook)
│   └── dist/                                  # fichiers à importer dans XSIAM
├── docs/talk-track-fr.md                      # déroulé de démo
├── deployment/Dockerfile, app.yaml
├── cloudbuild.yaml
└── deploy-cloudrun.sh                         # build + déploiement Cloud Run (accès au service : manuel)
```
