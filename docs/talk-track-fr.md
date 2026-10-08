# Talk track : de la vulnérabilité au poste corrigé (Exposure Management + Intune)

Durée : 8 à 10 minutes. Se place après l'acte « funnel de priorisation » du kit demo-exposure.
Public : non technique. Message clé : **Cortex décide quoi corriger en premier, Intune corrige, et tout est tracé dans un seul endroit.**

## Préparation (avant la séance)

- Simulateur déployé avec `--min-instances 1`, console ouverte dans un onglet : `<URL>/console`, bouton **Réinitialiser la démo** cliqué.
- XSIAM ouvert sur **Vulnerability Issues**, filtré sur le groupe `EM-demo-grp-Business-Corp`.
- L'issue **CVE-2024-38063 vulnerability at BSNS-WIN-ALICE** est **ouverte** : elle est souvent clôturée automatiquement par le playbook d'enrichissement générique du tenant, ou par une répétition. La passer en *Under Investigation* avant la séance (voir README, « Préparer le tenant avant la démo »). Alternative déjà ouverte : CVE-2023-42917 sur BSNS-MAC-EMMA.
- Pendant la démo, rester sur l'onglet de l'issue et sur la CVE hero : les autres CVE du poste viennent d'un simulateur de scanner et ne sont pas toutes cohérentes avec l'OS.
- Deux onglets côte à côte : XSIAM à gauche, console Intune à droite.

## 1. Le constat (1 min)

> « Vous l'avez vu : sur des centaines de vulnérabilités, Cortex en a retenu une poignée qui comptent vraiment. Prenons-en une. Le poste d'Alice, à la comptabilité, est exposé à une faille Windows critique, notée 9,8 sur 10, qui permet une prise de contrôle à distance. »

Montrer dans l'issue : la CVE, le score, l'asset, et le champ des correctifs : **Cortex sait déjà quel correctif Microsoft installer** (KB5041580 pour ce poste Windows 10).

> « Aujourd'hui, chez vous, que se passe-t-il ? Quelqu'un exporte la liste, ouvre la console Intune, cherche le poste, l'ajoute au bon groupe, et relance le suivi. Plusieurs jours, plusieurs outils, aucune traçabilité côté sécurité. »

## 2. Un clic pour lancer la remédiation (1 min)

Lancer le playbook **EM - Intune Patch Remediation** sur l'issue.

> « Je ne vais pas coder, je ne vais pas changer d'outil. Je demande à Cortex de traiter cette vulnérabilité. »

Ouvrir le **Work Plan** et commenter les premières étapes au fil de l'eau :
- Cortex identifie le poste et la vulnérabilité.
- Cortex vérifie que le poste est bien géré par Intune.
- Cortex prépare un résumé : poste, utilisateur, version actuelle, correctif.

## 3. L'humain garde la main (1 min)

Le playbook s'arrête sur **« Approuver le déploiement du correctif via Intune ? »**

> « Rien ne part sur le poste d'un collaborateur sans validation. Vous décidez du niveau d'automatisation : aujourd'hui une validation à chaque fois, demain une validation uniquement pour les postes sensibles, et automatique pour le reste. »

Répondre **Oui**.

## 4. Intune fait le travail (3 min)

Basculer sur la console Intune, et laisser le journal d'activité parler :

1. *Cortex XSIAM* : ajout du poste au groupe de remédiation Windows.
2. *Intune* : la stratégie de mise à jour accélérée est assignée.
3. *Cortex XSIAM* : synchronisation forcée du poste.
4. *Appareil* : téléchargement, installation, redémarrage.
5. *Intune* : mise à jour installée, **le poste passe de « Non conforme » à « Conforme »**.

> « Cortex ne remplace pas Intune. Il s'appuie sur vos stratégies existantes, vos anneaux de déploiement, vos règles de redémarrage. Il fait simplement en sorte que le bon poste reçoive le bon correctif au bon moment, sans ticket ni ressaisie. »

Pendant l'attente (environ 2 minutes), montrer les autres postes de la console : la majorité du parc est déjà conforme, seuls les postes signalés par Cortex sont en action.

## 5. La boucle est fermée (1 min)

Revenir sur l'issue dans XSIAM : elle est **clôturée**, avec la note de remédiation : CVE corrigée, version avant / après, poste conforme, durée.

> « Pour votre RSSI et pour l'audit : qui a décidé, quand, quel correctif, et la preuve que le poste est corrigé. Tout est dans l'issue. Et le prochain scan de vulnérabilités viendra confirmer. »

## 6. Et les serveurs ? (1 min, optionnel)

Lancer le même playbook sur une issue de serveur (par exemple `srv-web-01.business.org`).

> « Un serveur n'est pas géré par Intune. Cortex le détecte et confie la remédiation à l'équipe propriétaire de l'asset. Même processus, même suivi, le bon outil pour chaque type d'asset. »

## Questions fréquentes

- **« Et si le correctif casse quelque chose ? »** Cortex utilise vos stratégies Intune : anneaux pilotes, report, redémarrage maîtrisé. Les postes critiques peuvent être exclus de toute automatisation.
- **« Faut-il un développement spécifique ? »** Non. L'intégration Microsoft Graph est standard dans Cortex. Il faut une application Entra ID avec les bons droits, et des groupes Intune déjà ciblés par vos stratégies de mise à jour.
- **« Peut-on le déclencher automatiquement ? »** Oui, avec une règle d'automatisation : par exemple, toutes les vulnérabilités critiques des postes utilisateurs, avec validation pour la direction et automatique pour le reste.
- **« Et les logiciels tiers (Chrome, 7-Zip...) ? »** Même principe : un groupe Intune par application à mettre à jour, ou un script de remédiation Intune lancé à la demande.
