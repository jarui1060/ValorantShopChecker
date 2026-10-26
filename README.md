# Boutique VALORANT vers Discord

GitHub Actions consulte la boutique personnelle du compte Riot puis la publie
via un webhook Discord. Le PC peut rester éteint. Région : **Europe (eu)**.

## Configuration

Dans votre copie : **Settings → Secrets and variables → Actions**, ajouter :

| Repository secret | Valeur |
| --- | --- |
| RIOT_COOKIES | {"ssid":"VALEUR_COMPLETE_DU_COOKIE_RIOT"} |
| DISCORD_WEBHOOK_URL | L'adresse complète du webhook du salon Discord |

Le cookie doit venir de auth.riotgames.com. Ne jamais placer sa valeur ou le
webhook dans les fichiers du dépôt, une capture ou un message. Le mot de passe
Riot et un jeton personnel GitHub (GH_PAT) ne sont pas nécessaires.

## Premier lancement

Dans **Actions**, autoriser les workflows de cette copie si GitHub le demande.
Sélectionner **Valorant Store Check → Run workflow → master → Run workflow**.
Un succès affiche « Boutique récupérée ; message enregistré par Discord ».
La récupération réelle n'est confirmée qu'après ce premier succès.

Les modifications du programme sur master déclenchent également un passage.
Le workflow n'est jamais lancé sur une pull request d'un contributeur externe.

## Horaire

Passage prévu chaque jour à **00:17 UTC**, soit **01:17 en Belgique en hiver**
et **02:17 en été**. GitHub peut démarrer un passage avec du retard.
Dans un dépôt public, GitHub peut désactiver la planification après 60 jours
sans activité : vérifier alors Actions et réactiver le workflow.

## Session renouvelée

Riot peut renouveler ses cookies. Le checker conserve la session renouvelée
chiffrée avec Fernet dans le cache GitHub Actions. La clé est dérivée du ssid
initial déjà enregistré dans les secrets. Aucun cookie ne figure dans les
sorties du workflow, dans les messages Discord ou dans les fichiers du dépôt.
Aucun GH_PAT n'est utilisé ; un éventuel ancien secret de ce nom est ignoré.

Si Riot invalide la session, récupérer un nouveau ssid et remplacer
RIOT_COOKIES. Le nouveau secret réinitialise la sauvegarde chiffrée.
Le cache est temporaire : s'il disparaît, le checker réessaie le cookie initial
et peut demander une reconnexion.

## Tests sans connexion

    python -m pip install -r requirements.txt
    python -m unittest discover -s tests -v

## Limites

Outil communautaire non approuvé par Riot pour le suivi de boutique. Riot peut
changer ses interfaces ou refuser les connexions depuis GitHub. Le cookie donne
un accès sensible au compte, au-delà de la boutique. Sa validité dans un
navigateur ne garantit pas qu'il sera accepté par GitHub : le premier passage
sert à le vérifier.

Basé sur [Turtdle/ValorantShopChecker](https://github.com/Turtdle/ValorantShopChecker)
et les informations [ValorantClientAPI](https://github.com/HeyM1ke/ValorantClientAPI).
