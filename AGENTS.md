# Instructions pour les agents – Projet de Tunnel TCP Sécurisé

Bienvenue, agent ! Ce fichier contient les directives et conventions à suivre lors du travail sur ce projet.

## 1. Style de code & conventions

*   **Python :** Suivez les recommandations PEP 8. Utilisez un linter comme Flake8 ou Black si possible.
*   **Annotations de type :** Utilisez les annotations de type pour toutes les signatures de fonctions et les variables critiques.
*   **Journalisation :**
    *   Utilisez le module standard `logging`.
    *   Les messages de log doivent être clairs et informatifs.
    *   Utilisez les niveaux de log appropriés (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    *   Évitez les instructions print pour la journalisation ; utilisez le framework logging.
*   **Gestion des erreurs :**
    *   Gérez les exceptions de manière élégante.
    *   Fournissez du contexte dans les messages d’erreur.
    *   Évitez de capturer l’exception générique `Exception` ; ciblez des exceptions spécifiques.
*   **Modularité :**
    *   Privilégiez des fonctions et classes petites et ciblées.
    *   Les utilitaires partagés doivent aller dans le dossier `src/common/`.
*   **Configuration :**
    *   Tous les paramètres configurables doivent être gérés via des fichiers de configuration YAML. Évitez de coder en dur des valeurs susceptibles de changer.

## 2. Implémentation TLS/SSL

*   **Sécurité avant tout :** Privilégiez des paramètres sécurisés par défaut.
*   **Versions TLS explicites :** Lors de la configuration de `SSLContext`, désactivez explicitement les protocoles non sécurisés (SSLv3, TLSv1.0, TLSv1.1) et définissez la version minimale sur TLS 1.2.
*   **Validation des certificats :**
    *   Validez toujours les certificats pairs en mTLS.
    *   Effectuez une validation rigoureuse du nom d’hôte/CN/SAN.
*   **Messages d’erreur :** Les erreurs liées à TLS doivent être journalisées avec suffisamment de détails pour faciliter le diagnostic (ex : erreurs de vérification de certificat, échecs de handshake).

## 3. Tests

*   **Tests unitaires :** Écrivez des tests unitaires pour toute nouvelle fonctionnalité, en particulier pour la logique dans `src/common/` et la gestion des connexions principales.
    *   Utilisez les frameworks `unittest` ou `pytest`.
    *   Utilisez largement les mocks (`unittest.mock`) pour isoler les unités de code, notamment pour les opérations réseau et les interactions SSL/TLS.
*   **Tests d’intégration :** Le script `scripts/test_tunnel.sh` (ou équivalent) doit être maintenu pour garantir le bon fonctionnement de bout en bout.

## 4. Docker

*   Les Dockerfiles doivent rester minimalistes et efficaces.
*   Utilisez les builds multi-étapes si cela réduit significativement la taille de l’image.
*   Assurez-vous que `docker-compose.yml` est à jour pour faciliter les tests locaux.

## 5. Commits et Pull Requests (si applicable)

*   Suivez les formats de messages de commit conventionnels si le projet les adopte.
*   Vérifiez que le code est formaté et linté avant de committer.
*   Vérifiez que tous les tests passent.

## 6. Respect du plan

*   Suivez le plan établi. Si des écarts sont nécessaires, mettez à jour le plan via `set_plan` et informez l’utilisateur.
*   Marquez les étapes du plan comme complètes avec `plan_step_complete()`.

## 7. Dépendances

*   Ajoutez les nouvelles dépendances dans `requirements.txt`.
*   Privilégiez les bibliothèques bien maintenues et réputées.

En suivant ces directives, nous assurons la maintenabilité, la sécurité et la robustesse du projet. Merci !
