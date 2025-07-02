# Tunnel TCP Sécurisé (Refactorisé)

Ce projet fournit un tunnel TCP robuste et prêt pour la production, chiffré en TLS. Il s'agit d'une version refactorisée et améliorée d'un tunnel initial plus simple, conçue pour la sécurité, la résilience et la facilité de gestion. Le client écoute localement les connexions TCP et transfère le trafic via un lien TLS chiffré vers le serveur. Le serveur déchiffre ensuite ce trafic et le redirige vers un service TCP cible prédéfini.

## Vue d'ensemble de l'architecture

Le système se compose de deux composants principaux : `client.py` et `server.py`.

```
+-----------------+      TCP      +-------------+      TLS      +-------------+      TCP      +----------------+
| Application     |<------------->| Tunnel      |<------------->| Tunnel      |<------------->| Service        |
| locale          | en clair      | Client      |  Chiffré      | Serveur     | en clair      | Cible          |
| (ex : navigateur| (localhost)   | (client.py) |  (m)TLS       | (server.py) | (hôte serveur)| (ex : web, BD) |
|  ou outil BD)   |               |             |  Tunnel       |             |               |                |
+-----------------+               +-------------+               +-------------+               +----------------+
                                   ^                                           ^
                                   | écoute sur port local                     | écoute sur port public
                                   | configuré (ex : 1080)                     | configuré (ex : 8443)
```

## Fonctionnalités principales

*   **Sécurité (TLS et Authentification) :**
    *   Authentification mutuelle TLS (mTLS) : le serveur vérifie le certificat client via une CA ; le client vérifie le certificat serveur.
    *   Forçage TLS 1.2 ou 1.3 (configurable, par défaut TLS 1.2).
    *   Vérification stricte du CN/SAN (le client vérifie le CN/SAN du serveur ; le serveur peut vérifier le CN/SAN du client si configuré).
    *   Timeout de la poignée de main TLS pour éviter les attaques DoS.
*   **Réseau & Résilience :**
    *   Transfert bidirectionnel des données TCP.
    *   Timeouts sur les opérations socket (connexion, handshake TLS, réception/envoi de données).
    *   Reconnexion automatique du client : si le client échoue à se connecter au serveur pour une connexion locale, il réessaie avec un backoff exponentiel.
*   **Expérience Développeur/DevOps :**
    *   Configuration via fichiers YAML (`client_config.yaml`, `server_config.yaml`).
    *   Logs structurés dans des fichiers avec rotation et niveaux configurables.
    *   Flags CLI `--verbose`/`--debug` pour surcharger le niveau de log.
    *   Dockerfiles pour client et serveur.
    *   `docker-compose.yml` pour des tests multi-conteneurs locaux faciles.
    *   Tests unitaires pour la logique principale (chargement config, utilitaires réseau, gestionnaires client/serveur).
    *   Script shell local (`scripts/test_tunnel.sh`) pour tests end-to-end via Docker Compose.
*   **Supervision :**
    *   Le serveur journalise le nombre de connexions actives.
    *   Le serveur journalise les statistiques par session (durée, octets envoyés/reçus) à la fin de chaque session.

## Structure du projet

```
.
├── certs/                   # (Créé par l'utilisateur) Certificats TLS
│   ├── ca.crt
│   ├── server.crt
│   ├── server.key
│   ├── client.crt
│   └── client.key
├── config/                  # Fichiers de configuration
│   ├── client_config.yaml   # (À créer à partir de l'exemple)
│   ├── client_config.yaml.example
│   ├── server_config.yaml   # (À créer à partir de l'exemple)
│   └── server_config.yaml.example
├── docker/                  # Fichiers Docker
│   ├── client.Dockerfile
│   ├── server.Dockerfile
│   └── docker-compose.yml
├── logs/                    # (Auto-créé) Fichiers de logs
│   ├── client/
│   └── server/
├── scripts/                 # Scripts d'aide et de test
│   └── test_tunnel.sh
├── src/                     # Code source
│   ├── common/              # Modules utilitaires partagés
│   │   ├── config_loader.py
│   │   ├── logging_setup.py
│   │   └── network_utils.py
│   ├── client.py            # Application client
│   └── server.py            # Application serveur
├── tests/                   # Tests unitaires
│   ├── __init__.py
│   ├── test_client.py
│   ├── test_server.py
│   ├── test_config_loader.py
│   └── test_network_utils.py
├── AGENTS.md                # Instructions pour agents IA
├── README.md                # Ce fichier
└── requirements.txt         # Dépendances Python
```

## Démarrage rapide

### 1. Prérequis
*   Python 3.7+
*   OpenSSL (pour générer les certificats)
*   Docker et Docker Compose (pour l'exécution et les tests en conteneur)
*   `PyYAML` (installer via `pip install -r requirements.txt`)

### 2. Génération des certificats TLS (auto-signés pour tests)

Vous aurez besoin d'une Autorité de Certification (CA), d'un certificat serveur signé par la CA, et d'un certificat client signé par la CA pour le mTLS.

Créez un dossier `certs` à la racine du projet : `mkdir certs && cd certs`

**a. Créer la CA :**
```bash
# Générer la clé privée de la CA
openssl genpkey -algorithm RSA -out ca.key -pkeyopt rsa_keygen_bits:2048
# Générer le certificat CA (auto-signé)
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=MyTestCA"
```

**b. Créer le certificat serveur :**
(Remplacez `your.server.com` par le vrai nom d'hôte ou IP utilisé par le client, ou `tunnel-server` pour Docker Compose).
```bash
SERVER_HOSTNAME="your.server.com" # Ou "tunnel-server" pour docker-compose
openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key server.key -out server.csr -subj "/CN=${SERVER_HOSTNAME}"
# Signer le certificat serveur avec la CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 360 -extfile <(printf "subjectAltName=DNS:${SERVER_HOSTNAME},DNS:localhost,IP:127.0.0.1")
```
*Note : `localhost` et `127.0.0.1` sont ajoutés aux SANs pour faciliter les tests locaux si le serveur tourne sur l'hôte.*

**c. Créer le certificat client :**
(Remplacez `your.client.id` par un identifiant adapté si vous utilisez `allowed_client_cns` côté serveur).
```bash
CLIENT_ID="your.client.id" # ex : "client1" ou "testclient.example.com"
openssl genpkey -algorithm RSA -out client.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key client.key -out client.csr -subj "/CN=${CLIENT_ID}"
# Signer le certificat client avec la CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAserial ca.srl -out client.crt -days 360
```
Après ces étapes, le dossier `certs/` doit contenir : `ca.crt`, `ca.key`, `ca.srl`, `server.crt`, `server.key`, `server.csr`, `client.crt`, `client.key`, `client.csr`. Les fichiers `.csr` et `ca.key` (après signature) ne sont pas strictement nécessaires pour l'exécution mais font partie du processus de génération.

### 3. Configuration

Copiez les fichiers de configuration exemple et personnalisez-les :
```bash
mkdir -p config logs/client logs/server
cp config/client_config.yaml.example config/client_config.yaml
cp config/server_config.yaml.example config/server_config.yaml
```

Éditez `config/client_config.yaml` et `config/server_config.yaml`.

**Paramètres clés à ajuster :**

*   **`client_config.yaml`** :
    *   `remote_server.host` : Nom d'hôte/IP du serveur. Pour Docker Compose, utilisez `tunnel-server`.
    *   `remote_server.port` : Port d'écoute du serveur (ex : `8443`).
    *   `remote_server.server_ca_cert` : Chemin vers le certificat CA (ex : `certs/ca.crt`).
    *   `tls.client_cert` : Chemin vers le certificat client (ex : `certs/client.crt`).
    *   `tls.client_key` : Chemin vers la clé privée du client (ex : `certs/client.key`).
    *   `logging.log_file` : ex : `logs/client.log`.
    *   Chemins pour Docker : en conteneur, les chemins doivent être relatifs à `/app` (ex : `/app/certs/ca.crt`), logs dans `/app/logs/client.log` si montés dans le volume log. Voir les exemples/commentaires dans `docker-compose.yml`.

*   **`server_config.yaml`** :
    *   `server_listener.host` : Typiquement `0.0.0.0` pour écouter sur toutes les interfaces.
    *   `server_listener.port` : Port d'écoute du serveur (ex : `8443`).
    *   `target_service.host` : Nom d'hôte/IP du service cible. Pour Docker Compose, utilisez `echo-server`.
    *   `target_service.port` : Port du service cible (ex : `8080` pour le serveur echo de test).
    *   `tls.server_cert` : Chemin vers le certificat serveur (ex : `certs/server.crt`).
    *   `tls.server_key` : Chemin vers la clé privée du serveur (ex : `certs/server.key`).
    *   `tls.client_ca_cert` : Chemin vers le certificat CA pour la vérification mTLS (ex : `certs/ca.crt`). Si vide, mTLS désactivé (le serveur ne demandera pas de certificat client).
    *   `tls.allowed_client_cns` : (Optionnel) Liste des CN/SAN autorisés pour les clients si mTLS actif et liste renseignée.
    *   `logging.log_file` : ex : `logs/server.log`.
    *   Chemins pour Docker : idem client, adaptez pour `/app/certs/...` et `/app/logs/server.log`.

**Exemple de configuration pour Docker Compose :**

Voir les commentaires dans `docker-compose.yml` pour les valeurs à utiliser dans les fichiers YAML lors de l'utilisation de Docker :
*   `remote_server.host` du client : `tunnel-server`
*   `target_service.host` du serveur : `echo-server`
*   Tous les chemins de certificats dans les YAML : `certs/ca.crt` (montés dans `/app/certs/ca.crt` dans le conteneur)
*   Chemins de logs : `logs/client.log` (montés dans `/app/logs/client.log`)

### 4. Exécution de l'application

**a. Avec Docker Compose (recommandé pour tests) :**

C'est la méthode la plus simple pour tester l'ensemble, y compris le mTLS.
1.  Générez les certificats dans `./certs/`.
2.  Vérifiez que `config/client_config.yaml` et `config/server_config.yaml` sont créés et pointent vers les bons services (ex : `tunnel-server`, `echo-server`) et chemins cert/log en conteneur (ex : `certs/ca.crt`, `logs/client.log`).
3.  Créez les dossiers de logs : `mkdir -p logs/client logs/server` (Docker peut aussi les créer, mais c'est conseillé).

```bash
# Démarrer les services en mode détaché
docker-compose up --build -d

# Voir les logs
docker-compose logs -f tunnel-client
docker-compose logs -f tunnel-server
docker-compose logs -f echo-server

# Tester avec le script
bash scripts/test_tunnel.sh

# Arrêter les services
docker-compose down -v
```

**b. Exécution manuelle (Python directement) :**

1.  Installez les dépendances : `pip install -r requirements.txt`
2.  Vérifiez que les certificats sont générés et que les fichiers de configuration sont adaptés à votre environnement (ex : `remote_server.host` pointant vers l'IP réelle du serveur si pas en localhost).

    **Démarrer le serveur :**
    ```bash
    python src/server.py --config config/server_config.yaml
    # Pour logs verbeux :
    # python src/server.py --config config/server_config.yaml --verbose
    ```

    **Démarrer le client :**
    (Dans un autre terminal)
    ```bash
    python src/client.py --config config/client_config.yaml
    # Pour logs verbeux :
    # python src/client.py --config config/client_config.yaml --verbose
    ```
3.  Testez en envoyant du trafic vers le port d'écoute du client (ex : `localhost:1080` si configuré). Par exemple, si le serveur redirige vers un serveur web sur `target-host:80` :
    ```bash
    curl http://localhost:1080
    ```

### 5. Lancer les tests unitaires

Placez-vous à la racine du projet.
```bash
python -m unittest discover -s tests -v
```
Cela détectera et exécutera tous les tests du dossier `tests`.

### 6. Script de test end-to-end

Le script `scripts/test_tunnel.sh` automatise les tests via Docker Compose :
1.  Démarre les services `docker-compose` (client, serveur, echo-server).
2.  Attend leur initialisation.
3.  Envoie un message de test via `netcat` à `localhost:1080` (port du client).
4.  Vérifie si la réponse écho correspond au message envoyé.
5.  Affiche succès ou échec.

Assurez-vous que vos fichiers `config/*.yaml` sont adaptés à l'environnement Docker Compose (noms de services comme hôtes, chemins `/app/certs`).
```bash
bash scripts/test_tunnel.sh
```
Pour nettoyer automatiquement les conteneurs Docker après le script, décommentez `trap cleanup EXIT` en haut de `test_tunnel.sh`.

## Développement

*   **Style de code** : Suivre PEP 8. Utilisez un linter comme Flake8.
*   **Type Hinting** : Utilisé dans tout le code.
*   **Logging** : Utilisez le module `logging`. Voir `src/common/logging_setup.py`.
*   **Tests** : Ajoutez des tests unitaires pour toute nouvelle fonctionnalité dans `tests/`. Maintenez le script de test end-to-end.

## Licence

Licence MIT (supposée depuis le projet original, à confirmer ou modifier).
Ce projet a été refactorisé et amélioré à partir d'une version initiale.
