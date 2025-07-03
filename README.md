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
*   Python 3.9+ (le projet utilise des fonctionnalités de `python:3.9-slim` dans Docker)
*   Docker et Docker Compose (pour l'exécution du serveur en conteneur)
*   `PyYAML` et `cryptography` (installer via `pip install -r requirements.txt`)

### 2. Génération des certificats TLS

Ce projet inclut un script Python pour générer facilement les certificats auto-signés nécessaires pour les tests.

1.  Assurez-vous d'avoir installé les dépendances :
    ```bash
    pip install -r requirements.txt
    ```
2.  Créez un dossier `certs` à la racine du projet si ce n'est pas déjà fait : `mkdir -p certs`
3.  Exécutez le script de génération de certificats :
    ```bash
    python certs.py
    ```
    Cela créera les fichiers suivants dans le dossier `certs/` :
    *   `ca.crt`, `ca.key`: Autorité de Certification (CA)
    *   `server.crt`, `server.key`: Certificat et clé privée du serveur (CN=`tunnel-server`, avec SANs pour `localhost` et `127.0.0.1`)
    *   `client.crt`, `client.key`: Certificat et clé privée du client (CN=`client1`)

    Ces certificats sont configurés pour fonctionner avec les exemples et le `docker-compose.yml`.

**Alternative (Manuel avec OpenSSL) :**
Si vous préférez générer les certificats manuellement avec OpenSSL, vous pouvez suivre les étapes classiques. Assurez-vous que le CN du serveur correspond à ce que le client attendra (par exemple, `tunnel-server` pour les tests Docker, ou le nom d'hôte réel) et que les certificats client/serveur sont signés par la même CA. Le script `certs.py` est cependant la méthode recommandée pour ce projet.

### 3. Configuration

La configuration du client et du serveur se fait désormais via des fichiers `.env`. Des fichiers d'exemple (`.env.example`) sont fournis dans `client/config/` et `server/config/`.

1.  **Pour le client :** Copiez `client/config/.env.example` vers `client/config/.env` et personnalisez les valeurs.
2.  **Pour le serveur :** Copiez `server/config/.env.example` vers `server/config/.env` et personnalisez les valeurs.

```bash
mkdir -p client/config server/config logs/client logs/server # Créez les dossiers nécessaires

# Pour le client
cp client/config/.env.example client/config/.env
# Éditez client/config/.env

# Pour le serveur
cp server/config/.env.example server/config/.env
# Éditez server/config/.env
```

**Variables d'environnement clés (voir les fichiers `.env.example` pour la liste complète) :**

*   **Client (`client/config/.env`) :**
    *   `SHIELDNET_LOCAL_LISTENER_PORT`: Port d'écoute local du client (ex: `1080`).
    *   `SHIELDNET_REMOTE_SERVER_HOST`: Hôte du serveur ShieldNet (ex: `localhost`).
    *   `SHIELDNET_REMOTE_SERVER_PORT`: Port du serveur ShieldNet (ex: `8443`).
    *   `SHIELDNET_REMOTE_SERVER_CA_CERT`: Chemin vers `ca.crt` (ex: `certs/ca.crt`).
    *   `SHIELDNET_TLS_CLIENT_CERT`, `SHIELDNET_TLS_CLIENT_KEY`: Pour mTLS.
    *   `SHIELDNET_LOG_FILE`, `SHIELDNET_LOG_LEVEL`, etc. pour la journalisation.
    *   Divers `SHIELDNET_TIMEOUT_*` pour les timeouts.

*   **Serveur (`server/config/.env`) :**
    *   `SHIELDNET_SERVER_LISTENER_HOST`: Hôte d'écoute du serveur (ex: `0.0.0.0`).
    *   `SHIELDNET_SERVER_LISTENER_PORT`: Port d'écoute du serveur (ex: `8443`).
    *   `SHIELDNET_TLS_SERVER_CERT`, `SHIELDNET_TLS_SERVER_KEY`: Certificat et clé du serveur.
    *   `SHIELDNET_TLS_CLIENT_CA_CERT`: Pour mTLS (chemin vers `ca.crt`).
    *   `SHIELDNET_TLS_ALLOWED_CLIENT_CNS`: Pour mTLS (liste de CNs autorisés, séparés par des virgules).
    *   `SHIELDNET_TIMEOUT_TARGET_CONNECT`: Timeout pour la connexion à la cible dynamique.
    *   `SHIELDNET_LOG_FILE`, `SHIELDNET_LOG_LEVEL`, etc.

**Important pour les chemins (certificats, logs) :**
*   Lors de l'exécution locale, les chemins relatifs dans les fichiers `.env` (par exemple `certs/ca.crt`) sont généralement résolus par rapport au répertoire racine du projet (où se trouvent `client.py` et `server.py` ou leurs dossiers respectifs).
*   Pour Docker (serveur), les chemins spécifiés dans `server/config/.env` (comme `certs/server.crt`) seront résolus à l'intérieur du conteneur. Étant donné que `ENV_BASE_DIR` dans `server.py` est `/app` et que les volumes sont montés dans `/app` (par exemple, `./certs` est monté sur `/app/certs`), un chemin comme `certs/server.crt` dans le `.env` sera correctement trouvé à `/app/certs/server.crt`.

### 4. Architecture de Routage Dynamique

Avec le routage dynamique, le flux de données est le suivant :
1.  Une application locale se connecte au port d'écoute du **Client ShieldNet** (`local_listener.host`:`local_listener.port` dans `client_config.yaml`).
2.  Le **Client ShieldNet** est lancé avec des arguments `--target-host <host>` et `--target-port <port>` qui spécifient la destination finale.
3.  Le Client établit une connexion TLS avec le **Serveur ShieldNet**.
4.  Immédiatement après la poignée de main TLS, le Client envoie la chaîne `<host>:<port>\n` au Serveur.
5.  Le **Serveur ShieldNet** lit cette chaîne, se connecte à `<host>:<port>`, puis relaie les données de manière bidirectionnelle entre le Client (via le tunnel TLS) et la destination finale.

Cela signifie que la section `target_service` dans `server_config.yaml` n'est plus utilisée pour déterminer où le trafic est acheminé.

### 5. Exécution de l'application

**a. Déploiement du Serveur (avec Docker Compose) :**

Le `docker-compose.yml` est configuré pour ne démarrer que le service `tunnel-server`.
1.  Générez les certificats dans `./certs/` en utilisant `python certs.py`.
2.  Assurez-vous que `server/config/.env` est créé et configuré (copiez de `.env.example`). Les chemins pour les certificats et logs doivent être corrects pour l'environnement conteneur (ex: `SHIELDNET_TLS_SERVER_CERT="certs/server.crt"` qui devient `/app/certs/server.crt` dans le conteneur).
3.  Créez le dossier de logs du serveur : `mkdir -p logs/server`.

```bash
# Démarrer le service tunnel-server en mode détaché
docker-compose up --build -d tunnel-server

# Voir les logs du serveur
docker-compose logs -f tunnel-server

# Arrêter le service
docker-compose down # ou docker-compose stop tunnel-server
```

**b. Exécution manuelle du Client (Python directement) :**

Le client est exécuté localement et se connecte au serveur (qui peut être le serveur Docker).
1.  Installez les dépendances : `pip install -r requirements.txt`.
2.  Assurez-vous que les certificats sont générés (`certs/`) et que `client/config/.env` est configuré (copiez de `.env.example`) pour pointer vers le serveur (ex: `SHIELDNET_REMOTE_SERVER_HOST="localhost"`, `SHIELDNET_REMOTE_SERVER_PORT="8443"`) et les bons chemins de certificats locaux.
3.  Créez le dossier de logs du client : `mkdir -p logs/client`.

    **Démarrer le client :**
    Le client nécessite des arguments pour la destination dynamique et peut prendre un chemin vers son fichier `.env`.
    ```bash
    python client/client.py \
      --config client/config/.env \
      --target-host <destination_host> \
      --target-port <destination_port>
    # Exemple : python client/client.py --config client/config/.env --target-host localhost --target-port 8080
    # Pour logs verbeux : ajouter --verbose
    ```
    *   `<destination_host>`: L'hôte final auquel le serveur doit se connecter (ex: `localhost`, `www.google.com`).
    *   `<destination_port>`: Le port final sur `<destination_host>` (ex: `8080`, `80`).

4.  Testez en envoyant du trafic vers le port d'écoute local du client (configuré dans `client/config/.env` via `SHIELDNET_LOCAL_LISTENER_PORT`, ex: `localhost:1080`). Ce trafic sera tunnelisé vers le serveur, qui le redirigera ensuite vers `--target-host`:`--target-port`.
    Par exemple, si le client écoute sur `localhost:1080` (défini par `SHIELDNET_LOCAL_LISTENER_PORT=1080` dans son `.env`) et est lancé avec `--target-host localhost --target-port 8000` (où un service écoute sur `localhost:8000`):
    ```bash
    curl http://localhost:1080 # ou nc localhost 1080, etc.
    ```

### 6. Scénarios d'Exemple

#### ✅ Scénario 1 : Test Local (ex: application web locale)

*   **Objectif :** Accéder à un service web tournant sur `localhost:9090` via le tunnel, en faisant apparaître la connexion au service web comme venant du serveur ShieldNet (qui pourrait être sur la même machine ou une autre).
*   **Service Cible :** Un simple serveur web Python écoutant sur `localhost:9090`.
    ```bash
    # Dans un terminal, démarrez un serveur web simple (nécessite Python)
    mkdir test-site && cd test-site && echo "Hello from target service" > index.html
    python -m http.server 9090
    cd ..
    ```
*   **Serveur ShieldNet :** Démarrez le serveur ShieldNet (par exemple, via Docker Compose, écoutant sur `localhost:8443`).
    ```bash
    docker-compose up --build -d tunnel-server
    ```
*   **Client ShieldNet :** Démarrez le client pour qu'il écoute localement sur (par exemple) `localhost:1080` et dise au serveur ShieldNet de se connecter à `localhost:9090`.
    ```bash
    python client/client.py \
      --config client/config/.env \
      --target-host localhost \
      --target-port 9090
    ```
    (Assurez-vous que `client/config/.env` contient `SHIELDNET_REMOTE_SERVER_HOST="localhost"`, `SHIELDNET_REMOTE_SERVER_PORT="8443"`, et `SHIELDNET_LOCAL_LISTENER_PORT="1080"`).
*   **Test :** Ouvrez un navigateur ou utilisez `curl` pour accéder à `http://localhost:1080`.
    ```bash
    curl http://localhost:1080
    ```
    Vous devriez voir "Hello from target service". Le trafic est allé de `curl` -> client ShieldNet (1080) -> serveur ShieldNet (8443) -> service web Python (9090).

#### ✅ Scénario 2 : Routage vers un Service Externe (ex: site web public)

*   **Objectif :** Accéder à `example.com:80` via le tunnel, de sorte que la requête à `example.com` semble provenir de l'IP du serveur ShieldNet.
*   **Service Cible :** `example.com` sur le port `80`.
*   **Serveur ShieldNet :** Démarrez le serveur ShieldNet (peut être sur une machine distante avec une IP publique, ou localement via Docker pour ce test). Il écoute sur son port public (ex: `YOUR_SERVER_IP:8443`).
    ```bash
    # Sur la machine du serveur (ou localement avec Docker)
    docker-compose up --build -d tunnel-server
    ```
*   **Client ShieldNet :** Sur votre machine locale, démarrez le client pour qu'il écoute sur `localhost:1081` et dise au serveur ShieldNet de se connecter à `example.com:80`.
    ```bash
    python client/client.py \
      --config client/config/.env \
      --target-host example.com \
      --target-port 80
    ```
    (Modifiez `client/config/.env` pour que `SHIELDNET_REMOTE_SERVER_HOST` pointe vers l'IP/hostname de votre serveur ShieldNet, `SHIELDNET_REMOTE_SERVER_PORT` vers son port d'écoute, et `SHIELDNET_LOCAL_LISTENER_PORT` est `1081` pour cet exemple).
*   **Test :** Accédez à `http://localhost:1081` avec `curl`.
    ```bash
    curl -v http://localhost:1081
    ```
    Vous devriez recevoir la page d'accueil de `example.com`. Le serveur ShieldNet a effectué la requête à `example.com` pour vous.

### 7. Lancer les tests unitaires

Placez-vous à la racine du projet.
```bash
python -m unittest discover -s tests -v
```
Cela détectera et exécutera tous les tests du dossier `tests`.

### 8. Script de test end-to-end (`scripts/test_tunnel.sh`)

Le script `scripts/test_tunnel.sh` existant utilise `docker-compose` pour démarrer le client, le serveur et un `echo-server`. Avec les modifications pour un déploiement serveur uniquement via `docker-compose`, ce script nécessitera des ajustements importants (par exemple, exécuter le client localement). **Ce script n'est pas mis à jour dans le cadre de cette refactorisation initiale axée sur le routage dynamique et le déploiement Docker du serveur uniquement.**

## Développement

*   **Style de code** : Suivre PEP 8. Utilisez un linter comme Flake8. Les annotations de type sont utilisées.
*   **Journalisation** : Utilise le module `logging` standard. Voir `client/common/logging_setup.py`.
*   **Configuration** : Via fichiers `.env` et `client/common/env_config_loader.py`.
*   **TLS** : Paramètres TLS 1.2 minimum, mTLS optionnel (basé sur la configuration serveur via variables d'environnement).
*   **Tests** : Des tests unitaires sont présents dans `tests/` (auront besoin d'adaptation pour la configuration `.env`).

## Licence

Licence MIT (supposée depuis le projet original, à confirmer ou modifier).
Ce projet a été refactorisé et amélioré à partir d'une version initiale.
