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

*   **Client :** La configuration du client se fait via un fichier YAML. Copiez `client_config.yaml.example` (situé à la racine du projet ou dans `client/`) vers `client_config.yaml` (ou un autre nom de votre choix) et personnalisez les valeurs. Ce fichier permet de définir les paramètres communs (serveur distant, TLS, logging), les tunnels pour le mode `tcp-tunnel`, et les réglages du proxy pour le mode `socks5-proxy`.

*   **Serveur :** La configuration du serveur continue d'utiliser un fichier `.env`. Copiez `server/config/.env.example` vers `server/config/.env` et personnalisez les valeurs.

```bash
# Créez les dossiers nécessaires s'ils n'existent pas
mkdir -p certs logs/client logs/server server/config

# Pour le client (exemple, placez client_config.yaml où vous le souhaitez)
cp client_config.yaml.example client_config.yaml
# Éditez client_config.yaml

# Pour le serveur
cp server/config/.env.example server/config/.env
# Éditez server/config/.env
```

**Fichiers de configuration clés :**

*   **Client (`client_config.yaml`) :**
    *   `common_settings`: Adresse du serveur distant, certificats TLS, timeouts, configuration du logging.
    *   `tcp_tunnel_mode`: Liste des tunnels à établir (port d'écoute local, hôte cible, port cible).
    *   `socks5_proxy_mode`: Port d'écoute local pour le serveur SOCKS5.
    *   Consultez `client_config.yaml.example` pour tous les détails et options.

*   **Serveur (`server/config/.env`) :** (inchangé par cette refonte du client)
    *   `SHIELDNET_SERVER_LISTENER_HOST`: Hôte d'écoute du serveur (ex: `0.0.0.0`).
    *   `SHIELDNET_SERVER_LISTENER_PORT`: Port d'écoute du serveur (ex: `8443`).
    *   `SHIELDNET_TLS_SERVER_CERT`, `SHIELDNET_TLS_SERVER_KEY`: Certificat et clé du serveur.
    *   `SHIELDNET_TLS_CLIENT_CA_CERT`: Pour mTLS (chemin vers `ca.crt`).
    *   `SHIELDNET_TLS_ALLOWED_CLIENT_CNS`: Pour mTLS (liste de CNs autorisés, séparés par des virgules).
    *   `SHIELDNET_TIMEOUT_TARGET_CONNECT`: Timeout pour la connexion à la cible dynamique.
    *   `SHIELDNET_LOG_FILE`, `SHIELDNET_LOG_LEVEL`, etc.

**Important pour les chemins dans les configurations :**
*   **Client (`client_config.yaml`):** Les chemins relatifs pour les certificats (`server_ca_cert`, `client_cert`, `client_key`) et le fichier de log (`log_file`) sont résolus par rapport au répertoire racine du projet (le répertoire contenant le dossier `client/` et `certs/`). Par exemple, `certs/ca.crt` est attendu comme `PROJECT_ROOT/certs/ca.crt`. Les chemins absolus sont utilisés tels quels.
*   **Serveur (`server/config/.env`):** Pour Docker, les chemins spécifiés (comme `certs/server.crt`) sont résolus à l'intérieur du conteneur. Le `ENV_BASE_DIR` dans `server.py` est `/app`, et les volumes sont montés en conséquence (ex: `./certs` local est monté sur `/app/certs` dans le conteneur).

### 4. Modes de Fonctionnement du Client

Le client `client.py` supporte désormais deux modes principaux :

*   **`tcp-tunnel`**:
    *   Ce mode permet de configurer plusieurs tunnels TCP. Chaque tunnel écoute sur un port local spécifié et transfère le trafic vers un service cible (`target_service_host:target_service_port`) via le serveur ShieldNet.
    *   La configuration des tunnels (ports locaux, cibles) se fait dans la section `tcp_tunnel_mode.tunnels` du fichier `client_config.yaml`.
    *   Le serveur ShieldNet est toujours informé dynamiquement de la destination finale pour chaque connexion tunnelisée.

*   **`socks5-proxy`**:
    *   Ce mode démarre un serveur SOCKS5 local sur un port configurable (`socks5_proxy_mode.local_listen_port` dans `client_config.yaml`).
    *   Les applications clientes peuvent se connecter à ce proxy SOCKS5.
    *   Pour chaque connexion SOCKS entrante, le client ShieldNet établit dynamiquement un tunnel TLS vers le serveur ShieldNet, en lui indiquant la destination demandée par le client SOCKS.
    *   Ceci permet de naviguer sur des sites HTTP et HTTPS via le tunnel sécurisé. Aucune authentification SOCKS n'est implémentée pour le moment.

Dans les deux modes, la communication avec le serveur ShieldNet utilise les paramètres TLS définis dans `common_settings` du fichier `client_config.yaml`.

### 5. Exécution de l'application

**a. Déploiement du Serveur (avec Docker Compose) :** (inchangé)

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
2.  Assurez-vous que les certificats sont générés (`certs/`).
3.  Créez un fichier de configuration pour le client, par exemple `client_config.yaml`, en copiant et modifiant `client_config.yaml.example`. Assurez-vous que les chemins des certificats et les détails du serveur distant sont corrects.
4.  Créez le dossier de logs du client si vous spécifiez un fichier de log dans la configuration : `mkdir -p logs/client`.

    **Démarrer le client :**
    Le client s'exécute dans un mode spécifié (`tcp-tunnel` ou `socks5-proxy`).
    Par défaut, il recherche un fichier de configuration nommé `client_config.yaml` dans le dossier `client/config/`.
    Vous pouvez spécifier un autre chemin de configuration avec l'option `--config`.
    ```bash
    # Exécuter en mode TCP Tunnel avec la configuration par défaut (client/config/client_config.yaml)
    python client/client.py tcp-tunnel

    # Exécuter en mode SOCKS5 Proxy avec la configuration par défaut
    python client/client.py socks5-proxy

    # Spécifier un fichier de configuration personnalisé
    python client/client.py tcp-tunnel --config chemin/vers/votre_config.yaml

    # Pour surcharger le niveau de log (ex: DEBUG)
    python client/client.py tcp-tunnel --log-level DEBUG
    # (ceci utilisera la configuration par défaut si --config n'est pas spécifié)
    ```

5.  **Tester le mode `tcp-tunnel` :**
    Si vous avez configuré un tunnel dans `client/config/client_config.yaml` (ou votre fichier personnalisé) pour écouter, par exemple, sur `127.0.0.1:1080` et cibler `localhost:8080` (où un service écoute), vous pouvez tester avec :
    ```bash
    curl http://127.0.0.1:1080
    # ou nc 127.0.0.1 1080, etc.
    ```
    Le trafic sera acheminé via le serveur ShieldNet vers `localhost:8080`.

6.  **Tester le mode `socks5-proxy` :**
    Si vous avez configuré le proxy SOCKS5 pour écouter, par exemple, sur `127.0.0.1:1090` dans `client_config.yaml`, vous pouvez configurer votre navigateur ou un outil comme `curl` pour l'utiliser :
    ```bash
    # Accéder à un site HTTP via le proxy SOCKS5
    curl --socks5 127.0.0.1:1090 http://example.com

    # Accéder à un site HTTPS via le proxy SOCKS5
    curl --socks5 127.0.0.1:1090 https://example.com
    ```

### 6. Scénarios d'Exemple

Les exemples ci-dessous illustrent comment utiliser les nouveaux modes. Assurez-vous que votre `client_config.yaml` est correctement configuré pour les `common_settings` (serveur distant, certificats, etc.).

#### ✅ Scénario 1 : Mode `tcp-tunnel` - Accès à un service web local

*   **Objectif :** Accéder à un service web tournant sur `localhost:9090` via un tunnel local sur le port `1080`.
*   **Service Cible :** Un simple serveur web Python écoutant sur `localhost:9090`.
    ```bash
    # Dans un terminal, démarrez un serveur web simple
    mkdir -p test-site && cd test-site && echo "Hello from target service" > index.html
    python -m http.server 9090
    cd ..
    ```
*   **Serveur ShieldNet :** Démarrez le serveur ShieldNet (ex: via Docker Compose, écoutant sur `localhost:8443`).
*   **Configuration Client (`client_config.yaml`) (extrait pertinent) :**
    ```yaml
    # ... common_settings ...
    tcp_tunnel_mode:
      tunnels:
        - local_listen_host: "127.0.0.1"
          local_listen_port: 1080        # Le client écoute ici
          target_service_host: "localhost" # Le serveur ShieldNet se connectera ici
          target_service_port: 9090
    ```
*   **Client ShieldNet :**
    ```bash
    python client/client.py tcp-tunnel --config client_config.yaml
    ```
*   **Test :**
    ```bash
    curl http://127.0.0.1:1080
    ```
    Vous devriez voir "Hello from target service".

#### ✅ Scénario 2 : Mode `socks5-proxy` - Navigation Web via le Tunnel

*   **Objectif :** Naviguer sur `http://example.com` et `https://example.com` en utilisant le client ShieldNet comme proxy SOCKS5, écoutant localement sur le port `1090`.
*   **Serveur ShieldNet :** Démarrez le serveur ShieldNet.
*   **Configuration Client (`client_config.yaml`) (extrait pertinent) :**
    ```yaml
    # ... common_settings ...
    socks5_proxy_mode:
      local_listen_host: "127.0.0.1"
      local_listen_port: 1090 # Le client écoute ici pour les connexions SOCKS
    ```
*   **Client ShieldNet :**
    ```bash
    python client/client.py socks5-proxy --config client_config.yaml
    ```
*   **Test :**
    ```bash
    curl --socks5 127.0.0.1:1090 http://example.com
    curl --socks5 127.0.0.1:1090 https://example.com
    ```
    Vous devriez recevoir les pages d'accueil correspondantes. Le trafic vers `example.com` transite par le serveur ShieldNet.

### 7. Lancer les tests unitaires (Besoin de mise à jour)

Placez-vous à la racine du projet.
```bash
python -m unittest discover -s tests -v
```
Cela détectera et exécutera tous les tests du dossier `tests`.
**Note :** Les tests unitaires existants (`tests/test_client.py`, etc.) nécessiteront une mise à jour significative pour refléter la nouvelle structure du client (modes, configuration YAML) et pour mocker correctement les nouvelles fonctionnalités.

### 8. Script de test end-to-end (`scripts/test_tunnel.sh`)

Le script `scripts/test_tunnel.sh` existant n'est plus compatible avec la nouvelle structure du client et nécessiterait une refonte complète.

## Développement

*   **Style de code** : Suivre PEP 8. Utilisez un linter comme Flake8. Les annotations de type sont utilisées.
*   **Journalisation** : Utilise le module `logging` standard, amélioré avec `coloredlogs` pour la console. Configurable via `client_config.yaml`. Voir `client/common/logging_setup.py`.
*   **Configuration Client** : Via fichier YAML (par défaut `client_config.yaml`). Voir `client_config.yaml.example`.
*   **Configuration Serveur** : Via fichier `server/config/.env`.
*   **TLS** : Paramètres TLS 1.2 minimum (configurable), mTLS optionnel.
*   **Tests** : Les tests unitaires existants dans `tests/` nécessitent une adaptation.

## Licence

Licence MIT (supposée depuis le projet original, à confirmer ou modifier).
Ce projet a été refactorisé et amélioré à partir d'une version initiale.
