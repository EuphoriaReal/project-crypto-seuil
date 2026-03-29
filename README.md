# RSA à Seuil — Partage de Secret de Shamir

Implémentation d'un schéma de **chiffrement RSA à seuil (t, n)** basé sur le **partage de secret de Shamir**.  
Le principe : la clé privée `d` est découpée en `n` parts via un polynôme de degré `t-1`. Il faut au minimum `t` parts pour reconstruire `d` et déchiffrer un message.


## Fonctionnement

### Schéma cryptographique

1. **Génération RSA** : deux premiers `p`, `q` → `N = p·q`, `φ(N) = (p-1)(q-1)`, puis `e` et `d = e⁻¹ mod φ(N)`
2. **Partage de Shamir** : un polynôme `f(x) = d + a₁x + a₂x² + ... + aₜ₋₁xᵗ⁻¹` est évalué en `x = 1, 2, ..., n` modulo un premier `P > φ(N)` pour produire les parts `f(i)`
3. **Chiffrement** : `c = mᵉ mod N`
4. **Déchiffrement** : `t` participants soumettent leurs parts → reconstruction de `d` par interpolation de Lagrange → `m = cᵈ mod N`

### Protocole réseau

```
┌──────────┐     /register      ┌──────────────┐
│  Client  │ ──────────────────►│   Serveur    │
│          │ ◄──────────────────│   Flask      │
│          │     /get_part       │   :5000      │
│          │                     │              │
│          │     /encrypt        │              │
│          │ ──────────────────►│              │
│          │     /submit_partial │              │
│          │ ──────────────────►│              │
│          │     /combine        │              │
│          │ ◄──────────────────│              │
└──────────┘   message clair     └──────────────┘
```

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install flask requests rsa
```

Pour la visualisation (optionnel) :
```bash
pip install numpy matplotlib
```

## Utilisation

### 1. Lancer le serveur

```bash
cd Implementation_RSA
python3 server_de_distribution.py
```

Le serveur génère les clés RSA et précalcule les parts de Shamir au démarrage.

### 2. Lancer les clients (dans des terminaux séparés)

```bash
python3 utilisateur.py
# Entrer un nom : alice, bob, charlie, ...
```

### 3. Flux de chiffrement/déchiffrement

| Étape | Option | Description |
|-------|--------|-------------|
| 1 | `1` | Chaque client s'enregistre |
| 2 | `2` | Chaque client récupère sa part (chiffrée avec sa clé RSA) |
| 3 | `5` | Un client chiffre un message → reçoit un `session_id` |
| 4 | `6` | Au moins `t` clients soumettent leur part avec le `session_id` |
| 5 | `8` | Un client déclenche la combinaison → message déchiffré |

### 4. Visualisation

```bash
cd visualisation
python3 graph.py
```

Affiche le polynôme de Shamir et les points d'évaluation avec matplotlib.

## Configuration

Dans `server_de_distribution.py` :

```python
T = 3           # Seuil minimum de parts pour déchiffrer
N_PARTS = 5     # Nombre total de participants
nb_bits = 64    # Taille des clés RSA (augmenter pour la sécurité)
```

