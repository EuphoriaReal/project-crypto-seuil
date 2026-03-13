import rsa
import requests
import os
import base64

# ===========================================
# 1. CONFIGURATION DU CLIENT
# ===========================================

client_id = input("Entrez le nom du client : ")

SERVER_URL = "http://127.0.0.1:5000"
os.makedirs("keys", exist_ok=True)
PUBLIC_KEY_FILE  = f"keys/publickey_{client_id}.pem"
PRIVATE_KEY_FILE = f"keys/privatekey_{client_id}.pem"

# Part secrète reçue du serveur (entier)
ma_part       = None   # f(i) déchiffré
mon_index     = None   # i
rsa_public    = None   # (N, e) du serveur


# ===========================================
# 2. GESTION DES CLÉS RSA DU CLIENT
# ===========================================

def charger_ou_generer_cles():
    """Charge les clés depuis le disque ou en génère de nouvelles."""
    if os.path.exists(PUBLIC_KEY_FILE) and os.path.exists(PRIVATE_KEY_FILE):
        print(f"[{client_id}] Clés trouvées, chargement...")
        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())
        with open(PRIVATE_KEY_FILE, "rb") as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
        print(f"[{client_id}] Clés chargées.")
    else:
        print(f"[{client_id}] Aucune clé trouvée, génération en cours...")
        public_key, private_key = rsa.newkeys(2048)
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key.save_pkcs1())
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key.save_pkcs1())
        print(f"[{client_id}] Clés générées et sauvegardées.")
    return public_key, private_key


# ===========================================
# 3. COMMUNICATION AVEC LE SERVEUR
# ===========================================

def recuperer_params_serveur():
    """Récupère N et e du serveur (paramètres publics RSA)."""
    global rsa_public
    try:
        resp = requests.get(f"{SERVER_URL}/params")
        data = resp.json()
        rsa_public = {"N": int(data["N"]), "e": int(data["e"])}
        t = data["t"]
        n = data["n"]
        print(f"[{client_id}] Paramètres RSA reçus : N={rsa_public['N']}, e={rsa_public['e']}")
        print(f"[{client_id}] Schéma à seuil : t={t} participants parmi n={n}")
        return True
    except Exception as ex:
        print(f"[{client_id}] Erreur récupération params : {ex}")
        return False


def senregistrer(public_key_pem):
    """Envoie la clé publique au serveur pour s'enregistrer."""
    global mon_index
    try:
        resp = requests.post(
            f"{SERVER_URL}/register",
            json={"client_id": client_id, "public_key": public_key_pem}
        )
        data = resp.json()
        if resp.status_code != 200:
            print(f"[{client_id}] Enregistrement refusé : {data.get('error')}")
            return False
        mon_index = data["part_index"]
        print(f"[{client_id}] Enregistré. {data['message']}")
        return True
    except Exception as ex:
        print(f"[{client_id}] Erreur enregistrement : {ex}")
        return False


def demander_ma_part(public_key_pem, private_key):
    """
    Demande au serveur la part f(i) qui nous est destinée.
    La part arrive chiffrée avec notre clé publique, on la déchiffre localement.
    """
    global ma_part, mon_index
    try:
        resp = requests.post(
            f"{SERVER_URL}/get_part",
            json={"client_id": client_id, "public_key": public_key_pem}
        )
        data = resp.json()

        if resp.status_code != 200:
            print(f"[{client_id}] Erreur serveur : {data.get('error')}")
            return False

        mon_index = data["part_index"]
        encrypted_part_b64 = data["encrypted_part"]

        # Déchiffrement de la part avec notre clé privée
        encrypted_part = base64.b64decode(encrypted_part_b64)
        part_bytes = rsa.decrypt(encrypted_part, private_key)
        ma_part = int.from_bytes(part_bytes, byteorder='big')

        print(f"[{client_id}] Part reçue et déchiffrée : f({mon_index}) = {ma_part}")
        return True

    except Exception as ex:
        print(f"[{client_id}] Erreur réception de la part : {ex}")
        return False


def lister_participants():
    """Affiche la liste des participants enregistrés sur le serveur."""
    try:
        resp = requests.get(f"{SERVER_URL}/clients")
        data = resp.json()
        print(f"\n[{client_id}] Participants enregistrés ({data['total']}/{data['max']}) :")
        for c in data["clients"]:
            print(f"   - {c['client_id']} → index i={c['part_index']}")
        print(f"   Seuil requis : {data['seuil']} participants\n")
    except Exception as ex:
        print(f"[{client_id}] Erreur liste participants : {ex}")


# ===========================================
# 4. RECONSTRUCTION LOCALE (OPTIONNEL)
# ===========================================

def pgcd(a, b):
    while b:
        a, b = b, a % b
    return a

def inverse_mod(a, m):
    return pow(a, -1, m)

def interpolation_lagrange(parts_recues, modulus):
    """
    Reconstruit le secret d à partir d'au moins t parts.
    
    parts_recues : liste de tuples (index_i, valeur_fi)
    modulus      : lambda(N)
    
    Attention : cette fonction révèle d en clair localement.
    En production, on ferait du déchiffrement distribué sans reconstruire d.
    """
    secret = 0
    indices = [p[0] for p in parts_recues]

    for i, (xi, yi) in enumerate(parts_recues):
        # Calcul du coefficient de Lagrange λ_i
        numerateur   = 1
        denominateur = 1
        for xj in indices:
            if xj != xi:
                numerateur   = (numerateur   * (-xj))      % modulus
                denominateur = (denominateur * (xi - xj))  % modulus

        lagrange_i = (numerateur * inverse_mod(denominateur, modulus)) % modulus
        secret = (secret + yi * lagrange_i) % modulus

    return secret


def dechiffrer_avec_parts(chiffre, parts_recues, lambda_N, N):
    """
    Déchiffre un message RSA à partir des parts reçues.
    Reconstruit d puis déchiffre.
    
    En production : chaque participant calculerait c^(d_i) mod N
    et on combinerait les résultats sans jamais reconstruire d.
    """
    d_reconstruit = interpolation_lagrange(parts_recues, lambda_N)
    print(f"[{client_id}] d reconstruit = {d_reconstruit}")
    message_int = pow(chiffre, d_reconstruit, N)
    message_bytes = message_int.to_bytes((message_int.bit_length() + 7) // 8, byteorder='big')
    return message_bytes


# ===========================================
# 5. MENU PRINCIPAL
# ===========================================

def menu():
    print(f"""
┌─────────────────────────────────┐
│  Que voulez-vous faire ?        │
│  1. S'enregistrer               │
│  2. Demander ma part            │
│  3. Voir les participants       │
│  4. Afficher ma part            │
│  5. Quitter                     │
└─────────────────────────────────┘""")
    return input("Choix : ").strip()


# ===========================================
# 6. DÉMARRAGE
# ===========================================

if __name__ == "__main__":
    print("=" * 50)
    print(f"CLIENT RSA À SEUIL : {client_id}")
    print("=" * 50)

    # Chargement des clés
    public_key_client, private_key_client = charger_ou_generer_cles()
    public_key_pem = public_key_client.save_pkcs1().decode("utf-8")

    # Récupération des paramètres publics du serveur
    recuperer_params_serveur()

    # Boucle menu
    while True:
        choix = menu()

        if choix == "1":
            senregistrer(public_key_pem)

        elif choix == "2":
            if mon_index is None:
                print(f"[{client_id}] Enregistrez-vous d'abord (option 1).")
            else:
                demander_ma_part(public_key_pem, private_key_client)

        elif choix == "3":
            lister_participants()

        elif choix == "4":
            if ma_part is None:
                print(f"[{client_id}] Vous n'avez pas encore reçu de part.")
            else:
                print(f"[{client_id}] Ma part : f({mon_index}) = {ma_part}")

        elif choix == "5":
            print(f"[{client_id}] Au revoir.")
            break

        else:
            print("Choix invalide.")
