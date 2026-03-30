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


def lister_sessions():
    """Affiche toutes les sessions de déchiffrement en cours sur le serveur."""
    try:
        resp = requests.get(f"{SERVER_URL}/sessions")
        data = resp.json()
        sessions = data.get("sessions", [])
        if not sessions:
            print(f"[{client_id}] Aucune session en cours.")
            return
        print(f"\n[{client_id}] Sessions de déchiffrement ({data['total']}) :")
        for s in sessions:
            if s["done"]:
                statut = "déchiffré"
            elif s["ready"]:
                statut = "prêt à combiner"
            else:
                statut = f"en attente ({s['parts_received']}/{s['threshold']} parts)"
            print(f"   - {s['session_id']}  →  {statut}")
        print()
    except Exception as ex:
        print(f"[{client_id}] Erreur liste sessions : {ex}")


# ===========================================
# 4. CHIFFREMENT
# ===========================================

def chiffrer_message():
    """Chiffre un message via le serveur (c = m^e mod N)."""
    message = input("Entrez le message à chiffrer : ")
    try:
        resp = requests.post(
            f"{SERVER_URL}/encrypt",
            json={"message": message}
        )
        data = resp.json()
        if resp.status_code != 200:
            print(f"[{client_id}] Erreur : {data.get('error')}")
            return None

        print(f"[{client_id}] {data['message_info']}")
        print(f"[{client_id}] Chiffré c = {data['ciphertext']}")
        print(f"[{client_id}] Session ID : {data['session_id']}")
        return data['session_id']

    except Exception as ex:
        print(f"[{client_id}] Erreur chiffrement : {ex}")
        return None


# ===========================================
# 5. DÉCHIFFREMENT DISTRIBUÉ
# ===========================================

def soumettre_signature_partielle():
    """
    Calcule sigma_i = c^(d_i) mod N et l'envoie au serveur.
    Ici on envoie directement notre part d_i (le serveur fait la combinaison).
    """
    if ma_part is None:
        print(f"[{client_id}] Vous n'avez pas encore reçu de part. Faites l'option 2 d'abord.")
        return

    session_id = input("Entrez le session_id du message à déchiffrer : ").strip()

    try:
        resp = requests.post(
            f"{SERVER_URL}/submit_partial_decrypt",
            json={
                "session_id": session_id,
                "client_id": client_id,
                "part_index": mon_index,
                "partial_signature": str(ma_part)
            }
        )
        data = resp.json()
        if resp.status_code != 200:
            print(f"[{client_id}] Erreur : {data.get('error')}")
            return

        print(f"[{client_id}] {data['message']}")
        if data.get("ready"):
            print(f"[{client_id}] Le seuil est atteint ! Vous pouvez lancer la combinaison (option 8).")

    except Exception as ex:
        print(f"[{client_id}] Erreur soumission : {ex}")


def demander_combinaison():
    """Demande au serveur de combiner les parts et déchiffrer le message."""
    session_id = input("Entrez le session_id : ").strip()
    try:
        resp = requests.post(
            f"{SERVER_URL}/combine",
            json={"session_id": session_id}
        )
        data = resp.json()
        if resp.status_code != 200:
            print(f"[{client_id}] Erreur : {data.get('error')}")
            return

        print(f"\n[{client_id}] ============================")
        print(f"[{client_id}]  MESSAGE DÉCHIFFRÉ : {data['message_dechiffre']}")
        print(f"[{client_id}] ============================\n")

    except Exception as ex:
        print(f"[{client_id}] Erreur combinaison : {ex}")


# ===========================================
# 6. MENU PRINCIPAL
# ===========================================

def menu():
    print(f"""
   ╔══════════════════════════════════════╗
   ║   Client RSA à Seuil : {client_id:<12s}║
   ╠══════════════════════════════════════╣
   ║  1. S'enregistrer                    ║
   ║  2. Demander ma part                 ║
   ║  3. Voir les participants            ║
   ║  4. Afficher ma part                 ║
   ║  ──────────────────────────────────  ║
   ║  5. Voir les sessions en cours       ║
   ║  ──────────────────────────────────  ║
   ║  6. Chiffrer un message              ║
   ║  7. Soumettre ma signature partielle ║
   ║  8. Combiner et déchiffrer           ║
   ║  ──────────────────────────────────  ║
   ║  9. Quitter                          ║
   ╚══════════════════════════════════════╝
 """)
    return input("Choix : ").strip()


# ===========================================
# 7. DÉMARRAGE
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
        match choix:
            case "1":
                senregistrer(public_key_pem)
            case "2":
                if mon_index is None:
                    print(f"[{client_id}] Enregistrez-vous d'abord (option 1).")
                else:
                    demander_ma_part(public_key_pem, private_key_client)
            case "3":
                lister_participants()
            case "4":
                if ma_part is None:
                    print(f"[{client_id}] Vous n'avez pas encore reçu de part.")
                else:
                    print(f"[{client_id}] Ma part : f({mon_index}) = {ma_part}")
            case "5":
                lister_sessions()
            case "6":
                chiffrer_message()
            case "7":
                soumettre_signature_partielle()
            case "8":
                demander_combinaison()
            case "9":
                print(f"[{client_id}] Au revoir.")
                break
            case _:
                print("Choix invalide.")