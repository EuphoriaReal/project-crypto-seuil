from flask import Flask, request, jsonify
from RSA_seuil import generer_clef, evaluer_polynome
import rsa
import base64

app = Flask(__name__)

# ===========================================
# PARAMÈTRES DU SCHÉMA À SEUIL
# ===========================================

T = 3        # Seuil minimum pour reconstruire d
N_PARTS = 5  # Nombre total de parts à distribuer

# ===========================================
# STOCKAGE
# ===========================================

clients = {}
# { client_id: { "public_key": rsa.PublicKey, "part_index": int } }

# Paramètres issus de RSA_seuil.generer_clef()
rsa_params   = {}   # { "N", "e", "fi_n", "d" }
parts_index  = {}   # { index_i: valeur_fi }  — toutes les parts précalculées
next_index   = 1    # prochain index i libre

# ===========================================
# ROUTES FLASK
# ===========================================

@app.route("/params", methods=["GET"])
def get_params():
    """Retourne les paramètres publics RSA (N, e) et les infos du schéma."""
    return jsonify({
        "N": str(rsa_params["N"]),
        "e": str(rsa_params["e"]),
        "t": T,
        "n": N_PARTS
    })


@app.route("/register", methods=["POST"])
def register():
    """
    Enregistre un client avec sa clé publique.
    Lui attribue un index i unique dans le schéma de Shamir.
    """
    global next_index

    data = request.get_json()
    if not data or "client_id" not in data or "public_key" not in data:
        return jsonify({"error": "client_id et public_key requis"}), 400

    client_id      = data["client_id"]
    public_key_pem = data["public_key"]

    # Vérifier s'il reste de la place
    if client_id not in clients and next_index > N_PARTS:
        return jsonify({"error": f"Nombre maximum de participants ({N_PARTS}) atteint"}), 403

    try:
        public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode("utf-8"))
    except Exception as ex:
        return jsonify({"error": f"Clé publique invalide : {ex}"}), 400

    # Enregistrement du client
    if client_id not in clients:
        index_i = next_index
        next_index += 1
        clients[client_id] = {"public_key": public_key, "part_index": index_i}
        print(f"[SERVEUR] '{client_id}' enregistré -> index i={index_i}")
    else:
        index_i = clients[client_id]["part_index"]
        print(f"[SERVEUR] '{client_id}' déjà connu -> index i={index_i}")

    return jsonify({
        "status": "ok",
        "part_index": index_i,
        "message": f"Vous êtes le participant {index_i}/{N_PARTS}"
    })


@app.route("/get_part", methods=["POST"])
def get_part():
    """
    Envoie la part f(i) chiffrée avec la clé publique du client i.
    Utilise les parts précalculées par RSA_seuil.generer_clef().
    """
    data = request.get_json()
    if not data or "client_id" not in data or "public_key" not in data:
        return jsonify({"error": "client_id et public_key requis"}), 400

    client_id      = data["client_id"]
    public_key_pem = data["public_key"]

    if client_id not in clients:
        return jsonify({"error": "Client non enregistré. Appelez /register d'abord."}), 403

    # Vérification de la clé publique
    try:
        pk_envoyee = rsa.PublicKey.load_pkcs1(public_key_pem.encode("utf-8"))
    except Exception as ex:
        return jsonify({"error": f"Clé publique invalide : {ex}"}), 400

    pk_enregistree = clients[client_id]["public_key"]
    if pk_envoyee.n != pk_enregistree.n or pk_envoyee.e != pk_enregistree.e:
        return jsonify({"error": "Clé publique non reconnue"}), 403

    # Récupération de la part précalculée
    index_i = clients[client_id]["part_index"]
    part    = parts_index[index_i]   # f(i) calculé par RSA_seuil au démarrage

    print(f"[SERVEUR] Envoi de f({index_i}) à '{client_id}'")

    # Chiffrement de la part avec la clé publique du client
    part_bytes = part.to_bytes((part.bit_length() + 7) // 8, byteorder="big")
    try:
        encrypted_part     = rsa.encrypt(part_bytes, pk_enregistree)
        encrypted_part_b64 = base64.b64encode(encrypted_part).decode("utf-8")
    except Exception as ex:
        return jsonify({"error": f"Erreur de chiffrement : {ex}"}), 500

    return jsonify({
        "status":         "ok",
        "client_id":      client_id,
        "part_index":     index_i,
        "encrypted_part": encrypted_part_b64
    })


@app.route("/clients", methods=["GET"])
def list_clients():
    """Liste les clients enregistrés et leur index"""
    return jsonify({
        "clients": [
            {"client_id": cid, "part_index": info["part_index"]}
            for cid, info in clients.items()
        ],
        "total": len(clients),
        "max":   N_PARTS,
        "seuil": T
    })


# ===========================================
# DÉMARRAGE
# ===========================================

if __name__ == "__main__":
    print("=" * 50)
    print("SERVEUR DE DISTRIBUTION À SEUIL - Port 5000")
    print(f"Schéma ({T}, {N_PARTS}) : seuil {T} parmi {N_PARTS} participants")
    print("=" * 50)

    # --- Génération des clés via RSA_seuil.generer_clef() ---
    print("[SERVEUR] Génération des clés RSA à seuil via RSA_seuil...")
    tab_clef, params = generer_clef(N_PARTS, T)

    rsa_params  = params
    parts_index = {index: part for index, part in tab_clef}

    print(f"[SERVEUR] N    = {rsa_params['N']}")
    print(f"[SERVEUR] e    = {rsa_params['e']}")
    print(f"[SERVEUR] Parts précalculées : {parts_index}")
    print("[SERVEUR] Prêt.\n")

    app.run(host="127.0.0.1", port=5000, debug=True)
