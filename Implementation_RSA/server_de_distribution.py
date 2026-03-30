from flask import Flask, request, jsonify
from RSA_seuil import generer_clef
import rsa
import base64
import uuid

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
rsa_params   = {}   # { "N", "e" }
P_shamir     = None  # modulo premier pour l'interpolation de Lagrange
d_secret     = None  # clé privée — stocké séparément, jamais exposé
parts_index  = {}   # { index_i: valeur_fi }  — toutes les parts précalculées
next_index   = 1    # prochain index i libre

# Sessions de déchiffrement
decrypt_sessions = {}
# { session_id: { "ciphertext": int, "partials": [(index_i, sigma_i)], "result": None } }

# ===========================================
# ROUTES FLASK — GESTION DES CLÉS
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


@app.route("/sessions", methods=["GET"])
def list_sessions():
    """Liste toutes les sessions de déchiffrement en cours avec leur statut."""
    sessions = []
    for sid, session in decrypt_sessions.items():
        current = len(session["partials"])
        sessions.append({
            "session_id":    sid,
            "parts_received": current,
            "threshold":     T,
            "ready":         current >= T,
            "done":          session["result"] is not None,
        })
    return jsonify({
        "sessions": sessions,
        "total":    len(sessions)
    })


# ===========================================
# ROUTES FLASK — CHIFFREMENT / DÉCHIFFREMENT
# ===========================================

@app.route("/encrypt", methods=["POST"])
def encrypt():
    """
    Chiffre un message entier avec la clé publique RSA.
    c = m^e mod N
    """
    data = request.get_json()
    if not data or "message" not in data:
        return jsonify({"error": "Le champ 'message' est requis"}), 400

    try:
        message_str = data["message"]
        message_bytes = message_str.encode("utf-8")
        message_int = int.from_bytes(message_bytes, byteorder="big")

        N = rsa_params["N"]
        e = rsa_params["e"]

        if message_int >= N:
            return jsonify({"error": f"Message trop long. m ({message_int}) >= N ({N})"}), 400

        ciphertext = pow(message_int, e, N)

        # Créer une session de déchiffrement
        session_id = str(uuid.uuid4())[:8]
        decrypt_sessions[session_id] = {
            "ciphertext": ciphertext,
            "partials": [],
            "result": None
        }

        print(f"[SERVEUR] Message chiffré. Session={session_id}, c={ciphertext}")

        return jsonify({
            "status": "ok",
            "ciphertext": str(ciphertext),
            "session_id": session_id,
            "message_info": f"Message chiffré. Utilisez session_id='{session_id}' pour le déchiffrement."
        })

    except Exception as ex:
        return jsonify({"error": f"Erreur de chiffrement : {ex}"}), 500


@app.route("/submit_partial_decrypt", methods=["POST"])
def submit_partial_decrypt():
    """
    Un participant soumet sa signature partielle sigma_i = c^(d_i) mod N.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Données JSON requises"}), 400

    required = ["session_id", "client_id", "part_index", "partial_signature"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Champ '{field}' requis"}), 400

    session_id = data["session_id"]
    client_id  = data["client_id"]
    part_index = int(data["part_index"])
    sigma_i    = int(data["partial_signature"])

    if session_id not in decrypt_sessions:
        return jsonify({"error": f"Session '{session_id}' inconnue"}), 404

    if client_id not in clients:
        return jsonify({"error": "Client non enregistré"}), 403

    session = decrypt_sessions[session_id]

    # Vérifier que ce participant n'a pas déjà soumis
    existing_indices = [p[0] for p in session["partials"]]
    if part_index in existing_indices:
        return jsonify({"error": f"Le participant {part_index} a déjà soumis sa part"}), 409

    session["partials"].append((part_index, sigma_i))
    current = len(session["partials"])

    print(f"[SERVEUR] Session {session_id} : part {part_index} reçue de '{client_id}' ({current}/{T})")

    return jsonify({
        "status": "ok",
        "session_id": session_id,
        "parts_received": current,
        "threshold": T,
        "ready": current >= T,
        "message": f"Part soumise ({current}/{T}). "
                   + ("Prêt pour la combinaison !" if current >= T else f"Encore {T - current} part(s) nécessaire(s).")
    })


@app.route("/combine", methods=["POST"])
def combine():
    """
    Combine les signatures partielles pour reconstruire le message.

    Utilise l'interpolation de Lagrange sur les exposants :
    d = sum( d_i * L_i(0) ) mod fi_n
    Puis m = c^d mod N.
    """
    data = request.get_json()
    if not data or "session_id" not in data:
        return jsonify({"error": "session_id requis"}), 400

    session_id = data["session_id"]
    if session_id not in decrypt_sessions:
        return jsonify({"error": f"Session '{session_id}' inconnue"}), 404

    session = decrypt_sessions[session_id]

    if session["result"] is not None:
        return jsonify({
            "status": "ok",
            "session_id": session_id,
            "message_dechiffre": session["result"],
            "info": "Résultat déjà calculé (cache)."
        })

    partials = session["partials"]
    if len(partials) < T:
        return jsonify({
            "error": f"Pas assez de parts ({len(partials)}/{T}). Il en faut au minimum {T}."
        }), 400

    try:
        N = rsa_params["N"]
        c = session["ciphertext"]

        # Reconstruction de d par interpolation de Lagrange
        # sur les parts reçues du polynôme de Shamir
        indices = [p[0] for p in partials[:T]]
        values  = [p[1] for p in partials[:T]]

        # Les sigma_i soumises sont en réalité les d_i (parts du secret d)
        # On reconstruit d = sum( d_i * L_i(0) ) mod fi_n
        d_reconstruit = 0
        for i_idx, xi in enumerate(indices):
            numerateur   = 1
            denominateur = 1
            for xj in indices:
                if xj != xi:
                    numerateur   = (numerateur   * (-xj))     % P_shamir
                    denominateur = (denominateur * (xi - xj)) % P_shamir

            inv_denom = pow(denominateur, -1, P_shamir)
            lagrange_i = (numerateur * inv_denom) % P_shamir
            d_reconstruit = (d_reconstruit + values[i_idx] * lagrange_i) % P_shamir

        # Déchiffrement : m = c^d mod N
        message_int = pow(c, d_reconstruit, N)
        message_bytes = message_int.to_bytes(
            (message_int.bit_length() + 7) // 8, byteorder="big"
        )
        message_str = message_bytes.decode("utf-8", errors="replace")

        session["result"] = message_str

        print(f"[SERVEUR] Session {session_id} : déchiffrement réussi -> '{message_str}'")

        return jsonify({
            "status": "ok",
            "session_id": session_id,
            "message_dechiffre": message_str,
            "d_reconstruit": str(d_reconstruit)
        })

    except Exception as ex:
        return jsonify({"error": f"Erreur lors de la combinaison : {ex}"}), 500


# ===========================================
# DÉMARRAGE
# ===========================================

if __name__ == "__main__":
    print("=" * 50)
    print("SERVEUR DE DISTRIBUTION À SEUIL - Port 5000")
    print(f"Schéma ({T}, {N_PARTS}) : seuil {T} parmi {N_PARTS} participants")
    print("=" * 50)

    # Génération des clés via RSA_seuil.generer_clef() 
    print("[SERVEUR] Génération des clés RSA à seuil via RSA_seuil...")
    tab_clef, params, P, d = generer_clef(N_PARTS, T, nb_bits=64)

    rsa_params  = params
    P_shamir    = P
    d_secret    = d
    parts_index = {index: part for index, part in tab_clef}

    print(f"[SERVEUR] N    = {rsa_params['N']}")
    print(f"[SERVEUR] e    = {rsa_params['e']}")
    print(f"[SERVEUR] Parts précalculées : {parts_index}")
    print("[SERVEUR] Prêt.\n")

    app.run(host="127.0.0.1", port=5000, debug=True)