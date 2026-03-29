from RSA import RSA, test_de_primalite
from secrets import randbelow


def trouver_premier_suivant(n):
    """
    Trouve le plus petit nombre premier strictement supérieur à n.
    Nécessaire pour garantir que le partage de Shamir opère dans un corps fini (Z/pZ).
    """
    candidate = n + 1
    if candidate % 2 == 0:
        candidate += 1
    while not test_de_primalite(candidate):
        candidate += 2
    return candidate


def generer_coef(d, seuil, modulo):
    """
    Génère les coefficients du polynôme de Shamir.
    f(x) = d + a1*x + a2*x^2 + ... + a_{seuil-1}*x^{seuil-1}

    Le premier coefficient est d (le secret), les suivants sont aléatoires.
    Le coefficient de plus haut degré est garanti non nul pour conserver le degré.
    """
    coefs = [d]
    for i in range(seuil - 1):
        if i == seuil - 2:
            coef = randbelow(modulo - 1) + 1  # non nul
        else:
            coef = randbelow(modulo)
        coefs.append(coef)
    return coefs


def evaluer_polynome(coefs, x, modulo):
    """
    Évalue f(x) = coefs[0] + coefs[1]*x + coefs[2]*x^2 + ...  mod modulo
    """
    resultat = 0
    for i, coef in enumerate(coefs):
        resultat = (resultat + coef * pow(x, i, modulo)) % modulo
    return resultat


def generer_clef(n, seuil, nb_bits=512):
    """
    Génère les clés RSA et distribue n parts avec un seuil donné.

    Le partage de Shamir est effectué modulo un nombre premier P > φ(N),
    car l'interpolation de Lagrange nécessite un corps fini (Z/pZ).
    Utiliser φ(N) directement échouerait car φ(N) est composite.

    Retourne : (tab_clef, params_publics, P, d)
      - tab_clef      : liste de (index_i, part_fi) pour chaque participant
      - params_publics: dict avec N et e uniquement
      - P             : modulo premier pour l'interpolation de Lagrange
      - d             : clé privée — usage interne serveur uniquement
    """
    clefs = RSA(nb_bits)
    d      = clefs[0][0]
    N      = clefs[0][1]
    e      = clefs[1][0]
    fi_n   = clefs[2]

    # Trouver un premier P > fi_n pour que Shamir fonctionne dans Z/PZ
    P = trouver_premier_suivant(fi_n)

    tab_clef = []
    coefs = generer_coef(d, seuil, P)
    for i in range(1, n + 1):
        part = evaluer_polynome(coefs, i, P)
        tab_clef.append((i, part))

    params_publics = {"N": N, "e": e}
    return tab_clef, params_publics, P, d


if __name__ == "__main__":
    parts, params, P, d = generer_clef(5, 3, nb_bits=8)
    print(f"N={params['N']}, e={params['e']}")
    print(f"d={d}, P (modulo premier)={P}")
    print("Parts générées :")
    for idx, part in parts:
        print(f"  f({idx}) = {part}")
