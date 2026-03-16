from RSA import RSA
from secrets import randbelow


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
            coef = randbelow(modulo - 1) + 1
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


def generer_clef(n, seuil, nb_bit):
    """
    Génère les clés RSA et distribue n parts avec un seuil donné.

    Retourne : (tab_clef, params_publics, coefs)
      - tab_clef      : liste de (index_i, part_fi) pour chaque participant
      - params_publics: dict avec N et e uniquement (pas de fuite de d ou fi_n)
      - coefs         : coefficients du polynôme (usage interne / débogage uniquement)
    """
    clefs = RSA(nb_bit)          # clefs[0] = (d, n), clefs[1] = (e, n), clefs[2] = fi_n
    d      = clefs[0][0]
    N      = clefs[0][1]
    e      = clefs[1][0]
    fi_n   = clefs[2]

    tab_clef = []
    coefs = generer_coef(d, seuil, fi_n)
    for i in range(1, n + 1):
        part = evaluer_polynome(coefs, i, fi_n)
        tab_clef.append((i, part))

    params_publics = {"N": N, "e": e}
    return tab_clef, params_publics, coefs, fi_n, d


if __name__ == "__main__":
    parts, params, coefs, fi_n, d = generer_clef(5, 3, 4)
    print(f"N={params['N']}, e={params['e']}")
    print("Parts générées :")
    for idx, part in parts:
        print(f"  f({idx}) = {part}")