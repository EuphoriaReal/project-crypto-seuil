from RSA import RSA
from secrets import randbelow


def generer_coef(d, seuil, modulo):
    """
    Génère les coefficients du polynôme de Shamir.
    f(x) = d + a1*x + a2*x^2 + ... + a_{seuil-1}*x^{seuil-1}

    Le premier coefficient est d (le secret), les suivants sont aléatoires.
    """
    coefs = [d]
    for _ in range(seuil - 1):
        coefs.append(randbelow(modulo))
    return coefs


def evaluer_polynome(coefs, x, modulo):
    """
    Évalue f(x) = coefs[0] + coefs[1]*x + coefs[2]*x^2 + ...  mod modulo

    CORRECTION : l'ancienne version ajoutait d deux fois et n'élevait pas x
    à la bonne puissance.
    """
    resultat = 0
    for i, coef in enumerate(coefs):
        resultat = (resultat + coef * pow(x, i, modulo)) % modulo
    return resultat


def calcul_clef(d, seuil, x, modulo):
    """
    Calcule la part f(x) pour le participant d'index x.
    """
    coefs = generer_coef(d, seuil, modulo)
    return evaluer_polynome(coefs, x, modulo)


def generer_clef(n, seuil):
    """
    Génère les clés RSA et distribue n parts avec un seuil donné.

    Retourne : (tab_clef, params_publics)
      - tab_clef      : liste de (index_i, part_fi) pour chaque participant
      - params_publics: dict avec N, e, fi_n (=lambda_N ici phi_N) pour usage externe
    """
    clefs = RSA(8)          # clefs[0] = (d, n), clefs[1] = (e, n), clefs[2] = fi_n
    d      = clefs[0][0]
    N      = clefs[0][1]
    e      = clefs[1][0]
    fi_n   = clefs[2]       # phi(N) utilisé comme modulo pour les exposants

    # Génération des parts : index commence à 1 (f(0) = d, à ne jamais distribuer)
    tab_clef = []
    coefs = generer_coef(d, seuil, fi_n)
    for i in range(1, n + 1):
        part = evaluer_polynome(coefs, i, fi_n)
        tab_clef.append((i, part))

    params_publics = {"N": N, "e": e, "fi_n": fi_n, "d": d}
    return tab_clef, params_publics


if __name__ == "__main__":
    parts, params = generer_clef(5, 3)
    print(f"N={params['N']}, e={params['e']}")
    print("Parts générées :")
    for idx, part in parts:
        print(f"  f({idx}) = {part}")
