from random import randint


#########################
#   Fonctions pour RSA  #
#########################


def test_de_primalite(number, k=20):
    """
    Test de primalité de Miller-Rabin.

    Paramètres :
        number : entier à tester
        k      : nombre de rounds (défaut 20, erreur <= (1/4)^k)

    Retourne True si number est (probablement) premier.
    """
    if number <= 1:
        return False
    if number <= 3:
        return True
    if number % 2 == 0:
        return False

    # Écrire number-1 = 2^s * d avec d impair
    s, d = 0, number - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = randint(2, number - 2)
        x = pow(a, d, number)

        if x == 1 or x == number - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, number)
            if x == number - 1:
                break
        else:
            return False

    return True


def calcul_pgcd(a, b):
    """
    Calcule le PGCD de a et b (algorithme d'Euclide).
    """
    while b != 0:
        a, b = b, a % b
    return a


def generer_premier(nb_bits):
    """
    Génère un nombre premier aléatoire d'au plus nb_bits bits.
    """
    p = randint(2, 2 ** (nb_bits - 1))
    while not test_de_primalite(p):
        p = randint(2, 2 ** (nb_bits - 1))
    return p


def RSA(nb_bits):
    """
    Génère les clés RSA sur nb_bits bits.

    Retourne : [(d, n), (e, n), phi_n]
        - (d, n) : clé privée
        - (e, n) : clé publique
        - phi_n  : indicatrice d'Euler φ(n)
    """
    # Génération de p et q premiers distincts
    p = generer_premier(nb_bits)
    q = generer_premier(nb_bits)
    while q == p:
        q = generer_premier(nb_bits)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choisir e copremier avec φ(n), puis calculer d = e^(-1) mod φ(n)
    e = randint(2, phi_n - 1)
    while calcul_pgcd(e, phi_n) != 1:
        e = randint(2, phi_n - 1)
    d = pow(e, -1, phi_n)

    return [(d, n), (e, n), phi_n]
