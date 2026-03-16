from RSA_seuil import generer_clef
import numpy as np
import matplotlib.pyplot as plt


def afficher_polynome(tab_x, tab_y, coefs, deg):
    """
    Affiche le polynôme et sa courbe à partir :
    - tab_x, tab_y : les points (sans modulo, pour visualisation cohérente)
    - coefs : coefficients du polynôme en ordre croissant [a0, a1, a2, ...]
    - deg : degré du polynôme
    """
    p = np.poly1d(coefs[::-1])

    print("Polynôme :")
    print(p)

    x_courbe = np.linspace(min(tab_x), max(tab_x), 200)
    y_courbe = p(x_courbe)

    # Tracé
    plt.scatter(tab_x, tab_y, color='red', zorder=5, label="Points donnés")
    plt.plot(x_courbe, y_courbe, label="Polynôme interpolant")

    plt.xlabel("x")
    plt.ylabel("P(x)")
    plt.title(f"Polynome de degré {deg} (Shamir)")
    plt.legend()
    termes = []
    for i, coef in enumerate(coefs):
        if i == 0:
            termes.append(str(coef))
        elif i == 1:
            termes.append(f"{coef}x")
        else:
            termes.append(f"{coef}x^{i}")

    polynome_str = " + ".join(termes)
    plt.suptitle(f"A(x) = {polynome_str} --> Secret = {tab_y[0]}", y=0.02, fontsize=10, color="gray")
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    tab_clef, params_publics, coefs, fi_n, d = generer_clef(5, 3, 6)
    print(f"Modulo : {fi_n}")
    print(f"Clefs : {tab_clef   }")

    def evaluer_sans_modulo(coefs, x):
        resultat = 0
        for coef in reversed(coefs):
            resultat = resultat * x + coef
        return resultat

    tab_x = [0] + [elem[0] for elem in tab_clef]
    tab_y = [d] + [evaluer_sans_modulo(coefs, elem[0]) for elem in tab_clef]

    afficher_polynome(tab_x, tab_y, coefs, len(coefs) - 1)