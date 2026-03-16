from random import randint
from math import sqrt


#########################
#   Fonctions pour RSA  #
#########################

def test_de_primalite(number):
    """
    input : number : entier à tester -> int

    output : True si le nombre est premier, False sinon -> bool

    sémantique : Vérifie si l'entier fourni est un nombre premier.
    """
    if number <= 1:
        return False
    for i in range(2, int(sqrt(number))):
        if number % i == 0:
            return False
    return True

def calcul_pgcd(a, b):
    """
    input : a, b : int, int

    output : pgcd(a,b) : plus grand commun diviseur -> int

    sémantique : Calcule et retourne le pgcd des deux entiers donnés en entrée
                 en utilisant l'algorithme d'Euclide.
    """
    while b != 0:
        a, b = b, a % b
    return a


"""
Input : e(int), mod(int)
Output : int
sémantique : Calcule et retourne le modulo inverse de e par raport à mod
"""
def euclide(e, mod):
    results = []
    i = 0
    operand1 = mod
    operand2 = e
    reste = 1
    while reste != 0:
        result = operand1 // operand2
        results.append(result)
        reste = operand1%operand2
        operand1 = operand2
        operand2 = reste

    x = 1
    y = 0
    for j in range(len(results)-1, -1, -1):
        i+=1
        result = results[j]*y + x
        x = y
        y = result
    
    if i%2 == 1:
        return result
    else:
        result = -result
        return result + mod


"""
Input : m(int), e(int), n(int)
Output : int
sémantique : Calcule et retourne le résultat de l'oppération : m**e mod(n)
"""
def exponentiation_modulaire_rapide(m,e,n):
    bin_e = bin(e)[2:]
    calcul = m
    if bin_e[-1] == "1":
        result = m
    else:
        result = 1

    for i in range(len(bin_e)-2,-1,-1):
        calcul = calcul**2 % n
        if bin_e[i] == "1":
            result *= calcul
    
    return result%n


"""
Input : int
Output : list<tuple>
sémantique : Calcule et retourne les clefs privées et publics générées avec RSA sur n bits.  
"""
def RSA(nb_bits):
    #generation de p
    p = randint(2, 2**(nb_bits-1))
    while not test_de_primalite(p):
        p = randint(2, 2**(nb_bits-1))
    
    #generation de q
    q = randint(2, 2**(nb_bits-1))
    while not test_de_primalite(q) or q == p:
        q = randint(2, 2**(nb_bits-1))

    #calcul de n et fi de n
    n = p*q
    fi_n = (p-1) * (q-1)
    
    #generation de e et calcul de d
    e = randint(2, fi_n-1)
    while calcul_pgcd(e,fi_n) != 1:
        e = randint(2, fi_n-1)
    d = euclide(e, fi_n)

    return [(d,n), (e,n), fi_n]

