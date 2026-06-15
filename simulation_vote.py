"""
Architecture logicielle et simulation du scrutin
Projet: Application de vote électronique
"""

from paillier import Paillier, RSA

class Electeur:
    def __init__(self, id):
        self.id = id
        self.pub_key_rsa, self.__priv_key_rsa = RSA.generate_keys()

    def voter(self, choix, cle_publique_paillier):
        bulletin_chiffre = Paillier.encrypt(cle_publique_paillier, choix)
        signature = RSA.sign(self.__priv_key_rsa, bulletin_chiffre)
        
        return bulletin_chiffre, signature

class AutoriteElectorale:
    def __init__(self):
        self.pub_key, self.__priv_key = Paillier.generate_keys()
        
    def obtenir_cle_publique(self):
        return self.pub_key
        
    def dechiffrer_resultat(self, ciphertext_total):
        return Paillier.decrypt(self.pub_key, self.__priv_key, ciphertext_total)


class UrneServeur:
    def __init__(self, pub_key_paillier):
        self.pub_key_paillier = pub_key_paillier
        self.bulletins_acceptes = []
        self.liste_electorale = {}
        self.emargement = set()

    def enregistrer_electeur(self, electeur: Electeur):
        self.liste_electorale[electeur.id] = electeur.pub_key_rsa

    def recevoir_bulletin(self, id, bulletin_chiffre, signature):
        print(f"\n[Traitement Urne] Réception du bulletin de : {id}")

        if id not in self.liste_electorale:
            print(f" -> REJET : L'individu {id} n'est pas sur la liste électorale.")
            return False

        if id in self.emargement:
            print(f" -> REJET : Tentative de double vote détectée pour {id} !")
            return False

        pub_key_rsa_electeur = self.liste_electorale[id]
        if not RSA.verify(pub_key_rsa_electeur, bulletin_chiffre, signature):
            print(" -> REJET : Signature RSA invalide ! Le bulletin a été altéré ou usurpé.")
            return False

        self.bulletins_acceptes.append(bulletin_chiffre)
        self.emargement.add(id)
        print(f" -> SUCCÈS : Bulletin chiffré validé et inséré dans l'urne.")
        return True

    def calculer_total_chiffre(self):
        if not self.bulletins_acceptes:
            return Paillier.encrypt(self.pub_key_paillier, 0)
            
        total_chiffre = self.bulletins_acceptes[0]
        for bulletin in self.bulletins_acceptes[1:]:
            total_chiffre = Paillier.homomorphic_add(self.pub_key_paillier, total_chiffre, bulletin)
        return total_chiffre


# ==========================================
# SCÉNARIO DE TEST LOCAL COMPLET
# ==========================================
if __name__ == "__main__":
    print("=" * 60)
    print("  SIMULATION COMPLETE DU VOTE ÉLECTRONIQUE LOCAL (PAILLIER + RSA)")
    print("=" * 60)

    autorite = AutoriteElectorale()
    cle_paillier = autorite.obtenir_cle_publique()
    serveur_urne = UrneServeur(cle_paillier)

    axel = Electeur("signaxel")
    remi = Electeur("signremi")
    intrus = Electeur("signintrus")

    serveur_urne.enregistrer_electeur(axel)
    serveur_urne.enregistrer_electeur(remi)

    print("\n--- PHASE DE SCRUTIN ---")

    bulletin_c, sign = axel.voter(1, cle_paillier)
    print(f" -> Bulletin brut d'axel chiffré (Paillier) : {bulletin_c}") #juste pour tester
    serveur_urne.recevoir_bulletin(axel.id, bulletin_c, sign)

    bulletin_c, sign = remi.voter(0, cle_paillier)
    serveur_urne.recevoir_bulletin(remi.id, bulletin_c, sign)

    bulletin_c, sign = axel.voter(1, cle_paillier)
    serveur_urne.recevoir_bulletin(axel.id, bulletin_c, sign)

    bulletin_c, sign = intrus.voter(1, cle_paillier)
    serveur_urne.recevoir_bulletin(intrus.id, bulletin_c, sign)

    print("\n--- PHASE DE DÉPOUILLEMENT ---")

    total_chiffre = serveur_urne.calculer_total_chiffre()
    total_oui = autorite.dechiffrer_resultat(total_chiffre)
    total_non = len(serveur_urne.emargement) - total_oui

    print("-" * 45)
    print(" RÉSULTATS DU SCRUTIN VALIDÉS :")
    print(f" - Total des votants vérifiés : {len(serveur_urne.emargement)}")
    print(f" - Votes 'OUI' : {total_oui}")
    print(f" - Votes 'NON' : {total_non}")
    print("=" * 60)