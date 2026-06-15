# -*- coding: utf-8 -*-
"""
Interface locale interactive de vote avec vérification d'identité
Projet: Application de vote électronique (8INF874) - UQAC
"""

from paillier import Paillier, RSA

class Electeur:
    """Représente un citoyen votant identifié par son nom et prénom."""
    def __init__(self, prenom, nom):
        self.prenom = prenom
        self.nom = nom
        # L'identifiant unique devient "Prenom Nom" (ex: "Axel Grognet")
        self.identite = f"{prenom} {nom}"
        # Génération automatique de sa paire de clés de signature RSA
        self.pub_key_rsa, self.__priv_key_rsa = RSA.generate_keys()

    def voter(self, choix, cle_publique_paillier):
        """Chiffre le choix (Paillier) et signe le bulletin (RSA)."""
        # 1. Chiffrement (Confidentialité)
        bulletin_chiffre = Paillier.encrypt(cle_publique_paillier, choix)
        
        # 2. Signature du bloc chiffré (Authenticité et Intégrité)
        signature = RSA.sign(self.__priv_key_rsa, bulletin_chiffre)
        
        return bulletin_chiffre, signature


class UrneServeur:
    """Gère l'urne électorale et la vérification des droits de vote."""
    def __init__(self, pub_key_paillier):
        self.pub_key_paillier = pub_key_paillier
        self.bulletins_acceptes = []
        
        # Base de données d'identité : { "Prénom Nom": Clé_Publique_RSA }
        self.registre_identites = {}
        # Registre d'émargement pour interdire le double vote
        self.emargement = set()

    def enregistrer_citoyen(self, electeur: Electeur):
        """Inscrit officiellement l'électeur sur la liste électorale."""
        self.registre_identites[electeur.identite] = electeur.pub_key_rsa

    def verifier_et_deposer(self, identite, bulletin_chiffre, signature):
        """Vérifie l'identité et la signature avant d'accepter le bulletin."""
        # 1. Vérification de l'inscription
        if identite not in self.registre_identites:
            print(f"\n[URNE - REJET] L'individu '{identite}' n'est pas inscrit sur la liste électorale.")
            return False

        # 2. Vérification du double vote
        if identite in self.emargement:
            print(f"\n[URNE - REJET] Alerte ! '{identite}' a déjà voté. Tentative de fraude bloquée.")
            return False

        # 3. Vérification de la signature RSA (Prouve que c'est le bon émetteur et que rien n'a bougé)
        pub_key_rsa_attendue = self.registre_identites[identite]
        if not RSA.verify(pub_key_rsa_attendue, bulletin_chiffre, signature):
            print(f"\n[URNE - REJET] Signature invalide pour '{identite}'. Le bulletin semble altéré.")
            return False

        # Si tout est valide
        self.bulletins_acceptes.append(bulletin_chiffre)
        self.emargement.add(identite)
        print(f"\n[URNE - SUCCÈS] Bulletin de '{identite}' validé et inséré dans l'urne de manière anonyme.")
        return True

    def calculer_total_chiffre(self):
        """Additionne de manière homomorphe tous les bulletins sans les lire."""
        if not self.bulletins_acceptes:
            return Paillier.encrypt(self.pub_key_paillier, 0)
            
        total_chiffre = self.bulletins_acceptes[0]
        for bulletin in self.bulletins_acceptes[1:]:
            total_chiffre = Paillier.homomorphic_add(self.pub_key_paillier, total_chiffre, bulletin)
        return total_chiffre


class AutoriteElectorale:
    """Entité de confiance émettrice de la clé de l'élection et seule capable de décoder le total."""
    def __init__(self):
        self.pub_key, self.__priv_key = Paillier.generate_keys()
        
    def dechiffrer_resultat(self, ciphertext_total):
        return Paillier.decrypt(self.pub_key, self.__priv_key, ciphertext_total)


# ==========================================
# INTERFACE DE VOTE INTERACTIVE (CLI)
# ==========================================
if __name__ == "__main__":
    # Initialisation du système en arrière-plan
    autorite = AutoriteElectorale()
    cle_paillier = autorite.pub_key
    serveur_urne = UrneServeur(cle_paillier)

    # Simulation d'une liste électorale pré-enregistrée (les citoyens autorisés)
    base_citoyens = [
        Electeur("Axel", "Grognet"),
        Electeur("Rémi", "Drambricourt"),
        Electeur("Florentin", "Thullier")
    ]
    
    # Inscription de ces citoyens sur la liste de l'urne
    for citoyen in base_citoyens:
        serveur_urne.enregistrer_citoyen(citoyen)

    # Dictionnaire local pour retrouver l'objet Électeur par son nom lors de la saisie
    dictionnaire_electeurs = {c.identite.lower(): c for c in base_citoyens}

    print("=" * 60)
    print("      APPLICATION DE VOTE ÉLECTRONIQUE SECURISÉE")
    print("=" * 60)
    print("Citoyens inscrits d'office : Axel Grognet, Rémi Drambricourt (présent pour l'exemple seulement)")
    
    en_cours = True
    while en_cours:
        print("\n--- MENU PRINCIPAL ---")
        print("1. Accéder à l'isoloir pour voter")
        print("2. Clôturer le scrutin et afficher le résultat")
        print("3. Quitter l'application")
        
        choix_menu = input("Votre choix (1-3) : ").strip()

        if choix_menu == "1":
            print("\n--- ISOLOIR VIRTUEL ---")
            prenom_saisi = input("Entrez votre Prénom : ").strip()
            nom_saisi = input("Entrez votre Nom : ").strip()
            identite_saisie = f"{prenom_saisi} {nom_saisi}"
            identite_cle = identite_saisie.lower()

            # Est-ce que cette personne existe physiquement dans notre simulation ?
            if identite_cle in dictionnaire_electeurs:
                electeur_actuel = dictionnaire_electeurs[identite_cle]
                
                print(f"\nBonjour {electeur_actuel.identite}.")
                print("Question : Approuvez-vous le projet de cryptographie ?")
                print("1. OUI")
                print("2. NON")
                
                vote_saisi = input("Votre vote (1 ou 2) : ").strip()
                if vote_saisi in ["1", "2"]:
                    valeur_vote = 1 if vote_saisi == "1" else 0
                    
                    # Le client génère le bulletin chiffré et sa signature numérique
                    bulletin_c, signature = electeur_actuel.voter(valeur_vote, cle_paillier)
                    
                    print(f"\n[INFO CLIENT] Clé privée RSA activée pour signer.")
                    print(f" -> Aperçu du bulletin chiffré envoyé : {bulletin_c}")
                    
                    # Envoi à l'urne pour validation et dépôt
                    serveur_urne.verifier_et_deposer(electeur_actuel.identite, bulletin_c, signature)
                else:
                    print("Vote invalide. Opération annulée.")
            else:
                # Si le nom n'est pas dans la base, on simule un intrus non inscrit
                print(f"\n[INFO CLIENT] Génération d'une identité non enregistrée...")
                intrus = Electeur(prenom_saisi, nom_saisi)
                bulletin_c, signature = intrus.voter(1, cle_paillier)
                
                # L'urne va devoir analyser cette demande
                serveur_urne.verifier_et_deposer(identite_saisie, bulletin_c, signature)

        elif choix_menu == "2":
            print("\n--- FERMETURE DE L'URNE ET DÉPOUILLEMENT ---")
            total_votants = len(serveur_urne.emargement)
            
            if total_votants == 0:
                print("Aucun bulletin n'a été déposé. Impossible de procéder au dépouillement.")
                continue
                
            # 1. L'urne calcule la somme homomorphe des ciphertexts
            total_chiffre = serveur_urne.calculer_total_chiffre()
            print(f" -> Somme homomorphe calculée par l'urne : {total_chiffre}")
            print(" -> Envoi du bloc chiffré à l'Autorité Électorale...")
            
            # 2. L'autorité utilise sa clé privée Paillier pour casser l'enveloppe globale
            oui_recus = autorite.dechiffrer_resultat(total_chiffre)
            non_recus = total_votants - oui_recus
            
            print("\n" + "="*40)
            print("         RÉSULTATS DU SCRUTIN")
            print("="*40)
            print(f" Émargements enregistrés : {total_votants}")
            print(f" Votes 'OUI'             : {oui_recus}")
            print(f" Votes 'NON'             : {non_recus}")
            print("=" * 40)
            
            # Arrêt de l'élection après le dépouillement
            en_cours = False

        elif choix_menu == "3":
            print("Fermeture de l'application.")
            en_cours = False
        else:
            print("Option inconnue, veuillez recommencer.")