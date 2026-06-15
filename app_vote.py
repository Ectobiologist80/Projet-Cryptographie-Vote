# -*- coding: utf-8 -*-
"""
Application de vote électronique sécurisée (Interface Graphique)
Projet de session: Cryptographie (8INF874) - UQAC
Utilisation des bibliothèques officielles : 'phe' et 'pycryptodome'
"""

import customtkinter as ctk

# --- IMPORTATIONS DES MODULES OFFICIELS DE CRYPTOGRAPHIE ---
from phe import paillier
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Configuration visuelle globale de CustomTkinter
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# =====================================================================
# ENCAPSULATION DES MODULES OFFICIELS (Paillier & RSA)
# =====================================================================
class PaillierControleur:
    @staticmethod
    def generate_keys():
        # Génère une paire de clés industrielles sécurisées
        return paillier.generate_paillier_keypair(n_length=2048)

    @staticmethod
    def encrypt(public_key, message):
        # Utilise l'implémentation officielle pour chiffrer
        return public_key.encrypt(message)

    @staticmethod
    def decrypt(private_key, ciphertext):
        # Déchiffre le score cumulé ou individuel
        return private_key.decrypt(ciphertext)


class RSAControleur:
    @staticmethod
    def generate_keys():
        # Génère une vraie clé RSA de 2048 bits conforme aux standards
        key = RSA.generate(2048)
        private_key = key
        public_key = key.publickey()
        return public_key, private_key

    @staticmethod
    def sign(private_key, ciphertext_obj):
        # 1. On transforme le ciphertext Paillier en chaîne de caractères puis en bytes
        data_bytes = str(ciphertext_obj.ciphertext()).encode('utf-8')
        # 2. On applique un hachage SHA-256 standardisé (requis par PKCS#1 v1.5)
        h = SHA256.new(data_bytes)
        # 3. On signe le hachage avec la clé privée
        signature = pkcs1_15.new(private_key).sign(h)
        return signature

    @staticmethod
    def verify(public_key, ciphertext_obj, signature):
        data_bytes = str(ciphertext_obj.ciphertext()).encode('utf-8')
        h = SHA256.new(data_bytes)
        try:
            # Vérifie la validité de la signature selon le standard PKCS#1 v1.5
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False


class ElecteurSimulation:
    def __init__(self, prenom, nom, mot_de_passe):
        self.prenom = prenom
        self.nom = nom
        self.identite = f"{prenom} {nom}"
        self.mot_de_passe = mot_de_passe
        # Initialisation via les clés officielles durcies
        self.pub_key_rsa, self.__priv_key_rsa = RSAControleur.generate_keys()

    def verifier_mot_de_passe(self, mdp_saisi):
        return self.mot_de_passe == mdp_saisi

    def voter(self, choix, cle_paillier_publique):
        # Chiffrement officiel Paillier
        bulletin_c = PaillierControleur.encrypt(cle_paillier_publique, choix)
        # Signature officielle RSA PKCS#1 v1.5
        signature = RSAControleur.sign(self.__priv_key_rsa, bulletin_c)
        return bulletin_c, signature


# =====================================================================
# INTERFACE GRAPHIQUE (GUI)
# =====================================================================
class AppVoteEcheance(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Système de Vote Homomorphe - Spécifications Officielles")
        self.geometry("800x720")
        self.resizable(False, False)

        # Initialisation sécurisée
        self.p_pub, self.p_priv = PaillierControleur.generate_keys()
        self.bulletins_acceptes = []
        self.emargement = set()
        self.liste_electorale = {}
        
        # Liste officielle stable
        self.ajouter_individu_liste("Axel", "Grognet", "axel123")
        self.ajouter_individu_liste("Toto", "Test", "toto456")
        self.ajouter_individu_liste("Rémi", "Dambricourt", "remi789")
        self.ajouter_individu_liste("John", "Vote", "john000")

        self.container = ctk.CTkFrame(self)
        self.container.pack(side="top", fill="both", expand=True, padx=20, pady=20)

        self.creer_ecran_connexion()

    def ajouter_individu_liste(self, prenom, nom, mot_de_passe):
        nouvel_electeur = ElecteurSimulation(prenom, nom, mot_de_passe)
        cle_minuscule = f"{prenom} {nom}".lower()
        self.liste_electorale[cle_minuscule] = nouvel_electeur

    def nettoyer_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def creer_ecran_connexion(self):
        self.nettoyer_container()

        label_titre = ctk.CTkLabel(self.container, text="🗳️ Système de Vote Électronique (Production)", font=("Arial", 24, "bold"))
        label_titre.pack(pady=20)

        frame_form = ctk.CTkFrame(self.container)
        frame_form.pack(pady=15, padx=50, fill="x")

        label_instructions = ctk.CTkLabel(frame_form, text="Veuillez vous identifier pour accéder à l'isoloir :", font=("Arial", 14, "italic"))
        label_instructions.pack(pady=10)

        self.entry_prenom = ctk.CTkEntry(frame_form, placeholder_text="Prénom", width=300)
        self.entry_prenom.pack(pady=8)

        self.entry_nom = ctk.CTkEntry(frame_form, placeholder_text="Nom", width=300)
        self.entry_nom.pack(pady=8)

        self.entry_password = ctk.CTkEntry(frame_form, placeholder_text="Mot de passe", show="*", width=300)
        self.entry_password.pack(pady=8)

        self.label_status = ctk.CTkLabel(self.container, text="", text_color="red", font=("Arial", 13, "bold"))
        self.label_status.pack(pady=5)

        btn_connexion = ctk.CTkButton(self.container, text="Entrer dans l'isoloir", command=self.action_connexion, width=200, height=40)
        btn_connexion.pack(pady=10)

        btn_admin = ctk.CTkButton(self.container, text="Tableau de bord de l'Urne", fg_color="gray", hover_color="#555555", command=self.creer_ecran_urne, width=200)
        btn_admin.pack(pady=25)

    def action_connexion(self):
        prenom = self.entry_prenom.get().strip()
        nom = self.entry_nom.get().strip()
        password = self.entry_password.get().strip()
        identite_recherche = f"{prenom} {nom}".lower()

        if not prenom or not nom or not password:
            self.label_status.configure(text="❌ Veuillez remplir tous les champs.")
            return

        if identite_recherche in self.emargement:
            self.label_status.configure(text="❌ Sécurité : Vous avez déjà émargé et voté !")
            return

        if identite_recherche in self.liste_electorale:
            electeur = self.liste_electorale[identite_recherche]
            if electeur.verifier_mot_de_passe(password):
                self.label_status.configure(text="") 
                self.creer_ecran_isoloir(electeur)
            else:
                self.label_status.configure(text="❌ Authentification échouée : Mot de passe incorrect.")
        else:
            self.label_status.configure(text="❌ Accès refusé : Identité introuvable sur les listes.")

    def creer_ecran_isoloir(self, electeur):
        self.nettoyer_container()

        label_user = ctk.CTkLabel(self.container, text=f"Isoloir de : {electeur.identite}", font=("Arial", 20, "bold"))
        label_user.pack(pady=15)

        label_question = ctk.CTkLabel(self.container, text="Question : Approuvez-vous le prototype de cryptographie ?", font=("Arial", 15))
        label_question.pack(pady=15)

        self.vote_var = ctk.StringVar(value="1")
        radio_oui = ctk.CTkRadioButton(self.container, text="OUI", variable=self.vote_var, value="1")
        radio_oui.pack(pady=5)
        radio_non = ctk.CTkRadioButton(self.container, text="NON", variable=self.vote_var, value="0")
        radio_non.pack(pady=5)

        frame_tech = ctk.CTkFrame(self.container)
        frame_tech.pack(pady=15, padx=30, fill="both", expand=True)

        label_tech_title = ctk.CTkLabel(frame_tech, text="Aperçu des opérations cryptographiques standardisées :", font=("Arial", 12, "bold"))
        label_tech_title.pack(pady=5)

        self.txt_crypto = ctk.CTkTextbox(frame_tech, height=120, activate_scrollbars=True)
        self.txt_crypto.pack(fill="both", expand=True, padx=10, pady=5)
        self.txt_crypto.insert("0.0", "En attente de la validation de votre choix...")

        self.frame_actions_isoloir = ctk.CTkFrame(self.container, fg_color="transparent")
        self.frame_actions_isoloir.pack(pady=15, fill="x")

        self.btn_voter = ctk.CTkButton(self.frame_actions_isoloir, text="Chiffrer & Envoyer (Format Industriel)", fg_color="green", hover_color="darkgreen", command=lambda: self.action_voter(electeur), height=40)
        self.btn_voter.pack(side="top", pady=5)

    def action_voter(self, electeur):
        choix = int(self.vote_var.get())
        
        bulletin_c, signature = electeur.voter(choix, self.p_pub)

        # Extraction de la valeur numérique brute du chiffrement officiel pour l'affichage hexadécimal
        cipher_hex = hex(bulletin_c.ciphertext())[:60] + "..."
        sig_hex = signature.hex()[:60] + "..."

        self.txt_crypto.delete("0.0", "end")
        self.txt_crypto.insert("0.0", f"[CLIENT] Vote clair : {choix}\n")
        self.txt_crypto.insert("end", f"[CLIENT] Ciphertext Paillier (phe) : {cipher_hex}\n\n")
        self.txt_crypto.insert("end", f"[CLIENT] Signature RSA PKCS#1 v1.5 (PyCryptodome) : {sig_hex}\n\n")
        self.txt_crypto.insert("end", "[URNE] Validé par l'autorité.")

        self.btn_voter.configure(state="disabled", text="Bulletin archivé ✔")

        self.traitement_urne_silencieux(electeur.identite, bulletin_c, signature)

        btn_quitter_isoloir = ctk.CTkButton(self.frame_actions_isoloir, text="Quitter l'isoloir", fg_color="#333333", hover_color="#555555", command=self.creer_ecran_connexion)
        btn_quitter_isoloir.pack(side="top", pady=5)

    def traitement_urne_silencieux(self, identite, bulletin_c, signature):
        identite_cle = identite.lower()
        pub_key_rsa = self.liste_electorale[identite_cle].pub_key_rsa
        
        # Vérification robuste via PyCryptodome
        if RSAControleur.verify(pub_key_rsa, bulletin_c, signature):
            self.bulletins_acceptes.append(bulletin_c)
            self.emargement.add(identite_cle)
            print(f"[URNE] Bulletin validé mathématiquement pour {identite}")

    def creer_ecran_urne(self):
        self.nettoyer_container()

        label_titre = ctk.CTkLabel(self.container, text="📊 Tableau de bord de l'Urne", font=("Arial", 22, "bold"))
        label_titre.pack(pady=15)

        frame_list = ctk.CTkFrame(self.container)
        frame_list.pack(pady=15, padx=50, fill="both", expand=True)

        label_emarg = ctk.CTkLabel(frame_list, text="Registre des émargements (Qui a voté ?) :", font=("Arial", 13, "bold"))
        label_emarg.pack(pady=5)

        txt_emarg = ctk.CTkTextbox(frame_list, height=100)
        txt_emarg.pack(fill="both", expand=True, padx=15, pady=5)
        
        if self.emargement:
            for nom in self.emargement:
                txt_emarg.insert("end", f"✓ {nom.title()}\n")
        else:
            txt_emarg.insert("end", "Aucun vote enregistré pour le moment.")

        frame_crypto = ctk.CTkFrame(self.container)
        frame_crypto.pack(pady=10, padx=50, fill="x")

        label_somme = ctk.CTkLabel(frame_crypto, text="État actuel de l'urne (Agrégation homomorphe via opérateur + de 'phe') :", font=("Arial", 12, "bold"))
        label_somme.pack(pady=5)

        if self.bulletins_acceptes:
            # MAGIE DE 'PHE' : L'opérateur "+" est surchargé et gère la multiplication homomorphe automatiquement sous le capot !
            total_chiffre = self.bulletins_acceptes[0]
            for b in self.bulletins_acceptes[1:]:
                total_chiffre = total_chiffre + b
            preview_text = hex(total_chiffre.ciphertext())[:120] + "..."
        else:
            preview_text = "Urne vide."

        lbl_val_crypto = ctk.CTkLabel(frame_crypto, text=preview_text, text_color="cyan", wraplength=600, font=("Consolas", 11))
        lbl_val_crypto.pack(pady=5, padx=10)

        btn_depouiller = ctk.CTkButton(self.container, text="🔒 Dépouiller l'urne (Déchiffrement Centralisé)", fg_color="#A349A4", hover_color="#803380", command=self.action_depouillement, height=40)
        btn_depouiller.pack(pady=10)

        btn_retour = ctk.CTkButton(self.container, text="Retour à l'accueil", fg_color="gray", command=self.creer_ecran_connexion)
        btn_retour.pack(pady=5)

    def action_depouillement(self):
        if not self.bulletins_acceptes:
            return

        total_chiffre = self.bulletins_acceptes[0]
        for b in self.bulletins_acceptes[1:]:
            total_chiffre = total_chiffre + b

        # Déchiffrement officiel via la clé privée Paillier
        votes_oui = PaillierControleur.decrypt(self.p_priv, total_chiffre)
        total_votes = len(self.emargement)
        votes_non = total_votes - votes_oui

        result_text = f"Total des bulletins : {total_votes}\n\n🟢 Votes OUI : {votes_oui}\n🔴 Votes NON : {votes_non}"
        
        msg_box = ctk.CTkToplevel(self)
        msg_box.title("Résultats officiels du scrutin")
        msg_box.geometry("400x250")
        msg_box.transient(self)
        msg_box.grab_set()

        lbl_res = ctk.CTkLabel(msg_box, text=result_text, font=("Arial", 16, "bold"), pady=40)
        lbl_res.pack()
        
        btn_close = ctk.CTkButton(msg_box, text="Fermer cette fenêtre", command=msg_box.destroy)
        btn_close.pack(pady=10)


if __name__ == "__main__":
    app = AppVoteEcheance()
    app.mainloop()