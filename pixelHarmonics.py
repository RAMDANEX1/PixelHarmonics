import wave
import io
import os
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding

def derive_key(password:str, salt:bytes):
    # derive de la clé de 256 bits a partir d'un mot de passe et d'un sel
    kdf=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000)
    return kdf.derive(password.encode('utf-8'))


def cacher_image():

    print("n ---[mode 1] CACHER UNE IMAGE DANS UN AUDIO ---")
    audio_path = input("entrer le chemin du fichier audio (.wav): ").strip()
    image_path = input("entrer le chemin de l'image a cacher (png ou jpg): ").strip() 
    output_path = input("entrer le nom du fichier audio de sortie (ex secret_voice.wav): ").strip()
    password = input("entrer le mot de passe pour chiffrer l'image : ")

    try:

        # charger l'image et la convertir en octets PNG compressés
        print(" + preparation de l'image...")
        img = Image.open(image_path)
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr,format="PNG")
        img_bytes = img_byte_arr.getvalue()

        #chiffrement Aes mode cbc de l'image
        print("+ chiffrement AES en cours ...")
        salt=os.urandom(16)
        iv = os.urandom(16)
        key = derive_key(password,salt)

        # padding pkcs7 requis pour Aes
        padder=padding.PKCS7(128).padder()
        padded_data = padder.update(img_bytes)+ padder.finalize()

        #chiffrement AES avec l'IV et la clé dérivée 
        cipher = Cipher(algorithms.AES(key),modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        #assemblage du payload : sel + iv + longueur de l'image + image chiffrée
        ciphertext_length = len(ciphertext)
        length_bytes = ciphertext_length.to_bytes(4,byteorder='big') # transformer la longeur de playload (image pade chiffre +iv + salt) (en octets) sur 4 octets en big endian

        payload = salt + iv +length_bytes + ciphertext

        # charger le fichier audio WAV
        print("+ lecture du fichier audio source...")
        with wave.open(audio_path,'rb') as audio:
            params = audio.getparams()
            frames = audio.readframes(audio.getnframes())
        frame_bytes=bytearray(frames)

        #verifie la capacité du fichier audio pour contenir l'image chiffrée
        required_bits=len(payload)*8
        if required_bits > len(frame_bytes):
            print("Erreur: le fichier audio est trop petit pour contenir l'image chiffrée!")
            return

        # convertir le payload en bits et les cacher dans les bits de poids faible des octets audio
        binary_payload = ''.join(format(byte,'08b') for byte in payload)

        # injection LSB
        print("+ injection des données dans le fichier audio...")
        for i in range(len(binary_payload)):
            frame_bytes[i] = (frame_bytes[i] & 254) | int(binary_payload[i]) # nrttoyer l'octet du frame ex( 11110111 et 11111110)  pour mettre le bit de poids faible a 0 et ensuite on met le bit du payload a la place

        # sauvegarder le fichier audio modifié
        print("+ sauvegarde du fichier audio modifié...")   
        with wave.open(output_path,'wb') as output_audio:
            output_audio.setparams(params)
            output_audio.writeframes(frame_bytes)

        print(f" + l'image a été cachée avec succès dans le fichier audio: {output_path}")

    except Exception as e:
            print(f"Erreur: {e}")

def extraire_image():

    print("\n--- [MODE 2] DÉCHIFFRER & EXTRAIRE UNE IMAGE DEPUIS UN AUDIO ---")
    audio_path = input("Entrez le chemin du fichier audio piégé (.wav) : ").strip()
    output_image_path = input("Entrez le chemin de l'image de sortie (ex: recovered.png) : ").strip()
    password = input("Entrez le mot de passe secret : ")

    try:
        # charger le fichier audio WAV et extraire les octets audio
            print("+ Analyse et lecture du fichier audio...")
            with wave.open(audio_path, 'rb') as audio:
             frames = audio.readframes(audio.getnframes())
             frame_bytes = bytearray(frames)

            # extraire les 16 premiers octets pour le sel, les 16 suivants pour l'IV et les 4 suivants pour la longueur de l'image
            header_bits=""
            for i in range(288):  # 16 (salt) + 16 (IV) + 4 (length) = 36 octets, soit 288 bits
                header_bits += str(frame_bytes[i] & 1)  # extraire le bit de poids faible

            # convertir les bits du header extraits en octets
            header_bytes = bytearray()
            for i in range(0,len(header_bits),8):
                byte = header_bits[i:i+8]
                header_bytes.append(int(byte,2))

            salt = bytes(header_bytes[0:16])
            iv = bytes(header_bytes[16:32])
            cipher_text_length = int.from_bytes(header_bytes[32:36], byteorder='big')
                
            print (f"taille des données chiffrées : {cipher_text_length} octets")

            # extraire les bits de l'image chiffrée
            total_bits_to_extract = 288+ cipher_text_length * 8
            if total_bits_to_extract > len(frame_bytes):
                print("Erreur: données chiffrées incomplètes ou fichier audio corrompu!")
                return
            
            cipher_text_bits=""
            for i in range(288, total_bits_to_extract):
                cipher_text_bits += str(frame_bytes[i] & 1)
            ciphertext_bytes = bytearray()

            for i in range(0,len(cipher_text_bits),8):
                ciphertext_bytes.append(int(cipher_text_bits[i:i+8],2))

            # dériver la clé à partir du mot de passe et du sel pour dechiffrer l'image extraite
            print("+ Déchiffrement AES en cours...")
            key = derive_key(password,salt)
            cipher = Cipher(algorithms.AES(key),modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(bytes(ciphertext_bytes)) + decryptor.finalize()

            #retirer le padding PKCS7 pour obtenir les octets de l'image originale
            unpadder = padding.PKCS7(128).unpadder()
            image_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()

            #sauvegarder l'image extraite
            print("+ Sauvegarde de l'image extraite...")
            image = Image.open(io.BytesIO(image_bytes))
            image.save(output_image_path)
            print(f" + l'image a été extraite avec succès et sauvegardée sous : {output_image_path}")

    except Exception as e:
            print(f"erreur (mot de passe incorrect ou fichier audio corrompu ou invalide): {e}")




if __name__ == "__main__":
 print("========================================")
 print("          PIXEL HARMONICS (AES)         ")
 print("      Audio Steganography Tool          ")
 print("========================================")
 print("Sélectionnez le mode :")
 print("  1. Chiffrer et cacher une image dans un WAV")
 print("  2. Déchiffrer et extraire une image d'un WAV")
    
 choix = input("\nVotre choix (1 ou 2) : ").strip()

 if choix == "1":
        cacher_image()
 elif choix == "2":
        extraire_image()
 else:
        print("[-] Choix invalide.")   