import streamlit as st
import os

# --- Vernam Cipher Functions ---

ALPHABET_SIZE = 26
ASCII_A_UPPER = ord('A')
ASCII_A_LOWER = ord('a')

def _process_char_vernam(char, key_char, mode):
    """
    Helper function to process a single character for Vernam cipher (additive modulo 26).
    Ayuda a la función para procesar un solo carácter para el cifrado de Vernam (aditivo módulo 26).
    
    Args:
        char (str): The character from the message/ciphertext.
        key_char (str): The corresponding character from the key.
        mode (str): 'encrypt' or 'decrypt'.
        
    Returns:
        str: The processed character.
    """
    if not char.isalpha():
        return char # Non-alphabetic characters remain unchanged
    
    char_offset = 0
    if char.isupper():
        char_offset = ASCII_A_UPPER
    else:
        char_offset = ASCII_A_LOWER

    # Convert key character to its 0-25 numerical value
    key_val = ord(key_char.upper()) - ASCII_A_UPPER

    # Convert message character to its 0-25 numerical value
    char_val = ord(char) - char_offset

    if mode == 'encrypt':
        new_char_val = (char_val + key_val) % ALPHABET_SIZE
    elif mode == 'decrypt':
        new_char_val = (char_val - key_val + ALPHABET_SIZE) % ALPHABET_SIZE
    else:
        raise ValueError("Mode must be 'encrypt' or 'decrypt'")

    return chr(new_char_val + char_offset)

def cifrar_vernam(message, key):
    """
    Encrypts a message using the Vernam cipher (additive modulo 26).
    Cifra un mensaje usando el cifrado de Vernam (aditivo módulo 26).
    
    Args:
        message (str): The plaintext message.
        key (str): The one-time pad key. Must be at least as long as the message's alphabetic characters.
        
    Returns:
        str: The ciphertext.
    """
    processed_message = "".join(char for char in message if char.isalpha())
    processed_key = "".join(char for char in key if char.isalpha())

    if len(processed_key) < len(processed_message):
        raise ValueError("La clave debe ser al menos tan larga como el mensaje (solo caracteres alfabéticos).")
    
    ciphertext = []
    key_idx = 0
    
    for char in message:
        if char.isalpha():
            if key_idx < len(processed_key): # Ensure key_idx is within bounds of processed_key
                processed_char = _process_char_vernam(char, processed_key[key_idx], 'encrypt')
                ciphertext.append(processed_char)
                key_idx += 1
            else:
                # This case should ideally not be reached if key length validation is strict
                ciphertext.append(char) # Fallback: keep original char if key runs out
        else:
            ciphertext.append(char) # Non-alphabetic characters remain unchanged
            
    return "".join(ciphertext)

def descifrar_vernam(ciphertext, key):
    """
    Decrypts a message using the Vernam cipher (additive modulo 26).
    Descifra un mensaje usando el cifrado de Vernam (aditivo módulo 26).
    
    Args:
        ciphertext (str): The ciphertext.
        key (str): The one-time pad key. Must be at least as long as the ciphertext's alphabetic characters.
        
    Returns:
        str: The plaintext.
    """
    processed_ciphertext = "".join(char for char in ciphertext if char.isalpha())
    processed_key = "".join(char for char in key if char.isalpha())

    if len(processed_key) < len(processed_ciphertext):
        raise ValueError("La clave debe ser al menos tan larga como el texto cifrado (solo caracteres alfabéticos).")

    plaintext = []
    key_idx = 0
    
    for char in ciphertext:
        if char.isalpha():
            if key_idx < len(processed_key): # Ensure key_idx is within bounds of processed_key
                processed_char = _process_char_vernam(char, processed_key[key_idx], 'decrypt')
                plaintext.append(processed_char)
                key_idx += 1
            else:
                # This case should ideally not be reached if key length validation is strict
                plaintext.append(char) # Fallback: keep original char if key runs out
        else:
            plaintext.append(char) # Non-alphabetic characters remain unchanged
            
    return "".join(plaintext)

# --- Streamlit User Interface ---

st.set_page_config(page_title="Cifrador de Vernam", layout="centered")

st.title("🔐 Cifrador de Vernam")
st.subheader("(One-Time Pad)")
st.markdown("---")
st.write("Script desarrollado por **Marcos Sebastian Cunioli** - Especialista en Ciberseguridad")
st.markdown("---")

# Encryption Section
st.header("Cifrar Mensaje")
message_to_encrypt = st.text_area("Ingrese el mensaje a cifrar:", height=100, key="encrypt_message")
key_encrypt = st.text_area("Ingrese la clave (debe ser al menos tan larga como el mensaje y contener solo letras):", height=100, key="key_encrypt")

if st.button("Cifrar Mensaje", key="btn_encrypt"):
    if message_to_encrypt and key_encrypt:
        try:
            encrypted_text = cifrar_vernam(message_to_encrypt, key_encrypt)
            st.success(f"**Texto cifrado:** `{encrypted_text}`")
            st.download_button(
                label="Descargar Texto Cifrado",
                data=encrypted_text,
                file_name="mensaje_cifrado_vernam.txt",
                mime="text/plain"
            )
        except ValueError as e:
            st.error(f"Error al cifrar: {e}")
        except Exception as e:
            st.error(f"Error inesperado al cifrar: {e}")
    else:
        st.warning("Por favor, ingrese un mensaje y una clave para cifrar.")

st.markdown("---")

# Decryption Section
st.header("Descifrar Mensaje")

decryption_option = st.radio(
    "¿Cómo desea descifrar el mensaje?",
    ("Ingresar texto cifrado directamente", "Cargar desde un archivo"),
    key="decryption_option"
)

st.info("Para descifrar, asegúrese de usar la misma 'Clave' que se usó para cifrar. La clave debe ser al menos tan larga como el texto cifrado.")

if decryption_option == "Ingresar texto cifrado directamente":
    ciphertext_input = st.text_area("Ingrese el texto cifrado:", height=100, key="decrypt_input")
    key_decrypt_input = st.text_area("Ingrese la clave (debe coincidir con la clave de cifrado y ser al menos tan larga como el texto cifrado):", height=100, key="key_decrypt_input")

    if st.button("Descifrar Texto", key="btn_decrypt_input"):
        if ciphertext_input and key_decrypt_input:
            try:
                decrypted_text = descifrar_vernam(ciphertext_input, key_decrypt_input)
                st.info(f"**Texto descifrado:** `{decrypted_text}`")
            except ValueError as e:
                st.error(f"Error al descifrar: {e}")
            except Exception as e:
                st.error(f"Error inesperado al descifrar: {e}")
        else:
            st.warning("Por favor, ingrese el texto cifrado y la clave para descifrar.")

elif decryption_option == "Cargar desde un archivo":
    uploaded_file = st.file_uploader("Cargue un archivo de texto (.txt) con el mensaje cifrado:", type="txt", key="file_uploader")
    key_decrypt_file = st.text_area("Ingrese la clave (debe coincidir con la clave de cifrado y ser al menos tan larga como el texto cifrado):", height=100, key="key_decrypt_file")

    if st.button("Descifrar Archivo", key="btn_decrypt_file"):
        if uploaded_file is not None and key_decrypt_file:
            content_from_file = uploaded_file.read().decode("utf-8").strip()
            if content_from_file:
                try:
                    decrypted_text = descifrar_vernam(content_from_file, key_decrypt_file)
                    st.info(f"**Texto descifrado desde archivo:** `{decrypted_text}`")
                except ValueError as e:
                    st.error(f"Error al descifrar: {e}")
                except Exception as e:
                    st.error(f"Error inesperado al descifrar: {e}")
            else:
                st.error("El archivo cargado está vacío o no se pudo leer.")
        else:
            st.warning("Por favor, cargue un archivo y una clave válida para descifrar.")

st.markdown("---")
st.markdown("Una herramienta de criptografía clásica para fines educativos y demostrativos.")
