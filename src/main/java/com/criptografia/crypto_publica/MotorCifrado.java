/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.criptografia.crypto_publica;

/**
 *
 * @author washi
 */
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Clase encargada del cifrado y descifrado de mensajes.
 * 
 * Soporta dos modos:
 * 1. Cifrado RSA directo (para mensajes pequeños)
 * 2. Cifrado híbrido con ECC: usa AES para cifrar el contenido 
 *    y RSA/EC para proteger la clave AES (mejor rendimiento para datos grandes)
 * 
 * Formato de salida del cifrado híbrido:
 * [Clave AES cifrada con RSA (Base64)] + "||SEPARATOR||" + [Mensaje cifrado con AES (Base64)]
 */
public class MotorCifrado {

    // Algoritmos y transformaciones
    private static final String TRANSFORMACION_RSA    = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String ALGORITMO_AES         = "AES";
    private static final String TRANSFORMACION_AES    = "AES/GCM/NoPadding";
    private static final int    TAMANIO_IV_GCM        = 12; // 12 bytes recomendado para GCM
    private static final int    TAMANIO_TAG_GCM       = 128; // 128 bits para el tag de autenticación
    private static final String SEPARADOR_HIBRIDO    = "||SEPARATOR||";

    /**
     * Cifra un mensaje usando RSA directamente.
     * Limitación: solo puede cifrar mensajes pequeños (< tamaño clave en bytes - overhead de padding).
     *
     * @param mensajeOriginal Texto plano a cifrar
     * @param clavePub        Clave pública RSA del receptor
     * @return Mensaje cifrado en Base64
     * @throws Exception si el cifrado falla
     */
    public static String cifrarRSA(String mensajeOriginal, PublicKey clavePub) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMACION_RSA);
        cipher.init(Cipher.ENCRYPT_MODE, clavePub);
        byte[] cifrado = cipher.doFinal(mensajeOriginal.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(cifrado);
    }

    /**
     * Descifra un mensaje que fue cifrado con RSA.
     *
     * @param mensajeCifrado Texto cifrado en Base64
     * @param clavePriv      Clave privada RSA correspondiente
     * @return Mensaje original descifrado
     * @throws Exception si el descifrado falla
     */
    public static String descifrarRSA(String mensajeCifrado, PrivateKey clavePriv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMACION_RSA);
        cipher.init(Cipher.DECRYPT_MODE, clavePriv);
        byte[] descifrado = cipher.doFinal(Base64.getDecoder().decode(mensajeCifrado));
        return new String(descifrado, "UTF-8");
    }

    /**
     * Cifrado híbrido: genera una clave AES aleatoria, cifra el mensaje con AES-GCM,
     * y luego cifra la clave AES con RSA. Permite cifrar mensajes de cualquier tamaño.
     *
     * @param mensajeOriginal Texto plano a cifrar
     * @param clavePubRSA     Clave pública RSA para proteger la clave AES
     * @return String con formato: [ClavAES_cifrada]||SEPARATOR||[Mensaje_cifrado]
     * @throws Exception si el cifrado falla
     */
    public static String cifrarHibrido(String mensajeOriginal, PublicKey clavePubRSA) throws Exception {
        // 1. Generar clave AES aleatoria (256 bits)
        KeyGenerator genAES = KeyGenerator.getInstance(ALGORITMO_AES);
        genAES.init(256, new SecureRandom());
        SecretKey claveAES = genAES.generateKey();

        // 2. Generar IV aleatorio para AES-GCM
        byte[] iv = new byte[TAMANIO_IV_GCM];
        new SecureRandom().nextFloat();
//        new SecureRandom().nextFill(iv);

        // 3. Cifrar el mensaje con AES-GCM
        Cipher cipherAES = Cipher.getInstance(TRANSFORMACION_AES);
        javax.crypto.spec.GCMParameterSpec paramGCM = new javax.crypto.spec.GCMParameterSpec(TAMANIO_TAG_GCM, iv);
        cipherAES.init(Cipher.ENCRYPT_MODE, claveAES, paramGCM);
        byte[] mensajeCifrado = cipherAES.doFinal(mensajeOriginal.getBytes("UTF-8"));

        // 4. Concatenar IV + mensaje cifrado (el IV es necesario para descifrar)
        byte[] ivMasMensaje = new byte[iv.length + mensajeCifrado.length];
        System.arraycopy(iv, 0, ivMasMensaje, 0, iv.length);
        System.arraycopy(mensajeCifrado, 0, ivMasMensaje, iv.length, mensajeCifrado.length);

        // 5. Cifrar la clave AES con RSA (la protege para el transporte)
        Cipher cipherRSA = Cipher.getInstance(TRANSFORMACION_RSA);
        cipherRSA.init(Cipher.ENCRYPT_MODE, clavePubRSA);
        byte[] claveAES_cifrada = cipherRSA.doFinal(claveAES.getEncoded());

        // 6. Combinar ambas partes en un solo String
        String parte1 = Base64.getEncoder().encodeToString(claveAES_cifrada);
        String parte2 = Base64.getEncoder().encodeToString(ivMasMensaje);

        return parte1 + SEPARADOR_HIBRIDO + parte2;
    }

    /**
     * Descifra un mensaje que fue cifrado con el método híbrido.
     *
     * @param mensajeCifrado  String con formato híbrido (clave + separador + mensaje)
     * @param clavePrivRSA    Clave privada RSA para descifrar la clave AES
     * @return Mensaje original descifrado
     * @throws Exception si el descifrado falla o el formato es inválido
     */
    public static String descifrarHibrido(String mensajeCifrado, PrivateKey clavePrivRSA) throws Exception {
        // 1. Separar las dos partes
        String[] partes = mensajeCifrado.split(java.util.regex.Pattern.quote(SEPARADOR_HIBRIDO));
        if (partes.length != 2) {
            throw new IllegalArgumentException("Formato de cifrado híbrido inválido");
        }

        byte[] claveAES_cifrada = Base64.getDecoder().decode(partes[0]);
        byte[] ivMasMensaje     = Base64.getDecoder().decode(partes[1]);

        // 2. Descifrar la clave AES con RSA
        Cipher cipherRSA = Cipher.getInstance(TRANSFORMACION_RSA);
        cipherRSA.init(Cipher.DECRYPT_MODE, clavePrivRSA);
        byte[] claveAES_bytes = cipherRSA.doFinal(claveAES_cifrada);
        SecretKey claveAES = new SecretKeySpec(claveAES_bytes, ALGORITMO_AES);

        // 3. Extraer IV y mensaje cifrado
        byte[] iv             = new byte[TAMANIO_IV_GCM];
        byte[] mensajeCifBytes = new byte[ivMasMensaje.length - TAMANIO_IV_GCM];
        System.arraycopy(ivMasMensaje, 0, iv, 0, TAMANIO_IV_GCM);
        System.arraycopy(ivMasMensaje, TAMANIO_IV_GCM, mensajeCifBytes, 0, mensajeCifBytes.length);

        // 4. Descifrar el mensaje con AES-GCM
        Cipher cipherAES = Cipher.getInstance(TRANSFORMACION_AES);
        javax.crypto.spec.GCMParameterSpec paramGCM = new javax.crypto.spec.GCMParameterSpec(TAMANIO_TAG_GCM, iv);
        cipherAES.init(Cipher.DECRYPT_MODE, claveAES, paramGCM);
        byte[] mensajeOriginal = cipherAES.doFinal(mensajeCifBytes);

        return new String(mensajeOriginal, "UTF-8");
    }
}
