/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.criptografia.crypto_publica;

/**
 *
 * @author washi
 */
import java.security.*;
import java.util.Base64;

/**
 * Clase utilitaria para la generación de pares de claves criptográficas.
 * Soporta algoritmos RSA y ECC (EC).
 * 
 * Responsabilidades:
 * - Generar pares de claves según el algoritmo seleccionado
 * - Convertir claves a formato Base64 legible
 * - Extraer claves públicas y privadas del par generado
 */
public class GeneradorClaves {

    // Algoritmos soportados
    public static final String ALGORITMO_RSA = "RSA";
    public static final String ALGORITMO_EC  = "EC";

    /**
     * Genera un par de claves según el algoritmo y tamaño especificado.
     *
     * @param algoritmo Tipo de algoritmo ("RSA" o "EC")
     * @param tamanio   Tamaño de la clave en bits (ej: 2048 para RSA, 256 para EC)
     * @return KeyPair con las claves públicas y privadas generadas
     * @throws NoSuchAlgorithmException si el algoritmo no es soportado
     */
    public static KeyPair generarParClaves(String algoritmo, int tamanio) throws Exception {

        KeyPairGenerator generador = KeyPairGenerator.getInstance(algoritmo);

        if (algoritmo.equals(ALGORITMO_EC)) {
            // Para EC se usa ECGenParameterSpec con el nombre de la curva
            java.security.spec.ECGenParameterSpec curva = getCurvaEC(tamanio);
            generador.initialize(curva, new SecureRandom());
        } else {
            // Para RSA se usa directamente el tamaño en bits
            generador.initialize(tamanio, new SecureRandom());
        }

        return generador.generateKeyPair();
    }

    /**
     * Mapea el tamaño en bits a la curva elíptica correspondiente para EC.
     *
     * @param tamanio Tamaño en bits (256 o 384)
     * @return ECGenParameterSpec con la curva apropiada
     */
    private static java.security.spec.ECGenParameterSpec getCurvaEC(int tamanio) {
        switch (tamanio) {
            case 256:
                return new java.security.spec.ECGenParameterSpec("secp256r1"); // P-256
            case 384:
                return new java.security.spec.ECGenParameterSpec("secp384r1"); // P-384
            default:
                return new java.security.spec.ECGenParameterSpec("secp256r1"); // Por defecto P-256
        }
    }

    /**
     * Convierte una clave pública a formato Base64.
     *
     * @param clavePub Clave pública a convertir
     * @return String en formato Base64
     */
    public static String clavePubABase64(PublicKey clavePub) {
        return Base64.getEncoder().encodeToString(clavePub.getEncoded());
    }

    /**
     * Convierte una clave privada a formato Base64.
     *
     * @param clavePriv Clave privada a convertir
     * @return String en formato Base64
     */
    public static String clavePrivABase64(PrivateKey clavePriv) {
        return Base64.getEncoder().encodeToString(clavePriv.getEncoded());
    }

    /**
     * Reconstruye una clave pública RSA a partir de su representación Base64.
     *
     * @param base64     Clave pública codificada en Base64
     * @param algoritmo  Algoritmo de la clave ("RSA" o "EC")
     * @return PublicKey reconstruida
     * @throws Exception si la clave no es válida
     */
    public static PublicKey base64APublicKey(String base64, String algoritmo) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(base64);
        java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(bytes);
        KeyFactory factory = KeyFactory.getInstance(algoritmo);
        return factory.generatePublic(spec);
    }

    /**
     * Reconstruye una clave privada a partir de su representación Base64.
     *
     * @param base64     Clave privada codificada en Base64
     * @param algoritmo  Algoritmo de la clave ("RSA" o "EC")
     * @return PrivateKey reconstruida
     * @throws Exception si la clave no es válida
     */
    public static PrivateKey base64APrivateKey(String base64, String algoritmo) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(base64);
        java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(bytes);
        KeyFactory factory = KeyFactory.getInstance(algoritmo);
        return factory.generatePrivate(spec);
    }
}