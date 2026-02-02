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
 * Clase encargada de la creación y verificación de firmas digitales.
 * 
 * Soporta:
 * - SHA256withRSA: Firma digital con algoritmo RSA
 * - SHA256withECDSA: Firma digital con curvas elípticas (más eficiente)
 * 
 * La firma digital proporciona:
 * - Autenticidad: confirma que el remitente es quien dice ser
 * - Integridad: cualquier modificación al mensaje invalida la firma
 * - No repudio: el remitente no puede negar haber enviado el mensaje
 */
public class MotorFirma {

    // Algoritmos de firma soportados
    public static final String FIRMA_RSA  = "SHA256withRSA";
    public static final String FIRMA_ECDSA = "SHA256withECDSA";

    /**
     * Crea una firma digital para un mensaje dado.
     * 
     * Proceso interno:
     * 1. Calcula el hash SHA-256 del mensaje
     * 2. Cifra el hash con la clave privada del remitente
     * 3. Retorna la firma en formato Base64
     *
     * @param mensaje    Texto a firmar
     * @param clavePriv  Clave privada del remitente
     * @param algoritmo  Algoritmo de firma (FIRMA_RSA o FIRMA_ECDSA)
     * @return Firma digital codificada en Base64
     * @throws Exception si la firma falla
     */
    public static String firmar(String mensaje, PrivateKey clavePriv, String algoritmo) throws Exception {
        Signature firma = Signature.getInstance(algoritmo);
        firma.initSign(clavePriv);
        firma.update(mensaje.getBytes("UTF-8"));
        byte[] firmaBytes = firma.sign();
        return Base64.getEncoder().encodeToString(firmaBytes);
    }

    /**
     * Verifica una firma digital.
     * 
     * Proceso interno:
     * 1. Recalcula el hash SHA-256 del mensaje recibido
     * 2. Descifra la firma usando la clave pública del remitente
     * 3. Compara ambos hashes
     *
     * @param mensaje     Texto original (o recibido) para verificar
     * @param firmaBase64 Firma digital en Base64
     * @param clavePub    Clave pública del remitente
     * @param algoritmo   Algoritmo de firma (debe coincidir con el usado al firmar)
     * @return true si la firma es válida, false en caso contrario
     * @throws Exception si la verificación falla por error técnico
     */
    public static boolean verificar(String mensaje, String firmaBase64, PublicKey clavePub, String algoritmo) throws Exception {
        Signature firma = Signature.getInstance(algoritmo);
        firma.initVerify(clavePub);
        firma.update(mensaje.getBytes("UTF-8"));
        byte[] firmaBytes = Base64.getDecoder().decode(firmaBase64);
        return firma.verify(firmaBytes);
    }

    /**
     * Calcula el hash SHA-256 de un mensaje para mostrar en la interfaz.
     * Útil para visualizar la integridad del mensaje antes y después de modificaciones.
     *
     * @param mensaje Texto del cual calcular el hash
     * @return Hash SHA-256 en formato hexadecimal
     * @throws Exception si el cálculo falla
     */
    public static String calcularHash(String mensaje) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(mensaje.getBytes("UTF-8"));

        // Convertir bytes a hexadecimal
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
