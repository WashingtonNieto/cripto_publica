/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.criptografia.crypto_publica;

/**
 *
 * @author washington Nieto Arce
 * Especializacion de desarrollo de software
 * 
 */
import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Ventana principal de la aplicación.
 * 
 * Estructura de la interfaz:
 * ├── Tab 1: Generación de Claves
 * │   ├── Selección de algoritmo (RSA / EC)
 * │   ├── Selección de tamaño de clave
 * │   └── Visualización de claves generadas
 * ├── Tab 2: Cifrado y Descifrado
 * │   ├── Modo: RSA directo / Híbrido
 * │   ├── Áreas de texto para mensajes
 * │   └── Botones de cifrar / descifrar
 * └── Tab 3: Firma Digital
 *     ├── Área de texto del mensaje
 *     ├── Firma generada
 *     ├── Hash SHA-256
 *     └── Panel de verificación
 */
public class VentanaPrincipal extends JFrame {

    // Dimensiones de la ventana
    private static final int ANCHO  = 950;
    private static final int ALTO   = 720;

    // Variables globales para almacenar claves entre tabs
    private KeyPair parClaves          = null;
    private PublicKey  clavePub        = null;
    private PrivateKey clavePriv       = null;
    private String algoritmoActual     = GeneradorClaves.ALGORITMO_RSA;

    // ===================== COMPONENTES: Tab Claves =====================
    private JComboBox<String> comboAlgoritmo;
    private JComboBox<String> comboTamanio;
    private JTextArea areaClavePublica;
    private JTextArea areaClavePrivada;
    private JButton btnGenerarClaves;
    private JLabel lblEstadoClaves;

    // ===================== COMPONENTES: Tab Cifrado =====================
    private JComboBox<String> comboModoCifrado;
    private JTextArea areaMensajeOriginal;
    private JTextArea areaMensajeCifrado;
    private JTextArea areaMensajeDescifrado;
    private JButton btnCifrar;
    private JButton btnDescifrar;
    private JLabel lblEstadoCifrado;

    // ===================== COMPONENTES: Tab Firma =====================
    private JTextArea areaMensajeFirma;
    private JTextArea areaFirmaGenerada;
    private JTextArea areaHashMensaje;
    private JButton btnFirmar;
    private JButton btnVerificar;
    private JLabel lblEstadoFirma;
    private JComboBox<String> comboAlgoFirma;

    // ===================== CONSTRUCTOR =====================
    public VentanaPrincipal() {
        configurarVentana();
        construirInterfaz();
    }

    /**
     * Configuración básica de la ventana principal.
     */
    private void configurarVentana() {
        setTitle("CIFRADO ASIMETRICO - Sistema de Criptografía de Clave Pública - Washington Nieto Arce");
        setSize(ANCHO, ALTO);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setResizable(true);

        // Icono de la aplicación (si existe)
        // setIconImage(ImageIO.read(getClass().getResource("/icono.png")));
    }

    /**
     * Construye la interfaz completa con sus tres pestañas.
     */
    private void construirInterfaz() {
        // Panel principal con márgenes
        JPanel panelPrincipal = new JPanel(new BorderLayout(0, 5));
        panelPrincipal.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        add(panelPrincipal);

        // ---- HEADER ----
        panelPrincipal.add(crearHeader(), BorderLayout.NORTH);

        // ---- TABS ----
        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(new Font("SansSerif", Font.BOLD, 14));
        tabs.addTab("🔑 Generación de Claves", crearTabClaves());
        tabs.addTab("🔒 Cifrado / Descifrado", crearTabCifrado());
        tabs.addTab("✍️  Firma Digital",        crearTabFirma());
        panelPrincipal.add(tabs, BorderLayout.CENTER);

        // ---- FOOTER ----
        panelPrincipal.add(crearFooter(), BorderLayout.SOUTH);
    }

    // =========================================================================
    //                          HEADER Y FOOTER
    // =========================================================================

    private JPanel crearHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(new Color(34, 50, 75));
        header.setBorder(BorderFactory.createEmptyBorder(12, 15, 12, 15));

        JLabel titulo = new JLabel("CIFRADO ASIMETRICO - Sistema de Criptografía de Clave Pública - Washington Nieto Arce");
        titulo.setFont(new Font("SansSerif", Font.BOLD, 16));
        titulo.setForeground(Color.WHITE);
        header.add(titulo, BorderLayout.CENTER);

        JLabel version = new JLabel("v1.0");
        version.setFont(new Font("SansSerif", Font.PLAIN, 12));
        version.setForeground(new Color(180, 200, 230));
        header.add(version, BorderLayout.EAST);

        return header;
    }

    private JPanel crearFooter() {
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBackground(new Color(240, 242, 245));
        footer.setBorder(BorderFactory.createEmptyBorder(8, 15, 8, 15));

        // Panel contenedor para los dos JLabel
        JPanel contenedorTexto = new JPanel();
        contenedorTexto.setLayout(new BoxLayout(contenedorTexto, BoxLayout.Y_AXIS));
        contenedorTexto.setBackground(new Color(240, 242, 245));

        JLabel texto1 = new JLabel("⚠️ Esta aplicación es para uso educativo y demostrativo, creado por Washington Nieto - Estudiante de postgrado - Especialización en desarrollo de software.");
        JLabel texto2 = new JLabel("No use en entornos de producción sin auditoría de seguridad.");

        texto1.setFont(new Font("SansSerif", Font.ITALIC, 11));
        texto2.setFont(new Font("SansSerif", Font.ITALIC, 11));
        texto1.setForeground(new Color(150, 60, 60));
        texto2.setForeground(new Color(150, 60, 60));

        // Centrar ambos textos
        texto1.setAlignmentX(JLabel.CENTER_ALIGNMENT);
        texto2.setAlignmentX(JLabel.CENTER_ALIGNMENT);

        contenedorTexto.add(texto1);
        contenedorTexto.add(Box.createVerticalStrut(2)); // Espacio entre líneas
        contenedorTexto.add(texto2);

        footer.add(contenedorTexto, BorderLayout.CENTER);

        return footer;
    }

    // =========================================================================
    //                     TAB 1: GENERACIÓN DE CLAVES
    // =========================================================================

    private JPanel crearTabClaves() {
        JPanel tab = new JPanel(new BorderLayout(10, 10));
        tab.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // ---- Panel superior: controles ----
        JPanel panelControles = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 8));
        panelControles.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(),
                "Configuración",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 12)));

        // Selección de algoritmo
        panelControles.add(new JLabel("Algoritmo:"));
        comboAlgoritmo = new JComboBox<>(new String[]{"RSA", "EC (Curvas Elípticas)"});
        comboAlgoritmo.setFont(new Font("SansSerif", Font.PLAIN, 12));
        comboAlgoritmo.addActionListener(e -> actualizarOpcionesAlgoritmo());
        panelControles.add(comboAlgoritmo);

        // Selección de tamaño
        panelControles.add(new JLabel("Tamaño (bits):"));
        comboTamanio = new JComboBox<>(new String[]{"2048", "4096"});
        comboTamanio.setFont(new Font("SansSerif", Font.PLAIN, 12));
        panelControles.add(comboTamanio);

        // Botón generar
        btnGenerarClaves = new JButton("Generar Par de Claves");
        btnGenerarClaves.setFont(new Font("SansSerif", Font.BOLD, 12));
        btnGenerarClaves.setBackground(new Color(46, 125, 50));
        btnGenerarClaves.setForeground(Color.BLUE);
        btnGenerarClaves.setFocusPainted(false);
        btnGenerarClaves.addActionListener(this::accionGenerarClaves);
        panelControles.add(btnGenerarClaves);

        // Estado
        lblEstadoClaves = new JLabel("Estado: Sin claves generadas");
        lblEstadoClaves.setFont(new Font("SansSerif", Font.ITALIC, 11));
        lblEstadoClaves.setForeground(new Color(100, 100, 100));
        panelControles.add(lblEstadoClaves);

        tab.add(panelControles, BorderLayout.NORTH);

        // ---- Panel central: áreas de texto para claves ----
        JPanel panelClaves = new JPanel(new GridLayout(1, 2, 15, 0));

        // Clave pública
        JPanel panelPub = new JPanel(new BorderLayout(0, 5));
        panelPub.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(46, 125, 50), 2),
                "🔓 Clave Pública (se puede compartir libremente)",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 11),
                new Color(46, 125, 50)));

        areaClavePublica = new JTextArea();
        areaClavePublica.setEditable(false);
        areaClavePublica.setFont(new Font("Monospaced", Font.PLAIN, 11));
        areaClavePublica.setBackground(new Color(245, 250, 245));
        areaClavePublica.setLineWrap(true);
        areaClavePublica.setWrapStyleWord(true);
        panelPub.add(new JScrollPane(areaClavePublica), BorderLayout.CENTER);

        JButton btnCopiarPub = new JButton("Copiar");
        btnCopiarPub.addActionListener(e -> copiarAlClipboard(areaClavePublica.getText()));
        panelPub.add(btnCopiarPub, BorderLayout.SOUTH);

        panelClaves.add(panelPub);

        // Clave privada
        JPanel panelPriv = new JPanel(new BorderLayout(0, 5));
        panelPriv.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(180, 60, 60), 2),
                "🔐 Clave Privada (NUNCA compartir)",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 11),
                new Color(180, 60, 60)));

        areaClavePrivada = new JTextArea();
        areaClavePrivada.setEditable(false);
        areaClavePrivada.setFont(new Font("Monospaced", Font.PLAIN, 11));
        areaClavePrivada.setBackground(new Color(250, 245, 245));
        areaClavePrivada.setLineWrap(true);
        areaClavePrivada.setWrapStyleWord(true);
        panelPriv.add(new JScrollPane(areaClavePrivada), BorderLayout.CENTER);

        JButton btnCopiarPriv = new JButton("Copiar");
        btnCopiarPriv.addActionListener(e -> copiarAlClipboard(areaClavePrivada.getText()));
        panelPriv.add(btnCopiarPriv, BorderLayout.SOUTH);

        panelClaves.add(panelPriv);

        tab.add(panelClaves, BorderLayout.CENTER);

        return tab;
    }

    // =========================================================================
    //                    TAB 2: CIFRADO Y DESCIFRADO
    // =========================================================================

    private JPanel crearTabCifrado() {
        JPanel tab = new JPanel(new BorderLayout(10, 10));
        tab.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // ---- Panel superior: modo de cifrado ----
        JPanel panelModo = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 8));
        panelModo.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(),
                "Modo de Cifrado",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 12)));

        panelModo.add(new JLabel("Modo:"));
        comboModoCifrado = new JComboBox<>(new String[]{
                "RSA Directo (mensajes pequeños)",
                "Híbrido RSA+AES (mensajes grandes)"
        });
        comboModoCifrado.setFont(new Font("SansSerif", Font.PLAIN, 12));
        panelModo.add(comboModoCifrado);

        JLabel lblInfo = new JLabel("  ℹ️  Requerido: Genere claves en la pestaña anterior");
        lblInfo.setFont(new Font("SansSerif", Font.ITALIC, 11));
        lblInfo.setForeground(new Color(80, 100, 150));
        panelModo.add(lblInfo);

        tab.add(panelModo, BorderLayout.NORTH);

        // ---- Panel central: áreas de texto ----
        JPanel panelContenido = new JPanel(new GridLayout(3, 1, 0, 10));

        // Mensaje original
        panelContenido.add(crearPanelTextArea("📝 Mensaje Original (escriba aquí):",
                new Color(30, 80, 140), true));
        areaMensajeOriginal = ultimoTextArea;

        // Mensaje cifrado
        panelContenido.add(crearPanelTextArea("🔒 Mensaje Cifrado:",
                new Color(160, 80, 20), false));
        areaMensajeCifrado = ultimoTextArea;

        // Mensaje descifrado
        panelContenido.add(crearPanelTextArea("🔓 Mensaje Descifrado:",
                new Color(46, 125, 50), false));
        areaMensajeDescifrado = ultimoTextArea;

        tab.add(panelContenido, BorderLayout.CENTER);

        // ---- Panel inferior: botones ----
        JPanel panelBotones = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 8));

        btnCifrar = new JButton("🔒 Cifrar Mensaje");
        btnCifrar.setFont(new Font("SansSerif", Font.BOLD, 13));
        btnCifrar.setBackground(new Color(160, 80, 20));
        btnCifrar.setForeground(Color.RED);
        btnCifrar.setFocusPainted(false);
        btnCifrar.setPreferredSize(new Dimension(180, 40));
        btnCifrar.addActionListener(this::accionCifrar);
        panelBotones.add(btnCifrar);

        btnDescifrar = new JButton("🔓 Descifrar Mensaje");
        btnDescifrar.setFont(new Font("SansSerif", Font.BOLD, 13));
        btnDescifrar.setBackground(new Color(46, 125, 50));
        btnDescifrar.setForeground(Color.BLUE);
        btnDescifrar.setFocusPainted(false);
        btnDescifrar.setPreferredSize(new Dimension(180, 40));
        btnDescifrar.addActionListener(this::accionDescifrar);
        panelBotones.add(btnDescifrar);

        JButton btnLimpiar = new JButton("🗑️  Limpiar");
        btnLimpiar.setFont(new Font("SansSerif", Font.PLAIN, 12));
        btnLimpiar.setPreferredSize(new Dimension(100, 40));
        btnLimpiar.addActionListener(e -> {
            areaMensajeOriginal.setText("");
            areaMensajeCifrado.setText("");
            areaMensajeDescifrado.setText("");
            lblEstadoCifrado.setText("");
        });
        panelBotones.add(btnLimpiar);

        lblEstadoCifrado = new JLabel();
        lblEstadoCifrado.setFont(new Font("SansSerif", Font.ITALIC, 11));
        panelBotones.add(lblEstadoCifrado);

        tab.add(panelBotones, BorderLayout.SOUTH);

        return tab;
    }

    // =========================================================================
    //                       TAB 3: FIRMA DIGITAL
    // =========================================================================

    private JPanel crearTabFirma() {
        JPanel tab = new JPanel(new BorderLayout(10, 10));
        tab.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // ---- Panel superior: configuración ----
        JPanel panelConfig = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 8));
        panelConfig.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(),
                "Configuración de Firma",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 12)));

        panelConfig.add(new JLabel("Algoritmo de Firma:"));
        comboAlgoFirma = new JComboBox<>(new String[]{"SHA256withRSA", "SHA256withECDSA"});
        comboAlgoFirma.setFont(new Font("SansSerif", Font.PLAIN, 12));
        panelConfig.add(comboAlgoFirma);

        JLabel lblInfoFirma = new JLabel("  ℹ️  Requerido: Claves RSA generadas");
        lblInfoFirma.setFont(new Font("SansSerif", Font.ITALIC, 11));
        lblInfoFirma.setForeground(new Color(80, 100, 150));
        panelConfig.add(lblInfoFirma);

        tab.add(panelConfig, BorderLayout.NORTH);

        // ---- Panel central ----
        JPanel panelCentral = new JPanel(new BorderLayout(0, 10));

        // Mensaje a firmar
        JPanel panelMensaje = new JPanel(new BorderLayout(0, 5));
        panelMensaje.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(30, 80, 140), 2),
                "📝 Mensaje a Firmar",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 11),
                new Color(30, 80, 140)));

        areaMensajeFirma = new JTextArea(4, 40);
        areaMensajeFirma.setFont(new Font("SansSerif", Font.PLAIN, 12));
        areaMensajeFirma.setLineWrap(true);
        areaMensajeFirma.setWrapStyleWord(true);
        panelMensaje.add(new JScrollPane(areaMensajeFirma), BorderLayout.CENTER);
        panelCentral.add(panelMensaje, BorderLayout.NORTH);

        // Panel inferior: firma y hash lado a lado
        JPanel panelInferior = new JPanel(new GridLayout(1, 2, 15, 0));

        // Firma generada
        JPanel panelFirma = new JPanel(new BorderLayout(0, 5));
        panelFirma.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(100, 50, 150), 2),
                "✍️  Firma Digital Generada",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 11),
                new Color(100, 50, 150)));

        areaFirmaGenerada = new JTextArea();
        areaFirmaGenerada.setEditable(false);
        areaFirmaGenerada.setFont(new Font("Monospaced", Font.PLAIN, 10));
        areaFirmaGenerada.setBackground(new Color(248, 245, 252));
        areaFirmaGenerada.setLineWrap(true);
        areaFirmaGenerada.setWrapStyleWord(true);
        panelFirma.add(new JScrollPane(areaFirmaGenerada), BorderLayout.CENTER);
        panelInferior.add(panelFirma);

        // Hash del mensaje
        JPanel panelHash = new JPanel(new BorderLayout(0, 5));
        panelHash.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(30, 120, 160), 2),
                "🔢 Hash SHA-256 del Mensaje",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 11),
                new Color(30, 120, 160)));

        areaHashMensaje = new JTextArea();
        areaHashMensaje.setEditable(false);
        areaHashMensaje.setFont(new Font("Monospaced", Font.PLAIN, 11));
        areaHashMensaje.setBackground(new Color(245, 250, 252));
        areaHashMensaje.setLineWrap(true);
        areaHashMensaje.setWrapStyleWord(true);
        panelHash.add(new JScrollPane(areaHashMensaje), BorderLayout.CENTER);
        panelInferior.add(panelHash);

        panelCentral.add(panelInferior, BorderLayout.CENTER);
        tab.add(panelCentral, BorderLayout.CENTER);

        // ---- Panel inferior: botones ----
        JPanel panelBotones = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 8));

        btnFirmar = new JButton("✍️  Firmar Mensaje");
        btnFirmar.setFont(new Font("SansSerif", Font.BOLD, 13));
        btnFirmar.setBackground(new Color(100, 50, 150));
        btnFirmar.setForeground(Color.RED);
        btnFirmar.setFocusPainted(false);
        btnFirmar.setPreferredSize(new Dimension(180, 40));
        btnFirmar.addActionListener(this::accionFirmar);
        panelBotones.add(btnFirmar);

        btnVerificar = new JButton("✅ Verificar Firma");
        btnVerificar.setFont(new Font("SansSerif", Font.BOLD, 13));
        btnVerificar.setBackground(new Color(30, 120, 160));
        btnVerificar.setForeground(Color.BLUE);
        btnVerificar.setFocusPainted(false);
        btnVerificar.setPreferredSize(new Dimension(180, 40));
        btnVerificar.addActionListener(this::accionVerificar);
        panelBotones.add(btnVerificar);

        JButton btnLimpiarFirma = new JButton("🗑️  Limpiar");
        btnLimpiarFirma.setFont(new Font("SansSerif", Font.PLAIN, 12));
        btnLimpiarFirma.setPreferredSize(new Dimension(100, 40));
        btnLimpiarFirma.addActionListener(e -> {
            areaMensajeFirma.setText("");
            areaFirmaGenerada.setText("");
            areaHashMensaje.setText("");
            lblEstadoFirma.setText("");
        });
        panelBotones.add(btnLimpiarFirma);

        lblEstadoFirma = new JLabel();
        lblEstadoFirma.setFont(new Font("SansSerif", Font.BOLD, 12));
        panelBotones.add(lblEstadoFirma);

        tab.add(panelBotones, BorderLayout.SOUTH);

        return tab;
    }

    // =========================================================================
    //                    ACCIONES (EVENT HANDLERS)
    // =========================================================================

    /**
     * Genera un par de claves según la configuración seleccionada.
     */
    private void accionGenerarClaves(ActionEvent e) {
        btnGenerarClaves.setEnabled(false);
        lblEstadoClaves.setText("Generando claves... por favor espere");
        lblEstadoClaves.setForeground(new Color(160, 100, 0));

        // Ejecutar en hilo separado para no bloquear la UI
        new Thread(() -> {
            try {
                String algo = comboAlgoritmo.getSelectedIndex() == 0
                        ? GeneradorClaves.ALGORITMO_RSA
                        : GeneradorClaves.ALGORITMO_EC;

                int tamanio = Integer.parseInt((String) comboTamanio.getSelectedItem());
                algoritmoActual = algo;

                parClaves  = GeneradorClaves.generarParClaves(algo, tamanio);
                clavePub   = parClaves.getPublic();
                clavePriv  = parClaves.getPrivate();

                // Actualizar interfaz desde el hilo de Swing
                SwingUtilities.invokeLater(() -> {
                    areaClavePublica.setText(GeneradorClaves.clavePubABase64(clavePub));
                    areaClavePrivada.setText(GeneradorClaves.clavePrivABase64(clavePriv));
                    lblEstadoClaves.setText("✓ Claves generadas exitosamente (" + algo + " - " + tamanio + " bits)");
                    lblEstadoClaves.setForeground(new Color(46, 125, 50));
                    btnGenerarClaves.setEnabled(true);

                    // Actualizar combo de firma según algoritmo
                    if (algo.equals(GeneradorClaves.ALGORITMO_EC)) {
                        comboAlgoFirma.setSelectedItem("SHA256withECDSA");
                    } else {
                        comboAlgoFirma.setSelectedItem("SHA256withRSA");
                    }
                });

            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    lblEstadoClaves.setText("✗ Error: " + ex.getMessage());
                    lblEstadoClaves.setForeground(new Color(180, 60, 60));
                    btnGenerarClaves.setEnabled(true);
                });
            }
        }).start();
    }

    /**
     * Cifra el mensaje original.
     */
    private void accionCifrar(ActionEvent e) {
        if (clavePub == null) {
            mostrarError("Debe generar claves primero en la pestaña 'Generación de Claves'");
            return;
        }

        String mensaje = areaMensajeOriginal.getText().trim();
        if (mensaje.isEmpty()) {
            mostrarError("El mensaje no puede estar vacío");
            return;
        }

        try {
            String cifrado;
            if (comboModoCifrado.getSelectedIndex() == 0) {
                // RSA directo
                cifrado = MotorCifrado.cifrarRSA(mensaje, clavePub);
                lblEstadoCifrado.setText("✓ Cifrado RSA exitoso");
            } else {
                // Híbrido
                cifrado = MotorCifrado.cifrarHibrido(mensaje, clavePub);
                lblEstadoCifrado.setText("✓ Cifrado Híbrido (RSA+AES-GCM) exitoso");
            }
            lblEstadoCifrado.setForeground(new Color(46, 125, 50));
            areaMensajeCifrado.setText(cifrado);
            areaMensajeDescifrado.setText("");

        } catch (Exception ex) {
            lblEstadoCifrado.setText("✗ Error al cifrar: " + ex.getMessage());
            lblEstadoCifrado.setForeground(new Color(180, 60, 60));
        }
    }

    /**
     * Descifra el mensaje cifrado.
     */
    private void accionDescifrar(ActionEvent e) {
        if (clavePriv == null) {
            mostrarError("Debe generar claves primero en la pestaña 'Generación de Claves'");
            return;
        }

        String cifrado = areaMensajeCifrado.getText().trim();
        if (cifrado.isEmpty()) {
            mostrarError("El campo de mensaje cifrado está vacío");
            return;
        }

        try {
            String descifrado;
            if (comboModoCifrado.getSelectedIndex() == 0) {
                descifrado = MotorCifrado.descifrarRSA(cifrado, clavePriv);
                lblEstadoCifrado.setText("✓ Descifrado RSA exitoso");
            } else {
                descifrado = MotorCifrado.descifrarHibrido(cifrado, clavePriv);
                lblEstadoCifrado.setText("✓ Descifrado Híbrido exitoso");
            }
            lblEstadoCifrado.setForeground(new Color(46, 125, 50));
            areaMensajeDescifrado.setText(descifrado);

        } catch (Exception ex) {
            lblEstadoCifrado.setText("✗ Error al descifrar: " + ex.getMessage());
            lblEstadoCifrado.setForeground(new Color(180, 60, 60));
        }
    }

    /**
     * Firma el mensaje con la clave privada.
     */
    private void accionFirmar(ActionEvent e) {
        if (clavePriv == null) {
            mostrarError("Debe generar claves primero en la pestaña 'Generación de Claves'");
            return;
        }

        String mensaje = areaMensajeFirma.getText().trim();
        if (mensaje.isEmpty()) {
            mostrarError("El mensaje no puede estar vacío");
            return;
        }

        try {
            String algoritmoFirma = (String) comboAlgoFirma.getSelectedItem();
            String firma = MotorFirma.firmar(mensaje, clavePriv, algoritmoFirma);
            String hash  = MotorFirma.calcularHash(mensaje);

            areaFirmaGenerada.setText(firma);
            areaHashMensaje.setText(hash);
            lblEstadoFirma.setText("✓ Firma generada exitosamente");
            lblEstadoFirma.setForeground(new Color(100, 50, 150));

        } catch (Exception ex) {
            lblEstadoFirma.setText("✗ Error: " + ex.getMessage());
            lblEstadoFirma.setForeground(new Color(180, 60, 60));
        }
    }

    /**
     * Verifica la firma digital del mensaje.
     */
    private void accionVerificar(ActionEvent e) {
        if (clavePub == null) {
            mostrarError("Debe generar claves primero");
            return;
        }

        String mensaje = areaMensajeFirma.getText().trim();
        String firma   = areaFirmaGenerada.getText().trim();

        if (mensaje.isEmpty() || firma.isEmpty()) {
            mostrarError("Debe firmar un mensaje primero");
            return;
        }

        try {
            String algoritmoFirma = (String) comboAlgoFirma.getSelectedItem();
            boolean valida = MotorFirma.verificar(mensaje, firma, clavePub, algoritmoFirma);

            // Actualizar hash para mostrar el estado actual
            areaHashMensaje.setText(MotorFirma.calcularHash(mensaje));

            if (valida) {
                lblEstadoFirma.setText("✅ FIRMA VÁLIDA - El mensaje no fue modificado");
                lblEstadoFirma.setForeground(new Color(46, 125, 50));
            } else {
                lblEstadoFirma.setText("❌ FIRMA INVÁLIDA - El mensaje fue modificado");
                lblEstadoFirma.setForeground(new Color(180, 60, 60));
            }

        } catch (Exception ex) {
            lblEstadoFirma.setText("❌ FIRMA INVÁLIDA - " + ex.getMessage());
            lblEstadoFirma.setForeground(new Color(180, 60, 60));
        }
    }

    // =========================================================================
    //                         MÉTODOS AUXILIARES
    // =========================================================================

    /**
     * Actualiza las opciones de tamaño según el algoritmo seleccionado.
     */
    private void actualizarOpcionesAlgoritmo() {
        if (comboAlgoritmo.getSelectedIndex() == 0) {
            // RSA: tamaños en bits
            comboTamanio.removeAllItems();
            comboTamanio.addItem("2048");
            comboTamanio.addItem("4096");
        } else {
            // EC: tamaños de curvas elípticas
            comboTamanio.removeAllItems();
            comboTamanio.addItem("256");
            comboTamanio.addItem("384");
        }
    }

    /**
     * Copia texto al clipboard del sistema.
     */
    private void copiarAlClipboard(String texto) {
        if (texto == null || texto.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No hay contenido para copiar", "Aviso", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(texto);
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
        JOptionPane.showMessageDialog(this, "Contenido copiado al clipboard", "Copiado", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Muestra un diálogo de error.
     */
    private void mostrarError(String mensaje) {
        JOptionPane.showMessageDialog(this, mensaje, "Error", JOptionPane.ERROR_MESSAGE);
    }

    // Variable temporal para capturar el último TextArea creado
    private JTextArea ultimoTextArea;

    /**
     * Crea un panel reutilizable con un JTextArea estilizado.
     */
    private JPanel crearPanelTextArea(String titulo, Color colorBorde, boolean editable) {
        JPanel panel = new JPanel(new BorderLayout(0, 3));
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(colorBorde, 2),
                titulo,
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("SansSerif", Font.BOLD, 11),
                colorBorde));

        JTextArea area = new JTextArea(4, 40);
        area.setEditable(editable);
        area.setFont(new Font(editable ? "SansSerif" : "Monospaced", Font.PLAIN, editable ? 12 : 10));
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        if (!editable) {
            area.setBackground(new Color(245, 245, 248));
        }
        panel.add(new JScrollPane(area), BorderLayout.CENTER);

        ultimoTextArea = area; // Captura para referencia externa
        return panel;
    }
}
