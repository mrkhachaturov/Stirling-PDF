package stirling.software.SPDF.controller.api.security;

import java.awt.*;
import java.beans.PropertyEditorSupport;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;

import org.apache.commons.io.FileUtils;
import org.apache.pdfbox.examples.signature.CreateSignatureBase;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.graphics.blend.BlendMode;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.graphics.state.PDExtendedGraphicsState;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import io.micrometer.common.util.StringUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.servlet.http.HttpServletRequest;

import lombok.extern.slf4j.Slf4j;

import stirling.software.SPDF.config.swagger.StandardPdfResponse;
import stirling.software.SPDF.model.api.security.SignPDFWithCertRequest;
import stirling.software.SPDF.service.HardwareKeyStoreService;
import stirling.software.common.annotations.AutoJobPostMapping;
import stirling.software.common.enumeration.ResourceWeight;
import stirling.software.common.model.ApplicationProperties;
import stirling.software.common.service.CustomPDFDocumentFactory;
import stirling.software.common.service.ServerCertificateServiceInterface;
import stirling.software.common.service.UserCertificateServiceInterface;
import stirling.software.common.service.UserServiceInterface;
import stirling.software.common.util.ExceptionUtils;
import stirling.software.common.util.GeneralUtils;
import stirling.software.common.util.TempFile;
import stirling.software.common.util.TempFileManager;
import stirling.software.common.util.WebResponseUtils;

@RestController
@RequestMapping("/api/v1/security")
@Slf4j
@Tag(name = "Security", description = "Security APIs")
public class CertSignController {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        binder.registerCustomEditor(
                MultipartFile.class,
                new PropertyEditorSupport() {
                    @Override
                    public void setAsText(String text) throws IllegalArgumentException {
                        setValue(null);
                    }
                });
    }

    // Reserved byte-range size for the embedded signature. 64 KB comfortably fits a CMS signature
    // plus an RFC 3161 timestamp token and the TSA + signer certificate chains; PDFBox's ~9 KB
    // default is too small once timestamping is enabled.
    private static final int PREFERRED_SIGNATURE_SIZE = 0x10000;

    private final CustomPDFDocumentFactory pdfDocumentFactory;
    private final ServerCertificateServiceInterface serverCertificateService;
    private final UserCertificateServiceInterface userCertificateService;
    private final UserServiceInterface userService;
    private final TempFileManager tempFileManager;
    private final HardwareKeyStoreService hardwareKeyStoreService;
    private final ApplicationProperties applicationProperties;

    public CertSignController(
            CustomPDFDocumentFactory pdfDocumentFactory,
            @Autowired(required = false) ServerCertificateServiceInterface serverCertificateService,
            @Autowired(required = false) UserCertificateServiceInterface userCertificateService,
            @Autowired(required = false) UserServiceInterface userService,
            TempFileManager tempFileManager,
            HardwareKeyStoreService hardwareKeyStoreService,
            ApplicationProperties applicationProperties) {
        this.pdfDocumentFactory = pdfDocumentFactory;
        this.serverCertificateService = serverCertificateService;
        this.userCertificateService = userCertificateService;
        this.userService = userService;
        this.tempFileManager = tempFileManager;
        this.hardwareKeyStoreService = hardwareKeyStoreService;
        this.applicationProperties = applicationProperties;
    }

    /**
     * Resolve the TSA URL used to embed an RFC 3161 signature timestamp (PAdES B-T) at signing
     * time, or {@code null} when timestamping is disabled. Shared by the standalone signing
     * endpoint and the collaborative finalization path so both produce long-lived signatures.
     */
    public static String resolveSigningTsaUrl(ApplicationProperties applicationProperties) {
        if (applicationProperties == null) {
            return null;
        }
        ApplicationProperties.Security.Timestamp ts =
                applicationProperties.getSecurity().getTimestamp();
        if (ts == null || !ts.isSigningEnabled()) {
            return null;
        }
        String url = ts.getDefaultTsaUrl();
        return (url == null || url.isBlank()) ? null : url;
    }

    /**
     * Resolve the locale that drives the visible signature layout from {@code SYSTEM_DEFAULTLOCALE}
     * (the same setting the UI uses), so the stamp matches the configured instance language. Falls
     * back to {@link Locale#UK} (the upstream English stamp) when unset.
     */
    public static Locale resolveDefaultLocale(ApplicationProperties applicationProperties) {
        if (applicationProperties == null || applicationProperties.getSystem() == null) {
            return Locale.UK;
        }
        String tag = applicationProperties.getSystem().getDefaultLocale();
        if (tag == null || tag.isBlank()) {
            return Locale.UK;
        }
        return Locale.forLanguageTag(tag.replace('_', '-'));
    }

    public static void sign(
            CustomPDFDocumentFactory pdfDocumentFactory,
            MultipartFile input,
            OutputStream output,
            CreateSignature instance,
            Boolean showSignature,
            Integer pageNumber,
            String name,
            String location,
            String reason,
            Boolean showLogo,
            Locale locale) {
        try (PDDocument doc = pdfDocumentFactory.load(input)) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName(name);
            signature.setLocation(location);
            signature.setReason(reason);
            signature.setSignDate(Calendar.getInstance()); // PDFBox requires Calendar
            try (SignatureOptions signatureOptions = new SignatureOptions()) {
                // Reserve space for the CMS signature plus an optional RFC 3161 timestamp token and
                // its TSA certificate chain. The default (~9 KB) overflows once timestamping is
                // enabled ("Can't write signature, not enough space"), in both visible and
                // invisible
                // mode. Applied to every signature so non-timestamped ones are unaffected.
                signatureOptions.setPreferredSignatureSize(PREFERRED_SIGNATURE_SIZE);
                if (Boolean.TRUE.equals(showSignature)) {
                    signatureOptions.setVisualSignature(
                            instance.createVisibleSignature(
                                    doc, signature, pageNumber, showLogo, locale));
                    signatureOptions.setPage(pageNumber);
                }
                doc.addSignature(signature, instance, signatureOptions);
                doc.saveIncremental(output);
            }
        } catch (Exception e) {
            ExceptionUtils.logException("PDF signing", e);
        }
    }

    @AutoJobPostMapping(
            consumes = {
                MediaType.MULTIPART_FORM_DATA_VALUE,
                MediaType.APPLICATION_FORM_URLENCODED_VALUE
            },
            value = "/cert-sign",
            resourceWeight = ResourceWeight.LARGE_WEIGHT)
    @StandardPdfResponse
    @Operation(
            summary = "Sign PDF with a Digital Certificate",
            description =
                    "This endpoint accepts a PDF file, a digital certificate and related"
                            + " information to sign the PDF. It then returns the digitally signed PDF"
                            + " file. Input:PDF Output:PDF Type:SISO")
    public ResponseEntity<Resource> signPDFWithCert(
            @ModelAttribute SignPDFWithCertRequest request, HttpServletRequest httpRequest)
            throws Exception {
        MultipartFile pdf = request.getFileInput();
        String certType = request.getCertType();
        MultipartFile privateKeyFile = request.getPrivateKeyFile();
        MultipartFile certFile = request.getCertFile();
        MultipartFile p12File = request.getP12File();
        MultipartFile jksfile = request.getJksFile();
        String password = request.getPassword();
        Boolean showSignature = request.getShowSignature();
        String reason = request.getReason();
        String location = request.getLocation();
        String name = request.getName();
        // Convert 1-indexed page number (user input) to 0-indexed page number (API requirement)
        Integer pageNumber = request.getPageNumber() != null ? (request.getPageNumber() - 1) : null;
        Boolean showLogo = request.getShowLogo();

        if (StringUtils.isBlank(certType)) {
            throw ExceptionUtils.createIllegalArgumentException(
                    "error.optionsNotSpecified",
                    "{0} options are not specified",
                    "certificate type");
        }

        KeyStore ks = null;
        String keystorePassword = password;
        Provider signingProvider = null;
        HardwareKeyStoreService.Pkcs11Session pkcs11Session = null;

        switch (certType) {
            case "PEM":
                privateKeyFile =
                        validateFilePresent(
                                privateKeyFile, "PEM private key", "private key file is required");
                certFile =
                        validateFilePresent(
                                certFile, "PEM certificate", "certificate file is required");
                ks = KeyStore.getInstance("JKS");
                ks.load(null);
                PrivateKey privateKey = getPrivateKeyFromPEM(privateKeyFile.getBytes(), password);
                Certificate cert = (Certificate) getCertificateFromPEM(certFile.getBytes());
                ks.setKeyEntry(
                        "alias", privateKey, password.toCharArray(), new Certificate[] {cert});
                break;
            case "PKCS12":
            case "PFX":
                p12File =
                        validateFilePresent(
                                p12File, "PKCS12 keystore", "PKCS12/PFX keystore file is required");
                ks = KeyStore.getInstance("PKCS12");
                ks.load(p12File.getInputStream(), password.toCharArray());
                break;
            case "JKS":
                jksfile =
                        validateFilePresent(
                                jksfile, "JKS keystore", "JKS keystore file is required");
                ks = KeyStore.getInstance("JKS");
                ks.load(jksfile.getInputStream(), password.toCharArray());
                break;
            case "SERVER":
                if (serverCertificateService == null) {
                    throw ExceptionUtils.createIllegalArgumentException(
                            "error.serverCertificateNotAvailable",
                            "Server certificate service is not available in this edition");
                }
                if (!serverCertificateService.isEnabled()) {
                    throw ExceptionUtils.createIllegalArgumentException(
                            "error.serverCertificateDisabled",
                            "Server certificate feature is disabled");
                }
                if (!serverCertificateService.hasServerCertificate()) {
                    throw ExceptionUtils.createIllegalArgumentException(
                            "error.serverCertificateNotFound", "No server certificate configured");
                }
                ks = serverCertificateService.getServerKeyStore();
                keystorePassword = serverCertificateService.getServerCertificatePassword();
                break;
            case "WINDOWS_STORE":
                hardwareKeyStoreService.assertLocalDesktop(httpRequest);
                ks = hardwareKeyStoreService.loadWindowsKeyStore();
                signingProvider = hardwareKeyStoreService.windowsProvider();
                // PIN is prompted by the Windows CSP / token middleware, not passed here.
                keystorePassword = password;
                break;
            case "PKCS11":
                hardwareKeyStoreService.assertLocalDesktop(httpRequest);
                char[] pkcs11Pin = password != null ? password.toCharArray() : null;
                try {
                    pkcs11Session =
                            hardwareKeyStoreService.openPkcs11(
                                    request.getPkcs11LibraryPath(),
                                    request.getPkcs11Slot(),
                                    pkcs11Pin);
                } finally {
                    if (pkcs11Pin != null) {
                        java.util.Arrays.fill(pkcs11Pin, '\0');
                    }
                }
                ks = pkcs11Session.keyStore();
                signingProvider = pkcs11Session.provider();
                keystorePassword = password;
                break;
            case "USER_CERT":
                if (userCertificateService == null || !userCertificateService.isEnabled()) {
                    throw ExceptionUtils.createIllegalArgumentException(
                            "error.userCertificateNotAvailable",
                            "Personal certificate signing is not available or disabled");
                }
                String currentUsername =
                        userService != null ? userService.getCurrentUsername() : null;
                if (StringUtils.isBlank(currentUsername)) {
                    throw ExceptionUtils.createIllegalArgumentException(
                            "error.userCertificateRequiresAuth",
                            "Personal certificate signing requires an authenticated user");
                }
                ks = userCertificateService.getOrCreateUserKeyStore(currentUsername);
                keystorePassword = userCertificateService.getUserKeystorePassword(currentUsername);
                break;
            default:
                throw ExceptionUtils.createIllegalArgumentException(
                        "error.invalidArgument",
                        "Invalid argument: {0}",
                        "certificate type: " + certType);
        }

        char[] pin = keystorePassword != null ? keystorePassword.toCharArray() : null;
        CreateSignature createSignature =
                new CreateSignature(ks, pin, request.getAlias(), signingProvider);
        createSignature.setTsaUrl(resolveSigningTsaUrl(applicationProperties));
        TempFile signedOut = tempFileManager.createManagedTempFile(".pdf");
        try (OutputStream os = new FileOutputStream(signedOut.getFile())) {
            sign(
                    pdfDocumentFactory,
                    pdf,
                    os,
                    createSignature,
                    showSignature,
                    pageNumber,
                    name,
                    location,
                    reason,
                    showLogo,
                    resolveDefaultLocale(applicationProperties));
        } catch (IOException e) {
            signedOut.close();
            throw e;
        } finally {
            // Clear the PIN copy and log out the token session once signing is done.
            if (pin != null) {
                java.util.Arrays.fill(pin, '\0');
            }
            if (pkcs11Session != null) {
                pkcs11Session.close();
            }
        }
        // Return the signed PDF
        return WebResponseUtils.pdfFileToWebResponse(
                signedOut, GeneralUtils.generateFilename(pdf.getOriginalFilename(), "_signed.pdf"));
    }

    private MultipartFile validateFilePresent(
            MultipartFile file, String argumentName, String errorDescription) {
        if (file == null || file.isEmpty()) {
            throw ExceptionUtils.createIllegalArgumentException(
                    "error.invalidArgument",
                    "Invalid argument: {0}",
                    argumentName + " - " + errorDescription);
        }
        return file;
    }

    private PrivateKey getPrivateKeyFromPEM(byte[] pemBytes, String password)
            throws IOException, OperatorCreationException, PKCSException {
        try (PEMParser pemParser =
                new PEMParser(new InputStreamReader(new ByteArrayInputStream(pemBytes)))) {
            Object pemObject = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            PrivateKeyInfo pkInfo;
            if (pemObject instanceof PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo) {
                InputDecryptorProvider decProv =
                        new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password.toCharArray());
                pkInfo = pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decProv);
            } else if (pemObject instanceof PEMEncryptedKeyPair pemEncryptedKeyPair) {
                PEMDecryptorProvider decProv =
                        new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
                pkInfo = pemEncryptedKeyPair.decryptKeyPair(decProv).getPrivateKeyInfo();
            } else {
                pkInfo = ((PEMKeyPair) pemObject).getPrivateKeyInfo();
            }
            return converter.getPrivateKey(pkInfo);
        }
    }

    private Certificate getCertificateFromPEM(byte[] pemBytes)
            throws IOException, CertificateException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(pemBytes)) {
            return CertificateFactory.getInstance("X.509").generateCertificate(bis);
        }
    }

    public static class CreateSignature extends CreateSignatureBase {
        File logoFile;

        public CreateSignature(KeyStore keystore, char[] pin)
                throws KeyStoreException,
                        UnrecoverableKeyException,
                        NoSuchAlgorithmException,
                        IOException,
                        CertificateException {
            this(keystore, pin, null, null);
        }

        public CreateSignature(
                KeyStore keystore, char[] pin, String alias, Provider signingProvider)
                throws KeyStoreException,
                        UnrecoverableKeyException,
                        NoSuchAlgorithmException,
                        IOException,
                        CertificateException {
            super(keystore, pin, alias);
            setSigningProvider(signingProvider);
            loadLogo();
        }

        private void loadLogo() throws IOException {
            ClassPathResource resource = new ClassPathResource("static/images/signature.png");
            try (InputStream is = resource.getInputStream()) {
                logoFile = Files.createTempFile("signature", ".png").toFile();
                FileUtils.copyInputStreamToFile(is, logoFile);
            } catch (IOException e) {
                log.error("Failed to load image signature file");
                throw e;
            }
        }

        public InputStream createVisibleSignature(
                PDDocument srcDoc,
                PDSignature signature,
                Integer pageNumber,
                Boolean showLogo,
                Locale locale)
                throws IOException {
            // modified from org.apache.pdfbox.examples.signature.CreateVisibleSignature2
            boolean russian = locale != null && "ru".equals(locale.getLanguage());
            try (PDDocument doc = new PDDocument()) {
                PDRectangle media = srcDoc.getPage(pageNumber).getMediaBox();
                PDPage page = new PDPage(media);
                doc.addPage(page);
                PDAcroForm acroForm = new PDAcroForm(doc);
                doc.getDocumentCatalog().setAcroForm(acroForm);
                PDSignatureField signatureField = new PDSignatureField(acroForm);
                PDAnnotationWidget widget = signatureField.getWidgets().get(0);
                List<PDField> acroFormFields = acroForm.getFields();
                acroForm.setSignaturesExist(true);
                acroForm.setAppendOnly(true);
                acroForm.getCOSObject().setDirect(true);
                acroFormFields.add(signatureField);

                // The Russian stamp carries a header plus certificate and signing details, so it
                // needs a wider box sized to however many detail lines are present.
                List<String> russianLines = russian ? buildRussianBodyLines(signature) : null;
                float boxWidth = russian ? 320f : 200f;
                float boxHeight = russian ? (50f + russianLines.size() * 14f) : 50f;
                float margin = 18f;
                float gap = 10f;

                // Place the stamp at the bottom-right corner and stack repeated signatures
                // upward, so a document signed more than once shows each stamp in its own spot
                // instead of overlapping the previous one at a fixed position.
                int existingSignatures = srcDoc.getSignatureDictionaries().size();
                float x = media.getUpperRightX() - boxWidth - margin;
                float y = media.getLowerLeftY() + margin + existingSignatures * (boxHeight + gap);
                float maxY = media.getUpperRightY() - boxHeight - margin;
                if (y > maxY) {
                    y = maxY;
                }
                widget.setRectangle(new PDRectangle(x, y, boxWidth, boxHeight));

                // from PDVisualSigBuilder.createHolderForm()
                PDStream stream = new PDStream(doc);
                PDFormXObject form = new PDFormXObject(stream);
                PDResources res = new PDResources();
                form.setResources(res);
                form.setFormType(1);
                PDRectangle bbox = new PDRectangle(boxWidth, boxHeight);
                form.setBBox(bbox);
                // Embed a Unicode TrueType font (subset) so non-Latin signer names and reasons
                // (e.g. Cyrillic) render in the visible signature. The standard Times-Bold uses
                // WinAnsiEncoding and throws on any character outside Latin-1.
                PDFont font;
                try (InputStream fontStream =
                        new ClassPathResource("static/fonts/NotoSans-Bold.ttf").getInputStream()) {
                    font = PDType0Font.load(doc, fontStream);
                }

                // from PDVisualSigBuilder.createAppearanceDictionary()
                PDAppearanceDictionary appearance = new PDAppearanceDictionary();
                appearance.getCOSObject().setDirect(true);
                PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
                appearance.setNormalAppearance(appearanceStream);
                widget.setAppearance(appearance);

                try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream)) {
                    if (russian) {
                        drawRussianStamp(cs, font, russianLines, boxWidth, boxHeight);
                    } else {
                        drawDefaultStamp(cs, font, signature, boxHeight, showLogo, doc);
                    }
                }

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                doc.save(baos);
                return new ByteArrayInputStream(baos.toByteArray());
            }
        }

        /** Upstream three-line stamp: "Signed by &lt;name&gt;", sign date and reason. */
        private void drawDefaultStamp(
                PDPageContentStream cs,
                PDFont font,
                PDSignature signature,
                float height,
                Boolean showLogo,
                PDDocument doc)
                throws IOException {
            if (Boolean.TRUE.equals(showLogo)) {
                cs.saveGraphicsState();
                PDExtendedGraphicsState extState = new PDExtendedGraphicsState();
                extState.setBlendMode(BlendMode.MULTIPLY);
                extState.setNonStrokingAlphaConstant(0.5f);
                cs.setGraphicsStateParameters(extState);
                cs.transform(Matrix.getScaleInstance(0.08f, 0.08f));
                PDImageXObject img = PDImageXObject.createFromFileByExtension(logoFile, doc);
                cs.drawImage(img, 100, 0);
                cs.restoreGraphicsState();
            }

            float fontSize = 10;
            float leading = fontSize * 1.5f;
            cs.beginText();
            cs.setFont(font, fontSize);
            cs.setNonStrokingColor(Color.black);
            cs.newLineAtOffset(fontSize, height - leading);
            cs.setLeading(leading);

            X509Certificate cert = (X509Certificate) getCertificateChain()[0];
            // https://stackoverflow.com/questions/2914521/
            X500Name x500Name = new X500Name(cert.getSubjectX500Principal().getName());
            RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
            String name = IETFUtils.valueToString(cn.getFirst().getValue());

            String date = signature.getSignDate().getTime().toString();
            String reason = signature.getReason();

            cs.showText("Signed by " + name);
            cs.newLine();
            cs.showText(date);
            cs.newLine();
            cs.showText(reason);
            cs.endText();
        }

        /**
         * Russian e-signature stamp: a blue bordered box with a centred header and the certificate
         * serial, owner and validity period, rendered when the instance locale is Russian (see
         * {@code SYSTEM_DEFAULTLOCALE}).
         */
        /**
         * Build the detail lines of the Russian stamp: certificate serial and owner, the signing
         * date, and the signer-supplied reason and location when present.
         */
        private List<String> buildRussianBodyLines(PDSignature signature) {
            X509Certificate cert = (X509Certificate) getCertificateChain()[0];
            X500Name x500Name = new X500Name(cert.getSubjectX500Principal().getName());
            RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
            String owner = IETFUtils.valueToString(cn.getFirst().getValue());

            String serial = cert.getSerialNumber().toString(16).toUpperCase(Locale.ROOT);
            if (serial.length() % 2 != 0) {
                serial = "0" + serial;
            }

            String signedAt = "";
            if (signature.getSignDate() != null) {
                signedAt =
                        signature
                                .getSignDate()
                                .toInstant()
                                .atZone(ZoneId.systemDefault())
                                .toLocalDateTime()
                                .format(DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm"));
            }

            List<String> lines = new ArrayList<>();
            lines.add("Сертификат: " + serial);
            lines.add("Владелец: " + owner);
            lines.add("Подписано: " + signedAt);
            String reason = signature.getReason();
            if (reason != null && !reason.isBlank()) {
                lines.add("Примечание: " + reason);
            }
            String location = signature.getLocation();
            if (location != null && !location.isBlank()) {
                lines.add("Место: " + location);
            }
            return lines;
        }

        private void drawRussianStamp(
                PDPageContentStream cs,
                PDFont font,
                List<String> bodyLines,
                float boxWidth,
                float boxHeight)
                throws IOException {
            Color blue = new Color(0, 51, 204);

            // Blue border, like the conventional Russian e-signature stamp.
            cs.setStrokingColor(blue);
            cs.setLineWidth(1f);
            cs.addRect(1.5f, 1.5f, boxWidth - 3f, boxHeight - 3f);
            cs.stroke();

            cs.setNonStrokingColor(blue);
            float headerSize = 10f;
            float bodySize = 8f;
            drawCentered(cs, font, headerSize, "ДОКУМЕНТ ПОДПИСАН", boxWidth, boxHeight - 16f);
            drawCentered(cs, font, headerSize, "ЦИФРОВОЙ ПОДПИСЬЮ", boxWidth, boxHeight - 28f);

            float leftX = 10f;
            float y = boxHeight - 46f;
            for (String line : bodyLines) {
                drawLine(cs, font, bodySize, line, leftX, y);
                y -= 14f;
            }
        }

        private static void drawLine(
                PDPageContentStream cs, PDFont font, float size, String text, float x, float y)
                throws IOException {
            cs.beginText();
            cs.setFont(font, size);
            cs.newLineAtOffset(x, y);
            cs.showText(text);
            cs.endText();
        }

        private static void drawCentered(
                PDPageContentStream cs,
                PDFont font,
                float size,
                String text,
                float boxWidth,
                float y)
                throws IOException {
            float textWidth = font.getStringWidth(text) / 1000f * size;
            drawLine(cs, font, size, text, (boxWidth - textWidth) / 2f, y);
        }
    }
}
