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

import lombok.extern.slf4j.Slf4j;

import stirling.software.SPDF.config.swagger.StandardPdfResponse;
import stirling.software.SPDF.model.api.security.SignPDFWithCertRequest;
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
    private final ApplicationProperties applicationProperties;

    public CertSignController(
            CustomPDFDocumentFactory pdfDocumentFactory,
            @Autowired(required = false) ServerCertificateServiceInterface serverCertificateService,
            @Autowired(required = false) UserCertificateServiceInterface userCertificateService,
            @Autowired(required = false) UserServiceInterface userService,
            TempFileManager tempFileManager,
            ApplicationProperties applicationProperties) {
        this.pdfDocumentFactory = pdfDocumentFactory;
        this.serverCertificateService = serverCertificateService;
        this.userCertificateService = userCertificateService;
        this.userService = userService;
        this.tempFileManager = tempFileManager;
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

    /**
     * Optional appearance and placement settings for the visible signature stamp. All fields are
     * nullable: when the rectangle is absent the stamp keeps its automatic bottom-right placement,
     * and when colour/size are absent the locale default styling applies.
     *
     * <p>The rectangle is expressed in page fractions (0-1) with the origin at the top-left, which
     * is what the frontend overlay reports; {@link CreateSignature#createVisibleSignature} converts
     * it to PDF user-space (bottom-left origin) points.
     */
    public record VisibleSignatureSpec(
            Float x,
            Float y,
            Float width,
            Float height,
            Integer fontSize,
            String textColor,
            boolean showBorder) {

        public static final VisibleSignatureSpec DEFAULT =
                new VisibleSignatureSpec(null, null, null, null, null, null, true);

        /** True when a full, positive rectangle was supplied by the user. */
        public boolean hasExplicitRect() {
            return x != null
                    && y != null
                    && width != null
                    && height != null
                    && width > 0f
                    && height > 0f;
        }
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
            Locale locale,
            VisibleSignatureSpec stampSpec) {
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
                                    doc, signature, pageNumber, showLogo, locale, stampSpec));
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
    public ResponseEntity<Resource> signPDFWithCert(@ModelAttribute SignPDFWithCertRequest request)
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
        VisibleSignatureSpec stampSpec =
                new VisibleSignatureSpec(
                        request.getStampX(),
                        request.getStampY(),
                        request.getStampWidth(),
                        request.getStampHeight(),
                        request.getFontSize(),
                        request.getTextColor(),
                        !Boolean.FALSE.equals(request.getShowBorder()));

        if (StringUtils.isBlank(certType)) {
            throw ExceptionUtils.createIllegalArgumentException(
                    "error.optionsNotSpecified",
                    "{0} options are not specified",
                    "certificate type");
        }

        KeyStore ks = null;
        String keystorePassword = password;

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

        CreateSignature createSignature = new CreateSignature(ks, keystorePassword.toCharArray());
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
                    resolveDefaultLocale(applicationProperties),
                    stampSpec);
        } catch (IOException e) {
            signedOut.close();
            throw e;
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
            super(keystore, pin);
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
                Locale locale,
                VisibleSignatureSpec stampSpec)
                throws IOException {
            // modified from org.apache.pdfbox.examples.signature.CreateVisibleSignature2
            boolean russian = locale != null && "ru".equals(locale.getLanguage());
            VisibleSignatureSpec spec =
                    stampSpec != null ? stampSpec : VisibleSignatureSpec.DEFAULT;
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

                // Embed a Unicode TrueType font (subset) so non-Latin signer names and reasons
                // (e.g. Cyrillic) render in the visible signature. The standard Times-Bold uses
                // WinAnsiEncoding and throws on any character outside Latin-1. Loaded up front so
                // the Russian stamp can be sized to the actual rendered text width.
                PDFont font;
                try (InputStream fontStream =
                        new ClassPathResource("static/fonts/NotoSans-Bold.ttf").getInputStream()) {
                    font = PDType0Font.load(doc, fontStream);
                }

                // The Russian stamp carries a header plus certificate and signing details. Size the
                // box to the widest line (no large empty right margin) and to however many detail
                // lines are present. This natural size is the appearance BBox; the on-page widget
                // rectangle may differ, and viewers scale the appearance to fill it.
                List<String> russianLines = russian ? buildRussianBodyLines(signature) : null;
                float boxWidth = russian ? russianStampWidth(font, russianLines) : 200f;
                float boxHeight = russian ? (50f + russianLines.size() * 14f) : 50f;

                // The base font size is rendered at boxWidth/boxHeight; a larger fontSize simply
                // scales the whole stamp up by enlarging the widget rectangle (the appearance is
                // mapped onto it), so individual draw offsets stay fixed.
                float fontScale =
                        spec.fontSize() != null && spec.fontSize() > 0
                                ? spec.fontSize() / RU_HEADER_SIZE
                                : 1f;

                PDRectangle widgetRect =
                        computeWidgetRectangle(media, srcDoc, boxWidth, boxHeight, fontScale, spec);
                widget.setRectangle(widgetRect);

                // from PDVisualSigBuilder.createHolderForm()
                PDStream stream = new PDStream(doc);
                PDFormXObject form = new PDFormXObject(stream);
                PDResources res = new PDResources();
                form.setResources(res);
                form.setFormType(1);
                // BBox stays the natural content size; the widget rectangle above drives the final
                // on-page scale, so resizing the placement box stretches the whole stamp to fit.
                PDRectangle bbox = new PDRectangle(boxWidth, boxHeight);
                form.setBBox(bbox);

                // from PDVisualSigBuilder.createAppearanceDictionary()
                PDAppearanceDictionary appearance = new PDAppearanceDictionary();
                appearance.getCOSObject().setDirect(true);
                PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
                appearance.setNormalAppearance(appearanceStream);
                widget.setAppearance(appearance);

                Color textColor =
                        parseColor(spec.textColor(), russian ? RU_DEFAULT_COLOR : Color.black);

                try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream)) {
                    if (russian) {
                        drawRussianStamp(
                                cs,
                                font,
                                russianLines,
                                boxWidth,
                                boxHeight,
                                textColor,
                                spec.showBorder());
                    } else {
                        drawDefaultStamp(cs, font, signature, boxHeight, showLogo, doc, textColor);
                    }
                }

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                doc.save(baos);
                return new ByteArrayInputStream(baos.toByteArray());
            }
        }

        /**
         * Resolve the on-page rectangle for the stamp widget. When the request carries an explicit
         * rectangle (page fractions, top-left origin) it is converted to PDF user space; otherwise
         * the stamp keeps its automatic bottom-right placement, stacking repeated signatures upward
         * so they do not overlap, scaled by the requested font size.
         */
        private PDRectangle computeWidgetRectangle(
                PDRectangle media,
                PDDocument srcDoc,
                float boxWidth,
                float boxHeight,
                float fontScale,
                VisibleSignatureSpec spec) {
            float mediaW = media.getWidth();
            float mediaH = media.getHeight();

            if (spec.hasExplicitRect()) {
                // Scale the stamp to the drawn box WIDTH and derive the height from the stamp's
                // natural aspect ratio. Sizing both axes independently would stretch the text,
                // because the appearance BBox is mapped onto the widget rectangle non-uniformly.
                float rectW = spec.width() * mediaW;
                float rectH = rectW * (boxHeight / boxWidth);
                float rectX = media.getLowerLeftX() + spec.x() * mediaW;
                // The frontend reports y from the top; PDF user space measures from the bottom.
                // Anchor the stamp's top edge at the top of the drawn box.
                float rectY = media.getLowerLeftY() + (1f - spec.y()) * mediaH - rectH;
                // Keep the box on the page even if the client sends a slightly out-of-bounds value.
                rectX =
                        Math.max(
                                media.getLowerLeftX(),
                                Math.min(rectX, media.getUpperRightX() - rectW));
                rectY =
                        Math.max(
                                media.getLowerLeftY(),
                                Math.min(rectY, media.getUpperRightY() - rectH));
                return new PDRectangle(rectX, rectY, rectW, rectH);
            }

            float w = boxWidth * fontScale;
            float h = boxHeight * fontScale;
            float margin = 18f;
            float gap = 10f;
            int existingSignatures = srcDoc.getSignatureDictionaries().size();
            float x = media.getUpperRightX() - w - margin;
            float y = media.getLowerLeftY() + margin + existingSignatures * (h + gap);
            float maxY = media.getUpperRightY() - h - margin;
            if (y > maxY) {
                y = maxY;
            }
            return new PDRectangle(x, y, w, h);
        }

        /** Parse a {@code #RRGGBB} colour, falling back to {@code fallback} when absent/invalid. */
        private static Color parseColor(String hex, Color fallback) {
            if (hex == null || hex.isBlank()) {
                return fallback;
            }
            try {
                return Color.decode(hex.trim());
            } catch (NumberFormatException e) {
                return fallback;
            }
        }

        /** Upstream three-line stamp: "Signed by &lt;name&gt;", sign date and reason. */
        private void drawDefaultStamp(
                PDPageContentStream cs,
                PDFont font,
                PDSignature signature,
                float height,
                Boolean showLogo,
                PDDocument doc,
                Color textColor)
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
            cs.setNonStrokingColor(textColor);
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

        private static final String RU_HEADER_1 = "ДОКУМЕНТ ПОДПИСАН";
        private static final String RU_HEADER_2 = "ЦИФРОВОЙ ПОДПИСЬЮ";
        private static final float RU_HEADER_SIZE = 10f;
        private static final float RU_BODY_SIZE = 8f;
        private static final float RU_PAD = 10f;
        private static final Color RU_DEFAULT_COLOR = new Color(0, 51, 204);

        /**
         * Width of the Russian stamp box, fitted to its widest line so there is no empty margin.
         */
        private float russianStampWidth(PDFont font, List<String> bodyLines) throws IOException {
            float headerMax =
                    Math.max(
                            textWidth(font, RU_HEADER_1, RU_HEADER_SIZE),
                            textWidth(font, RU_HEADER_2, RU_HEADER_SIZE));
            float bodyMax = 0f;
            for (String line : bodyLines) {
                bodyMax = Math.max(bodyMax, textWidth(font, line, RU_BODY_SIZE));
            }
            // Headers are centred (pad both sides); body lines are left-aligned at RU_PAD.
            return Math.max(headerMax + 2f * RU_PAD, RU_PAD + bodyMax + RU_PAD);
        }

        private void drawRussianStamp(
                PDPageContentStream cs,
                PDFont font,
                List<String> bodyLines,
                float boxWidth,
                float boxHeight,
                Color color,
                boolean showBorder)
                throws IOException {
            // The background is left untouched (no fill) so the document shows through the stamp.

            if (showBorder) {
                // Border, like the conventional Russian e-signature stamp.
                cs.setStrokingColor(color);
                cs.setLineWidth(1f);
                cs.addRect(1.5f, 1.5f, boxWidth - 3f, boxHeight - 3f);
                cs.stroke();
            }

            cs.setNonStrokingColor(color);
            drawCentered(cs, font, RU_HEADER_SIZE, RU_HEADER_1, boxWidth, boxHeight - 16f);
            drawCentered(cs, font, RU_HEADER_SIZE, RU_HEADER_2, boxWidth, boxHeight - 28f);

            float y = boxHeight - 46f;
            for (String line : bodyLines) {
                drawLine(cs, font, RU_BODY_SIZE, line, RU_PAD, y);
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
            drawLine(cs, font, size, text, (boxWidth - textWidth(font, text, size)) / 2f, y);
        }

        private static float textWidth(PDFont font, String text, float size) throws IOException {
            return font.getStringWidth(text) / 1000f * size;
        }
    }
}
