package stirling.software.proprietary.workflow.service.issuer;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import stirling.software.proprietary.security.model.User;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Enrols the per-user signing certificate from a self-hosted <a
 * href="https://smallstep.com/docs/step-ca/">step-ca</a> instance using its OIDC provisioner.
 *
 * <p>Flow: generate an RSA key pair → build a PKCS#10 CSR → POST it to step-ca's {@code /1.0/sign}
 * endpoint together with the user's OIDC id token (the one-time token, {@code ott}) → store the
 * returned leaf-first certificate chain. The CA's signing key never enters this process; step-ca
 * applies its own subject/EKU template based on the authenticated identity.
 *
 * <p>The id token is normally supplied explicitly at login time (see {@code
 * UserCertificateOidcEnrollmentListener}), when the acting user's token is fresh and in context. As
 * a fallback it is read from the current security context, which only succeeds when the call runs
 * under the same user's authenticated request.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class StepCaUserCertificateIssuer implements UserCertificateIssuer {

    public static final String NAME = "stepca";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final UserCertificateSettings settings;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public IssuedUserCertificate issue(UserCertificateIssuanceRequest request) throws Exception {
        String caUrl = settings.getCaUrl();
        if (caUrl == null || caUrl.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "system.userCertificate.caUrl must be set when issuer=stepca");
        }

        User user = request.user();
        String idToken = resolveIdToken(request);

        log.info(
                "Enrolling signing certificate for user {} via step-ca at {}",
                user.getUsername(),
                caUrl);

        KeyPair keyPair = generateKeyPair();
        String csrPem = buildCsrPem(user, keyPair);
        X509Certificate[] chain = requestCertificate(caUrl, csrPem, idToken);

        return new IssuedUserCertificate(keyPair.getPrivate(), chain);
    }

    private String resolveIdToken(UserCertificateIssuanceRequest request) {
        if (request.oidcIdToken() != null && !request.oidcIdToken().isBlank()) {
            return request.oidcIdToken();
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof OidcUser oidcUser) {
            if (oidcUser.getIdToken() != null) {
                return oidcUser.getIdToken().getTokenValue();
            }
        }
        throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "step-ca enrolment requires an OIDC id token; the user must sign in via SSO before"
                        + " a signing certificate can be issued");
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        int keySize = settings.getKeySize() > 0 ? settings.getKeySize() : 2048;
        keyPairGenerator.initialize(keySize, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private String buildCsrPem(User user, KeyPair keyPair) throws Exception {
        // Subject is largely advisory: step-ca's OIDC provisioner derives the real subject and SANs
        // from the validated token and its leaf template. We still set the CN for traceability.
        X500Name subject = new X500Name("CN=" + user.getUsername());
        ContentSigner signer =
                new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC")
                        .build(keyPair.getPrivate());
        PKCS10CertificationRequest csr =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic())
                        .build(signer);
        return toPem("CERTIFICATE REQUEST", csr.getEncoded());
    }

    private X509Certificate[] requestCertificate(String caUrl, String csrPem, String idToken)
            throws Exception {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("csr", csrPem);
        body.put("ott", idToken);

        Duration timeout = Duration.ofSeconds(Math.max(1, settings.getRequestTimeoutSeconds()));
        HttpClient client =
                HttpClient.newBuilder()
                        .connectTimeout(timeout)
                        .sslContext(buildSslContext())
                        .build();

        String endpoint = caUrl.replaceAll("/+$", "") + "/1.0/sign";
        HttpRequest httpRequest =
                HttpRequest.newBuilder(URI.create(endpoint))
                        .timeout(timeout)
                        .header("Content-Type", "application/json")
                        .POST(
                                HttpRequest.BodyPublishers.ofString(
                                        MAPPER.writeValueAsString(body), StandardCharsets.UTF_8))
                        .build();

        HttpResponse<String> response =
                client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() / 100 != 2) {
            log.error(
                    "step-ca sign request failed: status={} body={}",
                    response.statusCode(),
                    response.body());
            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "step-ca rejected the signing request (status " + response.statusCode() + ")");
        }

        return parseChain(response.body());
    }

    private X509Certificate[] parseChain(String responseBody) throws Exception {
        JsonNode root = MAPPER.readTree(responseBody);
        List<String> pems = new ArrayList<>();

        // step-ca's /1.0/sign returns the full leaf-first chain as an array. Depending on the
        // version/serialiser the field is named "certChain" or "certChainPem"; accept either.
        // Reading only "crt" (leaf) + "ca" (immediate issuer) drops higher intermediates, so the
        // signature can't be chained to the trusted root and validators report "unable to find
        // valid certification path".
        JsonNode chainNode = root.get("certChain");
        if (chainNode == null || !chainNode.isArray() || chainNode.isEmpty()) {
            chainNode = root.get("certChainPem");
        }
        if (chainNode != null && chainNode.isArray() && !chainNode.isEmpty()) {
            for (JsonNode node : chainNode) {
                if (node.isTextual() && !node.asText().isBlank()) {
                    pems.add(node.asText());
                }
            }
        } else {
            JsonNode crt = root.get("crt");
            if (crt != null && crt.isTextual() && !crt.asText().isBlank()) {
                pems.add(crt.asText());
            }
            JsonNode ca = root.get("ca");
            if (ca != null && ca.isTextual() && !ca.asText().isBlank()) {
                pems.add(ca.asText());
            }
        }

        if (pems.isEmpty()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "step-ca response contained no certificate (expected 'certChain', 'certChainPem'"
                            + " or 'crt')");
        }

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> chain = new ArrayList<>();
        for (String pem : pems) {
            // A single PEM string may concatenate multiple certificates (e.g. a bundled "ca"), so
            // parse every certificate it contains rather than just the first.
            for (Certificate cert :
                    factory.generateCertificates(
                            new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)))) {
                chain.add((X509Certificate) cert);
            }
        }
        return chain.toArray(new X509Certificate[0]);
    }

    /**
     * Build an {@link SSLContext} trusting step-ca. When a CA bundle path is configured it becomes
     * the sole trust anchor set; otherwise the platform default trust store is used.
     */
    private SSLContext buildSslContext() throws Exception {
        String bundlePath = settings.getCaBundlePath();
        if (bundlePath == null || bundlePath.isBlank()) {
            return SSLContext.getDefault();
        }

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        byte[] bundle = Files.readAllBytes(Path.of(bundlePath));
        int index = 0;
        try (ByteArrayInputStream in = new ByteArrayInputStream(bundle)) {
            for (var certificate : factory.generateCertificates(in)) {
                trustStore.setCertificateEntry("step-ca-" + index++, certificate);
            }
        }
        if (index == 0) {
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "system.userCertificate.caBundlePath contained no certificates: " + bundlePath);
        }

        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), new SecureRandom());
        return context;
    }

    private static String toPem(String type, byte[] der) {
        String base64 =
                Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                        .encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
    }
}
