package stirling.software.proprietary.workflow.service.issuer;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

import stirling.software.proprietary.security.model.User;

/**
 * Default issuer: a self-signed RSA-2048 certificate, identical to Stirling's historical {@code
 * generateUserCertificate} behaviour. Trusted only via {@code serverAsAnchor}; never chained to an
 * external CA. Requires no configuration and makes no outbound calls.
 */
@Component
@Slf4j
public class SelfSignedUserCertificateIssuer implements UserCertificateIssuer {

    public static final String NAME = "selfsigned";

    private static final int VALIDITY_DAYS = 365;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public IssuedUserCertificate issue(UserCertificateIssuanceRequest request) throws Exception {
        User user = request.user();
        log.info("Generating self-signed signing certificate for user: {}", user.getUsername());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        String username = user.getUsername();
        X500Name subject = new X500Name("CN=" + username + ", OU=User, O=Stirling PDF Inc, C=US");
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter =
                new Date(notBefore.getTime() + ((long) VALIDITY_DAYS * 24 * 60 * 60 * 1000));

        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        subject, serialNumber, notBefore, notAfter, subject, keyPair.getPublic());

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        // End-entity certificate, not a CA
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Key usage for PDF digital signatures
        certBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));

        // Extended key usage for document signing
        certBuilder.addExtension(
                Extension.extendedKeyUsage,
                false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning));

        // Subject Key Identifier
        certBuilder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

        // Authority Key Identifier for self-signed cert
        certBuilder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()));

        ContentSigner signer =
                new JcaContentSignerBuilder("SHA256WithRSA")
                        .setProvider("BC")
                        .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate cert =
                new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        return new IssuedUserCertificate(keyPair.getPrivate(), new X509Certificate[] {cert});
    }
}
