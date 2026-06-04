package stirling.software.proprietary.workflow.service;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import stirling.software.proprietary.security.database.repository.UserRepository;
import stirling.software.proprietary.security.model.User;
import stirling.software.proprietary.workflow.model.CertificateType;
import stirling.software.proprietary.workflow.model.UserServerCertificateEntity;
import stirling.software.proprietary.workflow.repository.UserServerCertificateRepository;
import stirling.software.proprietary.workflow.service.issuer.IssuedUserCertificate;
import stirling.software.proprietary.workflow.service.issuer.UserCertificateIssuanceRequest;
import stirling.software.proprietary.workflow.service.issuer.UserCertificateIssuerResolver;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserServerCertificateService {

    private static final String KEYSTORE_ALIAS = "stirling-pdf-user-cert";
    private static final String DEFAULT_PASSWORD_PREFIX = "stirling-user-cert-";

    private final UserServerCertificateRepository certificateRepository;
    private final UserRepository userRepository;
    private final MetadataEncryptionService metadataEncryptionService;
    private final UserCertificateIssuerResolver issuerResolver;

    /** Get or create user certificate (auto-generate if not exists) */
    @Transactional
    public UserServerCertificateEntity getOrCreateUserCertificate(Long userId) throws Exception {
        Optional<UserServerCertificateEntity> existing = certificateRepository.findByUserId(userId);
        if (existing.isPresent()) {
            return existing.get();
        }

        User user =
                userRepository
                        .findById(userId)
                        .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return generateUserCertificate(user);
    }

    /**
     * Generate a new certificate for the user using the configured issuer (self-signed by default).
     */
    @Transactional
    public UserServerCertificateEntity generateUserCertificate(User user) throws Exception {
        return issueAndStore(UserCertificateIssuanceRequest.forUser(user));
    }

    /**
     * Enrol (or re-enrol) the user's signing certificate using an explicitly supplied OIDC id
     * token. Used at login time so an OIDC-backed issuer receives a fresh token in the acting
     * user's own context.
     */
    @Transactional
    public UserServerCertificateEntity enrollUserCertificate(User user, String oidcIdToken)
            throws Exception {
        return issueAndStore(new UserCertificateIssuanceRequest(user, oidcIdToken));
    }

    private UserServerCertificateEntity issueAndStore(UserCertificateIssuanceRequest request)
            throws Exception {
        User user = request.user();
        IssuedUserCertificate issued = issuerResolver.resolve().issue(request);

        X509Certificate leaf = issued.leaf();
        Certificate[] chain = issued.chain();

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        String password = generateUserPassword(user.getId());
        keyStore.setKeyEntry(KEYSTORE_ALIAS, issued.privateKey(), password.toCharArray(), chain);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        keyStore.store(baos, password.toCharArray());
        byte[] keystoreBytes = baos.toByteArray();

        UserServerCertificateEntity entity =
                certificateRepository
                        .findByUserId(user.getId())
                        .orElseGet(UserServerCertificateEntity::new);

        entity.setUser(user);
        entity.setKeystoreData(keystoreBytes);
        entity.setKeystorePassword(metadataEncryptionService.encrypt(password));
        entity.setCertificateType(CertificateType.AUTO_GENERATED);
        entity.setSubjectDn(leaf.getSubjectX500Principal().getName());
        entity.setIssuerDn(leaf.getIssuerX500Principal().getName());
        entity.setValidFrom(
                LocalDateTime.ofInstant(leaf.getNotBefore().toInstant(), ZoneId.systemDefault()));
        entity.setValidTo(
                LocalDateTime.ofInstant(leaf.getNotAfter().toInstant(), ZoneId.systemDefault()));

        return certificateRepository.save(entity);
    }

    /** Upload user-provided certificate */
    @Transactional
    public UserServerCertificateEntity uploadUserCertificate(
            User user, InputStream p12Stream, String password) throws Exception {
        log.info("Uploading user certificate for user: {}", user.getUsername());

        // Validate keystore
        byte[] keystoreBytes = p12Stream.readNBytes(10 * 1024 * 1024 + 1); // read at most 10 MB + 1
        if (keystoreBytes.length > 10 * 1024 * 1024) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "Keystore file exceeds maximum allowed size of 10 MB");
        }
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(keystoreBytes), password.toCharArray());

        // Extract certificate info
        String alias = keyStore.aliases().nextElement();
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

        if (cert == null) {
            throw new IllegalArgumentException("No certificate found in keystore");
        }

        // Create or update entity
        UserServerCertificateEntity entity =
                certificateRepository
                        .findByUserId(user.getId())
                        .orElse(new UserServerCertificateEntity());

        entity.setUser(user);
        entity.setKeystoreData(keystoreBytes);
        entity.setKeystorePassword(metadataEncryptionService.encrypt(password));
        entity.setCertificateType(CertificateType.USER_UPLOADED);
        entity.setSubjectDn(cert.getSubjectX500Principal().getName());
        entity.setIssuerDn(cert.getIssuerX500Principal().getName());
        entity.setValidFrom(
                LocalDateTime.ofInstant(cert.getNotBefore().toInstant(), ZoneId.systemDefault()));
        entity.setValidTo(
                LocalDateTime.ofInstant(cert.getNotAfter().toInstant(), ZoneId.systemDefault()));

        return certificateRepository.save(entity);
    }

    /** Get user's KeyStore for signing operations */
    @Transactional(readOnly = true)
    public KeyStore getUserKeyStore(Long userId) throws Exception {
        UserServerCertificateEntity cert =
                certificateRepository
                        .findByUserId(userId)
                        .orElseThrow(
                                () -> new IllegalArgumentException("User certificate not found"));

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(
                new ByteArrayInputStream(cert.getKeystoreData()),
                metadataEncryptionService.decrypt(cert.getKeystorePassword()).toCharArray());
        return keyStore;
    }

    /** Get user's keystore password */
    @Transactional(readOnly = true)
    public String getUserKeystorePassword(Long userId) {
        UserServerCertificateEntity cert =
                certificateRepository
                        .findByUserId(userId)
                        .orElseThrow(
                                () -> new IllegalArgumentException("User certificate not found"));
        return metadataEncryptionService.decrypt(cert.getKeystorePassword());
    }

    /** Delete user certificate */
    @Transactional
    public void deleteUserCertificate(Long userId) {
        certificateRepository.findByUserId(userId).ifPresent(certificateRepository::delete);
    }

    /** Check if user has certificate */
    @Transactional(readOnly = true)
    public boolean hasUserCertificate(Long userId) {
        return certificateRepository.findByUserId(userId).isPresent();
    }

    /** Get certificate info (without keystore data) */
    @Transactional(readOnly = true)
    public Optional<UserServerCertificateEntity> getCertificateInfo(Long userId) {
        return certificateRepository.findByUserId(userId);
    }

    /** Generate consistent password for user (based on user ID) */
    private String generateUserPassword(Long userId) {
        return DEFAULT_PASSWORD_PREFIX + userId;
    }
}
