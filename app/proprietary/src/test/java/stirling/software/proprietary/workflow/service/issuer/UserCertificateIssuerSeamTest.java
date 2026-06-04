package stirling.software.proprietary.workflow.service.issuer;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import stirling.software.proprietary.security.model.User;

/** Unit tests for the pluggable user-certificate issuer seam (no network, no persistence). */
class UserCertificateIssuerSeamTest {

    private UserCertificateSettings settings(String issuer) {
        UserCertificateSettings settings = new UserCertificateSettings();
        ReflectionTestUtils.setField(settings, "issuer", issuer);
        return settings;
    }

    private UserCertificateIssuerResolver resolver(UserCertificateSettings settings) {
        return new UserCertificateIssuerResolver(
                List.of(
                        new SelfSignedUserCertificateIssuer(),
                        new StepCaUserCertificateIssuer(settings)),
                settings);
    }

    @Test
    void resolve_defaultsToSelfSigned_whenIssuerBlank() {
        UserCertificateIssuerResolver resolver = resolver(settings("  "));

        assertThat(resolver.resolve()).isInstanceOf(SelfSignedUserCertificateIssuer.class);
        assertThat(resolver.isExternalIssuer()).isFalse();
    }

    @Test
    void resolve_selectsStepCa_whenConfigured() {
        UserCertificateIssuerResolver resolver = resolver(settings("stepca"));

        assertThat(resolver.resolve()).isInstanceOf(StepCaUserCertificateIssuer.class);
        assertThat(resolver.isExternalIssuer()).isTrue();
    }

    @Test
    void resolve_fallsBackToSelfSigned_whenIssuerUnknown() {
        UserCertificateIssuerResolver resolver = resolver(settings("does-not-exist"));

        assertThat(resolver.resolve()).isInstanceOf(SelfSignedUserCertificateIssuer.class);
    }

    @Test
    void selfSignedIssuer_producesSingleSelfIssuedLeaf() throws Exception {
        User user = new User();
        user.setId(7L);
        user.setUsername("alice");

        IssuedUserCertificate issued =
                new SelfSignedUserCertificateIssuer()
                        .issue(UserCertificateIssuanceRequest.forUser(user));

        assertThat(issued.chain()).hasSize(1);
        assertThat(issued.privateKey()).isNotNull();
        // Historical behaviour: self-issued (subject == issuer) with the username + fixed org.
        assertThat(issued.leaf().getSubjectX500Principal().getName())
                .contains("CN=alice")
                .contains("O=Stirling PDF Inc");
        assertThat(issued.leaf().getSubjectX500Principal())
                .isEqualTo(issued.leaf().getIssuerX500Principal());
    }
}
