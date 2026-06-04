package stirling.software.proprietary.workflow.service.issuer;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Unit tests for the fail-closed signing-group eligibility check. */
class UserCertificateGroupPolicyTest {

    private static final String CLAIM = "groups";
    private static final String GROUP = "PDF-Signers";

    @Test
    void blankRequiredGroup_disablesGate_everyoneEligible() {
        assertThat(UserCertificateGroupPolicy.isEligible("", CLAIM, Map.of())).isTrue();
        assertThat(UserCertificateGroupPolicy.isEligible(null, CLAIM, Map.of())).isTrue();
    }

    @Test
    void memberOfGroup_isEligible() {
        Map<String, Object> claims = Map.of(CLAIM, List.of("Domain Users", "PDF-Signers"));
        assertThat(UserCertificateGroupPolicy.isEligible(GROUP, CLAIM, claims)).isTrue();
    }

    @Test
    void matchIsCaseInsensitive() {
        Map<String, Object> claims = Map.of(CLAIM, List.of("pdf-signers"));
        assertThat(UserCertificateGroupPolicy.isEligible(GROUP, CLAIM, claims)).isTrue();
    }

    @Test
    void scalarClaimValue_isSupported() {
        Map<String, Object> claims = Map.of(CLAIM, "PDF-Signers");
        assertThat(UserCertificateGroupPolicy.isEligible(GROUP, CLAIM, claims)).isTrue();
    }

    @Test
    void nonMember_isNotEligible() {
        Map<String, Object> claims = Map.of(CLAIM, List.of("Domain Users"));
        assertThat(UserCertificateGroupPolicy.isEligible(GROUP, CLAIM, claims)).isFalse();
    }

    @Test
    void missingClaim_failsClosed() {
        // Gate enabled but the token carries no groups claim (e.g. scope not requested).
        assertThat(UserCertificateGroupPolicy.isEligible(GROUP, CLAIM, Map.of())).isFalse();
    }
}
