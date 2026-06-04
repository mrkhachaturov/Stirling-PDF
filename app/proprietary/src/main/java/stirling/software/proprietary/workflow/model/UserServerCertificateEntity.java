package stirling.software.proprietary.workflow.model;

import java.io.Serializable;
import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.*;

import lombok.*;

import stirling.software.proprietary.security.model.User;

@Entity
@Table(name = "user_server_certificates")
@NoArgsConstructor
@Getter
@Setter
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(onlyExplicitlyIncluded = true)
public class UserServerCertificateEntity implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    @EqualsAndHashCode.Include
    @ToString.Include
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", unique = true, nullable = false)
    @JsonIgnore
    private User user;

    // Bind as SQL VARBINARY so the byte[] is stored inline in the bytea column. @Lob would
    // instead map byte[] to a PostgreSQL Large Object (an OID/bigint reference), which mismatches
    // the bytea column ("column ... is of type bytea but expression is of type bigint"). The bug is
    // masked on H2 (the default DB) and only surfaces on PostgreSQL.
    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Basic(fetch = FetchType.EAGER)
    @Column(name = "keystore_data", nullable = false, columnDefinition = "bytea")
    @JsonIgnore
    private byte[] keystoreData;

    @Column(name = "keystore_password", nullable = false)
    @JsonIgnore
    private String keystorePassword;

    @Enumerated(EnumType.STRING)
    @Column(name = "certificate_type", nullable = false, length = 50)
    private CertificateType certificateType;

    @Column(name = "subject_dn", length = 500)
    private String subjectDn;

    @Column(name = "issuer_dn", length = 500)
    private String issuerDn;

    @Column(name = "valid_from")
    private LocalDateTime validFrom;

    @Column(name = "valid_to")
    private LocalDateTime validTo;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}
