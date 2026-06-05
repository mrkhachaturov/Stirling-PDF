package stirling.software.SPDF.model.api.security;

import org.springframework.web.multipart.MultipartFile;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Data;
import lombok.EqualsAndHashCode;

import stirling.software.common.model.api.PDFFile;

@Data
@EqualsAndHashCode(callSuper = true)
public class SignPDFWithCertRequest extends PDFFile {

    @Schema(
            description = "The type of the digital certificate",
            allowableValues = {"PEM", "PKCS12", "PFX", "JKS", "SERVER"},
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String certType;

    @Schema(
            description =
                    "The private key for the digital certificate (required for PEM type"
                            + " certificates, supports .pem, .der, or .key files)")
    private MultipartFile privateKeyFile;

    @Schema(
            description =
                    "The digital certificate (required for PEM type certificates, supports"
                            + " .pem, .der, .crt, or .cer files)")
    private MultipartFile certFile;

    @Schema(
            description =
                    "The PKCS12/PFX keystore file (required for PKCS12 or PFX type certificates)")
    private MultipartFile p12File;

    @Schema(description = "The JKS keystore file (Java Key Store)")
    private MultipartFile jksFile;

    @Schema(description = "The password for the keystore or the private key", format = "password")
    private String password;

    @Schema(
            description = "Whether to visually show the signature in the PDF file",
            defaultValue = "false",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private Boolean showSignature;

    @Schema(description = "The reason for signing the PDF", defaultValue = "Signed by SPDF")
    private String reason;

    @Schema(description = "The location where the PDF is signed", defaultValue = "SPDF")
    private String location;

    @Schema(description = "The name of the signer", defaultValue = "SPDF")
    private String name;

    @Schema(
            description =
                    "The page number where the signature should be visible. This is required if"
                            + " showSignature is set to true",
            defaultValue = "1")
    private Integer pageNumber;

    @Schema(
            description = "Whether to visually show a signature logo along with the signature",
            defaultValue = "true",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private Boolean showLogo;

    @Schema(
            description =
                    "Left edge of the visible signature stamp, as a fraction (0-1) of the page"
                            + " width, measured from the left. When this and the other stamp"
                            + " coordinates are supplied the stamp is placed there instead of the"
                            + " automatic bottom-right position.")
    private Float stampX;

    @Schema(
            description =
                    "Top edge of the visible signature stamp, as a fraction (0-1) of the page"
                            + " height, measured from the top.")
    private Float stampY;

    @Schema(
            description =
                    "Width of the visible signature stamp, as a fraction (0-1) of the page width.")
    private Float stampWidth;

    @Schema(
            description =
                    "Height of the visible signature stamp, as a fraction (0-1) of the page"
                            + " height.")
    private Float stampHeight;

    @Schema(
            description =
                    "Base font size (points) for the visible signature text. Header and body lines"
                            + " scale from this value.")
    private Integer fontSize;

    @Schema(
            description =
                    "Colour applied to the whole visible signature (text and border), as a"
                            + " #RRGGBB hex string.")
    private String textColor;

    @Schema(
            description = "Whether to draw the border around the visible signature stamp",
            defaultValue = "true")
    private Boolean showBorder;
}
