package stirling.software.SPDF.controller.api.security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

import stirling.software.common.model.api.PDFFile;
import stirling.software.common.service.CustomPDFDocumentFactory;
import stirling.software.common.util.TempFile;
import stirling.software.common.util.TempFileManager;

@DisplayName("RemoveCertSignController Tests")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RemoveCertSignControllerTest {
    private static ResponseEntity<Resource> streamingOk(byte[] bytes) {
        return ResponseEntity.ok(new ByteArrayResource(bytes));
    }

    private static byte[] drainBody(ResponseEntity<Resource> response) throws java.io.IOException {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        try (java.io.InputStream __in = response.getBody().getInputStream()) {
            __in.transferTo(baos);
        }
        return baos.toByteArray();
    }

    @Mock private CustomPDFDocumentFactory pdfDocumentFactory;
    @Mock private TempFileManager tempFileManager;

    @InjectMocks private RemoveCertSignController removeCertSignController;

    private byte[] simplePdfBytes;

    @BeforeEach
    void setUp() throws Exception {
        lenient()
                .when(tempFileManager.createManagedTempFile(anyString()))
                .thenAnswer(
                        inv -> {
                            File f =
                                    Files.createTempFile("test", inv.<String>getArgument(0))
                                            .toFile();
                            TempFile tf = mock(TempFile.class);
                            lenient().when(tf.getFile()).thenReturn(f);
                            lenient().when(tf.getPath()).thenReturn(f.toPath());
                            return tf;
                        });
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new PDPage());
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            simplePdfBytes = baos.toByteArray();
        }
    }

    @Nested
    @DisplayName("Remove Certificate Signature Tests")
    class RemoveCertSignTests {

        @Test
        @DisplayName("Should process PDF without signatures")
        void testRemoveCertSign_NoSignatures() throws Exception {
            MockMultipartFile pdfFile =
                    new MockMultipartFile(
                            "fileInput",
                            "test.pdf",
                            MediaType.APPLICATION_PDF_VALUE,
                            simplePdfBytes);

            PDFFile request = new PDFFile();
            request.setFileInput(pdfFile);

            when(pdfDocumentFactory.load(any(MultipartFile.class)))
                    .thenAnswer(inv -> Loader.loadPDF(simplePdfBytes));

            ResponseEntity<Resource> response = removeCertSignController.removeCertSignPDF(request);

            assertNotNull(response.getBody());
            assertTrue(drainBody(response).length > 0);
            assertEquals(HttpStatus.OK, response.getStatusCode());
        }

        @Test
        @DisplayName("Should process PDF with no AcroForm")
        void testRemoveCertSign_NoAcroForm() throws Exception {
            MockMultipartFile pdfFile =
                    new MockMultipartFile(
                            "fileInput",
                            "test.pdf",
                            MediaType.APPLICATION_PDF_VALUE,
                            simplePdfBytes);

            PDFFile request = new PDFFile();
            request.setFileInput(pdfFile);

            when(pdfDocumentFactory.load(any(MultipartFile.class)))
                    .thenAnswer(inv -> Loader.loadPDF(simplePdfBytes));

            ResponseEntity<Resource> response = removeCertSignController.removeCertSignPDF(request);

            assertNotNull(response.getBody());
        }

        @Test
        @DisplayName("Should process PDF with AcroForm but no signature fields")
        void testRemoveCertSign_AcroFormNoSignatures() throws Exception {
            byte[] pdfWithAcroForm;
            try (PDDocument doc = new PDDocument()) {
                doc.addPage(new PDPage());
                PDAcroForm acroForm = new PDAcroForm(doc);
                doc.getDocumentCatalog().setAcroForm(acroForm);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                doc.save(baos);
                pdfWithAcroForm = baos.toByteArray();
            }

            MockMultipartFile pdfFile =
                    new MockMultipartFile(
                            "fileInput",
                            "test.pdf",
                            MediaType.APPLICATION_PDF_VALUE,
                            pdfWithAcroForm);

            PDFFile request = new PDFFile();
            request.setFileInput(pdfFile);

            when(pdfDocumentFactory.load(any(MultipartFile.class)))
                    .thenAnswer(inv -> Loader.loadPDF(pdfWithAcroForm));

            ResponseEntity<Resource> response = removeCertSignController.removeCertSignPDF(request);
            assertNotNull(response.getBody());
        }

        @Test
        @DisplayName("Should handle PDF with signature field in AcroForm")
        void testRemoveCertSign_WithSignatureField() throws Exception {
            byte[] pdfWithSig;
            try (PDDocument doc = new PDDocument()) {
                PDPage page = new PDPage();
                doc.addPage(page);
                PDAcroForm acroForm = new PDAcroForm(doc);
                doc.getDocumentCatalog().setAcroForm(acroForm);
                PDSignatureField sigField = new PDSignatureField(acroForm);
                acroForm.getFields().add(sigField);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                doc.save(baos);
                pdfWithSig = baos.toByteArray();
            }

            MockMultipartFile pdfFile =
                    new MockMultipartFile(
                            "fileInput", "test.pdf", MediaType.APPLICATION_PDF_VALUE, pdfWithSig);

            PDFFile request = new PDFFile();
            request.setFileInput(pdfFile);

            when(pdfDocumentFactory.load(any(MultipartFile.class)))
                    .thenAnswer(inv -> Loader.loadPDF(pdfWithSig));

            ResponseEntity<Resource> response = removeCertSignController.removeCertSignPDF(request);
            assertNotNull(response.getBody());
        }

        @Test
        @DisplayName("Should remove the visible signature widget from the page, not flatten it")
        void testRemoveCertSign_RemovesVisibleWidget() throws Exception {
            // Build a PDF whose signature field has a visible widget annotation on the page,
            // mirroring the stamp a real signing produces.
            byte[] pdfWithVisibleSig;
            try (PDDocument doc = new PDDocument()) {
                PDPage page = new PDPage();
                doc.addPage(page);
                PDAcroForm acroForm = new PDAcroForm(doc);
                doc.getDocumentCatalog().setAcroForm(acroForm);
                PDSignatureField sigField = new PDSignatureField(acroForm);
                PDAnnotationWidget widget = sigField.getWidgets().get(0);
                widget.setRectangle(new PDRectangle(50, 50, 200, 50));
                widget.setPage(page);
                page.getAnnotations().add(widget);
                acroForm.getFields().add(sigField);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                doc.save(baos);
                pdfWithVisibleSig = baos.toByteArray();
            }

            // Sanity check: the widget really is present before removal.
            try (PDDocument before = Loader.loadPDF(pdfWithVisibleSig)) {
                assertFalse(before.getPage(0).getAnnotations().isEmpty());
            }

            MockMultipartFile pdfFile =
                    new MockMultipartFile(
                            "fileInput",
                            "signed.pdf",
                            MediaType.APPLICATION_PDF_VALUE,
                            pdfWithVisibleSig);
            PDFFile request = new PDFFile();
            request.setFileInput(pdfFile);
            when(pdfDocumentFactory.load(any(MultipartFile.class)))
                    .thenAnswer(inv -> Loader.loadPDF(pdfWithVisibleSig));

            ResponseEntity<Resource> response = removeCertSignController.removeCertSignPDF(request);

            try (PDDocument after = Loader.loadPDF(drainBody(response))) {
                assertTrue(
                        after.getPage(0).getAnnotations().isEmpty(),
                        "Visible signature widget should be gone from the page");
                PDAcroForm form = after.getDocumentCatalog().getAcroForm();
                boolean hasSignatureField =
                        form != null
                                && form.getFields().stream()
                                        .anyMatch(f -> f instanceof PDSignatureField);
                assertFalse(
                        hasSignatureField, "Signature field should be removed from the AcroForm");
            }
        }

        @Test
        @DisplayName("Should produce correct filename suffix")
        void testRemoveCertSign_FilenameSuffix() throws Exception {
            MockMultipartFile pdfFile =
                    new MockMultipartFile(
                            "fileInput",
                            "signed_doc.pdf",
                            MediaType.APPLICATION_PDF_VALUE,
                            simplePdfBytes);

            PDFFile request = new PDFFile();
            request.setFileInput(pdfFile);

            when(pdfDocumentFactory.load(any(MultipartFile.class)))
                    .thenAnswer(inv -> Loader.loadPDF(simplePdfBytes));

            ResponseEntity<Resource> response = removeCertSignController.removeCertSignPDF(request);
            assertNotNull(response);
            assertEquals(HttpStatus.OK, response.getStatusCode());
        }

        @Test
        @DisplayName("Should handle null original filename")
        void testRemoveCertSign_NullFilename() throws Exception {
            MockMultipartFile pdfFile =
                    new MockMultipartFile(
                            "fileInput", null, MediaType.APPLICATION_PDF_VALUE, simplePdfBytes);

            PDFFile request = new PDFFile();
            request.setFileInput(pdfFile);

            when(pdfDocumentFactory.load(any(MultipartFile.class)))
                    .thenAnswer(inv -> Loader.loadPDF(simplePdfBytes));

            ResponseEntity<Resource> response = removeCertSignController.removeCertSignPDF(request);
            assertNotNull(response.getBody());
        }

        @Test
        @DisplayName("Should handle multi-page PDF")
        void testRemoveCertSign_MultiPage() throws Exception {
            byte[] multiPagePdf;
            try (PDDocument doc = new PDDocument()) {
                doc.addPage(new PDPage());
                doc.addPage(new PDPage());
                doc.addPage(new PDPage());
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                doc.save(baos);
                multiPagePdf = baos.toByteArray();
            }

            MockMultipartFile pdfFile =
                    new MockMultipartFile(
                            "fileInput",
                            "multi.pdf",
                            MediaType.APPLICATION_PDF_VALUE,
                            multiPagePdf);

            PDFFile request = new PDFFile();
            request.setFileInput(pdfFile);

            when(pdfDocumentFactory.load(any(MultipartFile.class)))
                    .thenAnswer(inv -> Loader.loadPDF(multiPagePdf));

            ResponseEntity<Resource> response = removeCertSignController.removeCertSignPDF(request);
            assertNotNull(response.getBody());
        }

        @Test
        @DisplayName("Should handle IOException from factory")
        void testRemoveCertSign_IOException() throws Exception {
            MockMultipartFile pdfFile =
                    new MockMultipartFile(
                            "fileInput",
                            "test.pdf",
                            MediaType.APPLICATION_PDF_VALUE,
                            simplePdfBytes);

            PDFFile request = new PDFFile();
            request.setFileInput(pdfFile);

            when(pdfDocumentFactory.load(any(MultipartFile.class)))
                    .thenThrow(new IOException("Cannot load PDF"));

            assertThrows(
                    Exception.class, () -> removeCertSignController.removeCertSignPDF(request));
        }
    }
}
