import { useCallback, useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { createToolFlow } from "@app/components/tools/shared/createToolFlow";
import { useAppConfig } from "@app/contexts/AppConfigContext";
import CertificateTypeSettings from "@app/components/tools/certSign/CertificateTypeSettings";
import CertificateFormatSettings from "@app/components/tools/certSign/CertificateFormatSettings";
import CertificateFilesSettings from "@app/components/tools/certSign/CertificateFilesSettings";
import HardwareCertificateSettings from "@app/components/tools/certSign/HardwareCertificateSettings";
import SignatureAppearanceSettings from "@app/components/tools/certSign/SignatureAppearanceSettings";
import {
  useCertSignParameters,
  type CertSignStampPlacement,
} from "@app/hooks/tools/certSign/useCertSignParameters";
import { useCertSignOperation } from "@app/hooks/tools/certSign/useCertSignOperation";
import { useCertificateTypeTips } from "@app/components/tooltips/useCertificateTypeTips";
import { useSignatureAppearanceTips } from "@app/components/tooltips/useSignatureAppearanceTips";
import { useSignModeTips } from "@app/components/tooltips/useSignModeTips";
import { useBaseTool } from "@app/hooks/tools/shared/useBaseTool";
import { BaseToolProps, ToolComponent } from "@app/types/tool";
import { useNavigation } from "@app/contexts/NavigationContext";
import { useSignature } from "@app/contexts/SignatureContext";
import { useViewer } from "@app/contexts/ViewerContext";
import { buildCertStampPreview } from "@app/components/tools/certSign/stampPreview";

// EmbedPDF stamp annotation subtype (PDF FPDF_ANNOT_STAMP).
const STAMP_ANNOTATION_TYPE = 13;
// Let the viewer mount the annotation layer before selecting the stamp tool.
const PLACEMENT_ACTIVATION_DELAY = 150;

// The viewer reports an annotation rect either nested (origin/size) or flattened, depending on
// which EmbedPDF code path produced it; both shapes are read defensively when normalizing.
type StampRect = {
  origin?: { x: number; y: number };
  size?: { width: number; height: number };
  x?: number;
  y?: number;
  width?: number;
  height?: number;
};

const CertSign = (props: BaseToolProps) => {
  const { t, i18n } = useTranslation();

  const base = useBaseTool(
    "certSign",
    useCertSignParameters,
    useCertSignOperation,
    props,
  );

  const { config } = useAppConfig();
  // "Upload" is always available; the source chooser is only meaningful when a
  // server certificate or a hardware token gives the user an actual alternative.
  const hasCertSourceChoice =
    (config?.serverCertificateEnabled ?? false) ||
    (config?.hardwareSigningAvailable ?? false);

  // With Upload as the only source, keep signMode on MANUAL even if a saved
  // automation set AUTO/DEVICE, so the hidden source step can't strand the flow.
  useEffect(() => {
    if (!hasCertSourceChoice && base.params.parameters.signMode !== "MANUAL") {
      base.params.updateParameter("signMode", "MANUAL");
    }
  }, [
    hasCertSourceChoice,
    base.params.parameters.signMode,
    base.params.updateParameter,
  ]);

  const certTypeTips = useCertificateTypeTips();
  const appearanceTips = useSignatureAppearanceTips();
  const signModeTips = useSignModeTips();

  const { setWorkbench } = useNavigation();
  const {
    setSignatureConfig,
    setPlacementPreviewSize,
    activateSignaturePlacementMode,
    deactivateDrawMode,
    signatureApiRef,
    isPlacementMode,
  } = useSignature();
  const { getScrollState, getZoomState } = useViewer();

  const params = base.params.parameters;
  const { updateParameter } = base.params;

  // Feed the viewer a WYSIWYG preview of the stamp so the placement box looks like what the
  // backend will draw (same layout, colour, border, proportions). The real stamp is rendered
  // server-side at signing time, so this preview is never flattened into the PDF.
  useEffect(() => {
    if (!params.showSignature) return;
    const preview = buildCertStampPreview({
      language: i18n.language,
      fontSize: params.fontSize,
      textColor: params.textColor,
      showBorder: params.showBorder,
      name: params.name,
      reason: params.reason,
      location: params.location,
    });
    if (!preview) return;
    setSignatureConfig({
      signatureType: "image",
      signatureData: preview.dataUrl,
      textAlign: "left",
    });
    setPlacementPreviewSize({ width: preview.width, height: preview.height });
  }, [
    params.showSignature,
    params.fontSize,
    params.textColor,
    params.showBorder,
    params.name,
    params.reason,
    params.location,
    i18n.language,
    setSignatureConfig,
    setPlacementPreviewSize,
  ]);

  // Track the placeholder stamp left on the page so it can be cleared when the user repositions,
  // resets, or leaves the tool. It stays visible after placement as a preview of where the stamp
  // will land; it is never flattened (signing uses the original file, not the viewer copy).
  const placedStampsRef = useRef<Array<{ page: number; id: string }>>([]);
  const placementPollRef = useRef<number | null>(null);
  // True while the stamp tool is armed and waiting for the first click.
  const armedRef = useRef(false);
  // Last placement written to params, so the sync poll only updates on real movement.
  const lastPlacementRef = useRef<string>("");

  const stopPlacementPoll = useCallback(() => {
    if (placementPollRef.current !== null) {
      window.clearInterval(placementPollRef.current);
      placementPollRef.current = null;
    }
  }, []);

  const clearPlacedStamps = useCallback(() => {
    const api = signatureApiRef.current;
    if (api) {
      for (const { page, id } of placedStampsRef.current) {
        try {
          api.deleteAnnotation(id, page);
        } catch {
          // Non-fatal: the placeholder is cosmetic and never exported.
        }
      }
    }
    placedStampsRef.current = [];
  }, [signatureApiRef]);

  // Find the placeholder stamp on whichever page it was dropped on.
  const locatePlacedStamp = useCallback(async () => {
    const api = signatureApiRef.current;
    if (!api) return null;
    const { totalPages } = getScrollState();
    const pageCount = Math.max(1, totalPages);
    for (let pageIndex = 0; pageIndex < pageCount; pageIndex++) {
      const annotations = await api.getPageAnnotations(pageIndex);
      const stamp = (annotations || []).find(
        (a) => a?.rect && (a.type === STAMP_ANNOTATION_TYPE || a.imageSrc),
      );
      if (stamp) return { pageIndex, stamp };
    }
    return null;
  }, [signatureApiRef, getScrollState]);

  // Always leave placement mode (and remove any placeholder) when the tool unmounts.
  useEffect(
    () => () => {
      stopPlacementPoll();
      clearPlacedStamps();
      deactivateDrawMode();
    },
    [stopPlacementPoll, clearPlacedStamps, deactivateDrawMode],
  );

  // Normalize the placed box to (0-1, top-left) page fractions. The annotation rect is in PDF
  // points with a top-left origin; the page DOM node carries its zoom-scaled size, so dividing by
  // (size / zoom) yields fractions.
  const normalizeStamp = useCallback(
    (
      pageIndex: number,
      stamp: { rect: StampRect },
    ): CertSignStampPlacement | null => {
      const zoom = getZoomState()?.currentZoom ?? 1;
      const pageNode = document.querySelector<HTMLElement>(
        `[data-page-index="${pageIndex}"]`,
      );
      const pageWidth = parseFloat(pageNode?.dataset.pageWidth || "0") / zoom;
      const pageHeight = parseFloat(pageNode?.dataset.pageHeight || "0") / zoom;
      if (!pageWidth || !pageHeight) return null;

      const rect = stamp.rect;
      const originX = rect.origin?.x ?? rect.x ?? 0;
      const originY = rect.origin?.y ?? rect.y ?? 0;
      const width = rect.size?.width ?? rect.width ?? 0;
      const height = rect.size?.height ?? rect.height ?? 0;
      return {
        page: pageIndex,
        x: originX / pageWidth,
        y: originY / pageHeight,
        width: width / pageWidth,
        height: height / pageHeight,
      };
    },
    [getZoomState],
  );

  const handlePlaceOnPage = useCallback(() => {
    // Start fresh so only one placeholder is ever on the page.
    stopPlacementPoll();
    clearPlacedStamps();
    lastPlacementRef.current = "";
    armedRef.current = true;
    setWorkbench("viewer");
    window.setTimeout(() => {
      activateSignaturePlacementMode();
      // One poll does two jobs: the moment the first box is dropped it stops the stamp tool (so a
      // second copy is never armed and the cursor ghost disappears), then it keeps the stored
      // position in sync as the user drags or resizes that single box.
      placementPollRef.current = window.setInterval(async () => {
        const located = await locatePlacedStamp();
        if (!located) return;
        if (armedRef.current) {
          armedRef.current = false;
          deactivateDrawMode();
        }
        placedStampsRef.current = [
          { page: located.pageIndex, id: located.stamp.id },
        ];
        const placement = normalizeStamp(located.pageIndex, located.stamp);
        if (!placement) return;
        const key =
          `${placement.page}:${placement.x.toFixed(4)}:${placement.y.toFixed(4)}` +
          `:${placement.width.toFixed(4)}:${placement.height.toFixed(4)}`;
        if (key !== lastPlacementRef.current) {
          lastPlacementRef.current = key;
          updateParameter("stampPlacement", placement);
        }
      }, 300);
    }, PLACEMENT_ACTIVATION_DELAY);
  }, [
    stopPlacementPoll,
    clearPlacedStamps,
    setWorkbench,
    activateSignaturePlacementMode,
    locatePlacedStamp,
    normalizeStamp,
    deactivateDrawMode,
    updateParameter,
  ]);

  const handleClearPlacement = useCallback(() => {
    stopPlacementPoll();
    clearPlacedStamps();
    deactivateDrawMode();
    lastPlacementRef.current = "";
    updateParameter("stampPlacement", null);
  }, [
    stopPlacementPoll,
    clearPlacedStamps,
    deactivateDrawMode,
    updateParameter,
  ]);

  // Check if certificate files are configured for appearance step
  const areCertFilesConfigured = () => {
    const params = base.params.parameters;

    // Auto mode (server certificate) - always configured
    if (params.signMode === "AUTO") {
      return true;
    }

    // Manual mode - check for required files based on cert type
    switch (params.certType) {
      case "PEM":
        return !!(params.privateKeyFile && params.certFile);
      case "PKCS12":
      case "PFX":
        return !!params.p12File;
      case "JKS":
        return !!params.jksFile;
      case "WINDOWS_STORE":
        return !!params.alias;
      case "PKCS11":
        return !!(params.pkcs11LibraryPath && params.alias);
      default:
        return false;
    }
  };

  return createToolFlow({
    forceStepNumbers: true,
    files: {
      selectedFiles: base.selectedFiles,
      isCollapsed: base.hasResults,
    },
    steps: [
      {
        title: t("certSign.source.stepTitle", "Certificate source"),
        isVisible: hasCertSourceChoice,
        isCollapsed: base.settingsCollapsed,
        onCollapsedClick: base.settingsCollapsed
          ? base.handleSettingsReset
          : undefined,
        tooltip: signModeTips,
        content: (
          <CertificateTypeSettings
            parameters={base.params.parameters}
            onParameterChange={base.params.updateParameter}
            disabled={base.endpointLoading}
          />
        ),
      },
      ...(base.params.parameters.signMode === "MANUAL"
        ? [
            {
              title: t("certSign.certTypeStep.stepTitle", "Certificate Format"),
              isCollapsed: base.settingsCollapsed,
              onCollapsedClick: base.settingsCollapsed
                ? base.handleSettingsReset
                : undefined,
              tooltip: certTypeTips,
              content: (
                <CertificateFormatSettings
                  parameters={base.params.parameters}
                  onParameterChange={base.params.updateParameter}
                  disabled={base.endpointLoading}
                />
              ),
            },
          ]
        : []),
      ...(base.params.parameters.signMode === "MANUAL"
        ? [
            {
              title: t("certSign.certFiles.stepTitle", "Certificate Files"),
              isCollapsed: base.settingsCollapsed,
              onCollapsedClick: base.settingsCollapsed
                ? base.handleSettingsReset
                : undefined,
              content: (
                <CertificateFilesSettings
                  parameters={base.params.parameters}
                  onParameterChange={base.params.updateParameter}
                  disabled={base.endpointLoading}
                />
              ),
            },
          ]
        : []),
      ...(base.params.parameters.signMode === "DEVICE"
        ? [
            {
              title: t("certSign.device.stepTitle", "This device"),
              isCollapsed: base.settingsCollapsed,
              onCollapsedClick: base.settingsCollapsed
                ? base.handleSettingsReset
                : undefined,
              content: (
                <HardwareCertificateSettings
                  parameters={base.params.parameters}
                  onParameterChange={base.params.updateParameter}
                  disabled={base.endpointLoading}
                />
              ),
            },
          ]
        : []),
      {
        title: t("certSign.appearance.stepTitle", "Signature Appearance"),
        isCollapsed: base.settingsCollapsed || !areCertFilesConfigured(),
        onCollapsedClick:
          base.settingsCollapsed || !areCertFilesConfigured()
            ? base.handleSettingsReset
            : undefined,
        tooltip: appearanceTips,
        content: (
          <SignatureAppearanceSettings
            parameters={base.params.parameters}
            onParameterChange={base.params.updateParameter}
            disabled={base.endpointLoading}
            isPlacing={isPlacementMode}
            onPlaceOnPage={handlePlaceOnPage}
            onClearPlacement={handleClearPlacement}
          />
        ),
      },
    ],
    executeButton: {
      text: t("certSign.sign.submit", "Sign PDF"),
      isVisible: !base.hasResults,
      loadingText: t("loading"),
      onClick: base.handleExecute,
      endpointEnabled: base.endpointEnabled,
      paramsValid: base.params.validateParameters(),
    },
    review: {
      isVisible: base.hasResults,
      operation: base.operation,
      title: t("certSign.sign.results", "Signed PDF"),
      onFileClick: base.handleThumbnailClick,
      onUndo: base.handleUndo,
    },
  });
};

// Static method to get the operation hook for automation
CertSign.tool = () => useCertSignOperation;

export default CertSign as ToolComponent;
