import { BaseParameters } from "@app/types/parameters";
import {
  useBaseParameters,
  BaseParametersHook,
} from "@app/hooks/tools/shared/useBaseParameters";

// Manual placement of the visible stamp, captured from the viewer overlay. Coordinates are
// page fractions (0-1) with the origin at the top-left, matching what the overlay reports; the
// backend converts them to PDF user space. When absent the stamp keeps its automatic placement.
export interface CertSignStampPlacement {
  page: number; // 0-indexed page the stamp was dropped on
  x: number; // left edge, fraction of page width
  y: number; // top edge, fraction of page height
  width: number; // fraction of page width
  height: number; // fraction of page height
}

export interface CertSignParameters extends BaseParameters {
  // Sign mode selection
  signMode: "MANUAL" | "AUTO";
  // Certificate type. In MANUAL mode one of the upload formats; in AUTO mode the managed
  // identity ("SERVER" shared cert or "USER_CERT" personal cert) selected by the UI.
  certType: "" | "PEM" | "PKCS12" | "PFX" | "JKS" | "SERVER" | "USER_CERT";
  privateKeyFile?: File;
  certFile?: File;
  p12File?: File;
  jksFile?: File;
  password: string;

  // Signature appearance options
  showSignature: boolean;
  reason: string;
  location: string;
  name: string;
  pageNumber: number;
  showLogo: boolean;

  // Visible stamp styling (applied uniformly to the whole stamp)
  fontSize: number; // base font size in points
  textColor: string; // #RRGGBB applied to text and border
  showBorder: boolean; // draw the stamp border

  // Optional manual placement from the viewer; null = automatic bottom-right
  stampPlacement: CertSignStampPlacement | null;
}

export const defaultParameters: CertSignParameters = {
  signMode: "MANUAL",
  certType: "",
  password: "",
  showSignature: false,
  reason: "",
  location: "",
  name: "",
  pageNumber: 1,
  showLogo: true,
  fontSize: 10,
  textColor: "#0033CC",
  showBorder: true,
  stampPlacement: null,
};

export type CertSignParametersHook = BaseParametersHook<CertSignParameters>;

export const useCertSignParameters = (): CertSignParametersHook => {
  return useBaseParameters({
    defaultParameters,
    endpointName: "cert-sign",
    validateFn: (params) => {
      // Auto mode (server certificate) - no additional validation needed
      if (params.signMode === "AUTO") {
        return true;
      }

      // Manual mode - requires certificate type and files
      if (!params.certType) {
        return false;
      }

      // Check for required files based on cert type
      switch (params.certType) {
        case "PEM":
          return !!(params.privateKeyFile && params.certFile);
        case "PKCS12":
        case "PFX":
          return !!params.p12File;
        case "JKS":
          return !!params.jksFile;
        default:
          return false;
      }
    },
  });
};
