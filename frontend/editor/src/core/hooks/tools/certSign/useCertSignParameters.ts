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
  // Where the signing certificate comes from:
  //  MANUAL = upload a keystore file, AUTO = a managed identity on the server,
  //  DEVICE = a certificate held on this machine (Windows store or USB PKCS#11 token, desktop only).
  signMode: "MANUAL" | "AUTO" | "DEVICE";
  // For MANUAL this is the uploaded file format; for AUTO it is the managed identity
  // ("SERVER" shared cert or "USER_CERT" personal cert); for DEVICE it is the hardware kind
  // (WINDOWS_STORE or PKCS11). Hardware kinds are only offered in the desktop app.
  certType:
    | ""
    | "PEM"
    | "PKCS12"
    | "PFX"
    | "JKS"
    | "SERVER"
    | "USER_CERT"
    | "WINDOWS_STORE"
    | "PKCS11";
  privateKeyFile?: File;
  certFile?: File;
  p12File?: File;
  jksFile?: File;
  password: string;

  // Hardware signing (desktop only)
  alias?: string;
  pkcs11LibraryPath?: string;
  pkcs11Slot?: number;

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
        case "WINDOWS_STORE":
          // Need a chosen certificate from the Windows store.
          return !!params.alias;
        case "PKCS11":
          // Need a driver library and a chosen certificate on the token.
          return !!(params.pkcs11LibraryPath && params.alias);
        default:
          return false;
      }
    },
  });
};
