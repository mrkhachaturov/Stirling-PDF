import { Stack, Button } from "@mantine/core";
import { useTranslation } from "react-i18next";
import { CertSignParameters } from "@app/hooks/tools/certSign/useCertSignParameters";
import { useAppConfig } from "@app/contexts/AppConfigContext";

interface CertificateTypeSettingsProps {
  parameters: CertSignParameters;
  onParameterChange: (key: keyof CertSignParameters, value: any) => void;
  disabled?: boolean;
}

const CertificateTypeSettings = ({
  parameters,
  onParameterChange,
  disabled = false,
}: CertificateTypeSettingsProps) => {
  const { t } = useTranslation();
  const { config } = useAppConfig();
  const isServerCertificateEnabled = config?.serverCertificateEnabled ?? false;
  const isUserCertificateEnabled = config?.userCertificateEnabled ?? false;
  // Per-user personal cert takes priority as the managed "Auto" identity when enabled.
  const isAutoEnabled = isServerCertificateEnabled || isUserCertificateEnabled;

  // Reset to MANUAL if AUTO is selected but no managed certificate is available
  if (parameters.signMode === "AUTO" && !isAutoEnabled) {
    onParameterChange("signMode", "MANUAL");
  }

  return (
    <Stack gap="md">
      <div style={{ display: "flex", gap: "4px" }}>
        <Button
          variant={parameters.signMode === "MANUAL" ? "filled" : "outline"}
          color={
            parameters.signMode === "MANUAL" ? "blue" : "var(--text-muted)"
          }
          onClick={() => {
            onParameterChange("signMode", "MANUAL");
            // Reset cert type when switching to manual
            if (parameters.signMode === "AUTO") {
              onParameterChange("certType", "");
            }
          }}
          disabled={disabled}
          style={{
            flex: 1,
            height: "auto",
            minHeight: "40px",
            fontSize: "11px",
          }}
        >
          <div
            style={{ textAlign: "center", lineHeight: "1.1", fontSize: "11px" }}
          >
            Manual
          </div>
        </Button>
        {isAutoEnabled && (
          <Button
            variant={parameters.signMode === "AUTO" ? "filled" : "outline"}
            color={
              parameters.signMode === "AUTO" ? "green" : "var(--text-muted)"
            }
            onClick={() => {
              onParameterChange("signMode", "AUTO");
              // Select the managed identity: personal cert if enabled, else shared server cert
              onParameterChange(
                "certType",
                isUserCertificateEnabled ? "USER_CERT" : "SERVER",
              );
            }}
            disabled={disabled}
            style={{
              flex: 1,
              height: "auto",
              minHeight: "40px",
              fontSize: "11px",
            }}
          >
            <div
              style={{
                textAlign: "center",
                lineHeight: "1.1",
                fontSize: "11px",
              }}
            >
              {isUserCertificateEnabled
                ? t("certSign.signMode.autoPersonal", "Auto (personal)")
                : t("certSign.signMode.auto", "Auto (server)")}
            </div>
          </Button>
        )}
      </div>
    </Stack>
  );
};

export default CertificateTypeSettings;
