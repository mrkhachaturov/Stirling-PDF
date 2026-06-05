import {
  Stack,
  Text,
  Button,
  TextInput,
  NumberInput,
  ColorInput,
  Switch,
  Group,
} from "@mantine/core";
import { useTranslation } from "react-i18next";
import { CertSignParameters } from "@app/hooks/tools/certSign/useCertSignParameters";

interface SignatureAppearanceSettingsProps {
  parameters: CertSignParameters;
  onParameterChange: (key: keyof CertSignParameters, value: any) => void;
  disabled?: boolean;
  // Whether the viewer is armed for placement (waiting for the user to click the page)
  isPlacing?: boolean;
  // Enter placement mode so the user can drop the stamp box on the PDF
  onPlaceOnPage?: () => void;
  // Drop any manual placement and fall back to automatic positioning
  onClearPlacement?: () => void;
}

const SignatureAppearanceSettings = ({
  parameters,
  onParameterChange,
  disabled = false,
  isPlacing = false,
  onPlaceOnPage,
  onClearPlacement,
}: SignatureAppearanceSettingsProps) => {
  const { t } = useTranslation();

  const placement = parameters.stampPlacement;
  const hasPlacement = placement != null;
  const canPlace = Boolean(onPlaceOnPage);

  return (
    <Stack gap="md">
      {/* Signature Visibility */}
      <Stack gap="sm">
        <div style={{ display: "flex", gap: "4px" }}>
          <Button
            variant={!parameters.showSignature ? "filled" : "outline"}
            color={!parameters.showSignature ? "blue" : "var(--text-muted)"}
            onClick={() => onParameterChange("showSignature", false)}
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
              {t("certSign.appearance.invisible", "Invisible")}
            </div>
          </Button>
          <Button
            variant={parameters.showSignature ? "filled" : "outline"}
            color={parameters.showSignature ? "blue" : "var(--text-muted)"}
            onClick={() => onParameterChange("showSignature", true)}
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
              {t("certSign.appearance.visible", "Visible")}
            </div>
          </Button>
        </div>
      </Stack>

      {/* Visible Signature Options */}
      {parameters.showSignature && (
        <Stack gap="sm">
          <Text size="sm" fw={500}>
            {t("certSign.appearance.options.title", "Signature Details")}
          </Text>
          <TextInput
            label={t("certSign.reason", "Reason")}
            value={parameters.reason}
            onChange={(event) =>
              onParameterChange("reason", event.currentTarget.value)
            }
            disabled={disabled}
          />
          <TextInput
            label={t("certSign.location", "Location")}
            value={parameters.location}
            onChange={(event) =>
              onParameterChange("location", event.currentTarget.value)
            }
            disabled={disabled}
          />
          <TextInput
            label={t("certSign.name", "Name")}
            value={parameters.name}
            onChange={(event) =>
              onParameterChange("name", event.currentTarget.value)
            }
            disabled={disabled}
          />

          {/* Stamp styling — applied uniformly to the whole stamp */}
          <Group grow align="flex-start">
            <NumberInput
              label={t("certSign.appearance.fontSize", "Font size")}
              value={parameters.fontSize}
              onChange={(value) =>
                onParameterChange(
                  "fontSize",
                  typeof value === "number" ? value : 10,
                )
              }
              min={6}
              max={72}
              disabled={disabled}
            />
            <ColorInput
              label={t("certSign.appearance.textColor", "Text colour")}
              format="hex"
              value={parameters.textColor}
              onChange={(value) => onParameterChange("textColor", value)}
              disabled={disabled}
            />
          </Group>
          <Switch
            label={t("certSign.appearance.showBorder", "Show border")}
            checked={parameters.showBorder}
            onChange={(event) =>
              onParameterChange("showBorder", event.currentTarget.checked)
            }
            disabled={disabled}
          />

          {/* Placement — automatic by default, optional manual placement on the PDF */}
          {canPlace && (
            <Stack gap="xs">
              <Text size="sm" fw={500}>
                {t("certSign.appearance.placement.title", "Placement")}
              </Text>

              {isPlacing ? (
                <Text size="xs" c="dimmed">
                  {t(
                    "certSign.appearance.placement.hint",
                    "Click the page where the stamp should go.",
                  )}
                </Text>
              ) : hasPlacement ? (
                <Stack gap="xs">
                  <Text size="xs" c="dimmed">
                    {t(
                      "certSign.appearance.placement.set",
                      "Manual placement set on page {{page}}.",
                      { page: (placement?.page ?? 0) + 1 },
                    )}
                  </Text>
                  <Group grow>
                    <Button
                      variant="outline"
                      onClick={onPlaceOnPage}
                      disabled={disabled}
                    >
                      {t(
                        "certSign.appearance.placement.reposition",
                        "Reposition",
                      )}
                    </Button>
                    <Button
                      variant="subtle"
                      color="red"
                      onClick={onClearPlacement}
                      disabled={disabled}
                    >
                      {t(
                        "certSign.appearance.placement.reset",
                        "Reset to auto",
                      )}
                    </Button>
                  </Group>
                </Stack>
              ) : (
                <Stack gap="xs">
                  <NumberInput
                    label={t("certSign.pageNumber", "Page Number")}
                    value={parameters.pageNumber}
                    onChange={(value) =>
                      onParameterChange("pageNumber", value || 1)
                    }
                    min={1}
                    disabled={disabled}
                  />
                  <Button
                    variant="outline"
                    onClick={onPlaceOnPage}
                    disabled={disabled}
                  >
                    {t("certSign.appearance.placement.place", "Place on page")}
                  </Button>
                </Stack>
              )}
            </Stack>
          )}

          {/* Fallback page selector when manual placement is unavailable */}
          {!canPlace && (
            <NumberInput
              label={t("certSign.pageNumber", "Page Number")}
              value={parameters.pageNumber}
              onChange={(value) => onParameterChange("pageNumber", value || 1)}
              min={1}
              disabled={disabled}
            />
          )}

          <Stack gap="xs">
            <Text size="sm" fw={500}>
              {t("certSign.logoTitle", "Logo")}
            </Text>
            <div style={{ display: "flex", gap: "4px" }}>
              <Button
                variant={!parameters.showLogo ? "filled" : "outline"}
                color={!parameters.showLogo ? "blue" : "var(--text-muted)"}
                onClick={() => onParameterChange("showLogo", false)}
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
                  {t("certSign.noLogo", "No Logo")}
                </div>
              </Button>
              <Button
                variant={parameters.showLogo ? "filled" : "outline"}
                color={parameters.showLogo ? "blue" : "var(--text-muted)"}
                onClick={() => onParameterChange("showLogo", true)}
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
                  {t("certSign.showLogo", "Show Logo")}
                </div>
              </Button>
            </div>
          </Stack>
        </Stack>
      )}
    </Stack>
  );
};

export default SignatureAppearanceSettings;
