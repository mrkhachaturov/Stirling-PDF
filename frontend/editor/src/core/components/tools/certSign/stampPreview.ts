// Renders a WYSIWYG preview of the visible certificate stamp to a PNG data URL, so the placement
// box on the PDF looks like the stamp the backend will draw (same layout, colour, border and
// proportions). The certificate-derived fields (serial, owner) are not known on the client until
// signing — and are absent entirely for managed SERVER/USER_CERT certs — so they are shown as
// representative sample values; the shape, style and aspect ratio match the real stamp.

export interface StampPreviewInput {
  language: string;
  fontSize: number;
  textColor: string;
  showBorder: boolean;
  name?: string;
  reason?: string;
  location?: string;
}

export interface StampPreviewResult {
  dataUrl: string;
  width: number;
  height: number;
}

const FONT_FAMILY = "Arial, 'Helvetica Neue', Helvetica, sans-serif";
// Oversample the canvas so the downscaled placement image stays crisp.
const SUPERSAMPLE = 3;

const RU_HEADER = ["ДОКУМЕНТ ПОДПИСАН", "ЦИФРОВОЙ ПОДПИСЬЮ"];
const SAMPLE_SERIAL = "00A1B2C3D4E5F6A7";

function todayStamp(): string {
  // dd.MM.yyyy HH:mm — mirrors the backend stamp's date format.
  const now = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return (
    `${p(now.getDate())}.${p(now.getMonth() + 1)}.${now.getFullYear()} ` +
    `${p(now.getHours())}:${p(now.getMinutes())}`
  );
}

function buildLines(input: StampPreviewInput, russian: boolean): string[] {
  const lines: string[] = [];
  if (russian) {
    lines.push(`Сертификат: ${SAMPLE_SERIAL}`);
    lines.push(`Владелец: ${input.name?.trim() || "Владелец сертификата"}`);
    lines.push(`Подписано: ${todayStamp()}`);
    if (input.reason?.trim()) lines.push(`Примечание: ${input.reason.trim()}`);
    if (input.location?.trim()) lines.push(`Место: ${input.location.trim()}`);
  } else {
    lines.push(`Signed by ${input.name?.trim() || "Certificate owner"}`);
    lines.push(todayStamp());
    if (input.reason?.trim()) lines.push(input.reason.trim());
    if (input.location?.trim()) lines.push(input.location.trim());
  }
  return lines;
}

export function buildCertStampPreview(
  input: StampPreviewInput,
): StampPreviewResult | null {
  const russian = (input.language || "").toLowerCase().startsWith("ru");
  const base = input.fontSize > 0 ? input.fontSize : 10;
  // Ratios mirror the backend stamp metrics (header 10, body 8, pad 10, line step 14 at base 10).
  const headerSize = base;
  const bodySize = base * 0.8;
  const pad = base;
  const lineStep = base * 1.4;
  const headerGap = base * 1.2;

  const headerLines = russian ? RU_HEADER : [];
  const bodyLines = buildLines(input, russian);

  const measureCanvas = document.createElement("canvas");
  const mctx = measureCanvas.getContext("2d");
  if (!mctx) return null;

  const measure = (text: string, size: number) => {
    mctx.font = `bold ${size}px ${FONT_FAMILY}`;
    return mctx.measureText(text).width;
  };

  let contentWidth = 0;
  for (const h of headerLines)
    contentWidth = Math.max(contentWidth, measure(h, headerSize));
  for (const b of bodyLines)
    contentWidth = Math.max(contentWidth, measure(b, bodySize));

  const width = Math.ceil(contentWidth + pad * 2);
  const headerBlock = headerLines.length * (headerSize + 2) + headerGap;
  const height = Math.ceil(
    pad + headerBlock + bodyLines.length * lineStep + pad,
  );

  const canvas = document.createElement("canvas");
  canvas.width = width * SUPERSAMPLE;
  canvas.height = height * SUPERSAMPLE;
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  ctx.scale(SUPERSAMPLE, SUPERSAMPLE);

  const color = input.textColor || "#0033CC";

  if (input.showBorder) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 1;
    ctx.strokeRect(1, 1, width - 2, height - 2);
  }

  ctx.fillStyle = color;
  ctx.textBaseline = "alphabetic";

  let y = pad + headerSize;
  ctx.textAlign = "center";
  for (const h of headerLines) {
    ctx.font = `bold ${headerSize}px ${FONT_FAMILY}`;
    ctx.fillText(h, width / 2, y);
    y += headerSize + 2;
  }

  y += headerGap;
  ctx.textAlign = "left";
  for (const b of bodyLines) {
    ctx.font = `bold ${bodySize}px ${FONT_FAMILY}`;
    ctx.fillText(b, pad, y);
    y += lineStep;
  }

  return { dataUrl: canvas.toDataURL("image/png"), width, height };
}
