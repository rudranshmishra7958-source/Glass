const fs = require("fs");
const path = require("path");
const sharp = require("sharp");

const ROOT = __dirname;
const SVG_PATH = path.join(ROOT, "icons", "glass.svg");
const SIZES = [16, 48, 128];

async function main() {
  const svg = fs.readFileSync(SVG_PATH);
  for (const size of SIZES) {
    const dest = path.join(ROOT, "icons", `icon${size}.png`);
    await sharp(svg, { density: 384 })
      .resize(size, size, { fit: "contain", background: { r: 0, g: 0, b: 0, alpha: 0 } })
      .png()
      .toFile(dest);
    console.log("wrote", dest);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
