// utils/oui.mjs

import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

let OUI_DB = null;

// Try to import oui-data module, fall back to local file if it fails
async function loadOuiData() {
  try {
    const ouiData = await import("oui-data", { with: { type: "json" } }).then(module => module.default);
    console.log("[oui.mjs] Successfully loaded oui-data module with", Object.keys(ouiData).length, "entries");
    return ouiData;
  } catch (e) {
    console.error("[oui.mjs] Failed to load oui-data module:", e.message);
    // Fallback to local oui-data.json if available
    try {
      const __dirname = path.dirname(fileURLToPath(import.meta.url));
      const localPath = path.join(__dirname, "oui-data.json");
      const data = JSON.parse(await fs.readFile(localPath, "utf8"));
      console.log("[oui.mjs] Loaded fallback oui-data.json from", localPath, "with", Object.keys(data).length, "entries");
      return data;
    } catch (fallbackError) {
      console.error("[oui.mjs] Failed to load fallback oui-data.json:", fallbackError.message);
      return null;
    }
  }
}

// Initialize the database
export async function initOui() {
  OUI_DB = await loadOuiData();
  return !!OUI_DB;
}

// Convert a MAC address to its Organizationally Unique Identifier (OUI).
function macToOUI(mac) {
  if (!mac) return null;
  // Strip non-hex characters and take the first 6
  return String(mac).replace(/[^0-9A-Fa-f]/g, '').toUpperCase().slice(0, 6);
}

// Extract the vendor's name from an OUI database entry.
function pickOrgName(entry) {
  if (!entry) return null;
  if (typeof entry === 'string') return entry;
  return entry.company || entry.organizationName || entry.organization || entry.vendor || entry.name || null;
}

/**
 * Looks up the vendor name for a given MAC address.
 *
 * @param {string} mac The MAC address to look up.
 * @returns {string|null} The vendor name or null if not found.
 */
export function lookupVendor(mac) {
  // OUI_DB must be initialized via initOui() before calling this function.
  // Callers (plugin_manager.mjs) call initOui() at startup before any plugin runs.
  if (!OUI_DB || !mac || typeof mac !== 'string') {
    return null;
  }
  
  try {
    const oui = macToOUI(mac);
    const entry = OUI_DB[oui];
    const vendor = pickOrgName(entry);
    console.log(`[oui.mjs] Lookup for MAC ${mac} (OUI: ${oui}) -> Vendor: ${vendor || 'Not found'}`);
    return vendor;
  } catch (e) {
    console.error("[oui.mjs] Lookup error:", e.message);
    return null;
  }
}

/**
 * Heuristically guesses the probable operating system based on the vendor name.
 * This is a highly conservative guess and may be unreliable.
 *
 * @param {string} vendor The vendor name.
 * @returns {string} A short label for the probable OS, or 'Unknown'.
 */
export function probableOsFromVendor(vendor) {
  const v = (vendor || '').toLowerCase();
  if (!v) return 'Unknown';

  if (v.includes('apple')) return 'macOS or iOS';
  if (v.includes('samsung')) return 'Android';
  if (v.includes('microsoft')) return 'Windows';
  if (v.includes('google')) return 'Android or ChromeOS';
  if (v.includes('sony')) return 'Android';
  if (v.includes('hewlett') || v.includes('hp ') || v === 'hp') return 'Windows';
  if (v.includes('dell')) return 'Windows';

  // Common network / IoT vendors -> likely Embedded Linux
  if (v.includes('ring') || v.includes('ubiquiti') || v.includes('tp-link') ||
      v.includes('tplink') || v.includes('netgear') || v.includes('mikrotik') ||
      v.includes('synology') || v.includes('qnap') || v.includes('hikvision') ||
      v.includes('dahua') || v.includes('arris') || v.includes('avm') ||
      v.includes('asus') || v.includes('open-mesh') || v.includes('linksys') ||
      v.includes('tenda') || v.includes('roku') || v.includes('philips') ||
      v.includes('lg') || v.includes('xiaomi') || v.includes('huawei')) {
    return 'Embedded Linux';
  }

  return 'Unknown';
}