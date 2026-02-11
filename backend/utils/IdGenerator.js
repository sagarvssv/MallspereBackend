import { nanoid } from "nanoid";

//  GENERATE VENDOR ID
const generateVendorId = (mallName) => {
  const prefix = mallName
    .replace(/\s+/g, "")
    .substring(0, 5)
    .toUpperCase();
  return `MS-${prefix}-${nanoid(6).toUpperCase()}`;
};

//  GENERATE SHOP ID
const generateShopId = (mallName, category) => {
  const mallPrefix = mallName
    .replace(/\s+/g, "")
    .substring(0, 3)
    .toUpperCase();
  const categoryPrefix = category
    .replace(/\s+/g, "")
    .substring(0, 3)
    .toUpperCase();
  
  return `${mallPrefix}-${categoryPrefix}-${nanoid(6).toUpperCase()}`;
};

//  GENERATE LICENSE ID
const generateLicenseId = (mallName) => {
  const mallPrefix = mallName
    .replace(/\s+/g, "")
    .substring(0, 3)
    .toUpperCase();

  
  return `LIC-${mallPrefix}-${nanoid(8).toUpperCase()}`;
};

export { generateVendorId, generateShopId, generateLicenseId };