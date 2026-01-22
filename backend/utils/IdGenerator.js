import { nanoid } from "nanoid";

const generateVendorId = (mallName) => {
    const prefix = mallName
    .replace(/\s+/g, "").substring(0, 5).toUpperCase();
    return `MS-${prefix}-${nanoid(6).toUpperCase()}`
};

const generateShopId = (shopName) => {
  const prefix = shopName
    .replace(/\s+/g, "")
    .substring(0, 5)
    .toUpperCase();

  return `${prefix}-${nanoid(6).toUpperCase()}`;
};

export { generateVendorId, generateShopId };
