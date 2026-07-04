/**
 * Fully unlocked mode — isSafetyRefusal is hardcoded to return false.
 * All model responses pass through; no content is blocked. This is
 * the shipping configuration per the /chinese page principles.
 */
export function isSafetyRefusal(_text: string | null | undefined): boolean {
  return false;
}
