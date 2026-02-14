/**
 * Phone Number Formatter
 *
 * Normalizes phone numbers to E.164 format (+1XXXXXXXXXX for US)
 * with smart detection of country codes.
 */

/**
 * Format a phone number to E.164 format
 * Returns { formatted, original, wasModified, warning }
 */
export function formatPhoneNumber(input) {
  if (!input || typeof input !== 'string') {
    return { formatted: input, original: input, wasModified: false, warning: null };
  }

  // Strip quotes first (defense in depth for CSV embedded quotes)
  const original = input.trim().replace(/["']/g, '');

  // Remove all non-digit characters except leading +
  let digits = original.replace(/[^\d+]/g, '');

  // Handle empty or very short numbers
  if (digits.length < 7) {
    return {
      formatted: original,
      original,
      wasModified: false,
      warning: digits.length > 0 ? 'Phone number too short' : null
    };
  }

  // Already has + prefix - validate and clean
  if (digits.startsWith('+')) {
    const withoutPlus = digits.slice(1);
    // Already properly formatted
    if (withoutPlus.length >= 10 && withoutPlus.length <= 15) {
      const formatted = '+' + withoutPlus;
      return {
        formatted,
        original,
        wasModified: formatted !== original,
        warning: formatted !== original ? `Cleaned: ${original} → ${formatted}` : null
      };
    }
  }

  // Remove + for processing
  digits = digits.replace(/\+/g, '');

  let formatted;
  let warning;

  // Smart detection based on digit count
  if (digits.length === 10) {
    // 10 digits: Assume US number, add +1
    formatted = '+1' + digits;
    warning = `Added US country code: ${original} → ${formatted}`;
  } else if (digits.length === 11 && digits.startsWith('1')) {
    // 11 digits starting with 1: US number with country code
    formatted = '+' + digits;
    warning = `Formatted: ${original} → ${formatted}`;
  } else if (digits.length === 11 && !digits.startsWith('1')) {
    // 11 digits not starting with 1: Ambiguous, assume needs +
    formatted = '+' + digits;
    warning = `Added +: ${original} → ${formatted} (verify country code)`;
  } else if (digits.length >= 12 && digits.length <= 15) {
    // 12-15 digits: Likely already has country code
    formatted = '+' + digits;
    warning = `Formatted: ${original} → ${formatted}`;
  } else if (digits.length > 15) {
    // Too long
    formatted = '+' + digits.slice(0, 15);
    warning = `Truncated (too long): ${original} → ${formatted}`;
  } else {
    // 7-9 digits: Too short for reliable detection, assume US with area code missing or local
    formatted = '+1' + digits;
    warning = `Assumed US: ${original} → ${formatted} (verify)`;
  }

  return {
    formatted,
    original,
    wasModified: formatted !== original,
    warning
  };
}

/**
 * Format multiple phone numbers and collect warnings
 */
export function formatPhoneNumbers(values) {
  return values.map(v => formatPhoneNumber(v));
}

export default formatPhoneNumber;
