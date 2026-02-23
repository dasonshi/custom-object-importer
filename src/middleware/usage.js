// src/middleware/usage.js
// Fire-and-forget usage tracking middleware

export function usageTracking(installs) {
  return (req, res, next) => {
    // Track usage when response finishes (after auth has run)
    res.on('finish', () => {
      // Only track successful authenticated requests
      if (req.locationId && res.statusCode < 400) {
        // Fire-and-forget - don't await, don't block
        installs.incrementUsage(req.locationId).catch((err) => {
          // Silent fail - usage tracking should never break requests
          console.warn('Usage tracking failed:', err.message);
        });
      }
    });
    next();
  };
}
