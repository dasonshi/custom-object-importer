// src/utils/apiHelpers.js

export function handleAPIError(res, error, operation = 'Operation') {
  console.error(`${operation} error:`, error?.response?.data || error.message);
  res.status(error?.response?.status || 400).json({
    error: `${operation} failed`,
    message: error?.response?.data?.message || error.message,
    details: error?.response?.data || error.message
  });
}