/** Default timestamp tolerance used by providers (seconds) */
export const DEFAULT_TOLERANCE_S = 300;

/** Offset that exceeds the default tolerance — used to test expiry rejection */
export const EXPIRED_OFFSET_S = DEFAULT_TOLERANCE_S + 60;
