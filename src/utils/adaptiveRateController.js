/**
 * Adaptive Rate Controller
 * Dynamically adjusts request rate based on API feedback and file size
 *
 * Features:
 * - File-size based initial settings (conservative for large files)
 * - Circuit breaker pattern (pauses all requests on consecutive 429s)
 * - Dynamic concurrency/delay adjustment based on feedback
 * - Batch processing with pauses between batches
 */

export class AdaptiveRateController {
  constructor(recordCount, options = {}) {
    // Get initial settings based on file size
    const settings = AdaptiveRateController.getSettingsForSize(recordCount);

    // Configuration (can be overridden)
    this.initialConcurrency = options.concurrency || settings.concurrency;
    this.initialDelay = options.delay || settings.delay;
    this.batchSize = options.batchSize || settings.batchSize;
    this.batchPauseMs = options.batchPauseMs || 3000;
    this.minConcurrency = 1;
    this.maxConcurrency = 5;
    this.minDelay = 50;
    this.maxDelay = 2000;

    // State
    this.concurrency = this.initialConcurrency;
    this.delay = this.initialDelay;
    this.consecutive429s = 0;
    this.consecutiveSuccesses = 0;
    this.circuitBrokenUntil = 0;
    this.total429s = 0;
    this.totalProcessed = 0;
    this.recordCount = recordCount;

    console.log(`[RateController] Initialized for ${recordCount} records: concurrency=${this.concurrency}, delay=${this.delay}ms, batchSize=${this.batchSize}`);
  }

  /**
   * Get optimal settings based on file size
   * Larger files get more conservative settings to avoid rate limits
   */
  static getSettingsForSize(count) {
    if (count <= 100) {
      return { concurrency: 5, delay: 50, batchSize: 100 };
    } else if (count <= 500) {
      return { concurrency: 3, delay: 100, batchSize: 100 };
    } else if (count <= 2000) {
      return { concurrency: 2, delay: 150, batchSize: 200 };
    } else if (count <= 5000) {
      return { concurrency: 2, delay: 200, batchSize: 250 };
    } else {
      // 5000+ records: very conservative to ensure completion
      return { concurrency: 1, delay: 250, batchSize: 500 };
    }
  }

  /**
   * Check if circuit breaker is currently active
   */
  isCircuitBroken() {
    return Date.now() < this.circuitBrokenUntil;
  }

  /**
   * Wait for circuit breaker to reset if active
   */
  async waitIfCircuitBroken() {
    if (this.isCircuitBroken()) {
      const waitTime = this.circuitBrokenUntil - Date.now();
      console.log(`[RateController] Circuit broken, waiting ${waitTime}ms`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
  }

  /**
   * Trip the circuit breaker to pause all requests
   */
  tripCircuitBreaker() {
    // Exponential backoff: 6s, 12s, 18s, etc based on consecutive 429s
    const duration = Math.min(30000, 2000 * this.consecutive429s);
    this.circuitBrokenUntil = Date.now() + duration;
    console.log(`[RateController] Circuit breaker TRIPPED for ${duration}ms (${this.consecutive429s} consecutive 429s)`);
  }

  /**
   * Record a successful request
   * After enough successes, try to speed up
   */
  recordSuccess() {
    this.consecutiveSuccesses++;
    this.consecutive429s = 0;
    this.totalProcessed++;

    // After 50 consecutive successes, try to speed up slightly
    if (this.consecutiveSuccesses >= 50) {
      this.speedUp();
      this.consecutiveSuccesses = 0;
    }
  }

  /**
   * Record a rate limit (429) error
   * Immediately slow down and potentially trip circuit breaker
   */
  record429() {
    this.consecutive429s++;
    this.consecutiveSuccesses = 0;
    this.total429s++;

    // Immediately slow down
    this.slowDown();

    // Trip circuit breaker after 3+ consecutive 429s
    if (this.consecutive429s >= 3) {
      this.tripCircuitBreaker();
    }

    console.log(`[RateController] 429 recorded (${this.total429s} total, ${this.consecutive429s} consecutive)`);
  }

  /**
   * Slow down the request rate
   * Reduces concurrency and increases delay
   */
  slowDown() {
    const prevConcurrency = this.concurrency;
    const prevDelay = this.delay;

    // Halve concurrency (minimum 1)
    this.concurrency = Math.max(this.minConcurrency, Math.floor(this.concurrency / 2));

    // Double delay (maximum 2000ms)
    this.delay = Math.min(this.maxDelay, this.delay * 2);

    if (prevConcurrency !== this.concurrency || prevDelay !== this.delay) {
      console.log(`[RateController] SLOWING DOWN: concurrency ${prevConcurrency}→${this.concurrency}, delay ${prevDelay}→${this.delay}ms`);
    }
  }

  /**
   * Speed up the request rate (carefully)
   * Only called after many consecutive successes
   */
  speedUp() {
    const prevConcurrency = this.concurrency;
    const prevDelay = this.delay;

    // Increase concurrency by 1 (up to initial max)
    if (this.concurrency < this.initialConcurrency) {
      this.concurrency = Math.min(this.initialConcurrency, this.concurrency + 1);
    }

    // Decrease delay by 20% (minimum is initial delay)
    this.delay = Math.max(this.initialDelay, Math.floor(this.delay * 0.8));

    if (prevConcurrency !== this.concurrency || prevDelay !== this.delay) {
      console.log(`[RateController] Speeding up: concurrency ${prevConcurrency}→${this.concurrency}, delay ${prevDelay}→${this.delay}ms`);
    }
  }

  /**
   * Get current concurrency setting
   */
  getConcurrency() {
    return this.concurrency;
  }

  /**
   * Get current delay setting
   */
  getDelay() {
    return this.delay;
  }

  /**
   * Get batch size
   */
  getBatchSize() {
    return this.batchSize;
  }

  /**
   * Get pause time between batches
   */
  getBatchPause() {
    return this.batchPauseMs;
  }

  /**
   * Get statistics for logging/debugging
   */
  getStats() {
    return {
      recordCount: this.recordCount,
      totalProcessed: this.totalProcessed,
      total429s: this.total429s,
      currentConcurrency: this.concurrency,
      currentDelay: this.delay,
      batchSize: this.batchSize,
      circuitBroken: this.isCircuitBroken()
    };
  }

  /**
   * Apply the current delay between requests
   */
  async applyDelay() {
    await new Promise(resolve => setTimeout(resolve, this.delay));
  }

  /**
   * Apply pause between batches
   */
  async applyBatchPause() {
    console.log(`[RateController] Batch complete, pausing ${this.batchPauseMs}ms before next batch`);
    await new Promise(resolve => setTimeout(resolve, this.batchPauseMs));
  }
}

export default AdaptiveRateController;
