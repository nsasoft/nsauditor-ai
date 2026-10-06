// utils/scheduler.mjs
// Continuous scan scheduler with concurrency control.

/**
 * Create a scheduler that runs periodic scan cycles across a set of hosts.
 * @param {object} opts
 * @param {number} opts.intervalMs - interval between scan cycles in ms
 * @param {string[]} opts.hosts - hosts to scan each cycle
 * @param {number} [opts.parallel=1] - max concurrent scans
 * @param {function} opts.scanFn - async (host) => result — performs the scan
 * @param {function} [opts.onScanComplete] - (host, result, diff) => void
 * @param {function} [opts.onCycleComplete] - (results) => void
 * @returns {object} scheduler instance — `hosts` is the distinct list a cycle scans, `duplicatesDropped` how many
 *   repeats were removed from the list it was given
 */
export function createScheduler(opts) {
  const {
    intervalMs,
    hosts,
    parallel = 1,
    scanFn,
    onScanComplete,
    onCycleComplete,
  } = opts;

  if (!intervalMs || intervalMs <= 0) throw new Error('intervalMs must be a positive number');
  if (!Array.isArray(hosts) || hosts.length === 0) throw new Error('hosts must be a non-empty array');
  if (typeof scanFn !== 'function') throw new Error('scanFn must be a function');

  // A cycle scans each host ONCE. A repeated host (`--host h,h`, or one inside a CIDR it is also listed beside) used to
  // stall watch mode forever: results are keyed by host, so their count could never reach the list's length. Exact
  // strings only — two spellings of one name are two hosts as far as the scheduler can know (1.3.0 lane 4, item 10).
  const distinctHosts = Object.freeze([...new Set(hosts)]);
  const duplicatesDropped = hosts.length - distinctHosts.length;

  let _running = false;
  let _timer = null;
  let _cycleInProgress = false;
  let _stopRequested = false;
  let _cyclePromise = null;

  /**
   * Run scans for all hosts with concurrency control (semaphore pattern).
   * @returns {Promise<Map<string, object>>} host → result map
   */
  async function runCycle() {
    _cycleInProgress = true;
    const results = new Map();
    const concurrency = Math.max(1, parallel);
    let running = 0;
    let idx = 0;
    let done = 0; // completion counter: a cycle ends when every scan it started has settled, success or error

    await new Promise((resolve) => {
      if (distinctHosts.length === 0) return resolve();

      const tryNext = () => {
        while (running < concurrency && idx < distinctHosts.length) {
          if (_stopRequested) {
            // Don't start new scans, but let in-progress ones finish
            if (running === 0) return resolve();
            return;
          }
          const h = distinctHosts[idx++];
          running++;
          scanFn(h)
            .then((result) => {
              results.set(h, result);
              if (typeof onScanComplete === 'function') {
                try { onScanComplete(h, result, null); } catch { /* swallow callback errors */ }
              }
            })
            .catch((err) => {
              const errResult = { error: err?.message || String(err) };
              results.set(h, errResult);
              if (typeof onScanComplete === 'function') {
                try { onScanComplete(h, errResult, null); } catch { /* swallow */ }
              }
            })
            .finally(() => {
              running--;
              done++;
              if (done === distinctHosts.length) return resolve();
              tryNext();
            });
        }
        // If stop was requested and nothing is running, resolve
        if (_stopRequested && running === 0) return resolve();
      };
      tryNext();
    });

    if (typeof onCycleComplete === 'function') {
      try { await onCycleComplete(results); } catch (err) { console.error('[scheduler] onCycleComplete error:', err?.message || err); }
    }

    _cycleInProgress = false;
    return results;
  }

  const scheduler = {
    hosts: distinctHosts,
    duplicatesDropped,

    /**
     * Begin periodic scanning.
     */
    start() {
      if (_running) return;
      _running = true;
      _stopRequested = false;

      // Run first cycle immediately, then schedule subsequent ones
      const kick = async () => {
        if (_stopRequested) return;
        _cyclePromise = runCycle();
        await _cyclePromise;
        _cyclePromise = null;
      };

      kick(); // fire-and-forget first cycle
      _timer = setInterval(() => {
        if (!_cycleInProgress && !_stopRequested) {
          kick();
        }
      }, intervalMs);
    },

    /**
     * Stop scheduling. Waits for any in-progress cycle to finish.
     * @returns {Promise<void>}
     */
    async stop() {
      if (!_running) return;
      _stopRequested = true;

      if (_timer !== null) {
        clearInterval(_timer);
        _timer = null;
      }

      // Wait for in-progress cycle to complete
      if (_cyclePromise) {
        await _cyclePromise;
      }

      _running = false;
      _stopRequested = false;
      _cycleInProgress = false;
    },

    /**
     * @returns {boolean} whether the scheduler is running
     */
    isRunning() {
      return _running;
    },

    /**
     * Run a single scan cycle immediately (independent of the interval timer).
     * @returns {Promise<Map<string, object>>}
     */
    async runOnce() {
      return runCycle();
    },
  };

  return scheduler;
}
