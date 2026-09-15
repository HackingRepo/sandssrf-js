"use strict";

const { Sandbox } = require("./sandbox");
const { SandboxError, SandboxUnavailableError, BlockedError } = require(
  "./errors",
);
const ranges = require("./ranges");

/**
 * Create an SSRF sandbox.
 *
 * Returns immediately; the namespace comes up in the background and connections
 * queue until it is ready. Await `sandbox.ready()` if you want to know sooner.
 *
 * @param {object}   [options]
 * @param {string[]} [options.mock]   IPv4 CIDRs answered by the simulated network
 * @param {string[]} [options.mock6]  IPv6 CIDRs answered by the simulated network
 * @param {number[]} [options.ports]  ports the mock listens on
 * @param {string[]} [options.allow]  "addr" or "addr:port" reached for real despite the above
 * @param {number}   [options.connectTimeout=10000]
 * @param {number}   [options.startTimeout=10000]
 * @returns {Sandbox}
 */
function createSSRFSandbox(options) {
  return new Sandbox(options);
}

// Export all the items, that public
module.exports = {
  createSSRFSandbox,
  Sandbox,
  SandboxError,
  SandboxUnavailableError,
  BlockedError,
  ranges,
};
