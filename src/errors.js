"use strict";

class SandboxError extends Error {
  constructor(message, code) {
    super(`sandssrf: ${message}`);
    this.name = "SandboxError";
    this.code = code;
  }
}

/** The sandbox could not be created. do not fail silently, refuse instead. */
class SandboxUnavailableError extends SandboxError {
  constructor(message) {
    super(message, "SANDSSRF_UNAVAILABLE");
    this.name = "SandboxUnavailableError";
  }
}

/** A connection was answered by the simulated internal network. */
class BlockedError extends SandboxError {
  constructor(address, port, reason) {
    super(
      `connection to ${address}:${port} was contained (${reason})`,
      "SANDSSRF_BLOCKED",
    );
    this.name = "BlockedError";
    this.address = address;
    this.port = port;
    this.reason = reason;
  }
}

// Export the error classes
module.exports = { SandboxError, SandboxUnavailableError, BlockedError };
