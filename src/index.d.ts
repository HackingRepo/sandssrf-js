import { EventEmitter } from "node:events";
import {
  Agent as HttpAgent,
  AgentOptions as HttpAgentOptions,
} from "node:http";
import {
  Agent as HttpsAgent,
  AgentOptions as HttpsAgentOptions,
} from "node:https";
import { Socket } from "node:net";

// An interface covering the sandbox options how it looks like
export interface SandboxOptions {
  /** IPv4 CIDRs answered by the simulated internal network. */
  mock?: string[];
  /** IPv6 CIDRs answered by the simulated internal network. */
  mock6?: string[];
  /** Ports the mock listens on inside the sandbox. */
  ports?: number[];
  /** "addr" or "addr:port" entries reached for real despite matching a mocked range. */
  allow?: string[];
  connectTimeout?: number;
  startTimeout?: number;
}

// An interface covering a blocked event type structure
export interface BlockedEvent {
  host: string | null;
  method: string;
  path: string;
}

export interface ReadyEvent {
  /** Ranges verified as contained inside the sandbox. Equal to `requested`. */
  routes: number;
  /** Ranges the caller asked to mock. Equal to `routes` then the sandbox refuses
   *  to start if any requested range could not be contained. */
  requested: number;
  listening: number;
}

export type SandboxState = "starting" | "ready" | "failed" | "closed";

// The sandbox error type declaration
export declare class SandboxError extends Error {
  code: string;
}

// An empty declaration of the sandbox unavailable error
export declare class SandboxUnavailableError extends SandboxError {}

// A declaration of a blocked error, which extends from a SandboxError
export declare class BlockedError extends SandboxError {
  address: string;
  port: number;
  reason: string;
}

// The declaraion of the class methods and constructor
export declare class Sandbox extends EventEmitter {
  constructor(options?: SandboxOptions);
  readonly state: SandboxState;
  /** Resolves when usable; rejects if the sandbox can never start. */
  ready(): Promise<Sandbox>;
  /** Resolve once in the host namespace, then connect inside the sandbox. */
  connect(host: string, port: number): Promise<Socket>;
  /** An http.Agent whose sockets come from the sandbox. */
  Agent(options?: HttpAgentOptions): HttpAgent;
  /** An https.Agent whose sockets come from the sandbox. */
  httpsAgent(options?: HttpsAgentOptions): HttpsAgent;
  close(): Promise<void>;

  on(event: "ready", listener: (e: ReadyEvent) => void): this;
  on(event: "blocked", listener: (e: BlockedEvent) => void): this;
  on(event: "error", listener: (e: SandboxUnavailableError) => void): this;
}

// The signature of the create ssrf sandbox
export declare function createSSRFSandbox(options?: SandboxOptions): Sandbox;

// Declaration of constant types
export declare const ranges: {
  IPV4: string[];
  IPV4_CLOUD: string[];
  IPV6: string[];
  DEFAULT_PORTS: number[];
  defaultMock(): string[];
  defaultMock6(): string[];
};
