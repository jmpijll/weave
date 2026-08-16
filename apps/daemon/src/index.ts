import { PROTOCOL_NAME, PROTOCOL_VERSION } from "@weave/protocol";
import type { HostCapabilities, WireMessage } from "@weave/protocol";

export const component = {
  name: "daemon",
  protocol: `${PROTOCOL_NAME}/v${PROTOCOL_VERSION}`,
} as const;

export type DaemonMessage = WireMessage;
export type DaemonCapabilities = HostCapabilities;
