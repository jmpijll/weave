import { PROTOCOL_NAME, PROTOCOL_VERSION } from "@weave/protocol";
import type { WireMessage } from "@weave/protocol";

export const component = {
  name: "server",
  protocol: `${PROTOCOL_NAME}/v${PROTOCOL_VERSION}`,
} as const;

export type ServerMessage = WireMessage;
