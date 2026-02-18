import { http, createConfig } from "wagmi";
import { mainnet, sepolia, foundry } from "wagmi/chains";
import { injected } from "wagmi/connectors";

/** wagmi configuration with injected (MetaMask/browser) wallet connector. */
export const wagmiConfig = createConfig({
  chains: [mainnet, sepolia, foundry],
  connectors: [injected()],
  transports: {
    [mainnet.id]: http(),
    [sepolia.id]: http(),
    [foundry.id]: http("http://127.0.0.1:8545"),
  },
});
