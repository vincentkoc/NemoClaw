import type { NemoClawConfig, OpenClawPluginApi } from "./index.js";
type RuntimeSummary = {
    sandboxName: string;
    sandboxPhase: string | null;
    networkLines: string[];
    filesystemLines: string[];
};
export declare function getRuntimeSummary(pluginConfig: NemoClawConfig): Promise<RuntimeSummary>;
export declare function registerRuntimeContext(api: OpenClawPluginApi, pluginConfig: NemoClawConfig): void;
export {};
//# sourceMappingURL=runtime-context.d.ts.map