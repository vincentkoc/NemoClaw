/**
 * Handler for the /nemoclaw slash command (chat interface).
 *
 * Supports subcommands:
 *   /nemoclaw status   - show sandbox/blueprint/inference state
 *   /nemoclaw eject    - rollback to host installation
 *   /nemoclaw          - show help
 */
import type { PluginCommandContext, PluginCommandResult, OpenClawPluginApi, NemoClawConfig } from "../index.js";
export declare function handleSlashCommand(ctx: PluginCommandContext, _api: OpenClawPluginApi, pluginConfig: NemoClawConfig): PluginCommandResult | Promise<PluginCommandResult>;
//# sourceMappingURL=slash.d.ts.map