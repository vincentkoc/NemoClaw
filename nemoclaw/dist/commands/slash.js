"use strict";
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleSlashCommand = handleSlashCommand;
const state_js_1 = require("../blueprint/state.js");
const config_js_1 = require("../onboard/config.js");
const runtime_context_js_1 = require("../runtime-context.js");
function handleSlashCommand(ctx, _api, pluginConfig) {
    const subcommand = ctx.args?.trim().split(/\s+/)[0] ?? "";
    switch (subcommand) {
        case "status":
            return slashStatus(pluginConfig);
        case "eject":
            return slashEject();
        case "onboard":
            return slashOnboard();
        default:
            return slashHelp();
    }
}
function slashHelp() {
    return {
        text: [
            "**NemoClaw**",
            "",
            "OpenClaw runs inside an OpenShell sandbox.",
            "Expect sandboxed filesystem/process access and deny-by-default outbound network.",
            "Use `openshell term` to watch policy approvals or denials live.",
            "",
            "Usage: `/nemoclaw <subcommand>`",
            "",
            "Subcommands:",
            "  `status`  - Show sandbox, blueprint, and live restriction summary",
            "  `eject`   - Show rollback instructions",
            "  `onboard` - Show onboarding status and instructions",
            "",
            "For full management use the CLI:",
            "  `openclaw nemoclaw status`",
            "  `openclaw nemoclaw migrate`",
            "  `openclaw nemoclaw launch`",
            "  `openclaw nemoclaw connect`",
            "  `openclaw nemoclaw eject --confirm`",
        ].join("\n"),
    };
}
async function slashStatus(pluginConfig) {
    const state = (0, state_js_1.loadState)();
    const runtime = await (0, runtime_context_js_1.getRuntimeSummary)(pluginConfig);
    if (!state.lastAction) {
        return {
            text: [
                "**NemoClaw**: No operations performed yet.",
                "Run `openclaw nemoclaw launch` or `openclaw nemoclaw migrate` to get started.",
                "",
                `Sandbox: ${runtime.sandboxName}`,
                runtime.sandboxPhase ? `Phase: ${runtime.sandboxPhase}` : null,
                "Restrictions:",
                ...runtime.networkLines.slice(0, 2).map((line) => `- ${line}`),
            ]
                .filter(Boolean)
                .join("\n"),
        };
    }
    const lines = [
        "**NemoClaw Status**",
        "",
        `Last action: ${state.lastAction}`,
        `Blueprint: ${state.blueprintVersion ?? "unknown"}`,
        `Run ID: ${state.lastRunId ?? "none"}`,
        `Sandbox: ${state.sandboxName ?? "none"}`,
        runtime.sandboxPhase ? `Phase: ${runtime.sandboxPhase}` : null,
        `Updated: ${state.updatedAt}`,
        "",
        "Restrictions:",
        ...runtime.networkLines.map((line) => `- ${line}`),
        ...runtime.filesystemLines.map((line) => `- ${line}`),
    ];
    if (state.migrationSnapshot) {
        lines.push("", `Rollback snapshot: ${state.migrationSnapshot}`);
    }
    return { text: lines.join("\n") };
}
function slashOnboard() {
    const config = (0, config_js_1.loadOnboardConfig)();
    if (config) {
        return {
            text: [
                "**NemoClaw Onboard Status**",
                "",
                `Endpoint: ${config.endpointType} (${config.endpointUrl})`,
                config.ncpPartner ? `NCP Partner: ${config.ncpPartner}` : null,
                `Model: ${config.model}`,
                `Credential: $${config.credentialEnv}`,
                `Profile: ${config.profile}`,
                `Onboarded: ${config.onboardedAt}`,
                "",
                "To reconfigure, run: `openclaw nemoclaw onboard`",
            ]
                .filter(Boolean)
                .join("\n"),
        };
    }
    return {
        text: [
            "**NemoClaw Onboarding**",
            "",
            "No configuration found. Run the onboard command to set up inference:",
            "",
            "```",
            "openclaw nemoclaw onboard",
            "```",
            "",
            "Or non-interactively:",
            "```",
            'openclaw nemoclaw onboard --api-key "$NVIDIA_API_KEY" --endpoint build --model nvidia/nemotron-3-super-120b-a12b',
            "```",
        ].join("\n"),
    };
}
function slashEject() {
    const state = (0, state_js_1.loadState)();
    if (!state.lastAction) {
        return { text: "No NemoClaw deployment found. Nothing to eject from." };
    }
    if (!state.migrationSnapshot && !state.hostBackupPath) {
        return {
            text: "No migration snapshot found. Manual rollback required.",
        };
    }
    return {
        text: [
            "**Eject from NemoClaw**",
            "",
            "To rollback to your host OpenClaw installation, run:",
            "",
            "```",
            "openclaw nemoclaw eject --confirm",
            "```",
            "",
            `Snapshot: ${state.migrationSnapshot ?? state.hostBackupPath ?? "none"}`,
        ].join("\n"),
    };
}
//# sourceMappingURL=slash.js.map