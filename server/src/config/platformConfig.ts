// Centralized Operating Mode & Data Authenticity Configuration

export type PlatformMode = 'LIVE' | 'DEMO';

export interface PlatformConfiguration {
  platformMode: PlatformMode;
  enableSyntheticData: boolean;
  enableSeedData: boolean;
  enableAttackSimulation: boolean;
  allowRuntimeModeSwitch: boolean;
}

let activeConfigOverride: Partial<PlatformConfiguration> | null = null;

export function loadPlatformConfig(): PlatformConfiguration {
  const envMode = (process.env.PLATFORM_MODE || 'LIVE').toUpperCase();
  const baseMode: PlatformMode = envMode === 'DEMO' ? 'DEMO' : 'LIVE';

  const currentMode: PlatformMode = activeConfigOverride?.platformMode || baseMode;

  // Synthetic data, Seed data, and Attack simulations require BOTH DEMO mode AND explicit flags
  const enableSyntheticData =
    currentMode === 'DEMO' &&
    (activeConfigOverride?.enableSyntheticData ?? process.env.ENABLE_SYNTHETIC_DATA === 'true');

  const enableSeedData =
    currentMode === 'DEMO' &&
    (activeConfigOverride?.enableSeedData ?? process.env.ENABLE_SEED_DATA === 'true');

  const enableAttackSimulation =
    currentMode === 'DEMO' &&
    (activeConfigOverride?.enableAttackSimulation ?? process.env.ENABLE_ATTACK_SIMULATION === 'true');

  const allowRuntimeModeSwitch =
    activeConfigOverride?.allowRuntimeModeSwitch ?? process.env.ALLOW_RUNTIME_MODE_SWITCH === 'true';

  return {
    platformMode: currentMode,
    enableSyntheticData,
    enableSeedData,
    enableAttackSimulation,
    allowRuntimeModeSwitch,
  };
}

export function updatePlatformConfigOverride(newConfig: Partial<PlatformConfiguration>): PlatformConfiguration {
  activeConfigOverride = { ...activeConfigOverride, ...newConfig };
  return loadPlatformConfig();
}
