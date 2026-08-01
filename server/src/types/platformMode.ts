// Platform Mode Type Definitions

export type PlatformMode = 'LIVE' | 'DEMO';

export interface DataPolicy {
  allowSyntheticInCurrentMode: boolean;
  defaultIncludeSynthetic: boolean;
  allowSeedInCurrentMode: boolean;
}

export interface PlatformStatusResponse {
  platformMode: PlatformMode;
  syntheticDataEnabled: boolean;
  seedDataEnabled: boolean;
  attackSimulationEnabled: boolean;
  runtimeModeSwitchAllowed: boolean;
  dataPolicy: DataPolicy;
  uptimeSeconds: number;
}
