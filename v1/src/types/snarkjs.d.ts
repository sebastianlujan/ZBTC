// Minimal typings for the parts of snarkjs 0.7.6 that ZBTC uses.
declare module 'snarkjs' {
  export type NumericString = string;

  export interface Groth16Proof {
    pi_a: [NumericString, NumericString, NumericString];
    pi_b: [
      [NumericString, NumericString],
      [NumericString, NumericString],
      [NumericString, NumericString],
    ];
    pi_c: [NumericString, NumericString, NumericString];
    protocol: 'groth16';
    curve: 'bn128';
  }

  export type PublicSignals = NumericString[];

  export interface VerificationKey {
    protocol: string;
    curve: string;
    nPublic: number;
    [key: string]: unknown;
  }

  export interface R1csInfo {
    nVars: number;
    nConstraints: number;
    nPrvInputs: number;
    nPubInputs: number;
    nOutputs: number;
    nLabels: number;
    [key: string]: unknown;
  }

  export const groth16: {
    fullProve(
      input: Record<string, unknown>,
      wasmFile: string,
      zkeyFile: string,
      logger?: unknown,
    ): Promise<{ proof: Groth16Proof; publicSignals: PublicSignals }>;
    verify(
      vkey: VerificationKey,
      publicSignals: PublicSignals,
      proof: Groth16Proof,
      logger?: unknown,
    ): Promise<boolean>;
  };

  export const r1cs: {
    info(r1csFile: string, logger?: unknown): Promise<R1csInfo>;
  };
}
