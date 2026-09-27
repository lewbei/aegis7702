/** Presentation-only fixtures adapted from the pinned dashboard and judge walkthrough.
 * These records are never treated as responses from the live engine.
 */
export const SOURCE_COMMIT = 'bd15aecd94733efa247ad1d2c7fb846e467e4bfc';
export const REPO = 'https://github.com/lewbei/aegis7702';
export const RELEASE = 'hackathon-final-v1.0.13';
export const CI_RUN = '36149170988';
export const SOURCE = `${REPO}/blob/${SOURCE_COMMIT}`;

export interface FixtureTrace {
  title: string;
  description: string;
  balance: string;
}
export interface Scenario {
  id: string;
  name: string;
  protocol: string;
  description: string;
  capabilityLabel: string;
  fields: Record<string, string>;
  signing: string;
  lossDescription: string;
  recovery: string;
  strategy: string;
  replay: string;
  trace: FixtureTrace[];
}
const owner = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const spender = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const permit2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
export const SCENARIOS: Scenario[] = [
  {
    id: 'eip7702_prague', name: 'EIP-7702 delegation', protocol: 'Ethereum Prague',
    description: 'Account delegation · a two-step fixture',
    capabilityLabel: 'Signed EIP-7702 authorization tuple',
    fields: {
      'Authority / owner': owner,
      'Delegate address': '0x8464135c8f25da09e49bc8782676a84730c318bc',
      'Signed nonce': '2', 'Chain ID': '31337 · local Prague fixture',
      'Signature r': '0x754348be09f7d9930790b71fbc04c25c29114c0ff52f4e68b1ad0a5d1922c970',
      'Signature s': '0x661521dd2ab7e592c001ad223156dbe4b1ce85a6027bface138ae9688ccd3627',
      'yParity': '1',
    },
    signing: 'The fixture starts with an off-chain authorization and 10,000 test USDC. Signing alone changes no on-chain balance. The released capability can still enable a later loss path.',
    lossDescription: 'The bundled fixture reports a two-step loss path using the delegated account capability. The tracked test-token balance falls from 10,000 to zero on this branch.',
    recovery: 'On a separate copy of the initial state, the owner advances the account nonce before the authorization is consumed. Active delegation requires a different recovery strategy; this fixture shows the unconsumed case.',
    strategy: 'Nonce advancement before consumption',
    replay: 'The fixture reports that the old authorization no longer matches the recovered account state. Checking the original loss trace leaves 10,000 test USDC unchanged.',
    trace: [
      { title: 'Delegation installed', description: 'The recorded authorization is consumed in the local fixture.', balance: '10,000.00 test USDC' },
      { title: 'Tracked balance decreases', description: 'The delegated capability enables the recorded token-loss transition.', balance: '0.00 test USDC' },
    ],
  },
  {
    id: 'permit2_allowance', name: 'Permit2 allowance', protocol: 'AllowanceTransfer',
    description: 'Allowance permission · a two-step fixture',
    capabilityLabel: 'Signed PermitSingle EIP-712 message',
    fields: { 'Owner': owner, 'Spender': spender, 'Permit2 contract': permit2,
      'Token': '0xe7f1725e7734ce288f8367e1bb143e90bb3f0512', 'Amount': '10,000.00 test USDC',
      'Nonce': '0', 'Signature deadline (Unix)': '1893456000',
      'Fixture precondition': 'Existing ERC-20 approval to Permit2',
    },
    signing: 'The bundled PermitSingle fixture starts with 10,000 test USDC. Releasing an allowance signature does not immediately transfer tokens. Existing token approval to Permit2 is a fixture precondition.',
    lossDescription: 'The bundled fixture reports an allowance activation followed by a token-loss transition. The tracked balance falls from 10,000 to zero on this loss branch.',
    recovery: 'On a separate initial-state branch, the owner invalidates the allowance-permit nonce before the old permit is consumed. This prevents the recorded path; it does not restore tokens already lost.',
    strategy: 'Allowance-permit nonce invalidation',
    replay: 'The fixture reports that the old permit is rejected after nonce invalidation. The original trace leaves the tracked balance at 10,000 test USDC. Other allowances are outside this claim.',
    trace: [
      { title: 'Allowance activated', description: 'The recorded permit enables the fixture allowance.', balance: '10,000.00 test USDC' },
      { title: 'Tracked balance decreases', description: 'The activated capability enables the recorded token-loss transition.', balance: '0.00 test USDC' },
    ],
  },
  {
    id: 'permit2_signature', name: 'Permit2 signature', protocol: 'SignatureTransfer',
    description: 'One-time authorization · a one-step fixture',
    capabilityLabel: 'Signed PermitTransferFrom message',
    fields: { 'Owner': owner, 'Spender': spender, 'Permit2 contract': permit2,
      'Token': '0xe7f1725e7734ce288f8367e1bb143e90bb3f0512', 'Amount': '10,000.00 test USDC',
      'Unordered nonce': '1025 · word position 4, bit position 1',
      'Fixture precondition': 'Existing ERC-20 approval to Permit2',
    },
    signing: 'The fixture starts with a one-time signed transfer authorization and 10,000 test USDC. Signing has no immediate balance effect. Existing token approval to Permit2 is a fixture precondition.',
    lossDescription: 'The bundled fixture reports a one-step loss path when this transfer capability is consumed. The tracked test-token balance falls from 10,000 to zero.',
    recovery: 'On a separate copy of the initial state, the owner invalidates the relevant unordered nonce before the transfer authorization is used.',
    strategy: 'Unordered-nonce invalidation',
    replay: 'The fixture reports that the old signature fails its nonce check after invalidation. The original trace leaves the tracked balance at 10,000 test USDC. Unrelated signatures remain outside this check.',
    trace: [
      { title: 'One-time capability consumed', description: 'The recorded transfer authorization produces the fixture token-loss transition.', balance: '0.00 test USDC' },
    ],
  },
];
