pragma circom 2.2.3;

include "../common/adrs.circom";

// Trivial circuit: instantiate AdrsRangeCheck on a 7-tuple input.
// Confirms that params.circom and adrs.circom compile under
// `--prime secq256r1` with `optimization=2`.
template BenchAdrsSanity() {
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;

    component rc = AdrsRangeCheck();
    rc.layer     <== layer;
    rc.tree_high <== tree_high;
    rc.tree_low  <== tree_low;
    rc.type_     <== type_;
    rc.keypair   <== keypair;
    rc.chain     <== chain;
    rc.hash      <== hash;
}
