{ pkgs }:

self: super:

with { inherit (pkgs.stdenv) lib; };

with pkgs.haskell.lib;

{
  snmp = (
    with rec {
      snmpSource = pkgs.lib.cleanSource ../.;
      snmpBasic  = self.callCabal2nix "snmp" snmpSource { };
    };
    overrideCabal snmpBasic (old: {
    })
  );
}
