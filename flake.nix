{
  description = "Python library for the YubiHSM 2";
  inputs = {
    # Starting from 22.11 we get errors about missing `cryptography.utils.register_interface` decorator
    nixpkgs.url = "nixpkgs/nixos-22.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
   nixpkgs,
   flake-utils,
   ...
  }: flake-utils.lib.eachDefaultSystem (
    system:
    let
      pkgs = import nixpkgs { inherit system; };

      yubihsm = pkgs.python3Packages.buildPythonPackage {
        pname = "yubihsm";
        version = "1.2.2";

        propagatedBuildInputs = with pkgs.python3Packages; [
          cryptography
          requests
          six
        ];
        checkInputs = with pkgs.python3Packages; [
          pytest
          rsa
          ed25519
        ];

        src = ./.;

        # The tests in `test_yubihsm.py` require a network connection to a real YubiHSM
        # Therefore we only run `test_utils.py`
        checkPhase = ''
          python -m pytest test/test_utils.py
        '';
      };
    in
    {
      packages.yubihsm = yubihsm;
      packages.default = yubihsm;
      apps.yubihsm = yubihsm;
      apps.default = yubihsm;
      devShell = pkgs.mkShell { packages = [ yubihsm ]; };
    }
  );
}
