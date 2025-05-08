{
  description = "Python library for the YubiHSM 2";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
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
          rsa
          ed25519
        ];

        src = ./.;
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
