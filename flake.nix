{
  description = "Development shell for samirose/minutil";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          pkgs.bash
          pkgs.gnumake
          pkgs.gcc
          pkgs.clang
        ];
      };
      formatter.${system} = pkgs.nixfmt-rfc-style;
    };
}
