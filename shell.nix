{ pkgs ? import <nixpkgs> { } }: pkgs.mkShell {
  nativeBuildInputs = with pkgs; [ lld_18 rustup ];
  packages = with pkgs; [ gef ];
}
