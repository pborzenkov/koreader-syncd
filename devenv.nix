{pkgs, ...}: {
  languages.rust = {
    enable = true;
    version = "stable";
  };

  packages = [
    pkgs.cargo-nextest
  ];

  pre-commit = {
    hooks = {
      cargo-check.enable = true;
      clippy.enable = true;
      rustfmt.enable = true;
    };
    settings = {
      clippy.denyWarnings = true;
    };
  };
}
