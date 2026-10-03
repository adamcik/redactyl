{
  description = "redactyl";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";

    nix-tooling.url = "github:adamcik/nix-tooling";
    nix-tooling.inputs.nixpkgs.follows = "nixpkgs";

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs = {
        pyproject-nix.follows = "pyproject-nix";
        uv2nix.follows = "uv2nix";
        nixpkgs.follows = "nixpkgs";
      };
    };

  };

  outputs =
    inputs@{
      flake-parts,
      pyproject-build-systems,
      pyproject-nix,
      nix-tooling,
      uv2nix,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = inputs.nixpkgs.lib.systems.flakeExposed;
      imports = [
        nix-tooling.flakeModules.formatting.common
        nix-tooling.flakeModules.formatting.python
      ];

      perSystem =
        {
          pkgs,
          system,
          ...
        }:
        let
          inherit (pkgs) lib;
          workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };

          overlay = workspace.mkPyprojectOverlay {
            sourcePreference = "wheel";
          };

          editableOverlay = workspace.mkEditablePyprojectOverlay {
            root = "$REPO_ROOT";
          };

          python = pkgs.python312;
          baseSet = pkgs.callPackage pyproject-nix.build.packages { inherit python; };
          pythonSet = baseSet.overrideScope (
            lib.composeManyExtensions [
              pyproject-build-systems.overlays.default
              overlay
            ]
          );

          devVenv = pythonSet.mkVirtualEnv "redactyl-checks-env" {
            redactyl = [ "dev" ];
          };
          mkCheck =
            name: nativeBuildInputs: body:
            pkgs.runCommand name
              {
                src = ./.;
                inherit nativeBuildInputs;
              }
              ''
                cd "$src"
                export HOME="$TMPDIR"
                ${body}
                touch "$out"
              '';
        in
        {
          checks = {
            lock = mkCheck "uv-lock-check" [ devVenv pkgs.uv ] ''
              export UV_PYTHON="${devVenv}/bin/python"
              export UV_PYTHON_DOWNLOADS=never
              export UV_NO_MANAGED_PYTHON=1
              uv lock --check
            '';

            tests = mkCheck "pytest-check" [ devVenv ] ''
              pytest -q -o cache_dir="$TMPDIR/.pytest_cache"
            '';

            typing = mkCheck "basedpyright-check" [ devVenv ] ''
              basedpyright
            '';
          };

          treefmt.programs.zizmor.enable = true;
          treefmt.settings.formatter.tombi-lint = {
            command = "${pkgs.tombi}/bin/tombi";
            includes = [ "*.toml" ];
            options = [
              "lint"
              "--offline"
            ];
          };

          packages = {
            default = pythonSet.redactyl;
            redactyl = pythonSet.redactyl;
          };

          devShells.default = pkgs.mkShell {
            packages =
              let
                editablePythonSet = pythonSet.overrideScope (lib.composeManyExtensions [ editableOverlay ]);
                venv = editablePythonSet.mkVirtualEnv "redactyl-dev-env" {
                  redactyl = [ "dev" ];
                };
              in
              [
                pkgs.actionlint
                pkgs.tombi
                pkgs.uv
                pkgs.zizmor
                venv
              ];
            env = {
              UV_NO_SYNC = "1";
              UV_NO_MANAGED_PYTHON = "1";
              UV_PYTHON = python.interpreter;
              UV_PYTHON_DOWNLOADS = "never";
            };
            shellHook = ''
              unset PYTHONPATH
              export REPO_ROOT=$(git rev-parse --show-toplevel)
            '';
          };
        };
    };
}
