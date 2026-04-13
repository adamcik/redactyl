{
  description = "redactyl";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

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

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    nixpkgs,
    pyproject-build-systems,
    pyproject-nix,
    treefmt-nix,
    uv2nix,
    ...
  }: let
    inherit (nixpkgs) lib;
    forAllSystems = lib.genAttrs lib.systems.flakeExposed;

    workspace = uv2nix.lib.workspace.loadWorkspace {workspaceRoot = ./.;};

    overlay = workspace.mkPyprojectOverlay {
      sourcePreference = "wheel";
    };

    editableOverlay = workspace.mkEditablePyprojectOverlay {
      root = "$REPO_ROOT";
    };

    pythonSets = forAllSystems (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python312;
        baseSet = pkgs.callPackage pyproject-nix.build.packages {
          inherit python;
        };
      in
        baseSet.overrideScope (
          lib.composeManyExtensions [
            pyproject-build-systems.overlays.default
            overlay
          ]
        )
    );

    treefmtEval = forAllSystems (
      system:
        treefmt-nix.lib.evalModule nixpkgs.legacyPackages.${system} {
          projectRootFile = "flake.nix";
          programs = {
            alejandra.enable = true;
            actionlint.enable = true;
            prettier.enable = true;
            ruff-check.enable = true;
            ruff-format.enable = true;
            zizmor.enable = true;
          };
          settings.formatter = {
            tombi-format = {
              command = "${nixpkgs.legacyPackages.${system}.tombi}/bin/tombi";
              includes = ["*.toml"];
              options = ["format" "--offline"];
            };
            tombi-lint = {
              command = "${nixpkgs.legacyPackages.${system}.tombi}/bin/tombi";
              includes = ["*.toml"];
              options = ["lint" "--offline"];
            };
          };
        }
    );
  in {
    formatter = forAllSystems (system: treefmtEval.${system}.config.build.wrapper);

    checks = forAllSystems (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
        pythonSet = pythonSets.${system};
        devVenv = pythonSet.mkVirtualEnv "redactyl-checks-env" {
          redactyl = ["dev"];
        };
      in {
        lock =
          pkgs.runCommand "uv-lock-check" {
            src = ./.;
            nativeBuildInputs = [devVenv pkgs.uv];
          } ''
            cd "$src"
            export HOME="$TMPDIR"
            export UV_PYTHON="${devVenv}/bin/python"
            uv lock --check
            touch "$out"
          '';

        tests =
          pkgs.runCommand "pytest-check" {
            src = ./.;
            nativeBuildInputs = [devVenv];
          } ''
            cd "$src"
            export HOME="$TMPDIR"
            pytest
            touch "$out"
          '';

        typing =
          pkgs.runCommand "basedpyright-check" {
            src = ./.;
            nativeBuildInputs = [devVenv];
          } ''
            cd "$src"
            export HOME="$TMPDIR"
            basedpyright
            touch "$out"
          '';

        treefmt = treefmtEval.${system}.config.build.check ./.;
      }
    );

    packages = forAllSystems (system: {
      default = pythonSets.${system}.redactyl;
      redactyl = pythonSets.${system}.redactyl;
    });

    devShells = forAllSystems (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python312;
        editablePythonSet = pythonSets.${system}.overrideScope (
          lib.composeManyExtensions [editableOverlay]
        );
        venv = editablePythonSet.mkVirtualEnv "redactyl-dev-env" {
          redactyl = ["dev"];
        };
      in {
        default = pkgs.mkShell {
          packages = [
            pkgs.actionlint
            pkgs.tombi
            pkgs.uv
            pkgs.zizmor
            treefmtEval.${system}.config.build.wrapper
            venv
          ];
          env = {
            UV_NO_SYNC = "1";
            UV_PYTHON = python.interpreter;
            UV_PYTHON_DOWNLOADS = "never";
          };
          shellHook = ''
            unset PYTHONPATH
            export REPO_ROOT=$(git rev-parse --show-toplevel)
          '';
        };
      }
    );
  };
}
