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
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
        pythonSet = pythonSets.${system};
        lintVenv = pythonSet.mkVirtualEnv "redactyl-lint-env" {
          redactyl = ["dev"];
        };
      in
        treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs = {
            alejandra.enable = true;
            actionlint.enable = true;
            prettier.enable = true;
            zizmor.enable = true;
          };
          settings.formatter = {
            ruff-check = {
              command = "${lintVenv}/bin/ruff";
              includes = ["*.py"];
              options = ["check" "--fix"];
              priority = 10;
            };
            ruff-format = {
              command = "${lintVenv}/bin/ruff";
              includes = ["*.py"];
              options = ["format"];
              priority = 20;
            };
            tombi-format = {
              command = "${pkgs.tombi}/bin/tombi";
              includes = ["*.toml"];
              options = ["format" "--offline"];
            };
            tombi-lint = {
              command = "${pkgs.tombi}/bin/tombi";
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
        mkCheck = name: nativeBuildInputs: body:
          pkgs.runCommand name {
            src = ./.;
            inherit nativeBuildInputs;
          } ''
            cd "$src"
            export HOME="$TMPDIR"
            ${body}
            touch "$out"
          '';
      in {
        lock = mkCheck "uv-lock-check" [devVenv pkgs.uv] ''
          export UV_PYTHON="${devVenv}/bin/python"
          export UV_PYTHON_DOWNLOADS=never
          export UV_NO_MANAGED_PYTHON=1
          uv lock --check
        '';

        tests = mkCheck "pytest-check" [devVenv] ''
          pytest -q -o cache_dir="$TMPDIR/.pytest_cache"
        '';

        typing = mkCheck "basedpyright-check" [devVenv] ''
          basedpyright
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
            UV_NO_MANAGED_PYTHON = "1";
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
