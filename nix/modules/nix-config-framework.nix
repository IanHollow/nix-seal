{ config, ... }: { nixConfigFramework.extraSpecialArgs.nixSealCatalog = config.flake.nixSeal; }
