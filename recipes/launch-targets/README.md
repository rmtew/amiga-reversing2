# Launch-target recipes and authored analysis

This directory contains the reviewed labels, types, ordered decisions and source-only recovery recipes for FOFT SPS 0613, retail Conqueror SPS 1275, and SGII retail Amiga/ST. Rendered source, original media and binary assets are produced locally and are not framework inputs.

From a fresh framework checkout, supply the exact originals and separately supplied SDK/assembler tools:

```
python tools/replay_launch_targets.py --media-dir /private/originals \
  --output /private/new-output --vasm /private/tools/vasmm68k_mot.exe \
  --sdk-root /private/sdk-root
```

The SDK root contains `amiga_includes/` and `atarist_includes/`. The command builds native tools, restores reviewed annotation templates and derives checkpoints from ordered journals, regenerates packages, and builds them in separate reader directories. It checks original and rebuilt hashes. A source-file manifest pins the runtime code/knowledge/recipes independently of commit-message-only rewrites; actual checkout identity is logged with the private output. The original input hashes are constants in the command, and fact-template identity is pinned in recipe-contract.json.

The framework owns analysis and recipes. The separate outputs repository is reserved for reviewed fresh renders; this command does not publish or upload them. SDK redistribution, full-disk and emulator qualification are separate from exact program/member assembly.
