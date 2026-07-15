# native-lift runtime image

This image freezes the heavy Remill and LLVM runtime used by Rekit's `native-lift`
skill. It builds Remill v6.0.1 from commit
`0e324aee8c67a63ec759ef379dcfafa0b3cb1448` against LLVM 21.
The LLVM packages are pinned to the observed 21.1.8 apt.llvm.org revision.
The multi-platform Ubuntu 24.04 base is pinned to manifest digest
`sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90`,
and the upstream LLVM installer is accepted only at its recorded SHA-256.

The published image is multi-platform (`linux/amd64`, `linux/arm64`) and is invoked
by immutable manifest digest. The image reads one bounded raw-code file from `/input`
and writes LLVM artifacts beneath `/output`; it never parses or executes a complete
program.

Build locally from the repository root:

```bash
docker build -f containers/native-lift/Dockerfile \
  -t rekit-native-lift:dev .
```

Every image build lifts x86, amd64, and aarch64 smoke fixtures before the final stage
is emitted. The publication workflow builds both host platforms with provenance and
an SBOM.

## Publish an update

1. Select and record an exact Remill release commit, LLVM major, base manifest digest,
   and LLVM installer checksum in the Dockerfile and `scripts/image.json`.
2. Build the image locally and run the version and lifting checks.
3. Run the `native-lift image` GitHub Actions workflow from a reviewed commit.
4. Read the immutable manifest digest from its `native-lift-image` artifact.
5. Replace `digest` in `skills/native-lift/scripts/image.json`, run `rekit install
   native-lift`, and repeat the offline x86, amd64, and aarch64 fixtures.
6. Commit the digest change. Never retarget an existing version tag as a substitute
   for updating the digest.

The public skill never builds or pulls this image during analysis. `rekit install
native-lift` is the explicit networked installation step.
