# Faster 3D on a 68000: move the work out of the vertex loop

A polygon renderer repeats the same jobs many times per frame. On an original
Amiga 500, one useful question is: **what are we calculating for every vertex
that we could calculate once per object, or before the program even starts?**

This tutorial goes from a plain matrix transform to three lookup tables, then
uses the same idea for perspective. F.O.F.T. is a motivation for measuring these
techniques, not evidence that its renderer uses them or would benefit by a
particular amount. The examples are independent of the game and do not modify
the byte-exact restoration.

## 1. Rotate the axes, not every vertex

Take a model vertex `(x, y, z)`. Think of it as taking `x` steps along the model's
X axis, `y` along Y, and `z` along Z. A rotation plus linear scale changes the
direction and length of each step, but it doesn't change how many steps the
vertex takes. Call the transformed unit steps `A`, `B` and `C`. They are the
three columns of the transform matrix:

```text
view_vertex = translation + x*A + y*B + z*C
```

Each of those three products scales a **vector** with three components. A
straight implementation therefore has nine scalar multiplies and six additions
per vertex, before translation. Translation is separate: if the object moves
but its linear transform stays the same, the axis tables can be reused.

Now put the model vertices on an evenly spaced lattice. Each coordinate is a
step number, so the X contribution only has a small set of possible values.
Build `X[0] = (0, 0, 0)`, then `X[i+1] = X[i] + A`. Do the same for Y and Z.
Fold the grid spacing into each step vector if it isn't one model unit. Store
negative indices with a bias or walk the table backwards by subtraction.

![Two grids show a vertex reached by three X steps then one Y step, before and after a 45-degree turn.](illustrations/68000-grid-transform.svg)

In the vertex loop you now **load three vectors and sum them**. The six
component adds remain; the nine per-vertex multiplies don't. You pay to build
and read the tables, so this is most useful when the same transform serves many
vertices and the tables stay small. A 16-entry table for each axis, with three
16-bit components per entry, takes `3 × 16 × 3 × 2 = 288 bytes` of payload.

**Don't snap an existing game's geometry to a grid just to use the idea.** If
the source models reuse a small set of X, Y and Z coordinates, give each
distinct coordinate an index and compute its contribution once per transform.
Unevenly spaced coordinates still work; you lose the simple one-add table
builder, not the reuse. Exact output also depends on matching the original
order of rounding and overflow, not just on preserving the geometry.

## 2. Fixed point: keep the fractions while you add

The rotated axes are rarely whole numbers. With eight fractional bits, store
each value as an integer counting **256ths**: `256` is one unit, `128` is half
a unit, and `181` is roughly 0.707. The 68000 adds those integers normally;
it does not need to know where you put the binary point.

After a 45° turn around Z, the X step is approximately `(181,181,0)` and the Y
step is `(-181,181,0)`, both in 256ths. For the vertex `(3,1,0)`:

| Contribution | Stored integers | In model units |
| --- | --- | --- |
| Three X steps | (543, 543, 0) | (2.121, 2.121, 0) |
| One Y step | (-181, 181, 0) | (-0.707, 0.707, 0) |
| Sum | (362, 724, 0) | (1.414, 2.828, 0) |

Rounding the sum gives `(1,3,0)`; rounding each contribution before adding
would give `(1,4,0)`. Repeated integer addition introduces **no further
rounding**, provided nothing overflows. It does multiply the original
rounding error in the step by the number of steps. Keep more fractional bits
for more precision, use a wide enough accumulator, and normally round only
when producing screen pixels. A signed 16-bit entry with eight fractional
bits represents -128 through just under +128; check table entries and sums
separately. In assembly, sign-extend a signed word before accumulating it in a
long. An arithmetic right shift rounds negative values down, not towards zero
or to nearest, so pick the rounding rule explicitly.

## 3. Perspective: look up the depth scale once

Assume greater positive `z` means farther from the camera. If `f` is the focal
length in pixels, the horizontal screen offset is `x*f/z`; the vertical offset
is `y*f/z` (negate it when screen Y points down and camera Y points up). Both
components use exactly the same scale.

![Two vertices at the same camera-space height project to different heights. The one twice as far away has half the screen offset.](illustrations/68000-depth-projection.svg)

With `f=128` and `(x,y)=(12,8)`, depth 64 gives scale 2 and offsets `(24,16)`.
Depth 128 gives scale 1 and offsets `(12,8)`. Precompute `scale[z] = f/z` in
fixed point. Perspective then costs **one lookup, two multiplies and result
scaling**, instead of two divides. Depths outside the table need an explicit
policy. Clip geometry against the near plane before projecting; never index
with zero or negative depth. If the table has buckets rather than an entry
for every possible depth, use finer buckets near the camera, where the scale
changes most rapidly. Test moving edges for visible steps.

For a plain 68000 implementation with **signed-word** coordinates and scales,
a multiply-and-rescale fragment might be:

```asm
; d0.w = signed integer x; d2.w = signed scale in 256ths
muls.w  d2,d0           ; signed 16 × 16 -> signed 32 bits
asr.l   #8,d0           ; pixel offset, rounded down
```

If `x` also has eight fractional bits, the product has sixteen, not eight;
the shift must reflect both inputs, and a word multiply is only valid if both
raw inputs fit. The small example below keeps the grid result fractional
through projection.

## 4. Could logs replace the two remaining multiplies?

For nonzero magnitudes, `a*b = exp2(log2(a) + log2(b))` and division uses
subtraction instead. For perspective, store **the log of the scale** directly:
`depth_log[z] = log2(f/z)`. Look it up once, then use the same value twice:

```text
pixel_offset(a, depth_log):
    if a == 0: return 0
    magnitude = exp_table[coord_log[abs(a)] + depth_log]
    return magnitude if a > 0 else -magnitude
```

Choose an index bias for negative log sums and allow for the most negative
input when taking its absolute value. The exponent table can return pixel
magnitudes, so rounding and rescaling can be baked in. The logs of **rotated**
X and Y can't be baked into the model: the coordinates change with the view.
When using this for multiplication elsewhere, handle zero separately and
derive the sign from both operands. For division, zero denominator is invalid.

### More RAM can buy precision

With `N` evenly spaced log steps per doubling, rounding each input log adds at
most half a step of error. The summed log can be off by one step, so the
largest relative error from that rounding alone is at most
`2**(1/N) - 1`. For `N=256`, that's about **0.271%**; for `N=1024`, about
**0.068%**. A fractional exponent table for one doubling with 16-bit entries
grows from **512 bytes** to **2 KiB**. That is **not** the whole system's memory
cost. You also need the input log tables and either a shift for the whole
power of two or a wider exponent table. The input depth and coordinate
quantisation and the output word or pixel rounding have errors of their own.
A wider table won't undo information already lost there.

A sine/cosine table uses the same general tradeoff: look up sine by integer
angle step and obtain cosine with a quarter-turn offset. This can cheaply
supply the matrix setup. For a full turn of 1,024 entries the offset is 256,
with wraparound. Angle quantisation and the precision of each stored value
are separate choices.

### A 68000 cycle estimate, not a game benchmark

The [Motorola timing tables, §8](https://www.nxp.com/docs/en/reference-manual/MC68000UM.pdf)
give 38–70 clocks for register-source `MULS.W`, depending on transitions in
the source operand's bits. Nine multiplies at a midrange 54 clocks cost **486
clocks**. That is an illustrative operand mix, not a measured game average.

| One scalar product | Estimate |
| --- | ---: |
| Register-source `MULS.W` | 38–70 clocks |
| Two indexed log word loads, a word add, one indexed exp load (word/long) | 46–50 clocks |
| Both logs already in registers: word copy, word add, indexed exp load (word/long) | 22–26 clocks |

Those lookups assume indices are already byte offsets, table bases are in
address registers and memory is uncontended. They omit operand preparation,
sign/zero handling and register spills. The cheapest case is **not** an
assumption that all nine coefficients and all three coordinates are resident
in registers. The original 68000 has no scaled index addressing. For
perspective, the depth log is shared; once it is in a register, each nonzero
coordinate has a lookup, add and lookup before sign/index work. Benchmark the
whole projection loop with equivalent output formats. And don't claim a second
speedup for using logs on multiplies the grid already removed.

## 5. Try a small reference example

Paste this into Python 3. It deliberately uses the slow, simple reference
calculation as a check, not as a benchmark.

```python
from fractions import Fraction
from math import log2

UNIT = 256
axes = ((181, 181, 0), (-181, 181, 0), (0, 0, UNIT))

def add(u, v):
    return tuple(a + b for a, b in zip(u, v))

def axis_table(step, radius):
    entries = {0: (0, 0, 0)}
    reverse = tuple(-a for a in step)
    for i in range(1, radius + 1):
        entries[i] = add(entries[i - 1], step)
        entries[-i] = add(entries[1 - i], reverse)
    return entries

X, Y, Z = [axis_table(step, 3) for step in axes]

def transform(x, y, z):
    return add(add(X[x], Y[y]), Z[z])

for x in range(-3, 4):
    for y in range(-3, 4):
        for z in range(-3, 4):
            expected = tuple(x*a + y*b + z*c for a, b, c in zip(*axes))
            assert transform(x, y, z) == expected

x, y, _ = transform(3, 1, 0)  # Coordinates in 256ths.
f = 128
scale = {z: round(Fraction(f * UNIT, z)) for z in range(32, 257)}

def project(x, y, z):
    # z is whole camera-depth units (e.g. after adding object translation).
    # The caller clips and supplies a supported depth.
    return tuple(round(Fraction(a * scale[z], UNIT * UNIT)) for a in (x, y))

assert (x, y) == (362, 724)
assert project(x, y, 64) == (3, 6)
assert project(x, y, 128) == (1, 3)
# Build log tables off the hot path. Coordinate inputs are still in 256ths.
STEPS = 256
coord_log = {a: round(STEPS * log2(a / UNIT)) for a in range(1, 1025)}
depth_log = {z: round(STEPS * log2(f / z)) for z in scale}
lo = min(coord_log.values()) + min(depth_log.values())
hi = max(coord_log.values()) + max(depth_log.values())
exp_table = [round(2 ** (q / STEPS)) for q in range(lo, hi + 1)]

def project_log(x, y, z):
    s = depth_log[z]
    def offset(a):
        if a == 0:
            return 0
        p = exp_table[coord_log[abs(a)] + s - lo]
        return p if a > 0 else -p
    return offset(x), offset(y)

assert project_log(x, y, 64) == (3, 6)
assert project_log(-x, 0, 128) == (-1, 0)
print("Grid and both projection checks passed")
```

First exercise: try twelve fractional bits, recompute the axes, and compare
against a high-precision rotation. The table method should still match the
direct transform **using the same quantised axes**. Comparing to a high-precision
reference is a different test: it measures the approximation you chose.

## 6. What to measure before changing a game

1. **Take a baseline.** Replay the same busy scene and camera motion. Separate
   transform, projection, clipping, drawing and frame wait. Count the number of
   transformed vertices and the unique coordinates per model; include table
   setup as well as the fast loop. Report frame time as well as stage time.
2. **Change one thing at a time.** Compare direct transform and axis cache,
   then compare divides, fixed-point reciprocal and log/exp projection. Check
   vertex and pixel deltas, especially at the near plane and in motion. Where
   exact behaviour matters, compare against the original rounding, not just
   the visual appearance.
3. **Test memory placement separately.** Compare a stock-memory configuration
   with one that has genuine CPU-accessible Fast RAM. Code, model data and
   CPU-only tables can avoid competing for Chip RAM bus slots if placed in
   Fast RAM. Display bitplanes and buffers fetched directly by custom-chip DMA
   must remain in Chip RAM. Not all A500 expansion RAM is uncontended; check
   the actual configuration. See [Commodore's hardware manual on DMA and the
   display](https://www.amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node012B.html).
   Fast RAM doesn't change the `MULS` algorithm or
   speed up a rasteriser that's already limited by Chip RAM writes.
4. **Report whole-frame results.** If transforms consume half the original
   frame and become four times as fast, the frame takes
   `0.5 / 4 + 0.5 = 0.625` of the original time: **1.6× as fast** (60% higher
   throughput), assuming nothing else changes. If transforms take only one
   tenth of the frame, the same optimisation gives **1.08× as fast**.
   That's why it's worth measuring before building bigger tables.

The order I'd try: measure first, remove repeated work second, and only then
make the remaining arithmetic cheaper. Keep any such experiment separate
from the byte-exact reconstruction.
