# DRM framebuffer example

This example flattens `drm_device` kernel structue storing information about currently 
displayed desktops. Once flattened, application `drm_client` allows user to view 
information about framebuffer screen, including resolution and color mode, etc.

## Build

This kernel module is build alongside all other files in this repo - simply enter root
directory of KFLAT repo and run `make` command as described in README.md. After that,
there should be file `drm_framebuffer_recipe.ko` present in this directory.

Building userspace test app is a bit more complex as it has to be done manually. Start
by generating file `client_includes.h` with definitions of `drm_device` structure and all its dependencies. That can be achieved by using Auto-off-Target project and generating off-target for function `drm_ioctl`. Once, you obtain file `client_includes.h`, you can build this application as follow:

```bash
CFLAGS="-I../../include -I../../lib -I../../lib/include_priv -I. --static"

# Target: x86_64
gcc $CFLAGS -o drm_client drm_client.c ../../lib/libunflatten_x86_64.a -lstdc++

# Target: ARM64
aarch64-linux-gnu-gcc $CFLAGS -o drm_client drm_client.c ../../lib/libunflatten_arm64.a -lstdc++
```

## Run

Load `kflat_core.ko` module first. Next, load `drm_framebuffer_recipe.ko` module present in this directory.

Use `tools/executor` application to invoked `drm_ioctl` handler:

```bash
$ tools/executor -i IOCTL -o drm.bin -s -n drm_ioctl /dev/dri/card0
```

Finally, execute `./drm_client <output_file>` app to test flattening and display information about current framebuffer.

```
$ ./drm_client drm.bin
=== DRM device info ===
 Unique name:  ae00000.qcom,mdss_mdp
 Is unplugged: 0
 No. crtcs:    6
 Power state:  0
=== DRM mode config ===
 No. connectors: 4
 No. encoders:   6
 No. planes:     20
 No. fbuffers:   12
 Min size (W/H): 0_0
 Max size (W/H): 20480_8640
 FB base (phyS): 0
=== DRM framebuffer[0] ===
 Name:           composer-servic
 Width / Height: 1088/2320
 Pitches[4]:     4352/0/0/0
 Offsets[4]:     0/0/0/0
 Format:         875708993
 Depth:          32
 Num. planes:    1
 Has alpha ch:   1

...
```
