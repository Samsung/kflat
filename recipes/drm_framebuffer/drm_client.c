/**
 * @file drm_client.c
 * @author Pawel Wieczorek (p.wieczorek@samsung.com)
 * @brief App presenting the content of dumped DRM framebuffer structures
 * 
 */

/* Auto generated header file containing definition of drm structures*/
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <client_includes.h>

#include <unflatten.hpp>

/*
 * Entry point of example applicaiton
 */
int main(int argc, char** argv) {

    if(argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    FILE* file = fopen(argv[1], "rb");
    if(file == 0x0) {
        perror("Failed to open input file");
        return 1;
    }

    CFlatten flatten = flatten_init(0);
    if(flatten == NULL) {
        fprintf(stderr, "Failed to initialize LibFlatten\n");
        fclose(file);
        return 1;
    }

    int ret = flatten_load(flatten, file, 0x0);
    if(ret) {
        fprintf(stderr, "Failed to load input file");
        fclose(file);
        return 1;
    }

    printf("Loaded input file %s\n", argv[1]);
    fclose(file);

    struct drm_device* dev = flatten_root_pointer_named(flatten, "drm_device", 0x0);
    if(dev == NULL) {
        fprintf(stderr, "Failed to locate drm_device in loaded file\n");
        return 1;
    }

    printf("=== DRM device info ===\n");
    printf(" Unique name:  %s\n", dev->unique);
    printf(" Is unplugged: %d\n", dev->unplugged);
    printf(" No. crtcs:    %d\n", dev->num_crtcs);
    printf(" Power state:  %d\n", dev->switch_power_state);

    printf("=== DRM mode config ===\n");
    printf(" No. connectors: %d\n", dev->mode_config.num_connector);
    printf(" No. encoders:   %d\n", dev->mode_config.num_encoder);
    printf(" No. planes:     %d\n", dev->mode_config.num_total_plane);
    printf(" No. fbuffers:   %d\n", dev->mode_config.num_fb);
    printf(" Min size (W/H): %d_%d\n", dev->mode_config.min_width, dev->mode_config.min_height);
    printf(" Max size (W/H): %d_%d\n", dev->mode_config.max_width, dev->mode_config.max_height);
    printf(" FB base (phyS): %llx\n", dev->mode_config.fb_base);

    struct drm_framebuffer* fb = ((uintptr_t) dev->mode_config.fb_list.next) - offsetof(struct drm_framebuffer, head);
    for(int i = 0; i < dev->mode_config.num_fb; i++) {
        printf("=== DRM framebuffer[%d] ===\n", i);
        printf(" Name:           %s\n", fb->comm);
        printf(" Width / Height: %d/%d\n", fb->width, fb->height);
        printf(" Pitches[4]:     %d/%d/%d/%d\n", fb->pitches[0], fb->pitches[1], fb->pitches[2], fb->pitches[3]);
        printf(" Offsets[4]:     %d/%d/%d/%d\n", fb->offsets[0], fb->offsets[1], fb->offsets[2], fb->offsets[3]);
        printf(" Format:         %d\n", fb->format->format);
        printf(" Depth:          %d\n", fb->format->depth);
        printf(" Num. planes:    %d\n", fb->format->num_planes);
        printf(" Has alpha ch:   %d\n", fb->format->has_alpha);

        if(fb->head.next == NULL) {
            printf("=== End of framebuffers ===\n");
            break;
        }
        fb = ((uintptr_t) fb->head.next) - offsetof(struct drm_framebuffer, head);
    }

    return 0;
}
