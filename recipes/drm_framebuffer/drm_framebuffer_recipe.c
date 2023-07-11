/**
 * @file drm_framebuffer_recipe.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Example kflat recipe flattening DRM framebuffer structure
 * 
 */
#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"

#include <drm/drm_device.h>
#include <drm/drm_file.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_framebuffer.h>


// Declare recipes for required data types
FUNCTION_DECLARE_FLATTEN_STRUCT(drm_device);
FUNCTION_DECLARE_FLATTEN_STRUCT(drm_framebuffer);

FUNCTION_DEFINE_FLATTEN_STRUCT(drm_format_info);

FUNCTION_DEFINE_FLATTEN_STRUCT(drm_framebuffer,
    AGGREGATE_FLATTEN_STRUCT(drm_device, dev);
    AGGREGATE_FLATTEN_STRUCT(drm_format_info, format);
    AGGREGATE_FLATTEN_TYPE_ARRAY(char, obj[0], 792);

    AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(drm_framebuffer, 
            sizeof(struct list_head), 
            head.next, offsetof(struct drm_framebuffer, head.next), 
            1, 
            -offsetof(struct drm_framebuffer, head)
        );
    AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(drm_framebuffer, 
            sizeof(struct list_head),
            head.prev, offsetof(struct drm_framebuffer, head.prev),
            1,
            -offsetof(struct drm_framebuffer, head)
        );
);

FUNCTION_DEFINE_FLATTEN_STRUCT(drm_device,
    AGGREGATE_FLATTEN_STRING(unique);
    AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(drm_framebuffer, 
            sizeof(struct list_head), 
            mode_config.fb_list.next, offsetof(struct drm_device, mode_config.fb_list.next), 
            1, 
            -offsetof(struct drm_framebuffer, head)
        );
    AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(drm_framebuffer, 
            sizeof(struct list_head),
            mode_config.fb_list.prev, offsetof(struct drm_device,mode_config.fb_list.prev),
            1,
            -offsetof(struct drm_framebuffer, head)
        );
);


// Handler invoked before drm_ioctl
static void drm_ioctl_handler(struct kflat* kflat, struct probe_regs* regs) {
    struct file* file = (struct file*) regs->arg1;
    struct drm_file* file_priv = file->private_data;
    struct drm_device* dev = file_priv->minor->dev;
    
    FOR_EXTENDED_ROOT_POINTER(dev, "drm_device", sizeof(struct drm_device),
        FLATTEN_STRUCT(drm_device, dev);
    );
}


// Declaration of instrumented functions
KFLAT_RECIPE_LIST(
    KFLAT_RECIPE("drm_ioctl", drm_ioctl_handler)
);
KFLAT_RECIPE_MODULE("Example module dumping DRM framebuffer structure");
