#include "kflat.h"

#include <linux/module.h>

LIST_HEAD(kflat_recipes_registry);
DEFINE_MUTEX(kflat_recipes_registry_lock);


int kflat_recipe_register(struct kflat_recipe* recipe) {
    int ret = 0;
    struct kflat_recipe* entry = NULL;

    // Basic sanity checks
    if(!recipe || !recipe->owner || !recipe->symbol || !recipe->handler) {
        pr_err("cannot register incomplete recipe");
        return -EINVAL;
    }

    mutex_lock(&kflat_recipes_registry_lock);

    // Check for name duplicates
    list_for_each_entry(entry, &kflat_recipes_registry, list) {
        if(!strcasecmp(entry->symbol, recipe->symbol)) {
            pr_err("cannot register the same recipe twice");
            ret = -EBUSY;
            goto exit;
        }
    }
    list_add(&recipe->list, &kflat_recipes_registry);

exit:
    mutex_unlock(&kflat_recipes_registry_lock);
    return ret;
}
EXPORT_SYMBOL_GPL(kflat_recipe_register);


int kflat_recipe_unregister(struct kflat_recipe* recipe) {
    int ret = -EINVAL;
    struct kflat_recipe* entry;
    
    mutex_lock(&kflat_recipes_registry_lock);
    list_for_each_entry(entry, &kflat_recipes_registry, list) {
        if(entry == recipe) {
            list_del(&entry->list);
            goto exit;
        }
    }

exit:
    mutex_unlock(&kflat_recipes_registry_lock);
    return ret;
}
EXPORT_SYMBOL_GPL(kflat_recipe_unregister);


struct kflat_recipe* kflat_recipe_get(char* name) {
    struct kflat_recipe* entry, *ret = NULL;
    
    mutex_lock(&kflat_recipes_registry_lock);
    list_for_each_entry(entry, &kflat_recipes_registry, list) {
        if(!strcasecmp(entry->symbol, name)) {
            ret = entry;
            break;
        }
    }
    mutex_unlock(&kflat_recipes_registry_lock);

    if(ret)
        try_module_get(ret->owner); // TODO: Error handling
    return ret;
}

void kflat_recipe_put(struct kflat_recipe* recipe) {
    if(recipe == NULL)
        return;
    module_put(recipe->owner);
}

