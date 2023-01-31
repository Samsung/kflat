/**
 * @file kflat_recipe.h
 * @author Pawel Wieczorek (p.wieczorek@samsung.com)
 * @brief Macros used for recipe modules registration
 * 
 */
#ifndef _LINUX_KFLAT_RECIPE_H
#define _LINUX_KFLAT_RECIPE_H

#define KFLAT_RECIPE_LIST(...)                  static struct kflat_recipe __kflat_recipes_list[] = { __VA_ARGS__ }
#define KFLAT_RECIPE(SYM, FUNC)                 {.owner = THIS_MODULE, .symbol = SYM, .handler= FUNC}
#define KFLAT_RECIPE_EX(SYM, FUNC, PRE_FUNC)    {.owner = THIS_MODULE, .symbol = SYM, .handler = FUNC, .pre_handler = PRE_FUNC}

#define KFLAT_RECIPE_MODULE(DESC)       \
    MODULE_DESCRIPTION(DESC);           \
    MODULE_LICENSE("GPL");              \
    MODULE_SOFTDEP("pre: kflat-core");  \
                                        \
    static int __init __kflat_recipe_module_entry(void) {       \
        int ret;                                                \
        ssize_t i;                                              \
        for(i = 0; i < ARRAY_SIZE(__kflat_recipes_list); i++) { \
            ret = kflat_recipe_register(&__kflat_recipes_list[i]);      \
            if(ret) {       \
                for(i = i - 1; i >=0; i--)      \
                    kflat_recipe_unregister(&__kflat_recipes_list[i]);  \
                return ret; \
            }               \
        }                   \
        return 0;           \
    }                       \
    static void __exit __kflat_recipe_module_exit(void) {               \
        ssize_t i;                                                      \
        for(i = 0; i < ARRAY_SIZE(__kflat_recipes_list); i++)           \
            kflat_recipe_unregister(&__kflat_recipes_list[i]);          \
    }                                           \
                                                \
    module_init(__kflat_recipe_module_entry);   \
    module_exit(__kflat_recipe_module_exit);


#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)
INTERVAL_TREE_DEFINE(struct flat_node, rb,
            uintptr_t, __subtree_last,
            START, LAST, static __used, interval_tree)


#endif /* _LINUX_KFLAT_RECIPE_H */