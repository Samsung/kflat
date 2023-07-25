/**
 * @file unit_flatten_flexible_struct_array.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 *
 */

#include "common.h"

struct sound_engine {
	char* name;
	short flags;

	bool is_configured;
	unsigned long private_data[128];
	void* parent;
};

struct sound_core {
	int get_obj_supported;

	char* name;
	int flags;
	unsigned long config_data[64];

	unsigned long long amps_count;
	struct sound_engine amps[];
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT(sound_core);

FUNCTION_DEFINE_FLATTEN_STRUCT(sound_engine,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT(sound_core, parent);
);
FUNCTION_DEFINE_FLATTEN_STRUCT(sound_core,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT_FLEXIBLE(sound_engine, amps);
);


static int kflat_flexible_struct_array_test(struct flat *flat) {
	struct sound_core* core;
	FLATTEN_SETUP_TEST(flat);

	core = kmalloc(sizeof(*core) + 10 * sizeof(struct sound_engine), GFP_KERNEL);
	if(core == NULL)
		return 1;

	core->get_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);
	core->name = "Example sound card core";
	core->flags = 0xCAFECAFE;
	core->amps_count = 10;

	for(unsigned long long i = 0; i < 64; i++)
		core->config_data[i] = (i + 212) * 0x735d4f12;

	for(int i = 0; i < core->amps_count; i++) {
		core->amps[i].name = kmalloc(32, GFP_KERNEL);
		memset(core->amps[i].name, 'A' + i % 26, 31);
		core->amps[i].name[31] = '\0';

		core->amps[i].flags = i * 0xdf;
		core->amps[i].is_configured = true;
		core->amps[i].parent = core;
		for(unsigned long long j = 0; j < 128; j++)
			core->amps[i].private_data[j] = (i * j) * 0xffffdf34;
	}

	FOR_ROOT_POINTER(core,
		FLATTEN_STRUCT(sound_core, core);
	);

	for(int i = 0; i < core->amps_count; i++)
		kfree(core->amps[i].name);
	kfree(core);
	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flexible_struct_array_validate(void *memory, size_t size, CUnflatten flatten) {
	struct sound_core* core = (struct sound_core*) memory;
	
	if(!core->get_obj_supported)
		return KFLAT_TEST_UNSUPPORTED;

	ASSERT(!strcmp(core->name, "Example sound card core"));
	ASSERT_EQ(core->flags, 0xCAFECAFE);
	ASSERT_EQ(core->amps_count, 10);

	for(int i = 0; i < core->amps_count; i++) {
		ASSERT_EQ(core->amps[i].flags, i * 0xdf);
		ASSERT_EQ(core->amps[i].is_configured, true);
		ASSERT_EQ(core->amps[i].parent, core);
		for(int j = 0; j < 31; j++)
			ASSERT(core->amps[i].name[j] == 'A' + i % 26);
		for(unsigned long long j = 0; j < 128; j++)
			ASSERT_EQ(core->amps[i].private_data[j], (i * j) * 0xffffdf34);
	}

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] FLEXIBLE_STRUCT_ARRAY", kflat_flexible_struct_array_test, kflat_flexible_struct_array_validate);
