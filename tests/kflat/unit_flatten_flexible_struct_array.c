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

typedef struct {
	char* name;
	short flags;

	bool is_configured;
	unsigned long private_data[128];
	void* parent;
} sound_engine_t;

typedef struct {
	int get_obj_supported;

	char* name;
	int flags;
	unsigned long config_data[64];

	unsigned long long amps_count;
	sound_engine_t amps[];
} sound_core_t;

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT_FLEXIBLE(sound_core);
FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_FLEXIBLE(sound_core_t);
FUNCTION_DECLARE_FLATTEN_STRUCT_FLEXIBLE_SPECIALIZE(newimpl,sound_core);

FUNCTION_DEFINE_FLATTEN_STRUCT(sound_engine,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT(sound_core, parent);
);
FUNCTION_DEFINE_FLATTEN_STRUCT_FLEXIBLE(sound_core,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT_FLEXIBLE(sound_engine, amps);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(sound_engine_t,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT_TYPE(sound_core_t, parent);
);
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_FLEXIBLE(sound_core_t,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT_TYPE_FLEXIBLE(sound_engine_t, amps);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SPECIALIZE(newimpl,sound_engine,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT(sound_core, parent);
);
FUNCTION_DEFINE_FLATTEN_STRUCT_FLEXIBLE_SPECIALIZE(newimpl,sound_core,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT_FLEXIBLE(sound_engine, amps);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_SPECIALIZE(newimpl,sound_engine_t,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT_TYPE(sound_core_t, parent);
);
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_FLEXIBLE_SPECIALIZE(newimpl,sound_core_t,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT_TYPE_FLEXIBLE(sound_engine_t, amps);
);

static int kflat_flexible_struct_array_test(struct flat *flat) {
	struct sound_core* core;
	sound_core_t* core2;
	struct sound_core* core3;
	sound_core_t* core4;
	struct sound_core* core5;
	sound_core_t* core6;
	int* core5_flags;
	int* core6_flags;
	int get_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);
	FLATTEN_SETUP_TEST(flat);

	core = kmalloc(sizeof(*core) + 6 * sizeof(struct sound_engine), GFP_KERNEL);
	core2 = kmalloc(sizeof(*core2) + 6 * sizeof(sound_engine_t), GFP_KERNEL);
	core3 = kmalloc(sizeof(*core3) + 6 * sizeof(struct sound_engine), GFP_KERNEL);
	core4 = kmalloc(sizeof(*core4) + 6 * sizeof(sound_engine_t), GFP_KERNEL);
	core5 = kmalloc(sizeof(*core5) + 6 * sizeof(struct sound_engine), GFP_KERNEL);
	core6 = kmalloc(sizeof(*core6) + 6 * sizeof(sound_engine_t), GFP_KERNEL);

	if(core == NULL)
		return 1;
	if(core2 == NULL)
		return 1;
	if(core3 == NULL)
		return 1;
	if(core4 == NULL)
		return 1;
	if(core5 == NULL)
		return 1;
	if(core6 == NULL)
		return 1;

	core->get_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);
	core->name = "Example sound card core";
	core->flags = 0xCAFECAFE;
	core->amps_count = 6;

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

	core2->get_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);
	core2->name = "Example sound card core";
	core2->flags = 0xCAFECAFE;
	core2->amps_count = 6;

	for(unsigned long long i = 0; i < 64; i++)
		core2->config_data[i] = (i + 212) * 0x735d4f12;

	for(int i = 0; i < core2->amps_count; i++) {
		core2->amps[i].name = kmalloc(32, GFP_KERNEL);
		memset(core2->amps[i].name, 'A' + i % 26, 31);
		core2->amps[i].name[31] = '\0';

		core2->amps[i].flags = i * 0xdf;
		core2->amps[i].is_configured = true;
		core2->amps[i].parent = core2;
		for(unsigned long long j = 0; j < 128; j++)
			core2->amps[i].private_data[j] = (i * j) * 0xffffdf34;
	}

	core3->get_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);
	core3->name = "Example sound card core";
	core3->flags = 0xCAFECAFE;
	core3->amps_count = 6;

	for(unsigned long long i = 0; i < 64; i++)
		core3->config_data[i] = (i + 212) * 0x735d4f12;

	for(int i = 0; i < core3->amps_count; i++) {
		core3->amps[i].name = kmalloc(32, GFP_KERNEL);
		memset(core3->amps[i].name, 'A' + i % 26, 31);
		core3->amps[i].name[31] = '\0';

		core3->amps[i].flags = i * 0xdf;
		core3->amps[i].is_configured = true;
		core3->amps[i].parent = core3;
		for(unsigned long long j = 0; j < 128; j++)
			core3->amps[i].private_data[j] = (i * j) * 0xffffdf34;
	}

	core4->get_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);
	core4->name = "Example sound card core";
	core4->flags = 0xCAFECAFE;
	core4->amps_count = 6;

	for(unsigned long long i = 0; i < 64; i++)
		core4->config_data[i] = (i + 212) * 0x735d4f12;

	for(int i = 0; i < core4->amps_count; i++) {
		core4->amps[i].name = kmalloc(32, GFP_KERNEL);
		memset(core4->amps[i].name, 'A' + i % 26, 31);
		core4->amps[i].name[31] = '\0';

		core4->amps[i].flags = i * 0xdf;
		core4->amps[i].is_configured = true;
		core4->amps[i].parent = core4;
		for(unsigned long long j = 0; j < 128; j++)
			core4->amps[i].private_data[j] = (i * j) * 0xffffdf34;
	}

	core5->get_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);
	core5->name = "Example sound card core";
	core5->flags = 0xCAFECAFE;
	core5->amps_count = 6;

	for(unsigned long long i = 0; i < 64; i++)
		core5->config_data[i] = (i + 212) * 0x735d4f12;

	for(int i = 0; i < core5->amps_count; i++) {
		core5->amps[i].name = kmalloc(32, GFP_KERNEL);
		memset(core5->amps[i].name, 'A' + i % 26, 31);
		core5->amps[i].name[31] = '\0';

		core5->amps[i].flags = i * 0xdf;
		core5->amps[i].is_configured = true;
		core5->amps[i].parent = core5;
		for(unsigned long long j = 0; j < 128; j++)
			core5->amps[i].private_data[j] = (i * j) * 0xffffdf34;
	}
	core5_flags = &core5->flags;

	core6->get_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);
	core6->name = "Example sound card core";
	core6->flags = 0xCAFECAFE;
	core6->amps_count = 6;

	for(unsigned long long i = 0; i < 64; i++)
		core6->config_data[i] = (i + 212) * 0x735d4f12;

	for(int i = 0; i < core6->amps_count; i++) {
		core6->amps[i].name = kmalloc(32, GFP_KERNEL);
		memset(core6->amps[i].name, 'A' + i % 26, 31);
		core6->amps[i].name[31] = '\0';

		core6->amps[i].flags = i * 0xdf;
		core6->amps[i].is_configured = true;
		core6->amps[i].parent = core6;
		for(unsigned long long j = 0; j < 128; j++)
			core6->amps[i].private_data[j] = (i * j) * 0xffffdf34;
	}
	core6_flags = &core6->flags;

	FOR_ROOT_POINTER(&get_obj_supported,
		FLATTEN_TYPE(int, &get_obj_supported);
	);

#ifdef KFLAT_GET_OBJ_SUPPORT
	FOR_ROOT_POINTER(core,
		FLATTEN_STRUCT_FLEXIBLE(sound_core, core);
	);

	FOR_ROOT_POINTER(core2,
		FLATTEN_STRUCT_TYPE_FLEXIBLE(sound_core_t, core2);
	);

	FOR_ROOT_POINTER(core3,
		FLATTEN_STRUCT_SPECIALIZE_FLEXIBLE(newimpl,sound_core, core3);
	);

	FOR_ROOT_POINTER(core4,
		FLATTEN_STRUCT_TYPE_SPECIALIZE_FLEXIBLE(newimpl,sound_core_t, core4);
	);

	FOR_ROOT_POINTER(core5_flags,
		FLATTEN_STRUCT_SHIFTED_FLEXIBLE(sound_core, core5_flags, -offsetof(struct sound_core,flags));
	);

	FOR_ROOT_POINTER(core6_flags,
		FLATTEN_STRUCT_TYPE_SHIFTED_FLEXIBLE(sound_core_t, core6_flags, -offsetof(sound_core_t,flags));
	);
#endif

	for(int i = 0; i < core->amps_count; i++)
		kfree(core->amps[i].name);
	kfree(core);

	for(int i = 0; i < core2->amps_count; i++)
		kfree(core2->amps[i].name);
	kfree(core2);

	for(int i = 0; i < core3->amps_count; i++)
		kfree(core3->amps[i].name);
	kfree(core3);

	for(int i = 0; i < core4->amps_count; i++)
		kfree(core4->amps[i].name);
	kfree(core4);

	for(int i = 0; i < core5->amps_count; i++)
		kfree(core5->amps[i].name);
	kfree(core5);

	for(int i = 0; i < core6->amps_count; i++)
		kfree(core6->amps[i].name);
	kfree(core6);

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flexible_struct_array_validate(void *memory, size_t size, CUnflatten flatten) {
	struct sound_core* core, *core3, *core5;
	sound_core_t* core2, *core4, *core6;
	int* core5_flags, *core6_flags;

	int* get_obj_supported = (int*) unflatten_root_pointer_seq(flatten, 0);
	
	if(get_obj_supported == NULL || *get_obj_supported == false)
		return KFLAT_TEST_UNSUPPORTED;

	core = (struct sound_core*) unflatten_root_pointer_seq(flatten, 1);
	core2 = (sound_core_t*) unflatten_root_pointer_seq(flatten, 2);
	core3 = (struct sound_core*) unflatten_root_pointer_seq(flatten, 3);
	core4 = (sound_core_t*) unflatten_root_pointer_seq(flatten, 4);
	core5_flags = (int*) unflatten_root_pointer_seq(flatten, 5);
	core5 = (void*)core5_flags - offsetof(struct sound_core,flags);
	core6_flags = (int*) unflatten_root_pointer_seq(flatten, 6);
	core6 = (void*)core6_flags - offsetof(sound_core_t,flags);

	if(!core->get_obj_supported)
		return KFLAT_TEST_UNSUPPORTED;

	if(!core2->get_obj_supported)
		return KFLAT_TEST_UNSUPPORTED;

	if(!core3->get_obj_supported)
		return KFLAT_TEST_UNSUPPORTED;

	if(!core4->get_obj_supported)
		return KFLAT_TEST_UNSUPPORTED;

	if(!core5->get_obj_supported)
		return KFLAT_TEST_UNSUPPORTED;

	if(!core6->get_obj_supported)
		return KFLAT_TEST_UNSUPPORTED;

	ASSERT(!strcmp(core->name, "Example sound card core"));
	ASSERT_EQ(core->flags, 0xCAFECAFE);
	ASSERT_EQ(core->amps_count, 6);

	for(int i = 0; i < core->amps_count; i++) {
		ASSERT_EQ(core->amps[i].flags, i * 0xdf);
		ASSERT_EQ(core->amps[i].is_configured, true);
		ASSERT_EQ(core->amps[i].parent, core);
		for(int j = 0; j < 31; j++)
			ASSERT(core->amps[i].name[j] == 'A' + i % 26);
		for(unsigned long long j = 0; j < 128; j++)
			ASSERT_EQ(core->amps[i].private_data[j], (i * j) * 0xffffdf34);
	}

	ASSERT(!strcmp(core2->name, "Example sound card core"));
	ASSERT_EQ(core2->flags, 0xCAFECAFE);
	ASSERT_EQ(core2->amps_count, 6);

	for(int i = 0; i < core2->amps_count; i++) {
		ASSERT_EQ(core2->amps[i].flags, i * 0xdf);
		ASSERT_EQ(core2->amps[i].is_configured, true);
		ASSERT_EQ(core2->amps[i].parent, core2);
		for(int j = 0; j < 31; j++)
			ASSERT(core2->amps[i].name[j] == 'A' + i % 26);
		for(unsigned long long j = 0; j < 128; j++)
			ASSERT_EQ(core2->amps[i].private_data[j], (i * j) * 0xffffdf34);
	}

	ASSERT(!strcmp(core3->name, "Example sound card core"));
	ASSERT_EQ(core3->flags, 0xCAFECAFE);
	ASSERT_EQ(core3->amps_count, 6);

	for(int i = 0; i < core3->amps_count; i++) {
		ASSERT_EQ(core3->amps[i].flags, i * 0xdf);
		ASSERT_EQ(core3->amps[i].is_configured, true);
		ASSERT_EQ(core3->amps[i].parent, core3);
		for(int j = 0; j < 31; j++)
			ASSERT(core3->amps[i].name[j] == 'A' + i % 26);
		for(unsigned long long j = 0; j < 128; j++)
			ASSERT_EQ(core3->amps[i].private_data[j], (i * j) * 0xffffdf34);
	}

	ASSERT(!strcmp(core4->name, "Example sound card core"));
	ASSERT_EQ(core4->flags, 0xCAFECAFE);
	ASSERT_EQ(core4->amps_count, 6);

	for(int i = 0; i < core4->amps_count; i++) {
		ASSERT_EQ(core4->amps[i].flags, i * 0xdf);
		ASSERT_EQ(core4->amps[i].is_configured, true);
		ASSERT_EQ(core4->amps[i].parent, core4);
		for(int j = 0; j < 31; j++)
			ASSERT(core4->amps[i].name[j] == 'A' + i % 26);
		for(unsigned long long j = 0; j < 128; j++)
			ASSERT_EQ(core4->amps[i].private_data[j], (i * j) * 0xffffdf34);
	}

	ASSERT(!strcmp(core5->name, "Example sound card core"));
	ASSERT_EQ(core5->flags, 0xCAFECAFE);
	ASSERT_EQ(core5->amps_count, 6);

	for(int i = 0; i < core5->amps_count; i++) {
		ASSERT_EQ(core5->amps[i].flags, i * 0xdf);
		ASSERT_EQ(core5->amps[i].is_configured, true);
		ASSERT_EQ(core5->amps[i].parent, core5);
		for(int j = 0; j < 31; j++)
			ASSERT(core5->amps[i].name[j] == 'A' + i % 26);
		for(unsigned long long j = 0; j < 128; j++)
			ASSERT_EQ(core5->amps[i].private_data[j], (i * j) * 0xffffdf34);
	}

	ASSERT(!strcmp(core6->name, "Example sound card core"));
	ASSERT_EQ(core6->flags, 0xCAFECAFE);
	ASSERT_EQ(core4->amps_count, 6);

	for(int i = 0; i < core6->amps_count; i++) {
		ASSERT_EQ(core6->amps[i].flags, i * 0xdf);
		ASSERT_EQ(core6->amps[i].is_configured, true);
		ASSERT_EQ(core6->amps[i].parent, core6);
		for(int j = 0; j < 31; j++)
			ASSERT(core6->amps[i].name[j] == 'A' + i % 26);
		for(unsigned long long j = 0; j < 128; j++)
			ASSERT_EQ(core6->amps[i].private_data[j], (i * j) * 0xffffdf34);
	}

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] FLEXIBLE_STRUCT_ARRAY", kflat_flexible_struct_array_test, kflat_flexible_struct_array_validate);
