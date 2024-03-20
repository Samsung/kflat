/**
 * @file example_struct_variant.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct audio_device {
	char name[10];
	void* private_data;
	unsigned long ul;
};

struct fft_data {
	struct complex {
		int re;
		int im;
	} vals[10];
	struct audio_device internal_dev;
};

struct acoustic_data {
	int pressure;
	struct fft_data* fft_data;
};

struct spectrum_data {
	int num_coeffs;
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT(audio_device);
FUNCTION_DECLARE_FLATTEN_STRUCT(fft_data);
FUNCTION_DECLARE_FLATTEN_STRUCT(acoustic_data);
FUNCTION_DECLARE_FLATTEN_STRUCT(spectrum_data);

FUNCTION_DEFINE_FLATTEN_STRUCT(audio_device,
	if (__THIS_STRUCT==__ROOT_PTR) {
		AGGREGATE_FLATTEN_STRUCT(acoustic_data,private_data);
	}
	else {
		AGGREGATE_FLATTEN_STRUCT(spectrum_data,private_data);
	}
);

FUNCTION_DEFINE_FLATTEN_STRUCT(fft_data,
	AGGREGATE_FLATTEN_STRUCT_STORAGE(audio_device,internal_dev);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(acoustic_data,
	AGGREGATE_FLATTEN_STRUCT(fft_data,fft_data);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(spectrum_data);

static int kflat_struct_variant_test(struct flat *flat) {
	struct spectrum_data sdata = {10};
	struct fft_data fft_data = {{{0,1},{2,3},{4,5},{6,7},{8,9},{0,9},{8,7},{6,5},{4,3},{2,1}},{"fftdevice",&sdata,0x1000002}};
	struct acoustic_data adata = {500,&fft_data};
	struct audio_device main_device = {"maindevice",&adata,0x100001};

	FLATTEN_SETUP_TEST(flat);

	FOR_ROOT_POINTER(&main_device,
		FLATTEN_STRUCT(audio_device, &main_device);
	);

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_struct_variant_validate(void *memory, size_t size, CUnflatten flatten) {
	const struct audio_device *main_device = (const struct audio_device *)memory;

	ASSERT(!memcmp(main_device->name,"maindevice",10));
	ASSERT(main_device->ul==0x100001);

	struct acoustic_data* adata = main_device->private_data;

	ASSERT(adata->pressure==500);
	for (int i=0; i<10; ++i) {
		if (i<5) {
			ASSERT(adata->fft_data->vals[i].re==i*2);
			ASSERT(adata->fft_data->vals[i].im==i*2+1);
		}
		else {
			ASSERT(adata->fft_data->vals[i].re==(((10-i)*2)%10));
			ASSERT(adata->fft_data->vals[i].im==((10-i)*2-1));
		}
	}

	ASSERT(!strcmp(adata->fft_data->internal_dev.name,"fftdevice"));
	ASSERT(adata->fft_data->internal_dev.ul==0x1000002);

	struct spectrum_data* sdata = adata->fft_data->internal_dev.private_data;

	ASSERT(sdata->num_coeffs==10);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("STRUCT_VARIANT", kflat_struct_variant_test, kflat_struct_variant_validate);
