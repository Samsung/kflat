/**
 * @file example_circle.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

// Common structure types for both userspace and kernel
struct point {
	double x;
	double y;
	unsigned n;
	struct point **other;
};

struct figure {
	const char *name;
	unsigned n;
	struct point *points;
};

/********************************/
#ifdef __KERNEL__
/********************************/
#include "kflat_test_data.h"

FUNCTION_DECLARE_FLATTEN_STRUCT(point);
FUNCTION_DECLARE_FLATTEN_STRUCT(figure);

FUNCTION_DEFINE_FLATTEN_STRUCT(point,
	AGGREGATE_FLATTEN_TYPE_ARRAY(struct point *, other, ATTR(n));
	FOREACH_POINTER(struct point *, p, ATTR(other), ATTR(n),
		FLATTEN_STRUCT(point, p);
	);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(figure,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT_ARRAY(point, points, ATTR(n));
);


#define MAKE_POINT(p, i, N) \
	p.x = (cosx[i]);    \
	p.y = (sinx[i]);    \
	p.n = (N);          \
	p.other = kvzalloc((N) * sizeof *p.other, GFP_KERNEL);

static void create_circle(struct figure *circle, size_t num_points, double *cosx, double *sinx) {
	unsigned i, j, u;

	circle->n = num_points;
	circle->points = kvzalloc(circle->n * sizeof(struct point), GFP_KERNEL);
	for (i = 0; i < circle->n; ++i) {
		MAKE_POINT(circle->points[i], i, circle->n - 1);
	}

	for (i = 0; i < circle->n; ++i) {
		u = 0;
		for (j = 0; j < circle->n; ++j) {
			if (i == j)
				continue;
			circle->points[i].other[u++] = &circle->points[j];
		}
	}
}

static void free_circle(struct figure *circle) {
	unsigned i;

	for (i = 0; i < circle->n; ++i) {
		kvfree(circle->points[i].other);
	}
	kvfree(circle->points);
}

static int kflat_circle_test(struct kflat *kflat) {
	struct figure circle;

	circle.name = "circle";
	create_circle(&circle, 30, cosx, sinx);

	FOR_ROOT_POINTER(&circle,
		FLATTEN_STRUCT(figure, &circle);
	);

	free_circle(&circle);
	return 0;
}

/********************************/
#else
/********************************/

#include <math.h>

static int kflat_circle_validate(void *memory, size_t size, CUnflatten flatten) {
	const struct figure *circle = (const struct figure *)memory;
	double length = 0, circumference = 0;
	unsigned edge_number = 0;
	for (unsigned int i = 0; i < circle->n - 1; ++i) {
		for (unsigned int j = i; j < circle->n - 1; ++j) {
			if (circle->points[i].other[j]) {
				double path_len = sqrt(pow(circle->points[i].x - circle->points[i].other[j]->x, 2) +
						       pow(circle->points[i].y - circle->points[i].other[j]->y, 2));
				length += path_len;

				if (j == i)
					circumference += path_len;
				if ((i == 0) && (j == circle->n - 2))
					circumference += path_len;

				unsigned u;
				for (u = 0; u < circle->n - 1; ++u) {
					if (circle->points[i].other[j]->other[u] == &circle->points[i]) {
						circle->points[i].other[j]->other[u] = 0;
					}
				}
				edge_number++;
			}
		}
	}

	ASSERT(!strcmp(circle->name, "circle"));
	ASSERT(circle->n == 750 || circle->n == 30);
	ASSERT(edge_number == circle->n * (circle->n - 1) / 2);
	ASSERT(3.13 <= circumference / 2 && circumference / 2 <= 3.15);

	PRINT("Number of edges/diagonals: %d", circle->n / 2);
	PRINT("Sum of lengths of edges/diagonals: %lf", length);
	PRINT("Half of the circumference: %lf", circumference / 2);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif
/********************************/

KFLAT_REGISTER_TEST("CIRCLE", kflat_circle_test, kflat_circle_validate);
