#ifndef THREADS_FIXED_H
#define THREADS_FIXED_H
#include <stdint.h>
/*
int32_t to_fpn(int32_t integer);
int32_t to_integer_zero(int32_t fpn);
int32_t to_integer_nearest(int32_t fpn);
int32_t fpn_fpn_add(int32_t fpn1, int32_t fpn2);
int32_t fpn_fpn_sub(int32_t fpn1, int32_t fpn2);
int64_t fpn_fpn_mul(int32_t fpn1, int32_t fpn2);
int64_t fpn_fpn_div(int32_t fpn1, int32_t fpn2);
int32_t fpn_integer_add(int32_t fpn, int32_t integer);
int32_t fpn_integer_sub(int32_t fpn, int32_t integer);
int32_t fpn_integer_mul(int32_t fpn, int32_t integer);
int32_t fpn_integer_div(int32_t fpn, int32_t integer);*/

// 17.14 format fixed point number (fpn). Refer to the appendix, BSD scheduler. 
static int frac=1<<14;

static int32_t to_fpn(int32_t integer){
	return integer*frac;
}

static int32_t to_integer_zero(int32_t fpn){
	return fpn/frac;
}

static int32_t to_integer_nearest(int32_t fpn){
	if(fpn>0) 
		return (fpn+frac/2)/frac;
	else
		return (fpn-frac/2)/frac;
}

static int32_t fpn_fpn_add(int32_t fpn1, int32_t fpn2){
	return fpn1+fpn2;
}

static int32_t fpn_fpn_sub(int32_t fpn1, int32_t fpn2){
	return fpn1-fpn2;
}

static int64_t fpn_fpn_mul(int32_t fpn1, int32_t fpn2){
	return (int64_t)fpn1*fpn2/frac;
}

static int64_t fpn_fpn_div(int32_t fpn1, int32_t fpn2){
	return (int64_t)fpn1*frac/fpn2;
}

static int32_t fpn_integer_add(int32_t fpn, int32_t integer){
	return fpn+integer*frac;
}

static int32_t fpn_integer_sub(int32_t fpn, int32_t integer){
	return fpn-integer*frac;
}

static int32_t fpn_integer_mul(int32_t fpn, int32_t integer){
	return fpn*integer;
}

static int32_t fpn_integer_div(int32_t fpn, int32_t integer){
	return fpn/integer;
}

#endif





