#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "H264Analyzer.h"
#include "H264AnalyzerUtils.h"
#include "H264AnalyzerLog.h"


#define Max(x, y) ((x) > (y)? (x) : (y))
#define Min(x, y) ((x) < (y)? (x) : (y))


int parse_nal(unsigned char *pData, int length, H264_Context *h264_context);
int parse_sps(unsigned char *pData, int length, Seq_Parameter_Set *sps);
int parse_sps_ext(unsigned char *pData, int length, Seq_Parameter_Set_Ext *sps_ext);
int parse_pps(unsigned char *pData, int length, Pic_Parameter_Set *pps);
int parse_slice_layer(const Nal_Unit *nal_unit, const Seq_Parameter_Set *sps, const Pic_Parameter_Set *pps, unsigned char *pData, int length, Slice_Header *slice_header, Slice_Data *slice_data);
int parse_slice_header(const Nal_Unit *nal_unit, const Seq_Parameter_Set *sps, const Pic_Parameter_Set *pps, unsigned char *pData, int length, Slice_Header *slice_header, unsigned char *start_offset_bits);
int parse_slice_data(const Nal_Unit *nal_unit, const Seq_Parameter_Set *sps, const Pic_Parameter_Set *pps, const Slice_Header *slice_header, unsigned char *pData, int length, unsigned char *start_offset_bits,  Slice_Data *slice_data);
int get_exp_golomb_ue(unsigned char *pData, int length, unsigned char *start_bits, unsigned int *code_number);
int get_exp_golomb_se(unsigned char *pData, int length, unsigned char *start_bits, int *code_number);
int get_bits_u(unsigned char *pData, int length, unsigned char *start_bits, int need_bits_number, unsigned int *code_number);
int more_rbsp_data(unsigned char *pData, int length, int len, unsigned char *start_bits);

/*
*   从H264裸流中解析一个nal包，并返回其长度。
*   
*/
int parse_nal(unsigned char *pData, int length, H264_Context *h264_context)
{
	unsigned char *pRbsp = NULL;
	int len = 0, rbsp_len = 0, len_temp = 0, i = 0;
	Nal_Unit *nal_unit = NULL;
	Seq_Parameter_Set *sps = NULL;
	Seq_Parameter_Set_Ext *sps_ext = NULL;
	Pic_Parameter_Set *pps = NULL;
	Slice_Header slice_header;
	Slice_Data slice_data;
	
	if(length <= 4 || NULL == h264_context)
	{
		return -1;
	}
	if(0x0 != pData[0] || 0x0 != pData[1] || 0x0 != pData[2] || 0x1 != pData[3])
	{
		an_log(H264MODULE_NAL, AN_LOG_INFO, "Not a nal unit.\n");
		return -2;
	}

	if(NULL == h264_context->nal_unit)
	{	
		h264_context->nal_unit = malloc(sizeof(Nal_Unit));
	}
	if(NULL == h264_context->seq_parameter_set)
	{
		h264_context->seq_parameter_set = malloc(sizeof(Seq_Parameter_Set));
	}
	if(NULL == h264_context->sps_ext)
	{
		h264_context->sps_ext = malloc(sizeof(Seq_Parameter_Set_Ext));
	}
	if(NULL == h264_context->pic_parameter_set)
	{
		h264_context->pic_parameter_set = malloc(sizeof(Pic_Parameter_Set));
	}
	nal_unit = h264_context->nal_unit;
	sps = h264_context->seq_parameter_set;
	sps_ext = h264_context->sps_ext;
	pps = h264_context->pic_parameter_set;

	len = 4;
	memset(nal_unit, 0,  sizeof(Nal_Unit));
	nal_unit->nal_ref_idc = (0x60&pData[len])>>5;
	nal_unit->nal_unit_type = 0x1f&pData[len];
	an_log(H264MODULE_NAL, AN_LOG_INFO, "\n");
	an_log(H264MODULE_NAL, AN_LOG_INFO, "nal_ref_idc = %d, nal_unit_type = %d.\n", nal_unit->nal_ref_idc, nal_unit->nal_unit_type);
	
	//an_log(H264MODULE_NAL, AN_LOG_INFO, "\n");
	pRbsp = malloc(length);
	memset(pRbsp, 0, length);

	/*去掉0x03*/
	len = 5;
	while(len + 2 < length)
	{
		if(0x0 == pData[len] && 0x0 == pData[len+1] && 0x3 == pData[len+2] )
		{
			pRbsp[rbsp_len++]  = pData[len++];
			pRbsp[rbsp_len++]  = pData[len++];
			len++;
		}
		else
		{
			pRbsp[rbsp_len++]  = pData[len++];
		}
	}
	/*退出while循环的唯一条件是越界*/
	if(len + 2 >= length)
	{
		if(len + 2 == length)
		{
			pRbsp[rbsp_len++]  = pData[len++];
			pRbsp[rbsp_len++]  = pData[len++];
		}
		else if(len + 1 == length)
		{
			pRbsp[rbsp_len++]  = pData[len++];
		}
	}

	/*seq_parameter_set_rbsp*/
	if(7 == nal_unit->nal_unit_type)
	{
		parse_sps(pRbsp, rbsp_len, sps);
	}
	else if(13 == nal_unit->nal_unit_type)
	{
		parse_sps_ext(pRbsp, rbsp_len, sps_ext);
	}
	else if(8 == nal_unit->nal_unit_type)
	{					
		/*an_log(H264MODULE_NAL, AN_LOG_INFO, "RBSP: ");
		for(i = 0; i < rbsp_len; i++)
			an_log(H264MODULE_NAL, AN_LOG_INFO, "%x ", pRbsp[i]);
		an_log(H264MODULE_NAL, AN_LOG_INFO, "\n");*/
		parse_pps(pRbsp, rbsp_len, pps);
	}
	else if(5 >= nal_unit->nal_unit_type && 1 <= nal_unit->nal_unit_type)
	{					
		//parse_slice_header(nal_unit, sps, pps, pRbsp, rbsp_len, &slice_header);
		parse_slice_layer(nal_unit, sps, pps, pRbsp, rbsp_len, &slice_header, &slice_data);
	}
	return len;
}


int parse_sps(unsigned char *pData, int length, Seq_Parameter_Set *sps)
{
	int len = 0, ret = 0, i = 0, code_number = 0, exp_golomb_number_s = 0;
	unsigned char start_bits = 0xff;
	unsigned int exp_golomb_number_u = 0;

	//an_log(H264MODULE_SPS, AN_LOG_INFO, "\n");
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   SPS: sps = %x\n", sps);
	memset(sps, 0, sizeof(Seq_Parameter_Set));

	an_log(H264MODULE_SPS, AN_LOG_INFO, "   %x %x %x %x\n", pData[0], pData[1], pData[2], pData[3]);
	sps->profile_idc = pData[len];
	len++;
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   profile_idc = %d\n", sps->profile_idc);
		
	sps->constraint_set0_flag = pData[len]>>7;
	sps->constraint_set1_flag = pData[len]>>6&0x1;
	sps->constraint_set2_flag = pData[len]>>5&0x1;
	sps->constraint_set3_flag = pData[len]>>4&0x1;
	
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   constraint_set0_flag = %d\n", sps->constraint_set0_flag);
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   constraint_set1_flag = %d\n", sps->constraint_set1_flag);
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   constraint_set2_flag = %d\n", sps->constraint_set2_flag);
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   constraint_set3_flag = %d\n", sps->constraint_set3_flag);
	sps->reserved_zero_4bits = pData[len]&0x0f;
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   reserved_zero_4bits = %u\n", sps->reserved_zero_4bits);
	len++;
	
	sps->level_idc = pData[len];
	len++;
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   level_idc = %d\n", sps->level_idc);
	
	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
	len += ret;
	sps->seq_parameter_set_id = exp_golomb_number_u;	
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   seq_parameter_set_id = %u\n", sps->seq_parameter_set_id);

	if(100 == sps->profile_idc || 110 == sps->profile_idc || 122 == sps->profile_idc || 144 == sps->profile_idc)
	{
		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
		len += ret;
		sps->chroma_format_idc = exp_golomb_number_u;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      chroma_format_idc = %u\n", sps->chroma_format_idc);
		
		if(3 == sps->chroma_format_idc)
		{
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
			len += ret;
			sps->residual_colour_transform_flag = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      residual_colour_transform_flag = %u\n", sps->residual_colour_transform_flag);
			
		}		
		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
		len += ret;
		sps->bit_depth_luma_minus8 = exp_golomb_number_u;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      bit_depth_luma_minus8 = %u\n", sps->bit_depth_luma_minus8);

		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
		len += ret;
		sps->bit_depth_chroma_minus8 = exp_golomb_number_u;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      bit_depth_chroma_minus8 = %u\n", sps->bit_depth_chroma_minus8);

		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
		len += ret;
		sps->qpprime_y_zero_transform_bypass_flag = code_number;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      qpprime_y_zero_transform_bypass_flag = %u\n", sps->qpprime_y_zero_transform_bypass_flag);

		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
		len += ret;
		sps->seq_scaling_matrix_present_flag = code_number;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      seq_scaling_matrix_present_flag = %u\n", sps->seq_scaling_matrix_present_flag);

		if(1 == sps->seq_scaling_matrix_present_flag)
		{
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      Warning: Not support analyze scaling list\n");
#if 0			
			for( i = 0; i < 8; i++ )
			{
				ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
				len += ret;
				sps->seq_scaling_list_present_flag[i] = code_number;
				if( sps->seq_scaling_list_present_flag[ i ] )
				{
					
				}
			}
#endif
		}

	}
	else
	{
		/*chroma_format_idc  的值应该在 0到3 的范围内（包括0 和3）。
		    当chroma_format_idc 不存在时，应推断其值为1（4：2：0 的色度格式）*/
		sps->chroma_format_idc = 1;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "	   chroma_format_idc = %u\n", sps->chroma_format_idc);
	}
	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
	len += ret;
	sps->log2_max_frame_num_minus4 = exp_golomb_number_u;
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   log2_max_frame_num_minus4 = %u\n", sps->log2_max_frame_num_minus4);

	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
	len += ret;
	sps->pic_order_cnt_type = exp_golomb_number_u;
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   pic_order_cnt_type = %u\n", sps->pic_order_cnt_type);

	if(0 == sps->pic_order_cnt_type)
	{
		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
		len += ret;
		sps->log2_max_pic_order_cnt_lsb_minus4 = exp_golomb_number_u;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      log2_max_pic_order_cnt_lsb_minus4 = %u\n", sps->log2_max_pic_order_cnt_lsb_minus4);
	}
	else if(1 == sps->pic_order_cnt_type)
	{
		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
		len += ret;
		sps->delta_pic_order_always_zero_flag = code_number;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "   delta_pic_order_always_zero_flag = %u\n", sps->delta_pic_order_always_zero_flag);

		ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &exp_golomb_number_s);
		len += ret;
		sps->offset_for_non_ref_pic = exp_golomb_number_s;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "   offset_for_non_ref_pic = %d\n", sps->offset_for_non_ref_pic);

		ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &exp_golomb_number_s);
		len += ret;
		sps->offset_for_top_to_bottom_field = exp_golomb_number_s;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "   offset_for_top_to_bottom_field = %d\n", sps->offset_for_top_to_bottom_field);

		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
		len += ret;
		sps->num_ref_frames_in_pic_order_cnt_cycle = exp_golomb_number_u;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "   num_ref_frames_in_pic_order_cnt_cycle = %d\n", sps->num_ref_frames_in_pic_order_cnt_cycle);

		sps->offset_for_ref_frame = malloc(sps->num_ref_frames_in_pic_order_cnt_cycle);
		memset(sps->offset_for_ref_frame, 0, sps->num_ref_frames_in_pic_order_cnt_cycle);
		for(i = 0; i < sps->num_ref_frames_in_pic_order_cnt_cycle; i++)
		{
			ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &exp_golomb_number_s);
			len += ret;
			sps->offset_for_ref_frame[i] =  exp_golomb_number_s;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "   offset_for_ref_frame[%d]  = %d\n", i, sps->offset_for_ref_frame[i]);
		}
	}
	
	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
	len += ret;
	sps->num_ref_frames = exp_golomb_number_u;
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   num_ref_frames = %u\n", sps->num_ref_frames);
	
	ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
	len += ret;
	sps->gaps_in_frame_num_value_allowed_flag = code_number;
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   gaps_in_frame_num_value_allowed_flag = %u\n", sps->gaps_in_frame_num_value_allowed_flag);

	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
	len += ret;
	sps->pic_width_in_mbs_minus1 = exp_golomb_number_u;
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   pic_width_in_mbs_minus1 = %u\n", sps->pic_width_in_mbs_minus1);

	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
	len += ret;
	sps->pic_height_in_map_units_minus1 = exp_golomb_number_u;
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   pic_height_in_map_units_minus1 = %u\n", sps->pic_height_in_map_units_minus1);

	ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
	len += ret;
	sps->frame_mbs_only_flag = code_number;
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   frame_mbs_only_flag = %d\n", sps->frame_mbs_only_flag);

	if(!sps->frame_mbs_only_flag)
	{
		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
		len += ret;
		sps->mb_adaptive_frame_field_flag = code_number;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "   mb_adaptive_frame_field_flag = %u\n", sps->mb_adaptive_frame_field_flag);
	}
	
	ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
	len += ret;
	sps->direct_8x8_inference_flag = code_number;
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   direct_8x8_inference_flag = %u\n", sps->direct_8x8_inference_flag);

	ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
	len += ret;
	sps->frame_cropping_flag = code_number;
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   rame_cropping_flag = %u\n", sps->frame_cropping_flag);

	if(sps->frame_cropping_flag)
	{
		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
		len += ret;
		sps->frame_crop_left_offset = exp_golomb_number_u;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "   frame_crop_left_offset = %u\n", sps->frame_crop_left_offset);

		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
		len += ret;
		sps->frame_crop_right_offset = exp_golomb_number_u;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "   frame_crop_right_offset = %u\n", sps->frame_crop_right_offset);

		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
		len += ret;
		sps->frame_crop_top_offset = exp_golomb_number_u;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "   frame_crop_top_offset = %u\n", sps->frame_crop_top_offset);

		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
		len += ret;
		sps->frame_crop_bottom_offset = exp_golomb_number_u;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "    frame_crop_bottom_offset = %u\n", sps->frame_crop_bottom_offset);
		
	}
	
	ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
	len += ret;
	sps->vui_parameters_present_flag = code_number;
	an_log(H264MODULE_SPS, AN_LOG_INFO, "   vui_parameters_present_flag = %u\n", sps->vui_parameters_present_flag);
	
	if(sps->vui_parameters_present_flag)
	{
		Vui_Parameters *pVui = NULL;
		pVui = malloc(sizeof(Vui_Parameters));
		sps->pVui_Parameters = pVui;
		memset(pVui, 0, sizeof(Vui_Parameters));

		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
		len += ret;
		pVui->aspect_ratio_info_present_flag = code_number;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      aspect_ratio_info_present_flag = %u\n", pVui->aspect_ratio_info_present_flag);

		if(pVui->aspect_ratio_info_present_flag)
		{
			ret = get_bits_u(pData + len, length - len, &start_bits, 8, &code_number);
			len += ret;
			pVui->aspect_ratio_idc = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      aspect_ratio_idc = %u\n", pVui->aspect_ratio_idc);

			if(Extended_SAR == pVui->aspect_ratio_idc)
			{
				ret = get_bits_u(pData + len, length - len, &start_bits, 16, &code_number);
				len += ret;
				pVui->sar_width = code_number;
				an_log(H264MODULE_SPS, AN_LOG_INFO, "      sar_width = %u\n", pVui->sar_width);
				
				ret = get_bits_u(pData + len, length - len, &start_bits, 16, &code_number);
				len += ret;
				pVui->sar_height = code_number;
				an_log(H264MODULE_SPS, AN_LOG_INFO, "      sar_height = %u\n", pVui->sar_height);
			}
		}

		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
		len += ret;
		pVui->overscan_info_present_flag = code_number;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      overscan_info_present_flag = %u\n", pVui->overscan_info_present_flag);

		if(pVui->overscan_info_present_flag)
		{
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
			len += ret;
			pVui->overscan_appropriate_flag = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      overscan_appropriate_flag = %u\n", pVui->overscan_appropriate_flag);
		}

		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
		len += ret;
		pVui->video_signal_type_present_flag = code_number;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      video_signal_type_present_flag = %u\n", pVui->video_signal_type_present_flag);

		if(pVui->video_signal_type_present_flag)
		{
			ret = get_bits_u(pData + len, length - len, &start_bits, 3, &code_number);
			len += ret;
			pVui->video_format = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      video_format = %u\n", pVui->video_format);
			
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
			len += ret;
			pVui->video_full_range_flag = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      video_full_range_flag = %u\n", pVui->video_full_range_flag);
			
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
			len += ret;
			pVui->colour_description_present_flag = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      colour_description_present_flag = %u\n", pVui->colour_description_present_flag);

			if(pVui->colour_description_present_flag)
			{
				ret = get_bits_u(pData + len, length - len, &start_bits, 8, &code_number);
				len += ret;
				pVui->colour_primaries = code_number;
				an_log(H264MODULE_SPS, AN_LOG_INFO, "      colour_primaries = %u\n", pVui->colour_primaries);
				
				ret = get_bits_u(pData + len, length - len, &start_bits, 8, &code_number);
				len += ret;
				pVui->transfer_characteristics = code_number;
				an_log(H264MODULE_SPS, AN_LOG_INFO, "      transfer_characteristics = %u\n", pVui->transfer_characteristics);
				
				ret = get_bits_u(pData + len, length - len, &start_bits, 8, &code_number);
				len += ret;
				pVui->matrix_coefficients = code_number;
				an_log(H264MODULE_SPS, AN_LOG_INFO, "      matrix_coefficients = %u\n", pVui->matrix_coefficients);

			}
		}
		
		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
		len += ret;
		pVui->chroma_loc_info_present_flag = code_number;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      chroma_loc_info_present_flag = %u\n", pVui->chroma_loc_info_present_flag);

		if(pVui->chroma_loc_info_present_flag)
		{
			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
			len += ret;
			pVui->chroma_sample_loc_type_top_field = exp_golomb_number_u;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      chroma_sample_loc_type_top_field = %u\n", pVui->chroma_sample_loc_type_top_field);
			
			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
			len += ret;
			pVui->chroma_sample_loc_type_bottom_field = exp_golomb_number_u;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      chroma_sample_loc_type_bottom_field = %u\n", pVui->chroma_sample_loc_type_bottom_field);
		}

		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
		len += ret;
		pVui->timing_info_present_flag = code_number;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      timing_info_present_flag = %u\n", pVui->timing_info_present_flag);

		if(pVui->timing_info_present_flag)
		{
			ret = get_bits_u(pData + len, length - len, &start_bits, 32, &code_number);
			len += ret;
			pVui->num_units_in_tick = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      num_units_in_tick = %u\n", pVui->num_units_in_tick);
			
			ret = get_bits_u(pData + len, length - len, &start_bits, 32, &code_number);
			len += ret;
			pVui->time_scale = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      time_scale = %u\n", pVui->time_scale);
			
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
			len += ret;
			pVui->fixed_frame_rate_flag = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      fixed_frame_rate_flag = %u\n", pVui->fixed_frame_rate_flag);
		}
		
		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
		len += ret;
		pVui->nal_hrd_parameters_present_flag = code_number;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      nal_hrd_parameters_present_flag = %u\n", pVui->nal_hrd_parameters_present_flag);

		if(pVui->nal_hrd_parameters_present_flag)
		{
			int cpb_cnt_minus1 = 0;
			pVui->pnal_hrd_parameters = malloc(sizeof(Hrd_Parameters));
			memset(pVui->pnal_hrd_parameters, 0, sizeof(Hrd_Parameters));

			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
			len += ret;
			pVui->pnal_hrd_parameters->cpb_cnt_minus1 = exp_golomb_number_u;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      cpb_cnt_minus1 = %u\n", pVui->pnal_hrd_parameters->cpb_cnt_minus1);
			cpb_cnt_minus1 = pVui->pnal_hrd_parameters->cpb_cnt_minus1;

			ret = get_bits_u(pData + len, length - len, &start_bits, 4, &code_number);
			len += ret;
			pVui->pnal_hrd_parameters->bit_rate_scale = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      bit_rate_scale = %u\n", pVui->pnal_hrd_parameters->bit_rate_scale);

			ret = get_bits_u(pData + len, length - len, &start_bits, 4, &code_number);
			len += ret;
			pVui->pnal_hrd_parameters->cpb_size_scale = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      cpb_size_scale = %u\n", pVui->pnal_hrd_parameters->cpb_size_scale);

			pVui->pnal_hrd_parameters->bit_rate_value_minus1 = malloc((cpb_cnt_minus1 + 1) * sizeof(int));
			memset(pVui->pnal_hrd_parameters->bit_rate_value_minus1, 0, (cpb_cnt_minus1 + 1) * sizeof(int));
			pVui->pnal_hrd_parameters->cpb_size_value_minus1 = malloc((cpb_cnt_minus1 + 1) * sizeof(int));
			memset(pVui->pnal_hrd_parameters->cpb_size_value_minus1, 0, (cpb_cnt_minus1 + 1) * sizeof(int));
			pVui->pnal_hrd_parameters->cbr_flag = malloc((cpb_cnt_minus1 + 1) * sizeof(int));
			memset(pVui->pnal_hrd_parameters->cbr_flag, 0, (cpb_cnt_minus1 + 1) * sizeof(int));

			int SchedSelIdx;
			for(SchedSelIdx = 0; SchedSelIdx <= cpb_cnt_minus1; SchedSelIdx++)
			{
			
				ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
				len += ret;
				pVui->pnal_hrd_parameters->bit_rate_value_minus1[SchedSelIdx] = exp_golomb_number_u;
				an_log(H264MODULE_SPS, AN_LOG_INFO, "         bit_rate_value_minus1[%d] = %u\n", SchedSelIdx, pVui->pnal_hrd_parameters->bit_rate_value_minus1[SchedSelIdx]);
				ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
				len += ret;
				pVui->pnal_hrd_parameters->cpb_size_value_minus1[SchedSelIdx] = exp_golomb_number_u;
				an_log(H264MODULE_SPS, AN_LOG_INFO, "         cpb_size_value_minus1[%d] = %u\n", SchedSelIdx, pVui->pnal_hrd_parameters->cpb_size_value_minus1[SchedSelIdx]);
				ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
				len += ret;
				pVui->pnal_hrd_parameters->cbr_flag[SchedSelIdx] = code_number;
				an_log(H264MODULE_SPS, AN_LOG_INFO, "         cbr_flag[%d] = %u\n", SchedSelIdx, pVui->pnal_hrd_parameters->cbr_flag[SchedSelIdx]);

				
			}
			
			ret = get_bits_u(pData + len, length - len, &start_bits, 5, &code_number);
			len += ret;
			pVui->pnal_hrd_parameters->initial_cpb_removal_delay_length_minus1 = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      initial_cpb_removal_delay_length_minus1 = %u\n", pVui->pnal_hrd_parameters->initial_cpb_removal_delay_length_minus1);

			ret = get_bits_u(pData + len, length - len, &start_bits, 5, &code_number);
			len += ret;
			pVui->pnal_hrd_parameters->cpb_removal_delay_length_minus1 = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      cpb_removal_delay_length_minus1 = %u\n", pVui->pnal_hrd_parameters->cpb_removal_delay_length_minus1);

			ret = get_bits_u(pData + len, length - len, &start_bits, 5, &code_number);
			len += ret;
			pVui->pnal_hrd_parameters->dpb_output_delay_length_minus1 = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      dpb_output_delay_length_minus1 = %u\n", pVui->pnal_hrd_parameters->dpb_output_delay_length_minus1);

			ret = get_bits_u(pData + len, length - len, &start_bits, 5, &code_number);
			len += ret;
			pVui->pnal_hrd_parameters->time_offset_length = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      time_offset_length = %u\n", pVui->pnal_hrd_parameters->time_offset_length);
		}

		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
		len += ret;
		pVui->vcl_hrd_parameters_present_flag = code_number;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      vcl_hrd_parameters_present_flag = %u\n", pVui->vcl_hrd_parameters_present_flag);
		
		if(pVui->vcl_hrd_parameters_present_flag)
		{
			int cpb_cnt_minus1 = 0;
			pVui->pvcl_hrd_parameters = malloc(sizeof(Hrd_Parameters));
			memset(pVui->pvcl_hrd_parameters, 0, sizeof(Hrd_Parameters));

			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
			len += ret;
			pVui->pvcl_hrd_parameters->cpb_cnt_minus1 = exp_golomb_number_u;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      cpb_cnt_minus1 = %u\n", pVui->pvcl_hrd_parameters->cpb_cnt_minus1);
			cpb_cnt_minus1 = pVui->pvcl_hrd_parameters->cpb_cnt_minus1;

			ret = get_bits_u(pData + len, length - len, &start_bits, 4, &code_number);
			len += ret;
			pVui->pvcl_hrd_parameters->bit_rate_scale = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      bit_rate_scale = %u\n", pVui->pvcl_hrd_parameters->bit_rate_scale);

			ret = get_bits_u(pData + len, length - len, &start_bits, 4, &code_number);
			len += ret;
			pVui->pvcl_hrd_parameters->cpb_size_scale = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      cpb_size_scale = %u\n", pVui->pvcl_hrd_parameters->cpb_size_scale);

			pVui->pvcl_hrd_parameters->bit_rate_value_minus1 = malloc((cpb_cnt_minus1 + 1) * sizeof(int));
			memset(pVui->pvcl_hrd_parameters->bit_rate_value_minus1, 0, (cpb_cnt_minus1 + 1) * sizeof(int));
			pVui->pvcl_hrd_parameters->cpb_size_value_minus1 = malloc((cpb_cnt_minus1 + 1) * sizeof(int));
			memset(pVui->pvcl_hrd_parameters->cpb_size_value_minus1, 0, (cpb_cnt_minus1 + 1) * sizeof(int));
			pVui->pvcl_hrd_parameters->cbr_flag = malloc((cpb_cnt_minus1 + 1) * sizeof(int));
			memset(pVui->pvcl_hrd_parameters->cbr_flag, 0, (cpb_cnt_minus1 + 1) * sizeof(int));

			int SchedSelIdx;
			for(SchedSelIdx = 0; SchedSelIdx <= cpb_cnt_minus1; SchedSelIdx++)
			{
			
				ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
				len += ret;
				pVui->pnal_hrd_parameters->bit_rate_value_minus1[SchedSelIdx] = exp_golomb_number_u;
				an_log(H264MODULE_SPS, AN_LOG_INFO, "         bit_rate_value_minus1[%d] = %u\n", SchedSelIdx, pVui->pnal_hrd_parameters->bit_rate_value_minus1[SchedSelIdx]);
				ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
				len += ret;
				pVui->pnal_hrd_parameters->cpb_size_value_minus1[SchedSelIdx] = exp_golomb_number_u;
				an_log(H264MODULE_SPS, AN_LOG_INFO, "         cpb_size_value_minus1[%d] = %u\n", SchedSelIdx, pVui->pnal_hrd_parameters->cpb_size_value_minus1[SchedSelIdx]);
				ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
				len += ret;
				pVui->pnal_hrd_parameters->cbr_flag[SchedSelIdx] = code_number;
				an_log(H264MODULE_SPS, AN_LOG_INFO, "         cbr_flag[%d] = %u\n", SchedSelIdx, pVui->pnal_hrd_parameters->cbr_flag[SchedSelIdx]);

				
			}
			
			ret = get_bits_u(pData + len, length - len, &start_bits, 5, &code_number);
			len += ret;
			pVui->pnal_hrd_parameters->initial_cpb_removal_delay_length_minus1 = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      initial_cpb_removal_delay_length_minus1 = %u\n", pVui->pnal_hrd_parameters->initial_cpb_removal_delay_length_minus1);

			ret = get_bits_u(pData + len, length - len, &start_bits, 5, &code_number);
			len += ret;
			pVui->pnal_hrd_parameters->cpb_removal_delay_length_minus1 = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      cpb_removal_delay_length_minus1 = %u\n", pVui->pnal_hrd_parameters->cpb_removal_delay_length_minus1);

			ret = get_bits_u(pData + len, length - len, &start_bits, 5, &code_number);
			len += ret;
			pVui->pnal_hrd_parameters->dpb_output_delay_length_minus1 = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      dpb_output_delay_length_minus1 = %u\n", pVui->pnal_hrd_parameters->dpb_output_delay_length_minus1);

			ret = get_bits_u(pData + len, length - len, &start_bits, 5, &code_number);
			len += ret;
			pVui->pnal_hrd_parameters->time_offset_length = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      time_offset_length = %u\n", pVui->pnal_hrd_parameters->time_offset_length);
		}

		if(pVui->vcl_hrd_parameters_present_flag || pVui->nal_hrd_parameters_present_flag)
		{
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
			len += ret;
			pVui->low_delay_hrd_flag = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      low_delay_hrd_flag = %u\n", pVui->low_delay_hrd_flag);
		}

		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
		len += ret;
		pVui->pic_struct_present_flag = code_number;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      pic_struct_present_flag = %u\n", pVui->pic_struct_present_flag);

		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
		len += ret;
		pVui->bitstream_restriction_flag = code_number;
		an_log(H264MODULE_SPS, AN_LOG_INFO, "      bitstream_restriction_flag = %u\n", pVui->bitstream_restriction_flag);

		if(pVui->bitstream_restriction_flag)
		{
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &code_number);
			len += ret;
			pVui->motion_vectors_over_pic_boundaries_flag = code_number;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      motion_vectors_over_pic_boundaries_flag = %u\n", pVui->motion_vectors_over_pic_boundaries_flag);
			
			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
			len += ret;
			pVui->max_bytes_per_pic_denom = exp_golomb_number_u;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      max_bytes_per_pic_denom = %u\n", pVui->max_bytes_per_pic_denom);
			
			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
			len += ret;
			pVui->max_bits_per_mb_denom = exp_golomb_number_u;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      max_bits_per_mb_denom = %u\n", pVui->max_bits_per_mb_denom);

			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
			len += ret;
			pVui->log2_max_mv_length_horizontal = exp_golomb_number_u;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      log2_max_mv_length_horizontal = %u\n", pVui->log2_max_mv_length_horizontal);

			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
			len += ret;
			pVui->log2_max_mv_length_vertical = exp_golomb_number_u;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      log2_max_mv_length_vertical = %u\n", pVui->log2_max_mv_length_vertical);

			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
			len += ret;
			pVui->num_reorder_frames = exp_golomb_number_u;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      num_reorder_frames = %u\n", pVui->num_reorder_frames);

			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &exp_golomb_number_u);
			len += ret;
			pVui->max_dec_frame_buffering = exp_golomb_number_u;
			an_log(H264MODULE_SPS, AN_LOG_INFO, "      max_dec_frame_buffering = %u\n", pVui->max_dec_frame_buffering);
			
		}
		
	}
	
	
	return 0;
}


int parse_pps(unsigned char *pData, int length, Pic_Parameter_Set *pps)
{
	int len = 0, ret = 0, i = 0, code_number = 0, exp_golomb_number_s = 0, iGroup = 0;
	unsigned char start_bits = 0xff;
	unsigned int exp_golomb_number_u = 0;

	//an_log(H264MODULE_PPS, AN_LOG_INFO, "\n");
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   PPS:\n");
	memset(pps, 0, sizeof(Pic_Parameter_Set));

	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &pps->pic_parameter_set_id);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   pic_parameter_set_id = %u\n", pps->pic_parameter_set_id);
	
	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &pps->seq_parameter_set_id);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   seq_parameter_set_id = %u\n", pps->seq_parameter_set_id);
	
	ret = get_bits_u(pData + len, length - len, &start_bits, 1, &pps->entropy_coding_mode_flag);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   entropy_coding_mode_flag = %u\n", pps->entropy_coding_mode_flag);
	
	ret = get_bits_u(pData + len, length - len, &start_bits, 1, &pps->pic_order_present_flag);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   pic_order_present_flag = %u\n", pps->pic_order_present_flag);
	
	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &pps->num_slice_groups_minus1);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   num_slice_groups_minus1 = %u\n", pps->num_slice_groups_minus1);

	if(pps->num_slice_groups_minus1 > 0)
	{
		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &pps->slice_group_map_type);
		len += ret;
		an_log(H264MODULE_PPS, AN_LOG_INFO, "   slice_group_map_type = %u\n", pps->slice_group_map_type);

		if(0 == pps->slice_group_map_type)
		{
			
			pps->run_length_minus1 = malloc((pps->num_slice_groups_minus1 + 1)*sizeof(int));
			memset(pps->run_length_minus1, 0, (pps->num_slice_groups_minus1 + 1)*sizeof(int));
			for(iGroup = 0;iGroup <= pps->num_slice_groups_minus1; iGroup++)
			{
				ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &pps->run_length_minus1[iGroup]);
				len += ret;
				an_log(H264MODULE_PPS, AN_LOG_INFO, "   run_length_minus1[%d] = %u\n", iGroup, pps->run_length_minus1[iGroup]);
			}
		}
		else if(2 == pps->slice_group_map_type)
		{
			pps->top_left = malloc(pps->num_slice_groups_minus1*sizeof(int));
			memset(pps->top_left, 0, pps->num_slice_groups_minus1*sizeof(int));
			pps->bottom_right = malloc(pps->num_slice_groups_minus1*sizeof(int));
			memset(pps->bottom_right, 0, pps->num_slice_groups_minus1*sizeof(int));
			for(iGroup = 0;iGroup < pps->num_slice_groups_minus1; iGroup++)
			{
				ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &pps->top_left[iGroup]);
				len += ret;
				an_log(H264MODULE_PPS, AN_LOG_INFO, "   top_left[%d] = %u\n", iGroup, pps->top_left[iGroup]);
				ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &pps->bottom_right[iGroup]);
				len += ret;
				an_log(H264MODULE_PPS, AN_LOG_INFO, "   bottom_right[%d] = %u\n", iGroup, pps->bottom_right[iGroup]);
			}
		}
		else if(3 == pps->slice_group_map_type || 4 == pps->slice_group_map_type || 5 == pps->slice_group_map_type)
		{
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &pps->slice_group_change_direction_flag);
			len += ret;
			an_log(H264MODULE_PPS, AN_LOG_INFO, "   slice_group_change_direction_flag = %u\n", pps->slice_group_change_direction_flag);
			
			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &pps->slice_group_change_rate_minus1);
			len += ret;
			an_log(H264MODULE_PPS, AN_LOG_INFO, "   slice_group_change_rate_minus1 = %u\n", pps->slice_group_change_rate_minus1);
		}
		else if(6 == pps->slice_group_map_type)
		{
			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &pps->pic_size_in_map_units_minus1);
			len += ret;
			an_log(H264MODULE_PPS, AN_LOG_INFO, "   pic_size_in_map_units_minus1 = %u\n", pps->pic_size_in_map_units_minus1);

			pps->slice_group_id = malloc((pps->pic_size_in_map_units_minus1 + 1)*sizeof(int));
			memset(pps->slice_group_id, 0, (pps->pic_size_in_map_units_minus1 + 1)*sizeof(int));

			for(i = 0; i <= pps->pic_size_in_map_units_minus1; i++)
			{
				ret = get_bits_u(pData + len, length - len, &start_bits, ceil(log(pps->num_slice_groups_minus1 + 1)/log(2)), &pps->slice_group_id[i]);
				len += ret;
				an_log(H264MODULE_PPS, AN_LOG_INFO, "   slice_group_id[%d] = %u\n", pps->slice_group_id[i]);
			}
		}
	}

	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &pps->num_ref_idx_l0_active_minus1);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   num_ref_idx_l0_active_minus1 = %u\n", pps->num_ref_idx_l0_active_minus1);
	
	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &pps->num_ref_idx_l1_active_minus1);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   num_ref_idx_l1_active_minus1 = %u\n", pps->num_ref_idx_l1_active_minus1);

	ret = get_bits_u(pData + len, length - len, &start_bits, 1, &pps->weighted_pred_flag);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   weighted_pred_flag = %u\n", pps->weighted_pred_flag);

	ret = get_bits_u(pData + len, length - len, &start_bits, 2, &pps->weighted_bipred_idc);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   weighted_bipred_idc = %u\n", pps->weighted_bipred_idc);

	ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &pps->pic_init_qp_minus26);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   pic_init_qp_minus26 = %d\n", pps->pic_init_qp_minus26);

	ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &pps->pic_init_qs_minus26);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   pic_init_qs_minus26 = %d\n", pps->pic_init_qs_minus26);

	ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &pps->chroma_qp_index_offset);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   chroma_qp_index_offset = %d\n", pps->chroma_qp_index_offset);

	ret = get_bits_u(pData + len, length - len, &start_bits, 1, &pps->deblocking_filter_control_present_flag);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   deblocking_filter_control_present_flag = %u\n", pps->deblocking_filter_control_present_flag);

	ret = get_bits_u(pData + len, length - len, &start_bits, 1, &pps->constrained_intra_pred_flag);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   constrained_intra_pred_flag = %u\n", pps->constrained_intra_pred_flag);

	ret = get_bits_u(pData + len, length - len, &start_bits, 1, &pps->redundant_pic_cnt_present_flag);
	len += ret;
	an_log(H264MODULE_PPS, AN_LOG_INFO, "   redundant_pic_cnt_present_flag = %u\n", pps->redundant_pic_cnt_present_flag);

	//an_log(H264MODULE_PPS, AN_LOG_INFO, "   length = %d, len = %d, start_bits = 0x%x\n", length, len, start_bits);
	ret = more_rbsp_data(pData, length, len, &start_bits);
	//an_log(H264MODULE_PPS, AN_LOG_INFO, "   more_rbsp_data return %d\n", ret);
	if(ret > 0)
	{
		an_log(H264MODULE_PPS, AN_LOG_INFO, "   Threr are more data in RBSP! Need to continue analyze!\n");
		an_log(NULL, AN_LOG_INFO, "      ");
		for(i = len; i < length; i++)
			//printf(" 0x%2x", pData[i]);
			an_log(NULL, AN_LOG_INFO, " 0x%x", pData[i]);
			
		an_log(NULL, AN_LOG_INFO, "\n");
	}

	return 0;
}

int parse_sps_ext(unsigned char *pData, int length, Seq_Parameter_Set_Ext *sps_ext)
{
	int len = 0, ret = 0, i = 0, code_number = 0, exp_golomb_number_s = 0;
	unsigned char start_bits = 0xff;
	unsigned int exp_golomb_number_u = 0;

	//an_log(H264MODULE_SPS_EXT, AN_LOG_INFO, "\n");
	an_log(H264MODULE_SPS_EXT, AN_LOG_INFO, "   SPS_EXT:\n");
	memset(sps_ext, 0, sizeof(Seq_Parameter_Set_Ext));

	
	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &sps_ext->seq_parameter_set_id);
	len += ret;
	an_log(H264MODULE_SPS_EXT, AN_LOG_INFO, "	  seq_parameter_set_id = %u\n", sps_ext->seq_parameter_set_id);

	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &sps_ext->aux_format_idc);
	len += ret;
	an_log(H264MODULE_SPS_EXT, AN_LOG_INFO, "	  aux_format_idc = %u\n", sps_ext->aux_format_idc);

	if(sps_ext->aux_format_idc)
	{
		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &sps_ext->bit_depth_aux_minus8);
		len += ret;
		an_log(H264MODULE_SPS_EXT, AN_LOG_INFO, "	     bit_depth_aux_minus8 = %u\n", sps_ext->bit_depth_aux_minus8);
		
		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &sps_ext->alpha_incr_flag);
		len += ret;
		an_log(H264MODULE_SPS_EXT, AN_LOG_INFO, "	  alpha_incr_flag = %u\n", sps_ext->alpha_incr_flag);
		
		ret = get_bits_u(pData + len, length - len, &start_bits, sps_ext->bit_depth_aux_minus8 + 9, &sps_ext->alpha_opaque_value);
		len += ret;
		an_log(H264MODULE_SPS_EXT, AN_LOG_INFO, "	  alpha_opaque_value = %u\n", sps_ext->alpha_opaque_value);

		ret = get_bits_u(pData + len, length - len, &start_bits, sps_ext->bit_depth_aux_minus8 + 9, &sps_ext->alpha_transparent_value);
		len += ret;
		an_log(H264MODULE_SPS_EXT, AN_LOG_INFO, "	  alpha_transparent_value = %u\n", sps_ext->alpha_transparent_value);
	}
	
	ret = get_bits_u(pData + len, length - len, &start_bits, 1, &sps_ext->additional_extension_flag);
	len += ret;
	an_log(H264MODULE_SPS_EXT, AN_LOG_INFO, "	  additional_extension_flag = %u\n", sps_ext->additional_extension_flag);
}


/*
*   解析一个未分割的slice。
*
*/
int parse_slice_layer(const Nal_Unit *nal_unit, const Seq_Parameter_Set *sps, const Pic_Parameter_Set *pps, unsigned char *pData, int length, Slice_Header *slice_header, Slice_Data *slice_data)
{
	int ret = 0;
	unsigned char start_bits = 0xff;

	ret = parse_slice_header(nal_unit, sps, pps, pData, length, slice_header, &start_bits);
	if(ret < 0)
		return ret;
	ret = parse_slice_data(nal_unit, sps, pps, slice_header, pData + ret, length - ret, &start_bits, slice_data);
	return 0;
}


int parse_slice_header(const Nal_Unit *nal_unit, const Seq_Parameter_Set *sps, const Pic_Parameter_Set *pps, unsigned char *pData, int length, Slice_Header *slice_header, unsigned char *start_offset_bits)
{
	int len = 0, ret = 0, i = 0, j = 0, code_number = 0, exp_golomb_number_s = 0, iGroup = 0;
	unsigned char start_bits = 0xff;
	unsigned int exp_golomb_number_u = 0;

	//an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "\n");
#if 0	
	an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "   Slice Header: sps = %x\n", sps);
	an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      sps->pic_width_in_mbs_minus1 = %d\n", sps->pic_width_in_mbs_minus1);
	an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      sps->pic_height_in_map_units_minus1 = %d\n", sps->pic_height_in_map_units_minus1);
	an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      sps->frame_mbs_only_flag = %d\n", sps->frame_mbs_only_flag);
	an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      sps->direct_8x8_inference_flag = %d\n", sps->direct_8x8_inference_flag);
#endif
	memset(slice_header, 0, sizeof(Slice_Header));

	if(NULL == sps || NULL == pps)
	{
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "   Need sps or pps firstly\n");
		return -1;
	}
	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &slice_header->first_mb_in_slice);
	len += ret;
	an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "   first_mb_in_slice = %u\n", slice_header->first_mb_in_slice);

	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &slice_header->slice_type);
	len += ret;
	an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "   slice_type = %u\n", slice_header->slice_type);

	ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &slice_header->pic_parameter_set_id);
	len += ret;
	an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "   pic_parameter_set_id = %u\n", slice_header->pic_parameter_set_id);

	ret = get_bits_u(pData + len, length - len, &start_bits, sps->log2_max_frame_num_minus4 + 4, &slice_header->frame_num);
	len += ret;
	an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "   frame_num = %u\n", slice_header->frame_num);

	an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      sps->frame_mbs_only_flag = %d\n", sps->frame_mbs_only_flag);
	
	if(!sps->frame_mbs_only_flag)
	{
		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &slice_header->field_pic_flag);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  field_pic_flag = %u\n", slice_header->field_pic_flag);
		
		if(slice_header->field_pic_flag)
		{
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &slice_header->bottom_field_flag);
			len += ret;
			an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	     bottom_field_flag = %u\n", slice_header->bottom_field_flag);
		}
	}

	if(5 == nal_unit->nal_unit_type)
	{
		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &slice_header->idr_pic_id);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "   idr_pic_id = %d\n", slice_header->idr_pic_id);
	}

	if(0 == sps->pic_order_cnt_type)
	{
		ret = get_bits_u(pData + len, length - len, &start_bits, sps->log2_max_pic_order_cnt_lsb_minus4 + 4, &slice_header->pic_order_cnt_lsb);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  pic_order_cnt_lsb = %u\n", slice_header->pic_order_cnt_lsb);

		if(pps->pic_order_present_flag && !slice_header->field_pic_flag)
		{
			ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &slice_header->delta_pic_order_cnt_bottom);
			len += ret;
			an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      delta_pic_order_cnt_bottom = %d\n", slice_header->delta_pic_order_cnt_bottom);

		}
	}

	if( 1 == sps->pic_order_cnt_type  && !sps->delta_pic_order_always_zero_flag ) 
	{
		ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &slice_header->delta_pic_order_cnt[0]);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      delta_pic_order_cnt[0] = %d\n", slice_header->delta_pic_order_cnt[0]);

		if(pps->pic_order_present_flag && !slice_header->field_pic_flag)
		{
			ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &slice_header->delta_pic_order_cnt[1]);
			len += ret;
			an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      delta_pic_order_cnt[1] = %d\n", slice_header->delta_pic_order_cnt[1]);
		}
	}

	if(pps->redundant_pic_cnt_present_flag)
	{
		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &slice_header->redundant_pic_cnt);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "   redundant_pic_cnt = %d\n", slice_header->redundant_pic_cnt);
	}

	 //slice_type = = B
	if(1 == slice_header->slice_type || 6 == slice_header->slice_type)
	{
		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &slice_header->direct_spatial_mv_pred_flag);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  direct_spatial_mv_pred_flag = %u\n", slice_header->direct_spatial_mv_pred_flag);
	}

	//if( slice_type = = P | | slice_type = = SP | | slice_type = = B ) {
	if(0 == slice_header->slice_type 
		|| 5 == slice_header->slice_type 
		|| 3 == slice_header->slice_type
		|| 8 == slice_header->slice_type
		|| 1 == slice_header->slice_type
		|| 6 == slice_header->slice_type	)
	{
		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &slice_header->num_ref_idx_active_override_flag);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  num_ref_idx_active_override_flag = %u\n", slice_header->num_ref_idx_active_override_flag);

		if(slice_header->num_ref_idx_active_override_flag)
		{
			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &slice_header->num_ref_idx_l0_active_minus1);
			len += ret;
			an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      num_ref_idx_l0_active_minus1 = %d\n", slice_header->num_ref_idx_l0_active_minus1);
			if(1 == slice_header->slice_type || 6 == slice_header->slice_type)
			{
				ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &slice_header->num_ref_idx_l1_active_minus1);
				len += ret;
				an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      num_ref_idx_l1_active_minus1 = %d\n", slice_header->num_ref_idx_l1_active_minus1);
			}

		}
	}
	/*ref_pic_list_reordering*/
	Ref_Pic_List_Reordering *rplr = NULL;
	slice_header->ref_pic_list_reordering = malloc(sizeof(Ref_Pic_List_Reordering));
	memset(slice_header->ref_pic_list_reordering, 0, sizeof(Ref_Pic_List_Reordering));
	rplr = slice_header->ref_pic_list_reordering;
	
	if(2 != slice_header->slice_type || 7 != slice_header->slice_type)
	{	
		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &rplr->ref_pic_list_reordering_flag_l0);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  ref_pic_list_reordering_flag_l0 = %u\n", rplr->ref_pic_list_reordering_flag_l0);

		if(rplr->ref_pic_list_reordering_flag_l0)
		{
			do{
				
				ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &rplr->reordering_of_pic_nums_idc_0);
				len += ret;
				an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      reordering_of_pic_nums_idc_0 = %d\n", rplr->reordering_of_pic_nums_idc_0);

				if(0 == rplr->reordering_of_pic_nums_idc_0 || 1 == rplr->reordering_of_pic_nums_idc_0)
				{
					ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &rplr->abs_diff_pic_num_minus1_0);
					len += ret;
					an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      abs_diff_pic_num_minus1_0 = %d\n", rplr->abs_diff_pic_num_minus1_0);
				}
				else if(2 == rplr->reordering_of_pic_nums_idc_0)
				{
					ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &rplr->long_term_pic_num_0);
					len += ret;
					an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      long_term_pic_num_0 = %d\n", rplr->long_term_pic_num_0);
				}
			}while(3 != rplr->reordering_of_pic_nums_idc_0);
		}

	}
	
	 //slice_type = = B
	if(1 == slice_header->slice_type || 6 == slice_header->slice_type)
	{
		ret = get_bits_u(pData + len, length - len, &start_bits, 1, &rplr->ref_pic_list_reordering_flag_l1);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  ref_pic_list_reordering_flag_l1 = %u\n", rplr->ref_pic_list_reordering_flag_l1);

		if(rplr->ref_pic_list_reordering_flag_l1)
		{
			do{
				
				ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &rplr->reordering_of_pic_nums_idc_1);
				len += ret;
				an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      reordering_of_pic_nums_idc_1 = %d\n", rplr->reordering_of_pic_nums_idc_1);

				if(0 == rplr->reordering_of_pic_nums_idc_1 || 1 == rplr->reordering_of_pic_nums_idc_1)
				{
					ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &rplr->abs_diff_pic_num_minus1_1);
					len += ret;
					an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      abs_diff_pic_num_minus1_1 = %d\n", rplr->abs_diff_pic_num_minus1_1);
				}
				else if(2 == rplr->reordering_of_pic_nums_idc_1)
				{
					ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &rplr->long_term_pic_num_1);
					len += ret;
					an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      long_term_pic_num_1 = %d\n", rplr->long_term_pic_num_1);
				}
			}while(3 != rplr->reordering_of_pic_nums_idc_1);
		}
	}

	if((pps->weighted_pred_flag 
		&& (0 == slice_header->slice_type || 3 == slice_header->slice_type  || 5 == slice_header->slice_type || 8 == slice_header->slice_type))
		|| (1 == pps->weighted_bipred_idc && (1 == slice_header->slice_type || 6 == slice_header->slice_type))
		)
	{
		Pred_Weight_Table *pwt = NULL;
		slice_header->pred_weight_table = malloc(sizeof(Pred_Weight_Table));
		memset(slice_header->pred_weight_table, 0, sizeof(Pred_Weight_Table));
		pwt = slice_header->pred_weight_table;

		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &pwt->luma_log2_weight_denom);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      luma_log2_weight_denom = %d\n", pwt->luma_log2_weight_denom);

		if(0 != sps->chroma_format_idc)
		{
			ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &pwt->chroma_log2_weight_denom);
			len += ret;
			an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      chroma_log2_weight_denom = %d\n", pwt->chroma_log2_weight_denom);
		}

		pwt->luma_weight_l0_flag = malloc(slice_header->num_ref_idx_l0_active_minus1 * sizeof(int));
		memset(pwt->luma_weight_l0_flag, 0, slice_header->num_ref_idx_l0_active_minus1 * sizeof(int));
		pwt->luma_weight_l0 = malloc(slice_header->num_ref_idx_l0_active_minus1 * sizeof(int));
		memset(pwt->luma_weight_l0, 0, slice_header->num_ref_idx_l0_active_minus1 * sizeof(int));
		pwt->luma_offset_l0 = malloc(slice_header->num_ref_idx_l0_active_minus1 * sizeof(int));
		memset(pwt->luma_offset_l0, 0, slice_header->num_ref_idx_l0_active_minus1 * sizeof(int));

		pwt->chroma_weight_l0_flag = malloc(slice_header->num_ref_idx_l0_active_minus1 * sizeof(int));
		memset(pwt->chroma_weight_l0_flag, 0, slice_header->num_ref_idx_l0_active_minus1 * sizeof(int));				
		pwt->chroma_weight_l0 = malloc(slice_header->num_ref_idx_l0_active_minus1 * sizeof(int) * 2);
		memset(pwt->chroma_weight_l0, 0, slice_header->num_ref_idx_l0_active_minus1 * sizeof(int) * 2);				
		pwt->chroma_offset_l0 = malloc(slice_header->num_ref_idx_l1_active_minus1 * sizeof(int) * 2);
		memset(pwt->chroma_offset_l0, 0, slice_header->num_ref_idx_l1_active_minus1 * sizeof(int) * 2);				

		for( i = 0; i <= slice_header->num_ref_idx_l0_active_minus1; i++ ) 
		{
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &pwt->luma_weight_l0_flag[i]);
			len += ret;
			an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  luma_weight_l0_flag[%d] = %u\n", i, pwt->luma_weight_l0_flag[i]);

			if(pwt->luma_weight_l0_flag[i])
			{
				ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &pwt->luma_weight_l0[i]);
				len += ret;
				an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      pwt->luma_weight_l0[%d] = %d\n", i, pwt->luma_weight_l0[i]);
				ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &pwt->luma_offset_l0[i]);
				len += ret;
				an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      pwt->luma_offset_l0[%d] = %d\n", i, pwt->luma_offset_l0[i]);
			}
			
			if (0 != sps->chroma_format_idc) 
			{
				ret = get_bits_u(pData + len, length - len, &start_bits, 1, &pwt->chroma_weight_l0_flag[i]);
				len += ret;
				an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  chroma_weight_l0_flag[%d] = %u\n", i,  pwt->chroma_weight_l0_flag[i]);

				if(pwt->chroma_weight_l0_flag[i])
				{
					for( j = 0; j < 2; j++ ) 
					{
						an_log(H264MODULE_SLICE_HEADER, AN_LOG_TRACE, "		i = %d, j = %d.\n", i, j);
						ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &pwt->chroma_weight_l0[ i ][ j ]);
						len += ret;
						an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      pwt->chroma_weight_l0[ %d ][ %d ] = %d\n", i, j, pwt->chroma_weight_l0[ i ][ j ]);
						ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &pwt->chroma_offset_l0[ i ][ j ]);
						len += ret;
						an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      pwt->chroma_offset_l0[ %d ][ %d ] = %d\n", i, j, pwt->chroma_offset_l0[ i ][ j ]);
					}
				}
			}
		}

		 //slice_type = = B
		if(1 == slice_header->slice_type || 6 == slice_header->slice_type)
		{
			an_log(H264MODULE_SLICE_HEADER, AN_LOG_TRACE, "	  num_ref_idx_l1_active_minus1 = %d\n", slice_header->num_ref_idx_l1_active_minus1);
			pwt->luma_weight_l1_flag = malloc(slice_header->num_ref_idx_l1_active_minus1 * sizeof(int));
			memset(pwt->luma_weight_l1_flag, 0, slice_header->num_ref_idx_l1_active_minus1 * sizeof(int));
			pwt->luma_weight_l1 = malloc(slice_header->num_ref_idx_l1_active_minus1 * sizeof(int));
			memset(pwt->luma_weight_l1, 0, slice_header->num_ref_idx_l1_active_minus1 * sizeof(int));
			pwt->luma_offset_l1 = malloc(slice_header->num_ref_idx_l1_active_minus1 * sizeof(int));
			memset(pwt->luma_offset_l1, 0, slice_header->num_ref_idx_l1_active_minus1 * sizeof(int));

			pwt->chroma_weight_l1_flag = malloc(slice_header->num_ref_idx_l1_active_minus1 * sizeof(int));
			memset(pwt->chroma_weight_l1_flag, 0, slice_header->num_ref_idx_l1_active_minus1 * sizeof(int));				
			pwt->chroma_weight_l1 = malloc(slice_header->num_ref_idx_l1_active_minus1 * sizeof(int) * 2);
			memset(pwt->chroma_weight_l1, 0, slice_header->num_ref_idx_l1_active_minus1 * sizeof(int) * 2);				
			pwt->chroma_offset_l1 = malloc(slice_header->num_ref_idx_l1_active_minus1 * sizeof(int) * 2);
			memset(pwt->chroma_offset_l1, 0, slice_header->num_ref_idx_l1_active_minus1 * sizeof(int) * 2);				

			for( i = 0; i <= slice_header->num_ref_idx_l1_active_minus1; i++ ) 
			{
				ret = get_bits_u(pData + len, length - len, &start_bits, 1, &pwt->luma_weight_l1_flag[i]);
				len += ret;
				an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  luma_weight_l1_flag[%d] = %u\n", i, pwt->luma_weight_l1_flag[i]);

				if(pwt->luma_weight_l1_flag[i])
				{
					ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &pwt->luma_weight_l1[i]);
					len += ret;
					an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      pwt->luma_weight_l1[%d] = %d\n", i, pwt->luma_weight_l1[i]);
					ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &pwt->luma_offset_l1[i]);
					len += ret;
					an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      pwt->luma_offset_l1[%d] = %d\n", i, pwt->luma_offset_l1[i]);
				}
				
				if (0 != sps->chroma_format_idc) 
				{
					ret = get_bits_u(pData + len, length - len, &start_bits, 1, &pwt->chroma_weight_l1_flag[i]);
					len += ret;
					an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  chroma_weight_l1_flag[%d] = %u\n", i,  pwt->chroma_weight_l1_flag[i]);

					if(pwt->chroma_weight_l1_flag[i])
					{
						for( j =0; j < 2; j++ ) 
						{
							ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &pwt->chroma_weight_l1[ i ][ j ]);
							len += ret;
							an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      pwt->chroma_weight_l1[ %d ][ %d ] = %d\n", i, j, pwt->chroma_weight_l1[ i ][ j ]);
							ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &pwt->chroma_offset_l1[ i ][ j ]);
							len += ret;
							an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      pwt->chroma_offset_l1[ %d ][ %d ] = %d\n", i, j, pwt->chroma_offset_l1[ i ][ j ]);
						}
					}
				}
			}
		}

			
	}

	if(0 != nal_unit->nal_ref_idc)
	{
		//dec_ref_pic_marking( )
		//an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "   WARNING! Need to analyze dec_ref_pic_marking\n");
		Dec_Ref_Pic_Marking *dec_ref_pic_marking = NULL;
		slice_header->dec_ref_pic_marking = malloc(sizeof(Dec_Ref_Pic_Marking));
		dec_ref_pic_marking = slice_header->dec_ref_pic_marking;
		memset(dec_ref_pic_marking, 0, sizeof(Dec_Ref_Pic_Marking));
		if( 5 == nal_unit->nal_unit_type )
		{	
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &dec_ref_pic_marking->no_output_of_prior_pics_flag);
			len += ret;
			an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  no_output_of_prior_pics_flag = %u\n",  dec_ref_pic_marking->no_output_of_prior_pics_flag);
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &dec_ref_pic_marking->long_term_reference_flag);
			len += ret;
			an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  long_term_reference_flag = %u\n",  dec_ref_pic_marking->long_term_reference_flag);	
		}
		else
		{
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &dec_ref_pic_marking->adaptive_ref_pic_marking_mode_flag);
			len += ret;
			an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  adaptive_ref_pic_marking_mode_flag = %u\n",  dec_ref_pic_marking->adaptive_ref_pic_marking_mode_flag);
			if(dec_ref_pic_marking->adaptive_ref_pic_marking_mode_flag)
			{
				i = 0;
				do
				{
					ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &dec_ref_pic_marking->memory_management_control_operation[i]);
					len += ret;
					an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "		memory_management_control_operation[%d] = %d\n", i, dec_ref_pic_marking->memory_management_control_operation[i]);
					if(0 == dec_ref_pic_marking->memory_management_control_operation[i])
					{
						break;
					}
					if(1 == dec_ref_pic_marking->memory_management_control_operation[i] || 3 == dec_ref_pic_marking->memory_management_control_operation[i])
					{
						ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &dec_ref_pic_marking->difference_of_pic_nums_minus1[i]);
						len += ret;
						an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "		difference_of_pic_nums_minus1[%d] = %d\n", i, dec_ref_pic_marking->difference_of_pic_nums_minus1[i]);
					}
					if(2 == dec_ref_pic_marking->memory_management_control_operation[i])
					{
						ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &dec_ref_pic_marking->long_term_pic_num[i]);
						len += ret;
						an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "		long_term_pic_num[%d] = %d\n", i, dec_ref_pic_marking->long_term_pic_num[i]);
					}
					if(3 == dec_ref_pic_marking->memory_management_control_operation[i] || 6 == dec_ref_pic_marking->memory_management_control_operation[i])
					{
						ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &dec_ref_pic_marking->long_term_frame_idx[i]);
						len += ret;
						an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "		long_term_frame_idx[%d] = %d\n", i, dec_ref_pic_marking->long_term_frame_idx[i]);
					}
					if(4 == dec_ref_pic_marking->memory_management_control_operation[i])
					{
						ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &dec_ref_pic_marking->max_long_term_frame_idx_plus1[i]);
						len += ret;
						an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "		max_long_term_frame_idx_plus1[%d] = %d\n", i, dec_ref_pic_marking->max_long_term_frame_idx_plus1[i]);
					}
					i++;
				}while(i < MAXMMCOLEN);
			}
		}
	}

	//if( entropy_coding_mode_flag && slice_type != I && slice_type != SI )
	if(pps->entropy_coding_mode_flag && 2 != slice_header->slice_type && 7 != slice_header->slice_type && 4 != slice_header->slice_type && 9 != slice_header->slice_type)
	{	
		
		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &slice_header->cabac_init_idc);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      cabac_init_idc = %d\n", slice_header->cabac_init_idc);		
	}
	ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &slice_header->slice_qp_delta);
	len += ret;
	an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      slice_qp_delta = %d\n", slice_header->slice_qp_delta);

	//if( slice_type = = SP | | slice_type = = SI )
	if(3 == slice_header->slice_type || 4 == slice_header->slice_type || 8 == slice_header->slice_type || 9 == slice_header->slice_type )
	{
		//if( slice_type = = SP )
		if(3 == slice_header->slice_type || 8 == slice_header->slice_type)
		{
			ret = get_bits_u(pData + len, length - len, &start_bits, 1, &slice_header->sp_for_switch_flag);
			len += ret;
			an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  sp_for_switch_flag = %u\n", i,  slice_header->sp_for_switch_flag);

		}
		ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &slice_header->slice_qs_delta_sp_si);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      slice_qs_delta_sp_si = %d\n", slice_header->slice_qs_delta_sp_si);
			
	}

	if(pps->deblocking_filter_control_present_flag)
	{
		ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &slice_header->disable_deblocking_filter_idc);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      disable_deblocking_filter_idc = %d\n", slice_header->disable_deblocking_filter_idc);	
		if(1 != slice_header->disable_deblocking_filter_idc)
		{
			ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &slice_header->slice_alpha_c0_offset_div2);
			len += ret;
			an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      slice_alpha_c0_offset_div2 = %d\n", slice_header->slice_alpha_c0_offset_div2);
			ret = get_exp_golomb_se(pData + len, length - len, &start_bits, &slice_header->slice_beta_offset_div2);
			len += ret;
			an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "      slice_beta_offset_div2 = %d\n", slice_header->slice_beta_offset_div2);
		}
	}
	if( pps->num_slice_groups_minus1 > 0 && pps->slice_group_map_type >= 3 && pps->slice_group_map_type <= 5)
	{
		int PicSizeInMapUnits = (sps->pic_width_in_mbs_minus1+1) * (sps->pic_height_in_map_units_minus1+1);
		int SliceGroupChangeRate = pps->slice_group_change_rate_minus1 + 1;
		ret = get_bits_u(pData + len, length - len, &start_bits, ceil( log( PicSizeInMapUnits / SliceGroupChangeRate + 1 ) / log(2) ), &slice_header->slice_group_change_cycle);
		len += ret;
		an_log(H264MODULE_SLICE_HEADER, AN_LOG_INFO, "	  slice_group_change_cycle = %u\n", i,  slice_header->slice_group_change_cycle);
	}

	*start_offset_bits = start_bits;
	return len;
}

/*
*   
*   pData: buffer起始地址
*   length: buffer长度 
*   start_offset_bits: 第一个字节的有效bit标志。对应的bit为1表示有效。
*
*/
int parse_slice_data(const Nal_Unit *nal_unit, const Seq_Parameter_Set *sps, const Pic_Parameter_Set *pps, const Slice_Header *slice_header, unsigned char *pData, int length, unsigned char *start_offset_bits,  Slice_Data *slice_data)
{
	int i = 0, j = 0, k = 0, n = 0, len = 0, ret = 0, moreDataFlag = 1, prevMbSkipped = 0, iGroup = 0, nextMbAddress = 0;
	unsigned char start_bits = 0xff;

	an_log(H264MODULE_SLICE_DATA, AN_LOG_INFO, "	parse_slice_data:\n");
	an_log(H264MODULE_SLICE_DATA, AN_LOG_TRACE, "	%x %x %x %x, start_offset_bits = %x\n", pData[0], pData[1], pData[2], pData[3], *start_offset_bits);
	an_log(H264MODULE_SLICE_DATA, AN_LOG_DEBUG, "	entropy_coding_mode_flag = %d\n", pps->entropy_coding_mode_flag);
	if(pps->entropy_coding_mode_flag)
	{
		len = (0xff == *start_offset_bits)?0:1;
		//start_bits = (0 == len)?(*start_offset_bits):0xff;
	}
		an_log(H264MODULE_SLICE_DATA, AN_LOG_INFO, "	len = %d\n", len);
	ret = get_bits_u(pData + len, length - len, &start_bits, 1, &slice_data->cabac_alignment_one_bit);
	len += ret;
	an_log(H264MODULE_SLICE_DATA, AN_LOG_INFO, "	cabac_alignment_one_bit = %d\n", slice_data->cabac_alignment_one_bit);

	slice_data->MbaffFrameFlag = sps->mb_adaptive_frame_field_flag && (!slice_header->field_pic_flag);
	an_log(H264MODULE_SLICE_DATA, AN_LOG_DEBUG, "	MbaffFrameFlag = %d\n", slice_data->MbaffFrameFlag);
	slice_data->CurrMbAddr = slice_header->first_mb_in_slice * (1 + slice_data->MbaffFrameFlag);
	an_log(H264MODULE_SLICE_DATA, AN_LOG_DEBUG, "	CurrMbAddr = %d\n", slice_data->CurrMbAddr);
#if 1
	//do
	//{
		if(2 != slice_header->slice_type && 7 != slice_header->slice_type && 4 != slice_header->slice_type && 9 != slice_header->slice_type)
			if(!pps->entropy_coding_mode_flag)
			{
				ret = get_exp_golomb_ue(pData + len, length - len, &start_bits, &slice_data->mb_skip_run);
				len += ret;
				an_log(H264MODULE_SLICE_DATA, AN_LOG_INFO, "		mb_skip_run = %d\n", slice_data->mb_skip_run);	
				prevMbSkipped = ( slice_data->mb_skip_run > 0 );
				for( i = 0; i < slice_data->mb_skip_run; i++ ) 
				{
					//CurrMbAddr = NextMbAddress( CurrMbAddr ) 
					int PicSizeInMapUnits = (sps->pic_width_in_mbs_minus1+1) * (sps->pic_height_in_map_units_minus1+1);
					int *mapUnitToSliceGroupMap = NULL;
					int *MbToSliceGroupMap = NULL;
					mapUnitToSliceGroupMap = (int *)malloc(PicSizeInMapUnits*sizeof(int));
					memset(mapUnitToSliceGroupMap, 0, PicSizeInMapUnits*sizeof(int));
					MbToSliceGroupMap = (int *)malloc(PicSizeInMapUnits*sizeof(int));
					memset(MbToSliceGroupMap, 0, PicSizeInMapUnits*sizeof(int));
					
					/*隔行扫描型条带组映射类型*/
					if(0 == pps->slice_group_map_type)
					{
						i = 0;
				      	do 
				            for( iGroup = 0; iGroup <= pps->num_slice_groups_minus1 && i < PicSizeInMapUnits; i += pps->run_length_minus1[ iGroup++ ] + 1 ) 
				                  for( j = 0; j <= pps->run_length_minus1[ iGroup ] && i + j < PicSizeInMapUnits; j++ ) 
				                        mapUnitToSliceGroupMap[ i + j ] = iGroup;
				      	while( i < PicSizeInMapUnits );
					}
					/*分散型条带组映射类型*/
					else if(1 == pps->slice_group_map_type)
					{
						for( i = 0; i < PicSizeInMapUnits; i++ ) 
							mapUnitToSliceGroupMap[i] = (( i % (sps->pic_width_in_mbs_minus1+1) ) + ((( i / (sps->pic_width_in_mbs_minus1+1) ) * ( pps->num_slice_groups_minus1 + 1 )) / 2 )) % ( pps->num_slice_groups_minus1 + 1 );
					}
					/*具有残余条带组映射类型*/
					else if(2 == pps->slice_group_map_type)
					{
						int *top_left, *bottom_right;
						int yTopLeft, xTopLeft, yBottomRight, xBottomRight, x, y;
						if(pps->num_slice_groups_minus1 > 0)
						{
							top_left = (int *)malloc(pps->num_slice_groups_minus1 * sizeof(int));
							bottom_right = (int *)malloc(pps->num_slice_groups_minus1 * sizeof(int));
						}
						else
						{
							top_left = NULL;
							bottom_right = NULL;
						}
						for( i = 0; i < PicSizeInMapUnits; i++ ) 
									mapUnitToSliceGroupMap[ i ] = pps->num_slice_groups_minus1;
						for( iGroup = pps->num_slice_groups_minus1 - 1; iGroup >= 0; iGroup--) { 
							yTopLeft = top_left[ iGroup ] / (sps->pic_width_in_mbs_minus1+1);
							xTopLeft = top_left[ iGroup ] % (sps->pic_width_in_mbs_minus1+1);
							yBottomRight = bottom_right[ iGroup ] / (sps->pic_width_in_mbs_minus1+1);
							xBottomRight = bottom_right[ iGroup ] % (sps->pic_width_in_mbs_minus1+1);
							for( y = yTopLeft; y <= yBottomRight; y++ ) 
								  for( x = xTopLeft; x <= xBottomRight; x++ ) 
										mapUnitToSliceGroupMap[ y * (sps->pic_width_in_mbs_minus1+1) + x ] = iGroup;
							}
					}
					/*box-out条带组类型*/
					else if(3 == pps->slice_group_map_type)
					{
						int x, y, leftBound, topBound, rightBound, bottomBound, xDir, yDir, mapUnitVacant;
						int MapUnitsInSliceGroup0 =  Min( slice_header->slice_group_change_cycle * (pps->slice_group_change_rate_minus1 + 1), PicSizeInMapUnits ) ;
						for( i = 0; i < PicSizeInMapUnits; i++ ) 
									mapUnitToSliceGroupMap[ i ] = 1;
						x = ( (sps->pic_width_in_mbs_minus1+1) - pps->slice_group_change_direction_flag ) / 2;
						y = ( (sps->pic_height_in_map_units_minus1+1) - pps->slice_group_change_direction_flag ) / 2;
						leftBound = x;
						topBound = y;
						rightBound = x;
						bottomBound = y;
						xDir = pps->slice_group_change_direction_flag - 1;
						yDir = pps->slice_group_change_direction_flag;
						for( k = 0; k < MapUnitsInSliceGroup0; k += mapUnitVacant ) 
						{ 
							mapUnitVacant = ( mapUnitToSliceGroupMap[ y * (sps->pic_width_in_mbs_minus1+1) + x ]  == 1 );
							if( mapUnitVacant ) 
								  mapUnitToSliceGroupMap[ y * (sps->pic_width_in_mbs_minus1+1) + x ] = 0;
							if( xDir == -1  &&  x == leftBound ) { 
								  leftBound = Max( leftBound - 1, 0 );
								  x = leftBound;
								  //( xDir, yDir ) = ( 0, 2 * slice_group_change_direction_flag - 1 );
								  xDir = 0;
								  yDir = 2 * pps->slice_group_change_direction_flag - 1;
							} else if( xDir == 1 && x == rightBound ) { 
								  rightBound = Min( rightBound + 1, (sps->pic_width_in_mbs_minus1+1) - 1 );
								  x = rightBound;
								  //( xDir, yDir ) = ( 0, 1 - 2 * slice_group_change_direction_flag );
								  xDir = 0;
								  yDir = 1 - 2 * pps->slice_group_change_direction_flag;
							} else if( yDir  ==  -1  &&  y  ==  topBound ) { 
								  topBound = Max( topBound - 1, 0 );
								  y = topBound;
								  // ( xDir, yDir ) = ( 1 - 2 * slice_group_change_direction_flag, 0 );
								  xDir = 1  - 2 * pps->slice_group_change_direction_flag;
								  yDir = 0;
							} else if( yDir  ==  1  &&  y	==  bottomBound ) { 
								  bottomBound  =  Min( bottomBound + 1, (sps->pic_height_in_map_units_minus1+1) - 1 );
								  y = bottomBound;
								  // ( xDir, yDir ) = ( 2 * slice_group_change_direction_flag - 1, 0 );
								  xDir = 2 * pps->slice_group_change_direction_flag - 1;
								  yDir = 0;
							} else {
								  // ( x, y ) = ( x + xDir, y + yDir );
								  x = x + xDir;
								  y = y + yDir;
							}
						}
					}
					/*光栅扫描条带组类型*/
					else if(4 == pps->slice_group_map_type)
					{
						int MapUnitsInSliceGroup0 =  Min( slice_header->slice_group_change_cycle * (pps->slice_group_change_rate_minus1 + 1), PicSizeInMapUnits ) ;
						int sizeOfUpperLeftGroup = ( pps->slice_group_change_direction_flag ? ( PicSizeInMapUnits - MapUnitsInSliceGroup0 ) : MapUnitsInSliceGroup0 );
						for( i = 0; i < PicSizeInMapUnits; i++ ) 
							if( i < sizeOfUpperLeftGroup ) 
								  mapUnitToSliceGroupMap[ i ] = pps->slice_group_change_direction_flag;
							else
								  mapUnitToSliceGroupMap[ i ] = 1 - pps->slice_group_change_direction_flag;
					}
					/*消除条带组类型*/
					else if(5 == pps->slice_group_map_type)
					{
						k = 0; 
						int MapUnitsInSliceGroup0 =  Min( slice_header->slice_group_change_cycle * (pps->slice_group_change_rate_minus1 + 1), PicSizeInMapUnits ) ;
						int sizeOfUpperLeftGroup = ( pps->slice_group_change_direction_flag ? ( PicSizeInMapUnits - MapUnitsInSliceGroup0 ) : MapUnitsInSliceGroup0 );
						for( j = 0; j < (sps->pic_width_in_mbs_minus1+1); j++ ) 
							for( i = 0; i < (sps->pic_height_in_map_units_minus1+1); i++ ) 
								  if( k++ < sizeOfUpperLeftGroup ) 
										mapUnitToSliceGroupMap[ i * (sps->pic_width_in_mbs_minus1+1) + j ] = pps->slice_group_change_direction_flag;
								  else
										mapUnitToSliceGroupMap[ i * (sps->pic_width_in_mbs_minus1+1) + j ] = 1 - pps->slice_group_change_direction_flag;
					}
					/*显式条带组类型*/
					else if(6 == pps->slice_group_map_type)
					{
						for(i = 0; i <= PicSizeInMapUnits - 1; i++)
							mapUnitToSliceGroupMap[ i ] = pps->slice_group_id[ i ];
					}
					else
					{
						an_log(H264MODULE_SLICE_DATA, AN_LOG_INFO, "		slice_group_map_type = %d, ERROR\n", pps->slice_group_map_type);	
					}

					for(i = 0; i <= PicSizeInMapUnits - 1; i++)
						if(1 == sps->frame_mbs_only_flag || 1 == slice_header->field_pic_flag)
							MbToSliceGroupMap[ i ] = mapUnitToSliceGroupMap[ i ];
						else if(1 == slice_data->MbaffFrameFlag)
							MbToSliceGroupMap[ i ] = mapUnitToSliceGroupMap[ i / 2 ];
						else
							MbToSliceGroupMap[ i ] = mapUnitToSliceGroupMap[ ( i / ( 2 * (sps->pic_width_in_mbs_minus1+1) ) ) * (sps->pic_width_in_mbs_minus1+1) + ( i % (sps->pic_width_in_mbs_minus1+1) ) ];

					n = slice_data->CurrMbAddr;
					i = n + 1;
					while( i < PicSizeInMapUnits   &&  MbToSliceGroupMap[ i ]  !=  MbToSliceGroupMap[ n ] ) 
					    i++; 
					nextMbAddress = i;
					slice_data->CurrMbAddr = nextMbAddress;
				}
				moreDataFlag = more_rbsp_data(pData, length, len, &start_bits);
			}
			else
			{
				
			}
	//}while(moreDataFlag);
#endif
	return 0;
}



/*
*   从buffer中读取一个无符号的哥伦布指数。
*   返回值是用掉的字节数。即pData新起始地址减旧地址之差。
*   起始地址的字节可以有效比特数不足8。
*   得到的编码数被认为是一个无符号的数。
*   
*   pData: buffer起始地址
*   length: buffer长度 
*   start_bits: 第一个字节的有效bit标志。对应的bit为1表示有效。
*   code_number: 要获取的编码数。
*   
*/
int get_exp_golomb_ue(unsigned char *pData, int length, unsigned char *start_bits, unsigned int *code_number)
{

	int leading_zero_num = 0, valid_bits_num = 0, valid_bits_num_in_1st_byte = 0, i = 0, j = 0, code_num = 0;
	unsigned char first_byte = 0, cur_byte = 0, start_bits_cp = 0;
	an_log(H264MODULE_UNKOWN, AN_LOG_TRACE, "[%s, %d] *start_bits = %x, %x %x %x %x.\n", __FUNCTION__, __LINE__, *start_bits, pData[0], pData[1], pData[2], pData[3]);

	start_bits_cp = *start_bits;
	while(1)
	{
		if(0 == start_bits_cp)
		{
			break;
		}
		else
		{
			start_bits_cp = start_bits_cp >> 1;
			valid_bits_num_in_1st_byte++;
		}
	}
	start_bits_cp = *start_bits;
	//an_log(H264MODULE_UNKOWN, AN_LOG_INFO, "   start_bits_cp = %d\n", start_bits_cp);

	/*统计前缀0的个数。*/
	first_byte = pData[0]&start_bits_cp;

	for(j = 0; j < length; j++)
	{
		if(0 == j)
		{
			cur_byte = first_byte;
			valid_bits_num = valid_bits_num_in_1st_byte;
		}
		else
		{
			cur_byte = pData[j];
			valid_bits_num = 8;
		}
		for(i = valid_bits_num - 1; i >= 0; i--)
		{
			if(0 == cur_byte>>i&0x1)
				leading_zero_num++;
			else
				break;
		}
		if(i >= 0)
			break; /*遇到了bit 1 才退出*/
	}
	an_log(H264MODULE_UNKOWN, AN_LOG_TRACE, "[%s, %d] leading_zero_num = %d.\n", __FUNCTION__, __LINE__, leading_zero_num);

	if(j >= length)
	{
		an_log(H264MODULE_UNKOWN, AN_LOG_ERROR, "[%s, %d] j >= length\n", __FUNCTION__, __LINE__);
		return -1;
	}
	//an_log(H264MODULE_UNKOWN, AN_LOG_INFO, "   leading_zero_num = %d\n", leading_zero_num);

	valid_bits_num = i;
	code_num = 1;
	cur_byte = pData[j]<<(8 - valid_bits_num)>>(8 - valid_bits_num);
	for(; j < length; j++)
	{
		for(i = valid_bits_num - 1; i >= 0; i--)
		{
			if(leading_zero_num > 0)
			{
				code_num = code_num << 1;
				code_num += cur_byte>>i&0x1;
				leading_zero_num--;
			}
			else
				break;
		}
		valid_bits_num = 8;
		cur_byte = pData[j+1];
		if(leading_zero_num <= 0)
			break;
	}
	code_num--;

	if(j >= length)
		return -2;

	*start_bits = 0xff>>(7 - i);
	*code_number = code_num;
	if(0x0 == *start_bits)
	{
		*start_bits = 0xff;
		j += 1;
	}	
	an_log(H264MODULE_UNKOWN, AN_LOG_TRACE, "[%s, %d] start_bits = %x, return %d.\n", __FUNCTION__, __LINE__, *start_bits, j);
	return j;
}



int get_exp_golomb_se(unsigned char *pData, int length, unsigned char *start_bits, int *code_number)
{
	int ret = 0;
	unsigned int code_number_l = 0;
	
	ret = get_exp_golomb_ue(pData, length, start_bits, &code_number_l);
	if(ret < 0)
		return ret;
	an_log(H264MODULE_UNKOWN, AN_LOG_TRACE, "[%s, %d] code_number_l = %u\n", __FUNCTION__, __LINE__, code_number_l);
	if(0 == code_number_l%2)
	{
		*code_number = 0 - (int)code_number_l/2;
	}
	else
	{
		*code_number = (int)(code_number_l + 1)/2;
	}
	an_log(H264MODULE_UNKOWN, AN_LOG_TRACE, "[%s, %d] code_number = %d\n", __FUNCTION__, __LINE__, *code_number);
	return ret;
	
}


int get_bits_u(unsigned char *pData, int length, unsigned char *start_bits, int need_bits_number, unsigned int *code_number)
{
	int valid_bits_num = 0, valid_bits_num_in_1st_byte = 0, i = 0, j = 0;
	unsigned int code_num = 0;
	unsigned char first_byte = 0, cur_byte = 0, start_bits_cp = 0;
	
	//an_log(H264MODULE_UNKOWN, AN_LOG_TRACE, "[%s, %d] start_bits = %x. pData: %x %x %x %x.\n", __FUNCTION__, __LINE__, *start_bits, pData[0], pData[1], pData[2], pData[3]);
	start_bits_cp = *start_bits;
	while(1)
	{
		if(0 == start_bits_cp)
		{
			break;
		}
		else
		{
			start_bits_cp = start_bits_cp >> 1;
			valid_bits_num_in_1st_byte++;
		}
	}
	start_bits_cp = *start_bits;
	//an_log(H264MODULE_UNKOWN, AN_LOG_TRACE, "[%s, %d] valid_bits_num_in_1st_byte = %d.\n", __FUNCTION__, __LINE__, valid_bits_num_in_1st_byte);
	//*code_number = pData[0] >> (valid_bits_num_in_1st_byte - 1)&0x1;
	//*start_bits = (*start_bits) >> 1;

#if 1
	valid_bits_num = valid_bits_num_in_1st_byte;
	code_num = 0;
	
	for(; j < length; j++)
	{
		if(0 == j)
		{
			cur_byte = pData[j]<<(8 - valid_bits_num)>>(8 - valid_bits_num);
		}
		else
		{
			cur_byte = pData[j];
		}
		for(i = valid_bits_num - 1; i >= 0; i--)
		{
			if(need_bits_number > 0)
			{
				//an_log(H264MODULE_UNKOWN, AN_LOG_TRACE, "[%s, %d] code_num = %u, i = %d.\n", __FUNCTION__, __LINE__, code_num, i);
				code_num = code_num << 1;
				code_num += cur_byte>>i&0x1;
				need_bits_number--;
			}
			else
				break;
		}
		valid_bits_num = 8;
		
		if(need_bits_number <= 0)
			break;
	}

	if(j >= length)
	{
		//an_log(H264MODULE_UNKOWN, AN_LOG_ERROR, "[%s, %d] j >= length\n", __FUNCTION__, __LINE__);
		return -1;
	}
		
	
	//*start_bits = (0xff<<(8 - i))>>(8 - i);
	*start_bits = 0xff>>(7 - i);
	*code_number = code_num;
	//an_log(H264MODULE_UNKOWN, AN_LOG_TRACE, "[%s, %d] *code_number = %u.\n", __FUNCTION__, __LINE__, *code_number);
#endif
	if(0x0 == *start_bits)
	{
		*start_bits = 0xff;
		j += 1;
	}
	//an_log(H264MODULE_UNKOWN, AN_LOG_TRACE, "[%s, %d] start_bits = %x, return %d.\n", __FUNCTION__, __LINE__, *start_bits, j);
	return j;
}


/*
*   判断一个RBSP中是否还有更多数据。
*   即，是否接下来的数据只剩下rbsp_trailing_bits了。
*   pData: RBSP buffer起始地址
*   length: RBSP buffer长度 
*   len: 当前位置
*   start_bits: 当前字节(pData[len])中的有效bit标志。对应的bit为1表示有效。
*   
*   返回值: <0 - 数据编码出错; =0 - 没有更多数据; >0 - 还剩下的bit数.
*/
int more_rbsp_data(unsigned char *pData, int length, int len, unsigned char *start_bits)
{
	unsigned char left_bits = 0, start_bits_cp = 0, c = 0;
	int valid_bits_num_in_cur_byte = 0, i = 0;

	//an_log(H264MODULE_UNKOWN, AN_LOG_INFO, "more_rbsp_data: length = %d, len = %d, start_bits = 0x%x\n", length, len, *start_bits);
	start_bits_cp = *start_bits;
	while(1)
	{
		if(0 == start_bits_cp)
		{
			break;
		}
		else
		{
			start_bits_cp = start_bits_cp >> 1;
			valid_bits_num_in_cur_byte++;
		}
	}
	start_bits_cp = *start_bits;
	//an_log(H264MODULE_UNKOWN, AN_LOG_INFO, "more_rbsp_data: valid_bits_num_in_cur_byte = %d\n", valid_bits_num_in_cur_byte);
	
	if(len == length - 1)
	{
		left_bits = pData[len]&*start_bits;
		if(0x0 == left_bits)
			return -1;
		//an_log(H264MODULE_UNKOWN, AN_LOG_INFO, "more_rbsp_data: pData[%d] = %x\n", len, pData[len]);
		for(i = 0; i < 8; i++)
		{
			if(0x0 != (pData[len] >> i & 0x1))
				break;
		}
		if(8 == i)
			return -2;
		/*i+1就是trailing_bits的个数了*/
		//an_log(H264MODULE_UNKOWN, AN_LOG_INFO, "more_rbsp_data: i = %d\n", i);
		return valid_bits_num_in_cur_byte - (i + 1);
	}
	else if(len < length - 1)
	{
		for(i = 0; i < 8; i++)
		{
			if(0x1 == (pData[length - 1] >> i) & 0x1)
				break;
		}
		if(8 == i)
			return -3;
		//an_log(H264MODULE_UNKOWN, AN_LOG_INFO, "more_rbsp_data: i = %d\n", i);
		return valid_bits_num_in_cur_byte + 8*(length - 1 - len) + (8 - i - 1);
	}
	else
	{
		return -4;
	}
	return 0;
}
