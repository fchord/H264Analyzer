/*
* 关于变量的命名
* 1. 每一个单词以小写字母开头、用下划线分割，为语法变量
* 2. 每一个单词以大写字母开头、无下划线分割，为辅助变量，可以由语法变量推导得到。
* 3. 第一个单词以小写字母开头、其他单词以大写字母开头、无下划线分割，为临时变量，
*     可以由其他变量或函数计算得到，不定于在语法结构体中，通常定义为相关函数的局部变量。
*/

#ifndef H264ANALYZER_H
#define H264ANALYZER_H

#define Extended_SAR 255
#define MAXMMCOLEN 16

typedef struct Nal_Unit
{
	int nal_ref_idc;
	int nal_unit_type;
	int NumBytesInRBSP;
}Nal_Unit;

typedef struct Hrd_Parameters
{
	int cpb_cnt_minus1;
	int bit_rate_scale;
	int cpb_size_scale;
		int *bit_rate_value_minus1;
		int *cpb_size_value_minus1;
		int *cbr_flag;
	int initial_cpb_removal_delay_length_minus1;
	int cpb_removal_delay_length_minus1;
	int dpb_output_delay_length_minus1;
	int time_offset_length;
}Hrd_Parameters;

typedef struct Vui_Parameters
{
	int aspect_ratio_info_present_flag;
		int aspect_ratio_idc;
			int sar_width;
			int sar_height;
	int overscan_info_present_flag;
		int overscan_appropriate_flag;
	int video_signal_type_present_flag;
		int video_format;
		int video_full_range_flag;
		int colour_description_present_flag;
			int colour_primaries;
			int transfer_characteristics;
			int matrix_coefficients;
	int chroma_loc_info_present_flag;
		int chroma_sample_loc_type_top_field;
		int chroma_sample_loc_type_bottom_field;
	int timing_info_present_flag;
		int num_units_in_tick;
		int time_scale;
		int fixed_frame_rate_flag;
	int nal_hrd_parameters_present_flag;
		Hrd_Parameters *pnal_hrd_parameters;
	int vcl_hrd_parameters_present_flag;
		Hrd_Parameters *pvcl_hrd_parameters;
		int low_delay_hrd_flag;
	int pic_struct_present_flag;
	int bitstream_restriction_flag;
		int motion_vectors_over_pic_boundaries_flag;
		int max_bytes_per_pic_denom;
		int max_bits_per_mb_denom;
		int log2_max_mv_length_horizontal;
		int log2_max_mv_length_vertical;
		int num_reorder_frames;
		int max_dec_frame_buffering;
	
}Vui_Parameters;

typedef struct Seq_Parameter_Set
{
	int profile_idc;
	int level_idc;
	int constraint_set0_flag;
	int constraint_set1_flag;
	int constraint_set2_flag;
	int constraint_set3_flag;
	unsigned int reserved_zero_4bits;
	unsigned int seq_parameter_set_id;
	//if( profile_idc = = 100 | | profile_idc = = 110 | |profile_idc = = 122 | | profile_idc = = 144 ) {
		int chroma_format_idc; /*chroma_format_idc  的值应该在 0 到3 的范围内（包括0 和3）。当chroma_format_idc 不存在时，应推断其值为1（4：2：0 的色度格式）*/
		//if( chroma_format_idc = = 3 )	
			int residual_colour_transform_flag;
		int bit_depth_luma_minus8;
		int bit_depth_chroma_minus8;
		int qpprime_y_zero_transform_bypass_flag;
		int seq_scaling_matrix_present_flag;
		//if( seq_scaling_matrix_present_flag )
			//for( i = 0; i < 8; i++ ) {
				int seq_scaling_list_present_flag[8];
				//if( seq_scaling_list_present_flag[ i ] )
					//if( i < 6 )
						//scaling_list( ScalingList4x4[ i ], 16, UseDefaultScalingMatrix4x4Flag[ i ])
					//else
						//scaling_list( ScalingList8x8[ i – 6 ], 64, UseDefaultScalingMatrix8x8Flag[ i – 6 ] )
		//}
	//}
	int log2_max_frame_num_minus4;
	int pic_order_cnt_type;
	int log2_max_pic_order_cnt_lsb_minus4;
	int delta_pic_order_always_zero_flag;
	int offset_for_non_ref_pic;
	int offset_for_top_to_bottom_field;
	int num_ref_frames_in_pic_order_cnt_cycle;
	int *offset_for_ref_frame;
	int num_ref_frames;
	int gaps_in_frame_num_value_allowed_flag;
	int pic_width_in_mbs_minus1;
	int pic_height_in_map_units_minus1;
	int frame_mbs_only_flag;
	int mb_adaptive_frame_field_flag;
	int direct_8x8_inference_flag;
	int frame_cropping_flag;
	int frame_crop_left_offset, frame_crop_right_offset, frame_crop_top_offset, frame_crop_bottom_offset;
	int vui_parameters_present_flag;
	Vui_Parameters *pVui_Parameters;
}Seq_Parameter_Set;

typedef struct Seq_Parameter_Set_Ext
{
	int seq_parameter_set_id;
	int aux_format_idc;
		int bit_depth_aux_minus8;
		int alpha_incr_flag;
		int alpha_opaque_value;
		int alpha_transparent_value;
	int additional_extension_flag;
}Seq_Parameter_Set_Ext;

typedef struct Pic_Parameter_Set
{
	int pic_parameter_set_id;
	int seq_parameter_set_id;
	int entropy_coding_mode_flag;
	int pic_order_present_flag;
	int num_slice_groups_minus1;
		int slice_group_map_type;
			int *run_length_minus1;
			int *top_left;
			int *bottom_right;
		int slice_group_change_direction_flag;
		int slice_group_change_rate_minus1;
		int pic_size_in_map_units_minus1;
		int *slice_group_id;
	int num_ref_idx_l0_active_minus1;
	int num_ref_idx_l1_active_minus1;
	int weighted_pred_flag;
	int weighted_bipred_idc;
	int pic_init_qp_minus26;
	int pic_init_qs_minus26;
	int chroma_qp_index_offset;
	int deblocking_filter_control_present_flag;
	int constrained_intra_pred_flag;
	int redundant_pic_cnt_present_flag;
		int transform_8x8_mode_flag;
		int pic_scaling_matrix_present_flag;
		int *pic_scaling_list_present_flag;
		int second_chroma_qp_index_offset;
}Pic_Parameter_Set;

typedef struct Ref_Pic_List_Reordering
{
	//if( slice_type != I && slice_type != SI ) {
	int ref_pic_list_reordering_flag_l0;
	//if( ref_pic_list_reordering_flag_l0 )
	//do {
		int reordering_of_pic_nums_idc_0;
		//if( reordering_of_pic_nums_idc = = 0 | | reordering_of_pic_nums_idc = = 1 )
			int abs_diff_pic_num_minus1_0;
		//else if( reordering_of_pic_nums_idc = = 2 )
			int long_term_pic_num_0;
	//} while( reordering_of_pic_nums_idc != 3 )
	//}
	//if( slice_type = = B ) {
		int ref_pic_list_reordering_flag_l1;
		//if( ref_pic_list_reordering_flag_l1 )
		//do {
			int reordering_of_pic_nums_idc_1;
			//if( reordering_of_pic_nums_idc = = 0 | | reordering_of_pic_nums_idc = = 1 )
				int abs_diff_pic_num_minus1_1;
			//else if( reordering_of_pic_nums_idc = = 2 )
				int long_term_pic_num_1;
		//} while( reordering_of_pic_nums_idc != 3 )
	//}
	//}	
}Ref_Pic_List_Reordering;

typedef struct Pred_Weight_Table
{
	int luma_log2_weight_denom;
	//if( chroma_format_idc != 0 )
		int chroma_log2_weight_denom;
	//for( i = 0; i <= num_ref_idx_l0_active_minus1; i++ ) {
		int *luma_weight_l0_flag;
		//if( luma_weight_l0_flag ) {
		int *luma_weight_l0;
		int *luma_offset_l0;
		//}
		//if ( chroma_format_idc != 0 ) {
			int *chroma_weight_l0_flag;
			//if( chroma_weight_l0_flag )
				//for( j =0; j < 2; j++ ) {
				int (*chroma_weight_l0)[2];
				int (*chroma_offset_l0)[2];
			//}
		//}
	//}
	//if( slice_type = = B )
		//for( i = 0; i <= num_ref_idx_l1_active_minus1; i++ ) {
			int *luma_weight_l1_flag;
			//if( luma_weight_l1_flag ) {
				int *luma_weight_l1;
				int *luma_offset_l1;
			//}
			//if( chroma_format_idc != 0 ) {
				int *chroma_weight_l1_flag;
				//if( chroma_weight_l1_flag )
					//for( j = 0; j < 2; j++ ) {
						int (*chroma_weight_l1)[2];
						int (*chroma_offset_l1)[2];
					//}
				//}
			//}
		//}				
}Pred_Weight_Table;

typedef struct Dec_Ref_Pic_Marking
{
	//if( nal_unit_type = = 5 ) {
		/*仅在当前图像是 IDR 图像时出现这个句法元素，指明是否要将前面已解码的图像全部输出。??*/
		int no_output_of_prior_pics_flag; 
		/*与上个图像一样，仅在当前图像是 IDR 图像时出现这一句法元素。这个句法元素指明是否使用长期参考这个机制。如果取值为 1，表明使用长期参考，并且每个 IDR 图像被解码后自动成为长期参考帧，否则（取值为 0），IDR 图像被解码后自动成为短期参考帧。?*/
		int long_term_reference_flag;
	//} else {
		/*指明标记（marking）操作的模式
			0: 先入先出（FIFO）：使用滑动窗的机制，先入先出，在这种模式下没有办法对长期参考帧进行操作。
			1: 自适应标记（marking）：后续码流中会有一系列句法元素显式指明操作的步骤。自适应是指编码器可根据情况随机灵活地作出决策。??
		*/
		int adaptive_ref_pic_marking_mode_flag;
		//if( adaptive_ref_pic_marking_mode_flag )
			//do { 
				/*自适应标记（marking）模式中，指明本次操作的具体内容
					0:  结束循环，退出标记（marding）操作。
					1: 将一个短期参考图像标记为非参考图像，也即将一个短期参考图像移出参考帧队列。
					2: 将一个长期参考图像标记为非参考图像，也即将一个长期参考图像移出参考帧队列。
					3: 将一个短期参考图像转为长期参考图像。
					4: 指明长期参考帧的最大数目。
					5: 清空参考帧队列，将所有参考图像移出参考帧队列，并禁用长期参考机制。
					6: 将当前图像存为一个长期参考帧。
				*/
				int memory_management_control_operation[MAXMMCOLEN];
				//if( memory_management_control_operation  = =  1  | | memory_management_control_operation  = =  3 )
					int difference_of_pic_nums_minus1[MAXMMCOLEN];
				//if(memory_management_control_operation  = =  2  ) 
					int  long_term_pic_num[MAXMMCOLEN];
				// if( memory_management_control_operation  = =  3  | | memory_management_control_operation  = =  6 )
					int long_term_frame_idx[MAXMMCOLEN];
				// if( memory_management_control_operation  = =  4 ) 
					int  max_long_term_frame_idx_plus1[MAXMMCOLEN];
				//} while( memory_management_control_operation  !=  0 ) 
			//}
		//}
	//}
		
}Dec_Ref_Pic_Marking;

typedef struct Slice_Header
{
	int first_mb_in_slice;
	int slice_type;
	int pic_parameter_set_id;
	int frame_num;
	//if( !frame_mbs_only_flag ) {
		int field_pic_flag;
		//if( field_pic_flag )
			int bottom_field_flag;
	//}
	//if( nal_unit_type = = 5 )
		int idr_pic_id;
	//if( pic_order_cnt_type = = 0 ) {
		int pic_order_cnt_lsb;
		//if( pic_order_present_flag && !field_pic_flag )
			int delta_pic_order_cnt_bottom;
	//}
	//if( pic_order_cnt_type = = 1 && !delta_pic_order_always_zero_flag ) {
		int delta_pic_order_cnt[2];
	//}
	//if( redundant_pic_cnt_present_flag )
		int redundant_pic_cnt;
	//if( slice_type = = B )
		int direct_spatial_mv_pred_flag;
	//if( slice_type = = P | | slice_type = = SP | | slice_type = = B ) {
		int num_ref_idx_active_override_flag;
		//if( num_ref_idx_active_override_flag ) {
		int num_ref_idx_l0_active_minus1;
		//if( slice_type = = B )
		int num_ref_idx_l1_active_minus1;
		//}
	//}
	//ref_pic_list_reordering( )
	Ref_Pic_List_Reordering *ref_pic_list_reordering;
	//if( ( weighted_pred_flag && ( slice_type = = P | | slice_type = = SP ) ) | |( weighted_bipred_idc = = 1 && slice_type = = B ) )
		//pred_weight_table( )
		Pred_Weight_Table *pred_weight_table;
	//if( nal_ref_idc != 0 )
		//dec_ref_pic_marking( )
		Dec_Ref_Pic_Marking *dec_ref_pic_marking;
	//if( entropy_coding_mode_flag && slice_type != I && slice_type != SI )
		int cabac_init_idc;
	int slice_qp_delta;
	//if( slice_type = = SP | | slice_type = = SI ) {
		//if( slice_type = = SP )
			int sp_for_switch_flag;
		int slice_qs_delta_sp_si; /*RENAME*/
		//}
	//if( deblocking_filter_control_present_flag ) {
		int disable_deblocking_filter_idc;
		//if( disable_deblocking_filter_idc != 1 ) {
			int slice_alpha_c0_offset_div2;
			int slice_beta_offset_div2;
			//}
		//}
	//if( num_slice_groups_minus1 > 0 &&slice_group_map_type >= 3 && slice_group_map_type <= 5)
		int slice_group_change_cycle;			
}Slice_Header;


typedef struct Macroblock_Layer
{
	int mb_type;
	//if( mb_type = = I_PCM ) {
		//while( !byte_aligned( ) )
			int pcm_alignment_zero_bit;
		//for( i = 0; i < 256; i++ )
			int pcm_sample_luma[256];
		//for( i = 0; i < 2 * MbWidthC * MbHeightC; i++ )
			int *pcm_sample_chroma;
	//} else {
		//noSubMbPartSizeLessThan8x8Flag = 1
		//if( mb_type != I_NxN && MbPartPredMode( mb_type, 0 ) != Intra_16x16 && NumMbPart( mb_type ) = = 4 ) {
		//sub_mb_pred( mb_type )
		//for( mbPartIdx = 0; mbPartIdx < 4; mbPartIdx++ )
			//if( sub_mb_type[ mbPartIdx ] != B_Direct_8x8 ) {
				//if( NumSubMbPart( sub_mb_type[ mbPartIdx ] ) > 1 )
					//noSubMbPartSizeLessThan8x8Flag = 0
				//} else if( !direct_8x8_inference_flag )
					//noSubMbPartSizeLessThan8x8Flag = 0
	//} else {
		//if( transform_8x8_mode_flag && mb_type = = I_NxN )
			int transform_size_8x8_flag;
		//mb_pred( mb_type )
	//}

	//if( MbPartPredMode( mb_type, 0 ) != Intra_16x16 ) {
		int coded_block_pattern;
	//if( CodedBlockPatternLuma > 0 && transform_8x8_mode_flag && mb_type != I_NxN && noSubMbPartSizeLessThan8x8Flag && ( mb_type != B_Direct_16x16 | | direct_8x8_inference_flag ) )
		int transform_size_8x8_flag_1;
	//}
	//if( CodedBlockPatternLuma > 0 | | CodedBlockPatternChroma > 0 | | MbPartPredMode( mb_type, 0 ) = = Intra_16x16 ) {
		int mb_qp_delta;
		//residual( )
		//}
	//}
	//}	
}Macroblock_Layer;



typedef struct Slice_Data
{
	//if( entropy_coding_mode_flag )
	   //while( !byte_aligned( ) )
	   	int cabac_alignment_one_bit;
		int MbaffFrameFlag;
		int CurrMbAddr;
	//CurrMbAddr = first_mb_in_slice * ( 1 + MbaffFrameFlag )
	//moreDataFlag = 1
	//prevMbSkipped = 0
	//do {
	   //if( slice_type != I && slice_type != SI )
	      //if( !entropy_coding_mode_flag ) {
	         int mb_skip_run;
		//prevMbSkipped = ( mb_skip_run > 0 )
		//for( i=0; i<mb_skip_run; i++ )
		   //CurrMbAddr = NextMbAddress( CurrMbAddr )
		//moreDataFlag = more_rbsp_data( )
	   //} else {
	   	int mb_skip_flag;
		//moreDataFlag = !mb_skip_flag
	//}
	//if( moreDataFlag ) {
		//if( MbaffFrameFlag && ( CurrMbAddr % 2 = = 0 | |( CurrMbAddr % 2 = = 1 && prevMbSkipped ) ) )
			int mb_field_decoding_flag;
		//macroblock_layer( )
		Macroblock_Layer *macroblock_layer;
	//}
	//if( !entropy_coding_mode_flag )
		//moreDataFlag = more_rbsp_data( )
	//else {
		//if( slice_type != I && slice_type != SI )
			//prevMbSkipped = mb_skip_flag
		//if( MbaffFrameFlag && CurrMbAddr % 2 = = 0 )
			//moreDataFlag = 1
		//else {
			int end_of_slice_flag;
			//moreDataFlag = !end_of_slice_flag
		//}
	//}
	//CurrMbAddr = NextMbAddress( CurrMbAddr )
	//}while( moreDataFlag )
	//}
	
}Slice_Data;


typedef struct Slice_Data_Partition_A_Layer_Rbsp
{
	Slice_Header *slice_header;
	int slice_id;
	Slice_Data *slice_data;
}Slice_Data_Partition_A_Layer_Rbsp;


typedef struct H264_Context
{
	Nal_Unit *nal_unit;
	Seq_Parameter_Set *seq_parameter_set;
	Seq_Parameter_Set_Ext *sps_ext;
	Pic_Parameter_Set *pic_parameter_set;
	Slice_Header *slice_header;
	Slice_Data *slice_data;
}H264_Context;

#endif
